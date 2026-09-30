'use strict';
/**
 * NuGet supply-chain analysis — the layer the CVE scanners do not cover.
 *
 * Trivy and Snyk answer "is this version vulnerable?". They do NOT ask the NuGet-specific
 * attack questions: which FEED does an id resolve from, is resolution pinned and hash-verified,
 * does anything run at restore or install time, does the id look shaped like a squat. This
 * module answers those, from repository evidence alone, with the framework's canonical finding
 * model so the results correlate alongside tool findings.
 *
 * Shape: satisfies the adapter contract (id/name/kind/stacks/detect/run/parse) so it can be
 * registered exactly like an adapter, but needs NO external tool — detect() is always true.
 * What it degrades on instead is PROJECT SHAPE: a directory with no NuGet artifacts at all
 * returns NOT_APPLICABLE with zero findings, never an exception. An unexpected internal error
 * returns FAILED with a note — a crash is a bug, data is never an exception.
 *
 * SINGLE ENTRY FUNCTION: analyze(sourcePath, options) -> RunResult.
 * See WIRING.md for the one-line registration the CLI needs.
 */

const path = require('path');
const C = require('../core/adapter-contract');
const { buildInventory } = require('./scan');
const { selfCheck } = require('./finding');
const { dependencyConfusion } = require('./checks/dependency-confusion');
const { feedCredentials } = require('./checks/feed-credentials');
const { lockfilePinning } = require('./checks/lockfile-pinning');
const { nameRisk } = require('./checks/name-risk');
const { restoreExecution } = require('./checks/restore-execution');

const ID = 'supplychain';
const VERSION = '1.0.0';

const CHECKS = [
  ['dependency confusion / substitution', dependencyConfusion],
  ['feed and credential misconfiguration', feedCredentials],
  ['lockfile and pinning integrity', lockfilePinning],
  ['package-name risk heuristics', nameRisk],
  ['restore-time execution surface', restoreExecution]
];

/**
 * THE entry function.
 * @param {string} sourcePath  directory to analyse (never mutated)
 * @param {object} [options]   { outPath } — where a raw inventory copy may be written
 * @returns {Promise<RunResult>} contract-valid RunResult; never rejects, never throws
 */
async function analyze(sourcePath, options = {}) {
  const started = Date.now();
  const root = path.resolve(String(sourcePath || '.'));
  const command = 'internal: nuget supply-chain static analysis (reads manifests, nuget.config, ' +
    'packages.lock.json, packages/, nuspec — no external tool, no network)';

  try {
    const inv = buildInventory(root);

    if (!inv.hasNuGetSurface) {
      return {
        status: 'NOT_APPLICABLE', tool: ID, version: VERSION, command, exitCode: 0,
        durationMs: Date.now() - started, findings: [],
        notes: 'No NuGet artifacts of any kind were found under ' + root +
          ' (no nuget.config, packages.config, *.csproj/vbproj/fsproj, Directory.Packages.props, ' +
          'packages.lock.json, .nuspec, packages/ or install scripts). There is nothing for ' +
          'NuGet supply-chain analysis to reason about.',
        limitations: 'This is NOT a clean result — no NuGet surface was examined because none exists here.'
      };
    }

    // Write the parsed inventory for reproducibility, exactly as adapters persist raw output.
    let rawPath;
    if (options.outPath) {
      try {
        const fs = require('fs');
        rawPath = path.join(options.outPath, 'raw', 'supplychain.inventory.json');
        fs.mkdirSync(path.dirname(rawPath), { recursive: true });
        // The inventory cannot carry credentials — the nuget.config parser redacts at parse time.
        fs.writeFileSync(rawPath, JSON.stringify(inv, (k, v) => k === 'text' ? undefined : v, 2));
      } catch { rawPath = undefined; }
    }

    // parse() is pure model -> findings and must stay contract-clean (array only), so the
    // internal runner that also collects per-check failures is used here instead.
    const { findings, failures } = runChecks(inv);

    const result = {
      status: 'EXECUTED', tool: ID, version: VERSION, command, exitCode: 0,
      durationMs: Date.now() - started,
      findings,
      rawPath,
      notes: `NuGet supply-chain analysis examined ${inv.nugetConfigs.length} nuget.config(s), ` +
        `${inv.projects.length} project(s), ${inv.packagesConfig.length} packages.config, ` +
        `${inv.centralProps.length} central-versions file(s), ${inv.lockfiles.length} lockfile(s), ` +
        `${inv.nuspecs.length} nuspec(s), ${inv.installScripts.length} install script(s), ` +
        `${inv.packageBuildFiles.length} package build file(s) and reported ${findings.length} finding(s).` +
        (failures.length ? ` CHECKS DEGRADED: ${failures.join(' | ')}` : ''),
      limitations: 'Static, offline, repository-only: package resolution was NOT executed, no feed ' +
        'was contacted, so whether a public id is registered, which exact binary a restore would ' +
        'fetch today, and whether a script\'s logic is malicious are all explicitly UNVERIFIED. ' +
        'Multiple nuget.config files are read individually; hierarchical NuGet merge semantics ' +
        '(nearest-wins per section, machine/user inheritance) are approximated and flagged at ' +
        'lower confidence where a conclusion depends on them. bin/ and obj/ are not scanned.'
    };
    return result;
  } catch (e) {
    return C.failed(ID,
      `NuGet supply-chain analysis failed internally: ${String(e && e.message || e).slice(0, 300)}`,
      { command, durationMs: Date.now() - started });
  }
}

/**
 * Run every check over a parsed inventory, collecting contract violations and check crashes
 * as DATA (the RunResult notes name them) instead of letting one bad check sink the run.
 * @returns { findings: [...canonical], failures: [...string] }
 */
function runChecks(inv) {
  const findings = [];
  const failures = [];
  for (const [name, check] of CHECKS) {
    try {
      const produced = check(inv) || [];
      const problems = selfCheck(produced, `supplychain/${name}`);
      if (problems.length) failures.push(`${name}: contract violations — ${problems.slice(0, 3).join('; ')}`);
      findings.push(...produced);
    } catch (e) {
      failures.push(`${name}: threw ${String(e && e.message || e).slice(0, 120)}`);
    }
  }
  return { findings, failures };
}

/**
 * Pure: parsed inventory -> canonical findings. No I/O; accepts a JSON string for
 * fixture-style testing. Returns [] on junk input — it never invents findings, and a
 * per-check failure is visible in analyze()'s RunResult notes rather than thrown here.
 */
function parse(raw, ctx) {
  let inv = raw;
  if (typeof inv === 'string') {
    try { inv = JSON.parse(inv); } catch { return []; }
  }
  if (!inv || typeof inv !== 'object' || !Array.isArray(inv.nugetConfigs)) return [];
  return runChecks(inv).findings;
}

// ---- adapter-contract surface ---------------------------------------------------------------

/** Always available: everything it needs is in the repository itself. */
async function detect(ctx) {
  return {
    available: true,
    version: VERSION,
    command: 'node (built in)',
    reason: null
  };
}

/** Adapter-contract run(). ctx needs sourcePath; outPath is honoured when present. */
async function run(ctx) {
  const c = ctx || {};
  return analyze(c.sourcePath || '.', { outPath: c.outPath });
}

module.exports = {
  id: ID, name: 'NuGet Supply-Chain Analysis', kind: 'dependency',
  stacks: ['framework', 'core', 'both'],
  detect, run, parse,
  analyze                       // the single entry function other code should call
};
