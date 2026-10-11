// dotnet-codereview-framework — src/adapters/snyk.js
// Author: Amr Kadry (github.com/Amrkadry) · MIT License
'use strict';
/**
 * Snyk adapter — open-source dependency scanning (`snyk test`).
 *
 * Schema verified against Snyk's documented JSON output. Two behaviours matter and are easy to
 * get wrong:
 *
 *  1. `snyk test` EXITS 1 WHEN VULNERABILITIES ARE FOUND. Treating exit 1 as failure would report
 *     a successful scan as a broken tool, and — worse — produce an empty result that looks clean.
 *     Exit 0 and 1 are both EXECUTED here; only other codes are FAILED.
 *
 *  2. With `--all-projects` the top level is an ARRAY of project results, not an object. Handling
 *     only the object shape silently drops every project but the first.
 *
 * The `from` chain is preserved in the evidence because transitive depth changes the remediation:
 * a direct dependency is a version bump, a transitive one may not be upgradable at all.
 */

const { execFileSync } = require('child_process');
const fs = require('fs');
const path = require('path');
const C = require('../core/adapter-contract');

const ID = 'snyk';

function detect(ctx) {
  let version;
  try {
    version = execFileSync('snyk', ['--version'], { encoding: 'utf8', timeout: 60000 }).trim();
  } catch {
    return {
      available: false,
      reason: 'snyk is not installed, so no Snyk dependency scan ran.',
      command: 'npm install -g snyk && snyk auth'
    };
  }
  // Snyk needs authentication; an unauthenticated run fails in a way that is easy to misread.
  const env = ctx.env || process.env;
  if (!env.SNYK_TOKEN) {
    let configured = '';
    try { configured = execFileSync('snyk', ['config', 'get', 'api'], { encoding: 'utf8', timeout: 30000 }).trim(); }
    catch { /* treated as unconfigured */ }
    if (!configured) {
      return {
        available: false, version,
        reason: 'snyk is installed but not authenticated. Without a token it cannot query the ' +
          'vulnerability database, so it would produce no results — which must not be mistaken ' +
          'for a clean dependency tree.',
        command: 'set SNYK_TOKEN=<token>   # or run: snyk auth'
      };
    }
  }
  return { available: true, version, command: 'snyk --version' };
}

function run(ctx) {
  const d = detect(ctx);
  if (!d.available) return C.notAvailable(ID, d.reason, d.command);

  const rawPath = path.join(ctx.outPath, 'raw', 'snyk.json');
  fs.mkdirSync(path.dirname(rawPath), { recursive: true });

  const args = ['test', '--all-projects', '--json', `--json-file-output=${rawPath}`, ctx.sourcePath];
  const command = 'snyk ' + args.join(' ');
  const started = Date.now();

  let exitCode = 0;
  try {
    execFileSync('snyk', args, { encoding: 'utf8', timeout: 20 * 60 * 1000, stdio: 'pipe' });
  } catch (e) {
    exitCode = typeof e.status === 'number' ? e.status : 1;
    // 0 = no vulns, 1 = vulns found (success), 2 = failure, 3 = no supported projects.
    if (exitCode === 3) {
      return {
        status: 'NOT_APPLICABLE', tool: ID, version: d.version, command, exitCode, findings: [],
        notes: 'Snyk found no supported manifest to scan under this path.',
        limitations: 'No dependency data was obtained from Snyk.'
      };
    }
    if (exitCode !== 1 && !fs.existsSync(rawPath)) {
      return C.failed(ID, `snyk exited ${exitCode}: ${String(e.stderr || e.message).slice(0, 300)}`,
        { command, exitCode, durationMs: Date.now() - started });
    }
  }

  let raw = '';
  try { raw = fs.readFileSync(rawPath, 'utf8'); } catch { /* handled */ }
  if (!raw.trim()) return C.failed(ID, 'snyk produced an empty report.', { command, exitCode, rawPath });

  const findings = parse(raw, ctx);
  const transitive = findings.filter(f => f._transitive).length;
  findings.forEach(f => { delete f._transitive; });

  return {
    status: 'EXECUTED', tool: ID, version: d.version, command, exitCode,
    durationMs: Date.now() - started, rawPath, findings,
    notes: `Snyk reported ${findings.length} vulnerability(ies), ${transitive} of them transitive. ` +
      'Exit code 1 means vulnerabilities were found, which is a successful scan.',
    limitations: 'Reports on declared dependencies only. It does not establish whether the vulnerable ' +
      'code path is reachable from this application, so exploitability still needs judgement.'
  };
}

/** Pure. Handles both the single-project object and the --all-projects array. */
function parse(raw, ctx) {
  let doc;
  try { doc = typeof raw === 'string' ? JSON.parse(raw) : raw; } catch { return []; }
  if (!doc || typeof doc !== 'object') return [];

  const projects = Array.isArray(doc) ? doc : [doc];
  const out = [];
  const seen = new Set();   // snyk repeats a vuln once per path; one finding per id+package

  for (const proj of projects) {
    if (!proj || typeof proj !== 'object') continue;
    const vulns = Array.isArray(proj.vulnerabilities) ? proj.vulnerabilities : [];
    const target = proj.displayTargetFile || proj.targetFile || proj.projectName || 'packages.config';

    for (const v of vulns) {
      if (!v || !v.id) continue;
      const key = `${v.id}|${v.packageName}|${v.version}`;
      if (seen.has(key)) continue;
      seen.add(key);

      const score = Number(v.cvssScore);
      const vector = typeof v.CVSSv3 === 'string' && /^CVSS:3/.test(v.CVSSv3) ? v.CVSSv3 : null;
      const ident = v.identifiers || {};
      const cves = (ident.CVE || []).filter(Boolean);
      const cwes = (ident.CWE || []).filter(c => /^CWE-\d+$/.test(c));
      const chain = Array.isArray(v.from) ? v.from : [];
      const isTransitive = chain.length > 2;
      const fixedIn = Array.isArray(v.fixedIn) && v.fixedIn.length ? v.fixedIn[0] : null;

      out.push({
        title: `${v.packageName || 'package'} ${v.version || ''}: ${v.title || v.id}`.trim().slice(0, 200),
        category: 'dependency',
        subcategory: v.id,
        severity: isFinite(score) && score > 0
          ? C.severityFromCvss(score)
          : C.normaliseSeverity(v.severity, 'MEDIUM'),
        confidence: 'CONFIRMED',
        cvss: isFinite(score) && score > 0 ? {
          version: '3.1', score: Math.round(score * 10) / 10, vector,
          severity: C.severityFromCvss(score),
          note: vector ? undefined : 'Score from the Snyk database; no v3 vector supplied.'
        } : null,
        cwe: cwes.length ? cwes : undefined,
        advisories: [...new Set([...cves, v.id])],
        owasp: ['A06:2021'],
        package: { name: v.packageName, installed: v.version, fixed: fixedIn },
        location: { file: String(target).replace(/\\/g, '/') },
        evidence: {
          // The dependency chain is the most actionable single fact Snyk provides.
          snippet: chain.length ? chain.join('\n  -> ') : `${v.packageName} ${v.version}`,
          language: 'text',
          toolOutput: `snyk ${v.id} severity=${v.severity}` +
            (isFinite(score) ? ` cvss=${score}` : '') +
            ` upgradable=${!!v.isUpgradable} patchable=${!!v.isPatchable}`
        },
        problem: String(v.description || v.title || '').slice(0, 1200),
        impact: isTransitive
          ? `Reachable as a TRANSITIVE dependency, ${chain.length - 1} level(s) deep via ` +
            `${chain.slice(0, 2).join(' -> ')}. A transitive advisory often cannot be fixed by a ` +
            'direct version bump, so the parent package may need upgrading or replacing.'
          : `Reachable as a DIRECT dependency of this project.`,
        recommendation: v.isUpgradable && Array.isArray(v.upgradePath) && v.upgradePath.length
          ? `Upgrade along the path: ${v.upgradePath.filter(Boolean).join(' -> ')}. Then run the ` +
            'regression tests for every feature that touches this package.'
          : fixedIn
            ? `Upgrade ${v.packageName} to ${fixedIn} or later.`
            : v.isPatchable
              ? 'No upgrade is available, but Snyk offers a patch. Assess the patch, or replace the package.'
              : 'No upgrade or patch is available. Assess whether the vulnerable code path is reachable ' +
                'here; if it is, replace the package or apply the advisory mitigation.',
        tests: ['O-001', 'DEP-001'],
        detection: { class: 'DETERMINISTIC', rules: [{ engine: 'snyk', ruleId: v.id, status: 'EXISTS' }] },
        sources: [{ tool: ID, sourceFindingId: v.id, status: 'REPORTED' }],
        status: 'OPEN',
        references: [`https://security.snyk.io/vuln/${v.id}`]
          .concat(cves.map(c => `https://nvd.nist.gov/vuln/detail/${c}`)).slice(0, 4),
        _transitive: isTransitive
      });
    }
  }
  return out;
}

module.exports = {
  id: ID, name: 'Snyk', kind: 'dependency',
  stacks: ['framework', 'core', 'both'],
  detect, run, parse
};
