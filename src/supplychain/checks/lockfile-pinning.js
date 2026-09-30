'use strict';
/**
 * CHECK 3 — lockfile and pinning integrity.
 *
 * Reproducible restore is the defence that makes every other supply-chain check verifiable:
 * with a committed lockfile and --locked-mode, what was reviewed is what restores. This check
 * reports, with file/line evidence:
 *   - PackageReference project without a packages.lock.json (restore not reproducible)
 *   - lockfile present but DISAGREEING with the manifest (stale or hand-edited) — CONFIRMED
 *   - lockfile present but older on disk than the manifest — UNVERIFIED, mtimes can be
 *     rewritten by git operations; stated as a prompt to verify, never as proof
 *   - package entries missing their contentHash
 *   - floating versions ("1.*", "*") and range versions in PackageReference, CPM
 *     (Directory.Packages.props) and packages.config
 *   - a lockfile that is not valid JSON at all
 */

const fs = require('fs');
const path = require('path');
const { buildFinding } = require('../finding');

const MAX_LIST = 12;   // evidence lists at most this many entries, then says how many were cut

const listWith = (items) => {
  const head = items.slice(0, MAX_LIST).join('\n');
  return items.length > MAX_LIST
    ? head + `\n... and ${items.length - MAX_LIST} more`
    : head;
};

/** Directory of a project file in repo-relative, forward-slash form. */
const dirOf = relFile => path.posix.dirname(relFile.split(path.sep).join('/'));

function lockfilePinning(inv) {
  const out = [];

  // ---- central package versions, for resolving CPM references -------------------------------
  const cpm = new Map();   // lowercase id -> { version, file, line }
  for (const cp of inv.centralProps) {
    for (const v of cp.model.versions) {
      const key = v.id.toLowerCase();
      if (!cpm.has(key)) cpm.set(key, v);
    }
  }
  const cpmManaged = inv.centralProps.some(cp => cp.model.centrallyManaged &&
    cp.model.centrallyManaged.value !== false);

  // ---- floating / range / unpinned references, aggregated per manifest -----------------------
  const pinningProblems = (refs, file) => {
    const floating = [], missing = [];
    for (const r of refs) {
      const cpmEntry = cpm.get(r.id.toLowerCase());
      // A CPM entry IS the pin. When it exists, the props file owns the verdict: its floating
      // entries are reported ONCE, where they are defined, by the Directory.Packages.props
      // pass below — never duplicated per consuming project.
      if (r.version.kind === 'missing' && cpmEntry) continue;
      if (!cpmEntry && cpmManaged && r.version.kind === 'missing') {
        missing.push(`${r.id} (line ${r.line}) — no Version attribute and no CPM entry`);
        continue;
      }
      const v = r.version.kind !== 'missing' ? r.version : null;
      if (!v) { missing.push(`${r.id} (line ${r.line})`); continue; }
      if (v.kind === 'floating') floating.push(`${r.id} Version="${v.text}" (line ${r.versionLine})`);
      else if (v.kind === 'range') floating.push(`${r.id} Version="${v.text}"${v.unbounded ? ' — upper bound open' : ''} (line ${r.versionLine})`);
    }
    return { floating, missing, file };
  };

  for (const p of inv.projects) {
    const probs = pinningProblems(p.model.packageRefs, p.file);
    const all = probs.floating.concat(probs.missing);
    if (!all.length) continue;
    const first = p.model.packageRefs.find(r =>
      r.version.kind === 'floating' || r.version.kind === 'range' || r.version.kind === 'missing');
    out.push(buildFinding('nuget-floating-version', {
      title: `${all.length} package reference${all.length === 1 ? ' is' : 's are'} not exactly pinned in ${p.file}`,
      severity: 'MEDIUM',
      confidence: 'CONFIRMED',
      cwe: ['CWE-1357'],
      owasp: ['A08:2021'],
      location: { file: p.file, startLine: first ? first.versionLine : 1 },
      evidence: { snippet: listWith(all), language: 'xml' },
      problem: 'These references use a floating version ("*"/"1.*"), a version range with an open ' +
        'bound, or no version at all (and no Central Package Management entry). What restores can ' +
        'change from day to day without any commit.',
      impact: 'A build that was reviewed as clean can pick up a different package the next day — ' +
        'including a substituted one, if the feed topology ever allows it. Floating versions make ' +
        'every other integrity check temporarily true at best.',
      recommendation: 'Pin each reference to an exact version, or move to Central Package Management ' +
        'with RestorePackagesWithLockFile and restore with --locked-mode; automation (Renovate/' +
        'Dependabot) can then own upgrades deliberately instead of restore deciding implicitly.',
      tests: ['O-003'],
      effort: 'SMALL',
      priority: 'P2',
      engine: 'config-xml'
    }));
  }

  // ---- floating CPM versions, at the point they are defined ----------------------------------
  for (const cp of inv.centralProps) {
    const bad = cp.model.versions.filter(v => v.version.kind === 'floating' || v.version.kind === 'range');
    if (!bad.length) continue;
    out.push(buildFinding('nuget-floating-version', {
      title: `Central package versions in ${cp.file} are not exact pins`,
      severity: 'MEDIUM',
      confidence: 'CONFIRMED',
      cwe: ['CWE-1357'],
      owasp: ['A08:2021'],
      location: { file: cp.file, startLine: bad[0].line },
      evidence: { snippet: listWith(bad.map(v => `${v.id} Version="${v.version.text}" (line ${v.line})`)), language: 'xml' },
      problem: 'Directory.Packages.props is the single pin for every project that consumes these ' +
        'ids, and at least one entry floats.',
      impact: 'One floating entry here silently floats the version across every consuming project ' +
        'in the repository.',
      recommendation: 'Replace wildcards and ranges with exact versions; let automation propose the bump.',
      tests: ['O-003'],
      effort: 'TRIVIAL',
      priority: 'P2',
      engine: 'config-xml'
    }));
  }

  // ---- packages.config ranges vs exact pins ---------------------------------------------------
  for (const pc of inv.packagesConfig) {
    const ranged = pc.model.packages.filter(p => p.version.kind === 'range' || p.version.kind === 'floating');
    if (!ranged.length) continue;
    out.push(buildFinding('nuget-packages-config-range', {
      title: `packages.config uses version ranges instead of exact pins (${ranged.length} package${ranged.length === 1 ? '' : 's'})`,
      severity: 'MEDIUM',
      confidence: 'CONFIRMED',
      cwe: ['CWE-1357'],
      location: { file: pc.file, startLine: ranged[0].line },
      evidence: { snippet: listWith(ranged.map(p => `${p.id} version="${p.version.text}" (line ${p.line})`)), language: 'xml' },
      problem: 'packages.config entries with ranges resolve to whatever satisfies the range at ' +
        'install time; only a bare version (or [x.y.z]) pins.',
      impact: 'Reinstalling packages (Update-Package -reinstall, a new machine, a rebuilt CI agent) ' +
        'can silently pull different versions than the ones that were reviewed.',
      recommendation: 'Pin every entry to the exact version currently in packages/, and plan the ' +
        'migration to PackageReference, which adds NuGetAudit and a lockfile that packages.config can never have.',
      tests: ['O-003'],
      effort: 'SMALL',
      priority: 'P3',
      engine: 'config-xml'
    }));
  }

  // ---- per-project lockfile state --------------------------------------------------------------
  for (const p of inv.projects) {
    if (!p.model.packageRefs.length) continue;   // a project with no packages needs no lockfile

    const dir = dirOf(p.file);
    const lock = inv.lockfiles.find(l => dirOf(l.file) === dir);
    const hasDirsBuildProps = inv.rootBuild.some(rb =>
      /directory\.build\.props$/i.test(rb.file) &&
      (rb.text || '').match(/RestorePackagesWithLockFile/i));

    if (!lock) {
      const mitigation = p.model.lockFileEnabled || hasDirsBuildProps;
      out.push(buildFinding('nuget-lockfile-absent', {
        title: `No packages.lock.json beside ${p.file} — restore is not reproducible`,
        severity: 'MEDIUM',
        confidence: 'CONFIRMED',
        cwe: ['CWE-1357'],
        owasp: ['A08:2021'],
        location: { file: p.file, startLine: (p.model.lockFileEnabled && p.model.lockFileEnabled.line) || 1 },
        evidence: {
          snippet: mitigation
            ? 'RestorePackagesWithLockFile is enabled, but packages.lock.json does not exist next to this project'
            : `${p.model.packageRefs.length} PackageReference element(s); no packages.lock.json in ${dir || '.'}`,
          language: 'text'
        },
        problem: mitigation
          ? 'The project opts into lockfile generation, but no lockfile exists — restore has not been ' +
            'run with it enabled, or the generated file was never committed.'
          : 'The project restores ' + p.model.packageRefs.length + ' package(s) with no lockfile, so the ' +
            'transitive graph is chosen at restore time.',
        impact: 'There is no record of which exact package versions (including transitives) a build ' +
          'used, so a reviewed build and a rebuilt one can differ, and --locked-mode has nothing to ' +
          'enforce. Every integrity claim about this project\'s dependencies is provisional.',
        recommendation: 'Add <RestorePackagesWithLockFile>true</RestorePackagesWithLockFile>, commit the ' +
          'generated packages.lock.json, and restore with --locked-mode in CI so a drift fails the build.',
        tests: ['O-003'],
        effort: 'SMALL',
        priority: 'P2',
        engine: 'custom'
      }));
      continue;
    }

    // ---- lockfile present: integrity checks ----------------------------------------------------
    const lm = lock.model;
    if (!lm.parseOk) {
      out.push(buildFinding('nuget-lockfile-invalid', {
        title: `packages.lock.json beside ${p.file} is not valid JSON`,
        severity: 'MEDIUM',
        confidence: 'CONFIRMED',
        cwe: ['CWE-1357'],
        location: { file: lock.file, startLine: 1 },
        evidence: { snippet: `JSON parse error: ${lm.parseError}`, language: 'text' },
        problem: 'The lockfile exists but cannot be parsed, so locked-mode restore will fail or the ' +
          'file has been corrupted or hand-edited.',
        impact: 'The integrity anchor is broken: nothing can be concluded about which packages this ' +
          'project restores.',
        recommendation: 'Regenerate with dotnet restore after enabling RestorePackagesWithLockFile, ' +
          'review the diff, and commit the regenerated file.',
        tests: ['O-003'],
        effort: 'TRIVIAL',
        priority: 'P2',
        engine: 'custom'
      }));
      continue;
    }

    // (a) manifest disagrees with lockfile — CONFIRMED evidence of staleness or drift
    const conflicts = [], absent = [];
    for (const r of p.model.packageRefs) {
      const v = r.version.kind !== 'missing' ? r.version.text
        : (cpm.get(r.id.toLowerCase()) || { version: { text: null } }).version.text;
      const entry = lm.entries.find(e => e.id.toLowerCase() === r.id.toLowerCase());
      if (!entry) { absent.push(`${r.id} (declared ${p.file}:${r.line}, not in lockfile)`); continue; }
      if (v && entry.requested) {
        const req = entry.requested.replace(/^\[|\)$/g, '').split(',')[0].trim();
        if (req && req !== String(v).trim() && !/\*/.test(v)) {
          conflicts.push(`${r.id}: manifest pins ${v}, lockfile requested ${entry.requested} ` +
            `(lockfile line ${entry.line})`);
        }
      }
    }
    if (conflicts.length || absent.length) {
      const detail = conflicts.concat(absent);
      out.push(buildFinding('nuget-lockfile-stale', {
        title: `packages.lock.json disagrees with ${p.file} (${detail.length} package${detail.length === 1 ? '' : 's'})`,
        severity: 'MEDIUM',
        confidence: 'CONFIRMED',
        cwe: ['CWE-1357'],
        owasp: ['A08:2021'],
        location: { file: lock.file, startLine: 1 },
        evidence: { snippet: listWith(detail), language: 'text' },
        problem: conflicts.length
          ? 'Requested versions in the lockfile no longer match the manifest\'s pins.'
          : 'The manifest declares packages the lockfile has never recorded.',
        impact: 'The lockfile is stale or was hand-edited: --locked-mode restore will fail, or worse, ' +
          'the file was edited to make a different graph look locked. Either way the lock no longer ' +
          'describes what the manifest asks for.',
        recommendation: 'Run dotnet restore to regenerate, review the diff package by package (never ' +
          'accept an unexplained id change), and re-commit.',
        tests: ['O-003'],
        effort: 'SMALL',
        priority: 'P2',
        engine: 'custom'
      }));
    }

    // (b) mtime-based staleness — weak evidence, labelled as such
    try {
      const projStat = fs.statSync(path.join(inv.root, p.file));
      const lockStat = fs.statSync(path.join(inv.root, lock.file));
      if (projStat.mtimeMs > lockStat.mtimeMs + 1000) {
        out.push(buildFinding('nuget-lockfile-mtime-stale', {
          title: `packages.lock.json is older on disk than ${p.file}`,
          severity: 'LOW',
          confidence: 'UNVERIFIED',
          cwe: ['CWE-1357'],
          location: { file: lock.file, startLine: 1 },
          evidence: {
            snippet: `manifest mtime ${projStat.mtime.toISOString()} > lockfile mtime ${lockStat.mtime.toISOString()}`,
            language: 'text',
            toolOutput: 'filesystem mtimes only — git checkout and rebases rewrite them'
          },
          problem: 'The manifest was modified more recently than the lockfile. This may be perfectly ' +
            'innocent (checkout order) or the lockfile may genuinely lag the manifest.',
          impact: 'IF real, restores diverge from the manifest\'s intent. mtimes cannot establish that; ' +
            'treat this as a prompt to run a locked-mode restore, not as a defect.',
          recommendation: 'Run dotnet restore --locked-mode: failure proves staleness and tells you ' +
            'exactly which packages moved.',
          tests: ['O-003'],
          effort: 'TRIVIAL',
          priority: 'P3',
          engine: 'custom'
        }));
      }
    } catch { /* stat unavailable — skip the weak signal rather than guess */ }

    // (c) entries without contentHash
    const noHash = lm.entries.filter(e => !e.hasHash && (e.resolved || e.type === 'Direct'));
    if (noHash.length) {
      out.push(buildFinding('nuget-lockfile-missing-hash', {
        title: `packages.lock.json records ${noHash.length} package${noHash.length === 1 ? '' : 's'} without a contentHash`,
        severity: 'MEDIUM',
        confidence: 'CONFIRMED',
        cwe: ['CWE-494'],
        owasp: ['A08:2021'],
        location: { file: lock.file, startLine: noHash[0].line || 1 },
        evidence: {
          snippet: listWith(noHash.map(e =>
            `${e.id}${e.resolved ? ' ' + e.resolved : ''} — no contentHash (line ${e.line})`)),
          language: 'json'
        },
        problem: 'These entries pin a version but carry no hash, so the bytes that version restores ' +
          'are whatever the serving feed hands over.',
        impact: 'The hash is the last mechanical check that a package\'s bytes were not swapped — the ' +
          'exact swap a feed compromise or an in-path attacker performs. Entries without one are ' +
          'protected by nothing but the feed\'s goodwill.',
        recommendation: 'Regenerate the lockfile with a current SDK (hashes are written automatically) ' +
          'and investigate why the entries lost theirs — hand-editing is a plausible cause.',
        tests: ['O-003'],
        effort: 'SMALL',
        priority: 'P2',
        engine: 'custom'
      }));
    }
  }

  // ---- lockfiles with NO project beside them (orphaned) — informational only -------------------
  for (const lock of inv.lockfiles) {
    const dir = dirOf(lock.file);
    const owner = inv.projects.find(p => dirOf(p.file) === dir);
    if (owner) continue;
    if (!lock.model.parseOk) continue;
    const noHash = lock.model.entries.filter(e => !e.hasHash && (e.resolved || e.type === 'Direct'));
    if (!noHash.length) continue;
    out.push(buildFinding('nuget-lockfile-missing-hash', {
      title: `packages.lock.json in ${dir || '.'} has package entries without a contentHash`,
      severity: 'MEDIUM',
      confidence: 'CONFIRMED',
      cwe: ['CWE-494'],
      owasp: ['A08:2021'],
      location: { file: lock.file, startLine: noHash[0].line || 1 },
      evidence: {
        snippet: listWith(noHash.map(e => `${e.id}${e.resolved ? ' ' + e.resolved : ''} — no contentHash (line ${e.line})`)),
        language: 'json'
      },
      problem: 'Package entries pin versions but record no hash, so the restored bytes are whatever ' +
        'the feed serves.',
      impact: 'No mechanical integrity check exists for these packages.',
      recommendation: 'Regenerate the lockfile with a current SDK and commit it.',
      tests: ['O-003'],
      effort: 'SMALL',
      priority: 'P2',
      engine: 'custom'
    }));
  }

  return out;
}

module.exports = { lockfilePinning };
