// dotnet-codereview-framework — src/supplychain/checks/restore-execution.js
// Author: Amr Kadry (github.com/Amrkadry) · MIT License
'use strict';
/**
 * CHECK 5 — restore-time / install-time execution surface.
 *
 * Legacy NuGet (packages.config world) executed install.ps1 / init.ps1 from a package's
 * tools/ directory on install, and auto-imported packages/<id>/build/<id>.targets. Package-
 * provided .props/.targets files execute arbitrary MSBuild logic at build time in BOTH worlds.
 * A package that ships any of these is a package that runs code on the developer machine and
 * the build agent — which is what makes NuGet supply-chain attacks code execution and not
 * merely a wrong version number.
 *
 * Detected, all with file/line evidence:
 *   - install.ps1 / init.ps1 anywhere under packages/ (aggregated per restored package)
 *   - .props / .targets files inside a restored package directory
 *   - a csproj <Import> pulling a .targets/.props out of a package path
 *   - a .nuspec whose <file> entries ship a .ps1 into tools/ (the declaring form of the hook)
 *
 * Presence is a fact (CONFIRMED); whether the script is malicious is not decidable here, and
 * the text says so.
 */

const { buildFinding } = require('../finding');

/** Aggregate items by key, keeping the first location for the citation. */
function groupBy(items, keyOf) {
  const groups = new Map();
  for (const it of items) {
    const k = keyOf(it);
    if (!groups.has(k)) groups.set(k, []);
    groups.get(k).push(it);
  }
  return groups;
}

const MAX_LIST = 8;

function restoreExecution(inv) {
  const out = [];

  // ---- install/init scripts under packages/<id> ------------------------------------------------
  for (const [pkgDir, scripts] of groupBy(inv.installScripts, s => s.packageDir || s.file)) {
    const head = scripts[0];
    const lines = scripts.map(s => `${s.file}${s.head && s.head.length ? ' — starts: ' + JSON.stringify(s.head[0]).slice(0, 120) : ''}`);
    const list = lines.slice(0, MAX_LIST).join('\n') +
      (lines.length > MAX_LIST ? `\n... and ${lines.length - MAX_LIST} more` : '');
    out.push(buildFinding('nuget-install-script', {
      title: `Restored package directory ${pkgDir} ships NuGet install script(s) that run at install time`,
      severity: 'HIGH',
      confidence: 'CONFIRMED',
      cwe: ['CWE-494'],
      owasp: ['A08:2021'],
      location: { file: head.file, startLine: 1 },
      evidence: { snippet: list, language: 'text' },
      problem: 'install.ps1/init.ps1 in a package\'s tools/ folder is executed by legacy NuGet ' +
        '(packages.config restore/install in Visual Studio and nuget.exe) with full user rights, ' +
        'as is any build/<id>.targets imported at build time.',
      impact: 'Whoever controls this package (or a feed serving a tampered copy of it) controls ' +
        'code that runs on every developer machine and build agent that installs it. Presence of ' +
        'the hook is a fact; whether THIS script is malicious cannot be decided statically here — ' +
        'read it.',
      recommendation: 'Read the script end to end before the next restore. Prefer PackageReference, ' +
        'where install scripts are no longer executed at all; if the package genuinely needs one, ' +
        'pin it by hash in a lockfile and restore with --locked-mode, and vendor-audit the publisher.',
      tests: ['O-004'],
      effort: 'MEDIUM',
      priority: 'P1',
      engine: 'custom'
    }));
  }

  // ---- props/targets inside restored packages ----------------------------------------------------
  // Severity is graded on what the file DOES, not on the fact that it exists. Practically every
  // modern NuGet package ships buildTransitive/*.targets; reporting each one as HIGH buries the
  // real findings under the normal mechanics of restore. Only files containing an executable
  // construct (Exec/UsingTask/DownloadFile/script reference) are a build-time execution surface.
  const executing = [];
  const declarative = [];
  for (const [pkgDir, files] of groupBy(inv.packageBuildFiles, f => f.packageDir || f.file)) {
    const withExec = files.filter(f => f.executes);
    if (withExec.length) executing.push([pkgDir, files, withExec]);
    else declarative.push([pkgDir, files]);
  }

  for (const [pkgDir, files, withExec] of executing) {
    const head = withExec[0];
    const cite = head.execConstructs[0];
    const list = withExec.slice(0, MAX_LIST)
      .map(f => `${f.file}:${f.execConstructs[0].line} — ${f.execConstructs[0].why}`).join('\n') +
      (withExec.length > MAX_LIST ? `\n... and ${withExec.length - MAX_LIST} more` : '');
    out.push(buildFinding('nuget-package-msbuild-hook', {
      title: `Restored package ${pkgDir} ships MSBuild logic that EXECUTES at build time`,
      severity: 'HIGH',
      confidence: 'CONFIRMED',
      cwe: ['CWE-494'],
      owasp: ['A08:2021'],
      location: { file: head.file, startLine: cite.line },
      evidence: { snippet: `${cite.snippet}\n\n${list}`, language: 'xml' },
      problem: 'A .props/.targets file inside this restored package is imported automatically ' +
        '(packages.config world) or via the package\'s build/ folder (PackageReference world), and ' +
        `it contains an executable MSBuild construct — ${cite.why}.`,
      impact: 'The package gains code execution on every machine that builds against it — restore ' +
        'and build are both supply-chain execution points. Presence of the construct is a fact; ' +
        'whether THIS logic is malicious cannot be decided statically here — read it.',
      recommendation: 'Audit the cited .targets/.props logic; if the build logic is not required, ' +
        'exclude it (ExcludeAssets="build" on the reference); if it is required, pin the package by ' +
        'hash and restore with --locked-mode.',
      tests: ['O-004'],
      effort: 'MEDIUM',
      priority: 'P2',
      engine: 'custom'
    }));
  }

  if (declarative.length) {
    const names = declarative.map(([pkgDir]) => pkgDir);
    const list = names.slice(0, MAX_LIST).join('\n') +
      (names.length > MAX_LIST ? `\n... and ${names.length - MAX_LIST} more` : '');
    const total = declarative.reduce((n, [, files]) => n + files.length, 0);
    out.push(buildFinding('nuget-package-msbuild-declarative', {
      title: `${declarative.length} restored package(s) ship declarative MSBuild props/targets (no executable construct)`,
      severity: 'INFO',
      confidence: 'CONFIRMED',
      cwe: ['CWE-494'],
      owasp: ['A08:2021'],
      location: { file: declarative[0][1][0].file, startLine: 1 },
      evidence: { snippet: list, language: 'text' },
      problem: `${total} .props/.targets file(s) across these packages are imported at build time, ` +
        'but none contains an Exec, UsingTask, DownloadFile, WriteCodeFragment or script reference. ' +
        'They only declare items, properties and build warnings.',
      impact: 'This is the normal mechanics of a NuGet restore and is recorded for inventory ' +
        'completeness, not as an exploitable weakness. The import points still belong to whoever ' +
        'controls the package, so a tampered future version could add executable logic here.',
      recommendation: 'No action required on the current contents. To make the surface tamper-evident, ' +
        'pin every package by hash with a lockfile and restore with --locked-mode so a substituted ' +
        'copy fails the restore instead of silently changing the build.',
      tests: ['O-004'],
      effort: 'SMALL',
      priority: 'P3',
      engine: 'custom'
    }));
  }

  // ---- csproj importing package-provided MSBuild logic directly -----------------------------------
  // Graded the same way: an <Import> of a package-provided .props/.targets is standard restore
  // plumbing that Visual Studio writes automatically. It is only a build-time execution surface
  // when the imported file actually executes something, so resolve the import against the
  // classified build files and report presence-only imports once, as inventory.
  const BS = String.fromCharCode(92);  // avoid literal backslashes in regex sources
  const normImport = p => String(p || '').split(BS).join('/').replace(/^(\.\.\/)+/, '').toLowerCase();
  const execImports = [];
  const plainImports = [];
  for (const p of inv.projects) {
    for (const imp of p.model.importsFromPackages) {
      const want = normImport(imp.project);
      const hit = inv.packageBuildFiles.find(f => {
        const have = String(f.file || '').split(BS).join('/').toLowerCase();
        return want && (have === want || have.endsWith('/' + want) || want.endsWith(have));
      });
      if (hit && hit.executes) execImports.push({ p, imp, hit });
      else plainImports.push({ p, imp, hit });
    }
  }

  for (const { p, imp, hit } of execImports) {
    const cite = hit.execConstructs[0];
    out.push(buildFinding('nuget-project-imports-package-targets', {
      title: `${p.file} imports MSBuild logic that EXECUTES from a package path`,
      severity: 'HIGH',
      confidence: 'CONFIRMED',
      cwe: ['CWE-494'],
      owasp: ['A08:2021'],
      location: { file: p.file, startLine: imp.line },
      additionalLocations: [{ file: hit.file, note: `the imported file — ${cite.why} at line ${cite.line}` }],
      evidence: { snippet: `${imp.snippet}\n\n${hit.file}:${cite.line} — ${cite.snippet}`, language: 'xml' },
      problem: 'The project directly <Import>s a .props/.targets resolved from a NuGet packages ' +
        'directory, and that file contains an executable MSBuild construct, so the build executes ' +
        'whatever it contains at whatever version restores.',
      impact: 'A substituted or drifting package version swaps the imported build logic — code ' +
        'execution at build time with no code change in the repository.',
      recommendation: 'Pin the exact package version (and hash, via lockfile + --locked-mode), or ' +
        'vendor the needed targets into the repository so they are reviewed like code.',
      tests: ['O-004'],
      effort: 'SMALL',
      priority: 'P2',
      engine: 'config-xml'
    }));
  }

  if (plainImports.length) {
    const first = plainImports[0];
    const list = plainImports.slice(0, MAX_LIST)
      .map(({ p, imp, hit }) => `${p.file}:${imp.line} -> ${imp.project}${hit ? '' : ' (not restored here)'}`).join('\n') +
      (plainImports.length > MAX_LIST ? `\n... and ${plainImports.length - MAX_LIST} more` : '');
    out.push(buildFinding('nuget-project-imports-package-declarative', {
      title: `${plainImports.length} project <Import>(s) pull declarative MSBuild logic from a package path`,
      severity: 'INFO',
      confidence: 'CONFIRMED',
      cwe: ['CWE-494'],
      owasp: ['A08:2021'],
      location: { file: first.p.file, startLine: first.imp.line },
      evidence: { snippet: list, language: 'xml' },
      problem: 'These <Import> elements resolve .props/.targets out of the NuGet packages directory. ' +
        'Each imported file was read and none contains an Exec, UsingTask, DownloadFile, ' +
        'WriteCodeFragment or script reference — they are the restore plumbing Visual Studio ' +
        'writes automatically, not build-time code execution.',
      impact: 'No execution today. The import points remain under the control of whoever publishes ' +
        'the package, so a tampered future version could introduce executable logic at these lines ' +
        'without any change to the repository.',
      recommendation: 'Pin every package by hash with packages.lock.json and restore with ' +
        '--locked-mode, so a substituted package fails the restore rather than silently changing ' +
        'the build. Vendor any targets you genuinely depend on.',
      tests: ['O-004'],
      effort: 'SMALL',
      priority: 'P3',
      engine: 'config-xml'
    }));
  }

  // ---- nuspec DECLARING the hook: ships a .ps1 into tools/ ----------------------------------------
  for (const n of inv.nuspecs) {
    for (const sf of n.model.scriptFiles) {
      const sibling = inv.installScripts.find(s =>
        s.packageDir && n.file.startsWith(s.packageDir + '/')) || null;
      out.push(buildFinding('nuget-nuspec-declares-install-hook', {
        title: `${n.file} packages a PowerShell script into tools/ — the install/init hook`,
        severity: 'HIGH',
        confidence: 'CONFIRMED',
        cwe: ['CWE-494'],
        owasp: ['A08:2021'],
        location: { file: n.file, startLine: sf.line },
        additionalLocations: sibling
          ? [{ file: sibling.file, note: 'the packaged script itself, as restored' }]
          : undefined,
        evidence: { snippet: sf.snippet, language: 'xml' },
        problem: `The nuspec${n.model.id ? ' of ' + n.model.id : ''} ships ${sf.src} — the path NuGet's ` +
          'legacy install/init hook executes on consumers that still use packages.config.',
        impact: 'Every consumer installing this package runs this script with user rights. This is ' +
          'the pack side of the same execution surface as the install-script finding.',
        recommendation: 'Ship the script only if it is genuinely required for install-time ' +
          'configuration; prefer targets-based integration that consumers can inspect at build time, ' +
          'and document the script\'s behaviour in the package README.',
        tests: ['O-004'],
        effort: 'SMALL',
        priority: 'P2',
        engine: 'config-xml'
      }));
    }
  }

  return out;
}

module.exports = { restoreExecution };
