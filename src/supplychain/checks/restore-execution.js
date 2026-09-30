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
  for (const [pkgDir, files] of groupBy(inv.packageBuildFiles, f => f.packageDir || f.file)) {
    const list = files.slice(0, MAX_LIST).map(f => f.file).join('\n') +
      (files.length > MAX_LIST ? `\n... and ${files.length - MAX_LIST} more` : '');
    out.push(buildFinding('nuget-package-msbuild-hook', {
      title: `Restored package ${pkgDir} ships MSBuild props/targets that execute at build time`,
      severity: 'HIGH',
      confidence: 'CONFIRMED',
      cwe: ['CWE-494'],
      owasp: ['A08:2021'],
      location: { file: files[0].file, startLine: 1 },
      evidence: { snippet: list, language: 'text' },
      problem: 'A .props/.targets file inside packages/<id>/build is imported automatically ' +
        '(packages.config world) or via the package\'s build/ folder (PackageReference world). ' +
        'MSBuild files can define and run arbitrary Exec/Compile targets.',
      impact: 'The package gains code execution on every machine that builds against it — restore ' +
        'and build are both supply-chain execution points.',
      recommendation: 'Audit the .targets/.props contents; if the build logic is not required, ' +
        'exclude it (ExcludeAssets="build" on the reference); if it is required, pin the package by ' +
        'hash and restore with --locked-mode.',
      tests: ['O-004'],
      effort: 'MEDIUM',
      priority: 'P2',
      engine: 'custom'
    }));
  }

  // ---- csproj importing package-provided MSBuild logic directly -----------------------------------
  for (const p of inv.projects) {
    for (const imp of p.model.importsFromPackages) {
      out.push(buildFinding('nuget-project-imports-package-targets', {
        title: `${p.file} imports MSBuild logic from a package path`,
        severity: 'HIGH',
        confidence: 'CONFIRMED',
        cwe: ['CWE-494'],
        owasp: ['A08:2021'],
        location: { file: p.file, startLine: imp.line },
        evidence: { snippet: imp.snippet, language: 'xml' },
        problem: 'The project directly <Import>s a .props/.targets resolved from a NuGet packages ' +
          'directory, so the build executes whatever that file contains at whatever version restores.',
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
