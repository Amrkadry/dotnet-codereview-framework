'use strict';
/**
 * Manifest parsing — packages.config, PackageReference in csproj/vbproj/fsproj,
 * and Directory.Packages.props (Central Package Management).
 *
 * Pure: text in, plain model out, never throws. Line numbers are 1-based and point at the
 * exact element a finding will quote, so evidence is verbatim by construction.
 */

const X = require('./xml');

/**
 * Classify a NuGet version string. The distinction matters because only an exact pin
 * ("1.2.3" or "[1.2.3]") makes a restore deterministic.
 *   { kind: 'missing' | 'exact' | 'floating' | 'range', text }
 * 'range' with an open upper bound is also reported as unbounded — the worst kind.
 */
function classifyVersion(v) {
  if (v === undefined || v === null || String(v).trim() === '') return { kind: 'missing', text: v };
  const s = String(v).trim();
  if (s.includes('*')) return { kind: 'floating', text: s };
  if (/^[[(]/.test(s)) {
    if (/^\[\s*([^\s,)]+)\s*\]$/.test(s)) return { kind: 'exact', text: s };   // [1.2.3]
    const unbounded = /,\s*[)\]]?\s*$|,\s*\*\s*[)\]]/.test(s) || /,\s*\)/.test(s);
    return { kind: 'range', text: s, unbounded };
  }
  return { kind: 'exact', text: s };
}

/**
 * packages.config — one <package id version /> per dependency. Legacy projects carry the
 * whole dependency list here; there is no transitive graph and no hash information at all.
 */
function parsePackagesConfig(text, rel) {
  const model = { file: rel, packages: [] };
  const lines = X.lines(text);
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    if (!/<package\b/i.test(line)) continue;
    const id = X.attr(line, 'id');
    if (id === undefined) continue;
    const version = classifyVersion(X.attr(line, 'version'));
    model.packages.push({
      id, version,
      line: i + 1,
      snippet: X.clean(line),
      targetFramework: X.attr(line, 'targetFramework') || null
    });
  }
  return model;
}

/**
 * A csproj/vbproj/fsproj — PackageReference items, the RestorePackagesWithLockFile opt-in,
 * and any <Import> that pulls MSBuild logic out of a package directory.
 */
function parseProject(text, rel) {
  const model = {
    file: rel,
    packageRefs: [],         // { id, via:'Include'|'Update', version, line, snippet }
    lockFileEnabled: null,   // { line } when RestorePackagesWithLockFile appears
    restoreLockedMode: null, // { line } when RestoreLockedMode appears (locked-mode restore)
    importsFromPackages: []  // { line, snippet, project }
  };
  const lines = X.lines(text);

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    if (!line.trim()) continue;

    // ---- PackageReference, attribute form and child-element form ----
    if (/<PackageReference\b/i.test(line)) {
      const id = X.attr(line, 'Include') !== undefined ? X.attr(line, 'Include') : X.attr(line, 'Update');
      const via = X.attr(line, 'Include') !== undefined ? 'Include' : 'Update';
      if (id !== undefined) {
        let versionText = X.attr(line, 'Version');
        let versionLine = /Version\s*=/.test(line) ? i + 1 : null;
        let snippet = X.clean(line);

        // Child-element form: <PackageReference Include="X">\n <Version>1.2.3</Version>...
        if (!X.selfClosing(line, 'PackageReference') && versionText === undefined) {
          for (let j = i + 1; j < Math.min(i + 15, lines.length); j++) {
            if (X.closes(lines[j], 'PackageReference')) break;
            const vm = lines[j].match(/<Version\s*>([^<]+)<\/Version\s*>/i);
            if (vm) { versionText = vm[1]; versionLine = j + 1; snippet = X.clean(lines[j]); break; }
          }
        }
        model.packageRefs.push({
          id, via,
          version: classifyVersion(versionText),
          versionLine: versionLine || i + 1,
          line: i + 1,
          snippet
        });
      }
    }

    // ---- restore integrity opt-ins ----
    if (/<RestorePackagesWithLockFile\s*>\s*true\s*<\/RestorePackagesWithLockFile>/i.test(line) ||
        /RestorePackagesWithLockFile\s*=\s*"true"/i.test(line)) {
      model.lockFileEnabled = { line: i + 1 };
    }
    if (/<RestoreLockedMode\s*>\s*true\s*<\/RestoreLockedMode>/i.test(line) ||
        /RestoreLockedMode\s*=\s*"true"/i.test(line)) {
      model.restoreLockedMode = { line: i + 1 };
    }

    // ---- <Import Project="...\packages\...\.targets" /> — build logic from a package ----
    if (/<Import\b/i.test(line)) {
      const project = X.attr(line, 'Project');
      if (project && /([\\/]|^)packages([\\/])|NuGetPackageRoot|\.nuget[\\/]packages/i.test(project)) {
        model.importsFromPackages.push({ line: i + 1, snippet: X.clean(line), project });
      }
    }
  }
  return model;
}

/**
 * Directory.Packages.props — Central Package Management. A PackageReference without its own
 * Version is NOT unpinned when CPM holds the version; the props file is then the pin.
 */
function parseCentralProps(text, rel) {
  const model = { file: rel, centrallyManaged: null, versions: [] };
  const lines = X.lines(text);
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    if (/<ManagePackageVersionsCentrally\b[^>]*>([^<]*)</i.test(line)) {
      model.centrallyManaged = { value: RegExp.$1.trim().toLowerCase() === 'true', line: i + 1 };
    }
    if (/<PackageVersion\b/i.test(line)) {
      const id = X.attr(line, 'Include') || X.attr(line, 'Update');
      if (id !== undefined) {
        model.versions.push({
          id,
          version: classifyVersion(X.attr(line, 'Version')),
          line: i + 1,
          snippet: X.clean(line)
        });
      }
    }
  }
  return model;
}

/**
 * A .nuspec — looked at ONLY for declared install-time hooks: a <file> entry that ships a
 * .ps1 under tools/ is how a package declares the legacy install/init execution surface.
 */
function parseNuspec(text, rel) {
  const model = { file: rel, id: null, scriptFiles: [] };
  const lines = X.lines(text);
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    if (!model.id && /<id\s*>/i.test(line)) model.id = (line.match(/<id\s*>([^<]+)<\/id\s*>/i) || [])[1] || null;
    if (/<file\b/i.test(line)) {
      const src = X.attr(line, 'src') || '';
      if (/\.(ps1)$/i.test(src) || /tools[\\/]install\.ps1|tools[\\/]init\.ps1/i.test(src)) {
        model.scriptFiles.push({ line: i + 1, snippet: X.clean(line), src });
      }
    }
  }
  return model;
}

module.exports = {
  classifyVersion, parsePackagesConfig, parseProject, parseCentralProps, parseNuspec
};
