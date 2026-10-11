// dotnet-codereview-framework — src/supplychain/scan.js
// Author: Amr Kadry (github.com/Amrkadry) · MIT License
'use strict';
/**
 * Read-only inventory of a source tree's NuGet surface.
 *
 * Mirrors src/discover/project.js in spirit — walk once, never mutate, never execute — with
 * one deliberate difference: this walker does NOT skip packages/, because legacy install
 * scripts (install.ps1 / init.ps1) and package-provided .targets live exactly there and are
 * a core part of the supply-chain surface. It DOES skip build outputs (bin/obj): a tampered
 * obj/project.assets.json is a build-machine compromise, a different threat model, and
 * double-reporting restored copies of manifests would only create noise.
 *
 * Nothing here parses: it finds files, reads them, and hands raw text to the parsers so the
 * whole rest of the analyzer stays pure.
 */

const fs = require('fs');
const path = require('path');

const SKIP_DIRS = /^(bin|obj|node_modules|\.git|\.vs|\.svn|\.idea|\.moraa-review|\.sonarqube|TestResults|dist|out)$/i;
const MAX_DEPTH = 15;
const MAX_FILE_BYTES = 2 * 1024 * 1024;   // evidence quotes are small; refuse to slurp huge files

const isNuGetConfig = name => /^nuget\.config$/i.test(name);
const isProject = name => /\.(csproj|vbproj|fsproj)$/i.test(name);
const isPackagesConfig = name => /^packages\.config$/i.test(name);
const isCentralProps = name => /^directory\.packages\.props$/i.test(name);
const isRootBuildFile = name => /^directory\.build\.(props|targets)$/i.test(name);
const isLockfile = name => /^packages\.lock\.json$/i.test(name);
const isNuspec = name => /\.nuspec$/i.test(name);
const isInstallScript = name => /^(install|init)\.ps1$/i.test(name);
const isPackageBuildFile = name => /\.(props|targets)$/i.test(name);

/** Read a file as utf8, or return null — an unreadable file is reported, never fatal. */
function readText(full) {
  try {
    const st = fs.statSync(full);
    if (st.size > MAX_FILE_BYTES) return null;
    return fs.readFileSync(full, 'utf8');
  } catch { return null; }
}

/**
 * MSBuild constructs that actually RUN something at build time, as opposed to the declarative
 * majority (ItemGroup/PropertyGroup/Warning/Error) that every modern NuGet package ships.
 *
 * This distinction separates a fact worth a reviewer's attention from the universal background
 * noise of NuGet restore: System.Text.Json's buildTransitive targets contain a single <Warning>,
 * while a package shipping <Exec> or <UsingTask> genuinely gains code execution on the build
 * agent. Severity is graded on this evidence rather than on the presence of the file.
 */
const EXEC_CONSTRUCTS = [
  [/<\s*Exec\b/i,              'Exec task - runs a shell command at build time'],
  [/<\s*UsingTask\b/i,         'UsingTask - loads and runs a custom task assembly'],
  [/<\s*DownloadFile\b/i,      'DownloadFile - fetches a remote file during build'],
  [/<\s*WriteCodeFragment\b/i, 'WriteCodeFragment - generates compiled source'],
  [/\.(ps1|bat|cmd|vbs)\b/i,   'references a script file'],
];

/**
 * Locate executable MSBuild constructs with line citations, so a finding can quote the line
 * that justifies its severity instead of the mere existence of the file.
 */
function execConstructsIn(text) {
  const out = [];
  const lines = String(text || '').split(/\r?\n/);
  for (let i = 0; i < lines.length; i++) {
    for (const [re, why] of EXEC_CONSTRUCTS) {
      if (re.test(lines[i])) {
        out.push({ line: i + 1, why, snippet: lines[i].trim().slice(0, 200) });
        break;
      }
    }
  }
  return out;
}

/**
 * Walk sourcePath and bucket every NuGet-relevant file.
 * Returns raw buckets; parsing happens in buildInventory.
 */
function collectFiles(sourcePath) {
  const files = {
    nuget: [], projects: [], packagesConfig: [], centralProps: [],
    rootBuild: [], lockfiles: [], nuspecs: [], installScripts: [], packageBuild: []
  };
  let sawPackagesDir = false;

  const walk = (dir, depth, inPackages) => {
    if (depth > MAX_DEPTH) return;
    let entries = [];
    try { entries = fs.readdirSync(dir, { withFileTypes: true }); } catch { return; }
    for (const e of entries) {
      const full = path.join(dir, e.name);
      if (e.isDirectory()) {
        if (SKIP_DIRS.test(e.name)) continue;
        const nowInPackages = inPackages || /^packages$/i.test(e.name);
        if (nowInPackages && !inPackages) sawPackagesDir = true;
        walk(full, depth + 1, nowInPackages);
        continue;
      }
      // Inside a restored packages/ tree only execution-surface files matter; manifests there
      // are copies, and flagging them would double-report the real declarations.
      if (inPackages) {
        if (isInstallScript(e.name)) files.installScripts.push(full);
        else if (isPackageBuildFile(e.name) && !isCentralProps(e.name) && !isRootBuildFile(e.name))
          files.packageBuild.push(full);
        else if (isNuspec(e.name)) files.nuspecs.push(full);
        continue;
      }
      if (isNuGetConfig(e.name)) files.nuget.push(full);
      else if (isProject(e.name)) files.projects.push(full);
      else if (isPackagesConfig(e.name)) files.packagesConfig.push(full);
      else if (isCentralProps(e.name)) files.centralProps.push(full);
      else if (isLockfile(e.name)) files.lockfiles.push(full);
      else if (isNuspec(e.name)) files.nuspecs.push(full);
      else if (isRootBuildFile(e.name) && depth <= 1) files.rootBuild.push(full);
    }
  };

  walk(sourcePath, 0, false);
  return { files, sawPackagesDir };
}

const relOf = (root, full) => path.relative(root, full).split(path.sep).join('/');

/** Path segments of the restored package a file belongs to, e.g. ['Newtonsoft.Json', '13.0.1']. */
function packageDirOf(root, full) {
  const parts = path.dirname(full).split(path.sep);
  for (let i = parts.length - 1; i >= 0; i--) {
    if (/^packages$/i.test(parts[i])) {
      const id = parts[i + 1] || null;
      const version = parts[i + 2] || null;
      return { id, version, dir: path.relative(root, path.join(...parts.slice(0, i + 2))).split(path.sep).join('/') };
    }
  }
  return { id: null, version: null, dir: null };
}

/** First meaningful script lines, for evidence quotes about what a hook does. */
function firstScriptLines(text, max = 3) {
  const out = [];
  for (const l of String(text || '').split(/\r?\n/)) {
    const t = l.trim();
    if (!t) continue;
    out.push(t.slice(0, 160));
    if (out.length >= max) break;
  }
  return out;
}

/**
 * Build the full parsed inventory this analyzer reasons over. Pure with respect to its
 * inputs; the only I/O is reading the files found by collectFiles.
 */
function buildInventory(sourcePath) {
  const { files, sawPackagesDir } = collectFiles(sourcePath);
  const root = sourcePath;

  const inv = {
    root,
    sawPackagesDir,
    hasNuGetSurface: false,
    nugetConfigs: [],      // { file, text, model }
    projects: [],          // { file, text, model }
    packagesConfig: [],    // { file, text, model }
    centralProps: [],      // { file, text, model }
    rootBuild: [],         // { file, text }
    lockfiles: [],         // { file, text, model }
    nuspecs: [],           // { file, text, model }
    installScripts: [],    // { file, packageId, packageDir, head }
    packageBuildFiles: []  // { file, packageId, packageDir, execConstructs, executes }
  };

  for (const full of files.nuget) {
    const text = readText(full);
    const { parseNugetConfig } = require('./nuget-config');
    inv.nugetConfigs.push({
      file: relOf(root, full), text,
      model: parseNugetConfig(text === null ? '' : text, relOf(root, full))
    });
  }
  for (const full of files.projects) {
    const text = readText(full);
    const { parseProject } = require('./manifests');
    inv.projects.push({
      file: relOf(root, full), text,
      model: parseProject(text === null ? '' : text, relOf(root, full))
    });
  }
  for (const full of files.packagesConfig) {
    const text = readText(full);
    const { parsePackagesConfig } = require('./manifests');
    inv.packagesConfig.push({
      file: relOf(root, full), text,
      model: parsePackagesConfig(text === null ? '' : text, relOf(root, full))
    });
  }
  for (const full of files.centralProps) {
    const text = readText(full);
    const { parseCentralProps } = require('./manifests');
    inv.centralProps.push({
      file: relOf(root, full), text,
      model: parseCentralProps(text === null ? '' : text, relOf(root, full))
    });
  }
  for (const full of files.rootBuild) {
    inv.rootBuild.push({ file: relOf(root, full), text: readText(full) });
  }
  for (const full of files.lockfiles) {
    const text = readText(full);
    const { parseLockfile } = require('./lockfile');
    inv.lockfiles.push({
      file: relOf(root, full), text,
      model: parseLockfile(text === null ? '' : text, relOf(root, full))
    });
  }
  for (const full of files.nuspecs) {
    const text = readText(full);
    const { parseNuspec } = require('./manifests');
    inv.nuspecs.push({
      file: relOf(root, full), text,
      model: parseNuspec(text === null ? '' : text, relOf(root, full))
    });
  }
  for (const full of files.installScripts) {
    const text = readText(full) || '';
    const pd = packageDirOf(root, full);
    inv.installScripts.push({
      file: relOf(root, full), packageId: pd.id, packageDir: pd.dir,
      head: firstScriptLines(text)
    });
  }
  for (const full of files.packageBuild) {
    const pd = packageDirOf(root, full);
    const execConstructs = execConstructsIn(readText(full) || '');
    inv.packageBuildFiles.push({
      file: relOf(root, full), packageId: pd.id, packageDir: pd.dir,
      execConstructs, executes: execConstructs.length > 0
    });
  }

  inv.hasNuGetSurface =
    inv.nugetConfigs.length > 0 || inv.projects.length > 0 || inv.packagesConfig.length > 0 ||
    inv.centralProps.length > 0 || inv.lockfiles.length > 0 || inv.nuspecs.length > 0 ||
    inv.installScripts.length > 0 || inv.packageBuildFiles.length > 0 || sawPackagesDir;

  return inv;
}

module.exports = { buildInventory, collectFiles, relOf, packageDirOf, firstScriptLines };
