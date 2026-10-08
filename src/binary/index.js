// dotnet-codereview-framework — src/binary/index.js
// Author: Amr Kadry (github.com/Amrkadry) · MIT License
'use strict';
/**
 * BINARY / ASSEMBLY REVIEW PATH — analysis of deployed .NET applications where source is
 * partial or absent: just bin/*.dll and a Web.config.
 *
 * Two layers, deliberately separated:
 *
 *   1. ALWAYS WORKS (no external tool): PE/COFF + ECMA-335 metadata parsed directly from the
 *      bytes. Assembly inventory, target framework, debug-build detection, strong-name state,
 *      the AssemblyRef dependency surface, binding redirects, known-vulnerable version checks,
 *      and the embedded string surface with secret REDACTION.
 *
 *   2. OPTIONAL (degrades gracefully): a decompiler (ilspycmd > dotPeek > monodis > ikdasm).
 *      When one exists, assemblies are decompiled to a temp directory and the recovered source
 *      is handed to the framework's existing source analyzers. When NONE exists, the gap is
 *      reported as an explicit capability finding naming the install command
 *      (`dotnet tool install -g ilspycmd`) — never a crash, never a spurious pass.
 *
 * Exports the adapter contract (id/name/kind/stacks/detect/run/parse) so the orchestrator can
 * register it like any adapter, plus `analyze()` — the single entry function for direct use.
 */

const fs = require('fs');
const path = require('path');

const C = require('../core/adapter-contract');
const PE = require('./pe');
const METADATA = require('./metadata');
const STRINGS = require('./strings');
const KV = require('./known-vulnerable');
const CONFIG = require('./config-surface');
const DECOMPILER = require('./decompile');
const F = require('./findings');

const ID = 'binary';
const VERSION = '1.0.0';

const SKIP_DIRS = /^(node_modules|\.git|\.svn|\.vs|\.idea|\.moraa-review|\.moraa-tmp|\.sonarqube|TestResults|obj\\ref|\.ghc)$/i;
const MAX_FILES = 5000;
const MAX_ASSEMBLY_BYTES = 200 * 1024 * 1024;   // parse guard; bigger files are recorded, not read

// .NET Framework targets past end of support (TargetFrameworkAttribute values).
const EOL_FRAMEWORKS = ['v2.0', 'v3.0', 'v3.5', 'v4.0', 'v4.5', 'v4.5.1', 'v4.5.2', 'v4.6', 'v4.6.1'];

// ---------------------------------------------------------------------------------- discovery

/** Walk for *.dll / *.exe. Deliberately DOES skip bin|obj: this path exists FOR bin folders. */
function findAssemblyFiles(root) {
  const out = [];
  const walk = (dir, depth) => {
    if (depth > 10 || out.length >= MAX_FILES) return;
    let entries = [];
    try { entries = fs.readdirSync(dir, { withFileTypes: true }); } catch { return; }
    for (const e of entries) {
      const full = path.join(dir, e.name);
      if (e.isDirectory()) {
        if (SKIP_DIRS.test(e.name)) continue;
        walk(full, depth + 1);
      } else if (/\.(dll|exe)$/i.test(e.name)) {
        out.push(full);
      }
    }
  };
  walk(root, 0);
  return out.slice(0, MAX_FILES);
}

function findConfigFiles(root) {
  const out = [];
  const walk = (dir, depth) => {
    if (depth > 6 || out.length >= 50) return;
    let entries = [];
    try { entries = fs.readdirSync(dir, { withFileTypes: true }); } catch { return; }
    for (const e of entries) {
      const full = path.join(dir, e.name);
      if (e.isDirectory()) {
        if (SKIP_DIRS.test(e.name)) continue;
        walk(full, depth + 1);
      } else if (/(^|\.)(web|app)\.config$/i.test(e.name)) {
        out.push(full);
      }
    }
  };
  walk(root, 0);
  return out;
}

function findDepsJsonFiles(root) {
  const out = [];
  const walk = (dir, depth) => {
    if (depth > 6 || out.length >= 20) return;
    let entries = [];
    try { entries = fs.readdirSync(dir, { withFileTypes: true }); } catch { return; }
    for (const e of entries) {
      const full = path.join(dir, e.name);
      if (e.isDirectory()) {
        if (SKIP_DIRS.test(e.name)) continue;
        walk(full, depth + 1);
      } else if (/\.deps\.json$/i.test(e.name)) out.push(full);
    }
  };
  walk(root, 0);
  return out;
}

// ------------------------------------------------------------------------------- parsing core

/** Build information (debug/release) and target framework from assembly-level attributes. */
function extractBuildInfo(parsed) {
  let debug = null;
  let targetFramework = null;
  for (const a of parsed.attributes || []) {
    if (/^DebuggableAttribute$/i.test(a.typeName) && !debug) {
      const modes = METADATA.attrUint32Arg(a.blob);
      if (modes !== null) {
        debug = {
          present: true,
          debuggingModes: modes,
          jitOptimizerDisabled: (modes & 0x100) !== 0   // DebuggingModes.DisableOptimizations
        };
      } else {
        const bools = METADATA.attrBoolArgs(a.blob, 2); // (isJITTrackingEnabled, isJITOptimizerDisabled)
        if (bools) {
          debug = {
            present: true,
            debuggingModes: null,
            isJITTrackingEnabled: bools[0],
            jitOptimizerDisabled: bools[1]
          };
        }
      }
    } else if (/^TargetFrameworkAttribute$/i.test(a.typeName) && !targetFramework) {
      const s = METADATA.attrStringArg(a.blob);
      if (s) targetFramework = s;
    }
  }
  return { debug, targetFramework };
}

/** Parse ONE file. Returns the inventory record — never throws. */
function inspectAssemblyFile(absPath, sourcePath) {
  const rel = sourcePath ? path.relative(sourcePath, absPath).replace(/\\/g, '/') : absPath;
  let buf;
  try {
    const size = fs.statSync(absPath).size;
    if (size > MAX_ASSEMBLY_BYTES) {
      return { file: rel, bytes: size, error: `file exceeds ${MAX_ASSEMBLY_BYTES >> 20}MB parse guard`, managed: null };
    }
    buf = fs.readFileSync(absPath);
  } catch (e) {
    return { file: rel, error: `unreadable: ${e.message}`, managed: null };
  }

  const parsed = METADATA.inspectAssemblyBuffer(buf);
  if (!parsed.managed) {
    // Native or not-managed: still inventory it — a native DLL shipped in bin/ is a fact.
    return {
      file: rel, bytes: buf.length,
      managed: false, native: true,
      machine: parsed.pe ? parsed.pe.machineName : null,
      isDll: parsed.pe ? parsed.pe.isDll : null,
      linkTime: parsed.pe ? parsed.pe.timeStampIso : null,
      pdbPaths: (parsed.debugEntries || []).filter(e => e.pdbPath).map(e => e.pdbPath),
      error: parsed.error || null,
      assembly: null, references: []
    };
  }
  if (parsed.managed === null) {
    return { file: rel, bytes: buf.length, managed: null, error: parsed.error || 'undetermined', assembly: null, references: [] };
  }

  const { debug, targetFramework } = extractBuildInfo(parsed);
  return {
    file: rel,
    bytes: buf.length,
    managed: true,
    native: false,
    machine: parsed.pe.machineName,
    isDll: parsed.pe.isDll,
    linkTime: parsed.pe.timeStampIso,
    assembly: parsed.assembly,
    module: parsed.module,
    cli: {
      flags: parsed.cli.cliHeader.flags,
      runtimeVersion: parsed.cli.runtimeVersion,
      runtimeLabel: parsed.cli.runtimeLabel
    },
    runtime: { version: parsed.cli.runtimeVersion, label: parsed.cli.runtimeLabel },
    bitness: parsed.cli.bitness,
    ilOnly: parsed.cli.ilOnly,
    mixedMode: parsed.cli.mixedMode,
    strongNameSigned: parsed.cli.strongNameSigned,
    strongNameFlagOnly: parsed.cli.strongNameFlagOnly,
    targetFramework,
    debug,
    pdbPaths: (parsed.debugEntries || []).filter(e => e.pdbPath).map(e => e.pdbPath),
    references: parsed.references,
    metadata: parsed.metadata,
    widthResidual: parsed.metadata.widthResidual,
    error: null,
    _buffer: buf      // consumed by the string scan below, stripped before returning
  };
}

// ------------------------------------------------------------------------------ aggregation

function versionConflictGroups(assemblies) {
  const byName = new Map();
  for (const a of assemblies) {
    if (!a.managed || !a.assembly || !a.assembly.name) continue;
    if (/(^|\/)packages\//i.test(a.file)) continue;   // NuGet cache, not deployment layout
    const key = a.assembly.name.toLowerCase();
    if (!byName.has(key)) byName.set(key, { name: a.assembly.name, files: [] });
    byName.get(key).files.push({ file: a.file, version: a.assembly.version });
  }
  return [...byName.values()].filter(g => new Set(g.files.map(f => f.version)).size > 1);
}

function coLocatedNames(assemblies) {
  const set = new Set();
  for (const a of assemblies) {
    if (a.assembly && a.assembly.name) set.add(a.assembly.name.toLowerCase());
    if (a.module && a.module.name && /\.dll$/i.test(a.module.name)) {
      set.add(path.basename(a.module.name, path.extname(a.module.name)).toLowerCase());
    }
  }
  return set;
}

/** Build the full inventory + surface document for a directory. I/O happens only here. */
function buildInventory(sourcePath, opts = {}) {
  const files = findAssemblyFiles(sourcePath);
  const assemblies = [];
  const stringHits = [];
  const errors = [];

  for (const file of files) {
    const entry = inspectAssemblyFile(file, sourcePath);
    const buf = entry._buffer;
    delete entry._buffer;
    assemblies.push(entry);
    if (entry.error) errors.push({ file: entry.file, error: entry.error });

    if (entry.managed && buf) {
      try {
        const parsedForStrings = {
          managed: true,
          assembly: entry.assembly,
          userStringsHeap: null
        };
        // Re-derive the heap cheaply: parseMetadataRoot over the CLI header already stored.
        // To avoid re-reading the PE, keep it simple: run the raw+US scan via a light reparse.
        const pe = PE.parsePe(buf);
        const cli = pe ? require('./cli').describeManaged(pe, buf) : null;
        if (cli && cli.managed && cli.cliHeader) {
          const root = METADATA.parseMetadataRoot(buf, pe.rvaToOffset(cli.cliHeader.metadata.rva));
          parsedForStrings.userStringsHeap = root ? root.streams['#US'] : null;
        }
        for (const hit of STRINGS.scanAssemblyStrings(buf, parsedForStrings, opts.strings || {})) {
          stringHits.push(Object.assign({ file: entry.file }, hit));
        }
      } catch (e) {
        errors.push({ file: entry.file, error: `string scan failed: ${e.message}` });
      }
    }
  }

  // ---- configuration-derived dependency surface
  const redirects = [];
  for (const cfg of findConfigFiles(sourcePath)) {
    let xml = '';
    try { xml = fs.readFileSync(cfg, 'utf8'); } catch { continue; }
    for (const rd of CONFIG.parseBindingRedirects(xml)) {
      redirects.push(Object.assign({ file: path.relative(sourcePath, cfg).replace(/\\/g, '/') }, rd));
    }
  }

  const depsJson = [];
  for (const dj of findDepsJsonFiles(sourcePath)) {
    let raw = '';
    try { raw = fs.readFileSync(dj, 'utf8'); } catch { continue; }
    const parsed = CONFIG.parseDepsJson(raw);
    if (parsed) depsJson.push(Object.assign({
      file: path.relative(sourcePath, dj).replace(/\\/g, '/')
    }, parsed));
  }

  const coLocated = coLocatedNames(assemblies);
  const missing = [];
  for (const a of assemblies) {
    if (!a.managed || !Array.isArray(a.references)) continue;
    for (const ref of a.references) {
      const key = String(ref.name || '').toLowerCase();
      // The referencing module's own file name is not a dependency on disk (e.g. App_Code).
      if (key && !coLocated.has(key) &&
          key !== path.basename(a.file, path.extname(a.file)).toLowerCase() &&
          !missing.some(m => m.name.toLowerCase() === key)) {
        missing.push(Object.assign({ referencedBy: a.file }, ref));
      }
    }
  }

  return {
    generatedAt: new Date().toISOString(),
    sourcePath,
    counts: {
      files: files.length,
      managed: assemblies.filter(a => a.managed === true).length,
      native: assemblies.filter(a => a.managed === false).length,
      undetermined: assemblies.filter(a => a.managed === null).length,
      stringHits: stringHits.length,
      redirects: redirects.length,
      missing
    },
    assemblies,
    stringHits,
    redirects,
    depsJson,
    missing,
    errors: errors.slice(0, 100)
  };
}

// --------------------------------------------------------------------------- pure -> findings

/**
 * Map the inventory document to canonical findings. PURE — no I/O, never throws.
 * This is the adapter's parse(); the same logic is reused by run().
 */
function parse(raw, ctx) {
  let doc;
  try { doc = typeof raw === 'string' ? JSON.parse(raw) : raw; } catch { return []; }
  if (!doc || !Array.isArray(doc.assemblies)) return [];
  const sourceRoot = String((ctx && ctx.sourcePath) || doc.sourcePath || '');
  const rel = (p) => {
    const s = String(p || '').replace(/\\/g, '/');
    return sourceRoot && s.startsWith(sourceRoot.replace(/\\/g, '/'))
      ? s.slice(sourceRoot.replace(/\\/g, '/').length).replace(/^\//, '') : s;
  };
  const out = [];

  for (const a of doc.assemblies) {
    const file = rel(a.file);
    if (a.managed !== true || !a.cli) continue;
    const inv = Object.assign({ cli: a.cli }, a);

    if (a.debug && a.debug.jitOptimizerDisabled) out.push(F.debugBuild(inv, file));
    if (a.targetFramework) {
      const m = String(a.targetFramework).match(/version=v([0-9.]+)/i);
      if (m && EOL_FRAMEWORKS.includes(m[1].toLowerCase())) out.push(F.eolRuntime(inv, file));
    }
    if (a.strongNameSigned === false) out.push(F.strongName(inv, file));
    for (const pdb of (a.pdbPaths || []).slice(0, 3)) out.push(F.pdbPath(inv, file, { typeName: 'codeview-pdb', pdbPath: pdb }));

    for (const ref of a.references || []) {
      const entry = KV.checkReference(ref.name, ref.version);
      if (entry) out.push(F.knownVulnerableDep(ref, entry, file, 'AssemblyRef table'));
    }
  }

  for (const hit of doc.stringHits || []) out.push(F.secretString(hit, rel(hit.file)));

  for (const rd of doc.redirects || []) {
    const targetVulnerable = KV.isVulnerable(rd.assemblyName, rd.newVersion);
    out.push(F.bindingRedirect(rd, rel(rd.file), { targetVulnerable }));
  }

  for (const group of versionConflictGroups(doc.assemblies)) {
    out.push(F.versionConflict(group, rel(group.files[0].file)));
  }

  for (const m of (doc.missing || []).slice(0, 20)) out.push(F.missingDependency(m, rel(m.referencedBy)));

  if (doc.decompiler && doc.decompiler.available === false && doc.counts.managed > 0) {
    out.push(F.noDecompiler(doc.decompiler));
  }

  return out;
}

// --------------------------------------------------------------------------- adapter surface

/** No external tool is required; "available" means there is something to inventory. */
function detect(ctx) {
  const dec = DECOMPILER.detectDecompiler();
  try {
    const files = ctx && ctx.sourcePath ? findAssemblyFiles(ctx.sourcePath) : [];
    return {
      available: files.length > 0,
      version: VERSION,
      command: 'node: built-in (PE/ECMA-335 parser; no external tool required)',
      reason: files.length ? undefined : 'no .dll/.exe files found to inventory',
      decompiler: dec
    };
  } catch (e) {
    return { available: false, version: VERSION, reason: `detection failed: ${e.message}` };
  }
}

function run(ctx) {
  const started = Date.now();
  const log = ctx.log || (() => {});
  const d = DECOMPILER.detectDecompiler();

  const inventory = buildInventory(ctx.sourcePath, { strings: (ctx.config.tools && ctx.config.tools[ID]) || {} });

  // ---- optional decompiler hand-off (structurally implemented; exercised only when installed)
  let recoveredSource = null;
  if (d.available) {
    const targets = inventory.assemblies
      .filter(a => a.managed && a.ilOnly)
      .map(a => path.join(ctx.sourcePath, a.file));
    const decomp = DECOMPILER.decompileAssemblies(d, targets);
    if (decomp.ok) {
      const sub = DECOMPILER.handToSourceAnalyzers(decomp, ctx);
      recoveredSource = {
        decompiler: decomp.tool, outputKind: decomp.outputKind,
        decompiledCount: decomp.decompiled.length, files: decomp.files,
        analyzer: sub && sub.tool ? sub.tool : null,
        analyzerResult: sub && sub.tool ? { status: sub.status, findings: (sub.findings || []).length, notes: sub.notes } : sub
      };
    } else {
      recoveredSource = { decompiler: d.tool, decompiledCount: 0, errors: decomp.errors };
    }
  }

  // ---- raw artifact for reproducibility, then the pure mapping to canonical findings
  const doc = Object.assign({ decompiler: d }, inventory);
  let rawPath = null;
  try {
    rawPath = path.join(ctx.outPath, 'raw', 'binary.json');
    fs.mkdirSync(path.dirname(rawPath), { recursive: true });
    const stripped = JSON.parse(JSON.stringify(doc, (k, v) => (k === '_buffer' || Buffer.isBuffer(v) ? undefined : v)));
    fs.writeFileSync(rawPath, JSON.stringify(stripped, null, 2));
  } catch (e) {
    rawPath = null;
    log(`  binary: could not persist raw inventory: ${e.message}`);
  }

  let findings = [];
  try { findings = parse(doc, ctx); } catch { findings = []; }

  const managed = inventory.counts.managed;
  return Object.assign({
    status: 'EXECUTED',                       // the inventory layer always executes
    tool: ID,
    version: VERSION,
    command: 'node: built-in PE/COFF + ECMA-335 parser (no external tool required)',
    exitCode: 0,
    durationMs: Date.now() - started,
    rawPath,
    findings,
    notes: d.available
      ? `Inventoried ${inventory.counts.files} image(s): ${managed} managed, ${inventory.counts.native} native. ` +
        `Decompiled with ${d.tool} ${d.version || ''} and handed recovered source to the source analyzers.`
      : `Inventoried ${inventory.counts.files} image(s): ${managed} managed, ${inventory.counts.native} native, ` +
        `${inventory.counts.undetermined} undetermined. ${d.reason} Enable with: ${d.command}`,
    limitations: 'Metadata- and string-level analysis only: no dataflow, no reachability, no logic ' +
      'analysis. Known-vulnerable matching uses a small curated offline table, not an advisory feed. ' +
      (d.available ? '' : 'No decompiler installed: source-level analysis of recovered code did NOT run.')
  }, {
    inventory: JSON.parse(JSON.stringify(doc, (k, v) => (k === '_buffer' || Buffer.isBuffer(v) ? undefined : v))),
    decompiler: d,
    recoveredSource
  });
}

/** Single clear entry function: analyze a directory (or one file) and get the RunResult. */
function analyze(sourcePath, opts = {}) {
  let st;
  try { st = fs.statSync(sourcePath); } catch {
    return C.failed(ID, `source path not found: ${sourcePath}`);
  }
  if (st.isFile()) {
    const entry = inspectAssemblyFile(sourcePath, path.dirname(sourcePath));
    const buf = entry._buffer; delete entry._buffer;
    const parsed = { assemblies: [entry], stringHits: [], redirects: [], depsJson: [], missing: [], counts: { files: 1, managed: entry.managed === true ? 1 : 0, native: entry.managed === false ? 1 : 0, undetermined: entry.managed === null ? 1 : 0 }, errors: [] };
    let strings = [];
    if (entry.managed && buf) {
      try {
        const pe = PE.parsePe(buf);
        const cli = pe ? require('./cli').describeManaged(pe, buf) : null;
        const root = cli && cli.managed ? METADATA.parseMetadataRoot(buf, pe.rvaToOffset(cli.cliHeader.metadata.rva)) : null;
        strings = STRINGS.scanAssemblyStrings(buf, {
          managed: true, assembly: entry.assembly, userStringsHeap: root ? root.streams['#US'] : null
        }, opts.strings || {}).map(h => Object.assign({ file: entry.file }, h));
      } catch { /* string surface is additive; parse result stands */ }
    }
    parsed.stringHits = strings;
    const dec = DECOMPILER.detectDecompiler();
    const doc = Object.assign({ decompiler: dec }, parsed);
    const findings = parse(doc, { sourcePath: path.dirname(sourcePath) });
    return {
      status: 'EXECUTED', tool: ID, version: VERSION,
      command: 'node: built-in PE/COFF + ECMA-335 parser (no external tool required)',
      exitCode: 0, findings, rawPath: null, durationMs: 0,
      notes: `Parsed ${sourcePath}: managed=${entry.managed}${entry.assembly ? `, ${entry.assembly.name} ${entry.assembly.version}` : ''}.`,
      limitations: 'Metadata- and string-level analysis only; single-file mode cannot check co-location or redirects.',
      inventory: doc, decompiler: dec
    };
  }
  const sourceRoot = sourcePath;
  const outPath = opts.outPath || path.join(sourcePath, '.moraa-review');
  return run({
    sourcePath: sourceRoot,
    outPath,
    config: { tools: (opts.config && opts.config.tools) || {} },
    env: process.env,
    log: opts.log || (() => {})
  });
}

// Self-check on load: the module must satisfy the adapter contract mechanically.
if (process.env.MORAA_VALIDATE_BINARY !== '0') {
  const problems = C.validateAdapter({ id: ID, name: 'Binary / Assembly Review', kind: 'sast', stacks: ['framework', 'core', 'both'], detect, run, parse }, 'src/binary/index.js');
  if (problems.length) throw new Error('binary adapter violates the contract: ' + problems[0]);
}

module.exports = {
  id: ID,
  name: 'Binary / Assembly Review',
  kind: 'sast',
  stacks: ['framework', 'core', 'both'],
  detect, run, parse,
  analyze,                    // <-- single entry function
  inspectAssembly: inspectAssemblyFile,
  buildInventory,
  findAssemblyFiles
};
