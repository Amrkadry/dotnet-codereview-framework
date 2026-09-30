'use strict';
/**
 * Decompiler integration — the OPTIONAL part of the binary path.
 *
 * Preference order: ilspycmd, dotPeek command line, monodis, ikdasm. When one is available the
 * assemblies are decompiled into a temp directory and the recovered C#/IL is handed to the
 * framework's existing source analyzers, so normal source checks apply to recovered code.
 * When NONE is available this module returns an explicit, actionable status — it never throws,
 * never fabricates findings, and never lets the orchestrator report a spurious pass.
 */

const { execFileSync } = require('child_process');
const fs = require('fs');
const os = require('os');
const path = require('path');

const INSTALL_COMMAND = 'dotnet tool install -g ilspycmd';

/** Candidate tools, in preference order. */
const TOOLS = [
  {
    id: 'ilspycmd',
    label: 'ilspycmd (ICSharpCode.Decompiler CLI)',
    outputKind: 'csharp',
    versionArgs: ['--version'],
    decompileArgs: (file, outDir) => ['-p', '-o', outDir, file]
  },
  {
    id: 'dotpeek',
    label: 'JetBrains dotPeek command line',
    outputKind: 'csharp',
    // dotPeek ships a command-line decompiler on some installs, but the CLI contract is not
    // stable enough to drive blind, so it is detected and reported, not executed.
    probePaths: () => {
      try {
        const pf = ['C:/Program Files/JetBrains', 'C:/Program Files (x86)/JetBrains'];
        for (const root of pf) {
          if (!fs.existsSync(root)) continue;
          for (const d of fs.readdirSync(root)) {
            if (/dotpeek/i.test(d)) return [path.join(root, d)];
          }
        }
      } catch { /* not installed / not Windows */ }
      return [];
    },
    reason: 'dotPeek installation detected, but its command-line decompilation is not scriptable ' +
      'here. Export the assembly manually from the dotPeek UI if source-level analysis is needed.'
  },
  {
    id: 'monodis',
    label: 'monodis (Mono disassembler)',
    outputKind: 'il',
    versionArgs: ['--version'],
    decompileArgs: (file, outDir) => [`--output=${path.join(outDir, path.basename(file) + '.il')}`, file]
  },
  {
    id: 'ikdasm',
    label: 'ikdasm',
    outputKind: 'il',
    versionArgs: ['--version'],
    decompileArgs: (file, outDir) => ['--output=' + path.join(outDir, path.basename(file) + '.il'), file]
  }
];

/** Probe one candidate. Returns { available, usable, version, reason } — never throws. */
function probeTool(tool) {
  if (tool.probePaths) {
    const found = tool.probePaths();
    return found.length
      ? { available: true, usable: false, version: 'unknown', reason: tool.reason }
      : { available: false, usable: false, reason: `${tool.id} not found` };
  }
  try {
    const out = execFileSync(tool.id, tool.versionArgs, { encoding: 'utf8', timeout: 15000, stdio: 'pipe' });
    const m = String(out).match(/([0-9]+\.[0-9]+(\.[0-9]+)?)/);
    return { available: true, usable: true, version: m ? m[1] : 'unknown', outputKind: tool.outputKind };
  } catch (e) {
    return { available: false, usable: false, reason: `${tool.id} not on PATH (${e.code || 'not found'})` };
  }
}

/**
 * Detect the best available decompiler.
 * Returns { available: true, tool, version, outputKind } or
 *         { available: false, tried: [...], command, reason }.
 */
function detectDecompiler() {
  const tried = [];
  for (const tool of TOOLS) {
    const r = probeTool(tool);
    tried.push({ id: tool.id, available: r.available, usable: r.usable, version: r.version || null });
    if (r.available && r.usable) {
      return { available: true, tool: tool.id, toolLabel: tool.label, version: r.version, outputKind: r.outputKind };
    }
  }
  return {
    available: false,
    tried,
    reason: 'No decompiler installed. Assembly-level analysis ran; source-level analysis of ' +
      'recovered code did NOT run and its checks are absent from this result.',
    command: INSTALL_COMMAND
  };
}

/**
 * Decompile `files` into a fresh temp directory. Returns
 * { ok, tool, outDir, files: [decompiled files], errors: [{file, message}] }.
 * Per-file failures are data, not exceptions.
 */
function decompileAssemblies(detection, files, maxFiles = 200) {
  const tool = TOOLS.find(t => t.id === detection.tool);
  if (!tool || !tool.decompileArgs) {
    return { ok: false, errors: [{ file: null, message: 'tool has no executable decompile path' }] };
  }
  const outDir = fs.mkdtempSync(path.join(os.tmpdir(), 'moraa-decomp-'));
  const produced = [];
  const errors = [];
  for (const file of files.slice(0, maxFiles)) {
    try {
      execFileSync(tool.id, tool.decompileArgs(file, outDir),
        { timeout: 120000, stdio: 'pipe' });
      produced.push(file);
    } catch (e) {
      errors.push({ file, message: String(e.message).slice(0, 200) });
    }
  }
  let outputs = [];
  try { outputs = fs.readdirSync(outDir).map(f => path.join(outDir, f)); } catch { /* temp gone */ }
  return { ok: produced.length > 0, tool: tool.id, outputKind: tool.outputKind, outDir, decompiled: produced, files: outputs, errors };
}

/**
 * Hand recovered source/IL to the framework's existing source analyzers (Semgrep with the
 * bundled .NET ruleset). Returns the adapter's RunResult, or { error } — never throws.
 */
function handToSourceAnalyzers(decomp, ctx) {
  if (!decomp || !decomp.ok || !decomp.files.length) {
    return { skipped: true, reason: 'no decompiled output to analyse' };
  }
  try {
    // Lazy require: the dependency is read-only; a missing/moved adapter must not break the
    // binary path, which is fully functional without it.
    const semgrep = require('../adapters/semgrep');
    const subCtx = Object.assign({}, ctx, {
      sourcePath: decomp.outDir,
      outPath: fs.mkdtempSync(path.join(os.tmpdir(), 'moraa-decomp-run-')),
      log: ctx.log || (() => {})
    });
    return semgrep.run(subCtx);
  } catch (e) {
    return { error: `recovered-source analysis failed: ${e.message}` };
  }
}

module.exports = { TOOLS, detectDecompiler, decompileAssemblies, handToSourceAnalyzers, INSTALL_COMMAND };
