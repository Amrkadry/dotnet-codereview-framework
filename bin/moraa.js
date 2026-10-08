#!/usr/bin/env node
// dotnet-codereview-framework — bin/moraa.js
// Author: Amr Kadry (github.com/Amrkadry) · MIT License
'use strict';
/**
 * moraa — .NET code review orchestrator.
 *
 *   moraa review <sourcePath> [--out .moraa-review] [--only trivy,snyk] [--skip ai-review]
 *                              [--diff <base>] [--diff-two-dot] [--diff-context]
 *                              [--fail-on-new <sev>] [--format all|vault,json,sarif,md,excel]
 *                              [--no-color] [--config <path>]
 *                              [--ai-report] [--ai-review] [--ai-provider <p>] [--ai-model <m>]
 *   moraa discover <sourcePath>          project shape + capability detection, no scanning
 *   moraa tools [sourcePath]             list adapters and whether each can run here
 *   moraa native <sourcePath>            ONLY the built-in engine (no tools, no AI needed)
 *   moraa supplychain <sourcePath>       ONLY the NuGet supply-chain analyzer
 *   moraa binary <sourcePath>            ONLY the assembly/bin review path
 *   moraa config                         which integrations are configured (values redacted)
 *   moraa baseline create <sourcePath>   freeze current findings as the baseline
 *   moraa init <sourcePath>              write a starter moraa.config.json
 *
 * Pipeline: discover -> detect capabilities -> run external-tool adapters -> run BUILT-IN
 * sources (native engine, NuGet supply-chain, binary review — all need no external tool)
 * -> normalise -> correlate/dedup EVERYTHING into one canonical set -> project into the
 * Obsidian-style vault + JSON + SARIF + Markdown + Excel.
 *
 * PR mode (--diff <base>): the scanners still see the WHOLE tree — scanning only changed files
 * would break cross-file analysis — but after correlation the reported finding set is filtered
 * to files the branch changed (merge base semantics, `base...HEAD`). --fail-on-new then gates
 * on the diff set only, so a PR is blocked by what it introduced, not by pre-existing debt.
 *
 * Baseline mode: when <source>/<outDir>/data/baseline.json exists (created by `moraa baseline
 * create`), every review classifies findings NEW / EXISTING / FIXED against it and the summary
 * leads with NEW. Fingerprints are rule+file+normalised-snippet, so they survive reformatting.
 *
 * AI modes (BOTH DEFAULT OFF): --ai-review runs direct code review as one more tool (findings
 * correlate like any other tool's and never override them); --ai-report post-processes the
 * ALREADY-WRITTEN report, enriching each finding's own Markdown page in place (idempotent).
 * With both off, nothing AI-related runs and no API key is required anywhere.
 *
 * API keys are read from the environment (or moraa.config.json keys.*) — never from a report,
 * never echoed; the config check shows last-4 only. See `moraa config`.
 */

const fs = require('fs');
const path = require('path');

const repoRoot = path.resolve(__dirname, '..');
const C = require(path.join(repoRoot, 'src/core/adapter-contract'));
const { discover, discoveryFindings } = require(path.join(repoRoot, 'src/discover/project'));
const { correlate, consolidate } = require(path.join(repoRoot, 'src/correlate/merge'));
const { writeVault } = require(path.join(repoRoot, 'src/report/vault'));
const { writeExcel, verify: verifyExcel } = require(path.join(repoRoot, 'src/report/excel'));
const { writeMarkdown } = require(path.join(repoRoot, 'src/report/markdown'));
const { changedFiles, resolveDiffRange } = require(path.join(repoRoot, 'src/diff/changed-files'));
const { partitionFindings } = require(path.join(repoRoot, 'src/diff/filter'));
const NATIVE = require(path.join(repoRoot, 'src/native'));
const SUPPLY = require(path.join(repoRoot, 'src/supplychain'));
const BINARY = require(path.join(repoRoot, 'src/binary'));
const BASELINE = require(path.join(repoRoot, 'src/baseline'));
const cfg = require(path.join(repoRoot, 'src/config'));
const PLATFORM = require(path.join(repoRoot, 'src/core/platform'));
const INSTALL = require(path.join(repoRoot, 'src/install'));
const UI = require(path.join(repoRoot, 'src/ui'));
const aiReviewAdapter = require(path.join(repoRoot, 'src/adapters/ai-review'));

const argv = process.argv.slice(2);

/**
 * Resolve the positional <sourcePath>, refusing an option in its place.
 *
 * Every path-taking command reads argv[1] positionally, so `moraa discover --path X` used to
 * resolve a directory literally named "--path", scan nothing, and still report a confident
 * "0 projects" with findings derived from that emptiness. A wrong answer that looks like a
 * real one is worse than an error, so this fails loudly instead.
 */
function sourceArg(a) {
  if (typeof a === 'string' && a.startsWith('-')) {
    console.error(`expected a source path but got the option "${a}".
` +
      'The path is positional: moraa <command> <sourcePath> [options]');
    process.exit(2);
  }
  // Accept a path in whichever shell's convention the user pasted: PowerShell's D:\x,
  // Git Bash's /d/x, or WSL's /mnt/d/x. An existing path is never rewritten.
  const r = PLATFORM.resolveUserPath(a);
  if (r.translatedFrom) {
    log(paint.dim(`  path ${r.translatedFrom} resolved as ${r.path} (${PLATFORM.describe().label})`));
  }
  return r.path;
}
const cmd = argv[0];
const flag = (name, def) => {
  const i = argv.indexOf('--' + name);
  return i >= 0 ? (argv[i + 1] && !argv[i + 1].startsWith('--') ? argv[i + 1] : true) : def;
};
const logRaw = (...a) => console.log(...a);

// Colour is decided once per stream: NO_COLOR > FORCE_COLOR > TTY. `--no-color` forces off.
const paint = UI.paintFor(process.stdout, process.env);
if (flag('no-color', false) === true) { paint.enabled = false; }
const log = (...a) => logRaw(...a.map(x => (typeof x === 'string' ? x : x)));

function loadAdapters() {
  const dir = path.join(repoRoot, 'src', 'adapters');
  if (!fs.existsSync(dir)) return [];
  const out = [];
  for (const f of fs.readdirSync(dir).filter(x => x.endsWith('.js')).sort()) {
    try {
      const mod = require(path.join(dir, f));
      const problems = C.validateAdapter(mod, f);
      if (problems.length) { console.error(`  skipping ${f}: ${problems[0]}`); continue; }
      out.push(mod);
    } catch (e) { console.error(`  skipping ${f}: ${e.message}`); }
  }
  return out;
}

/** Config through the real config layer (precedence, .gitignore guard, redaction helpers). */
function loadConfig(sourcePath) {
  const res = cfg.loadConfig({
    configPath: flag('config', undefined) === true ? undefined : flag('config', undefined),
    sourcePath, env: process.env,
    flags: {
      aiReport: flag('ai-report'), aiReview: flag('ai-review'),
      aiProvider: flag('ai-provider'), aiModel: flag('ai-model'),
      aiBaseUrl: flag('ai-base-url'), aiKey: flag('ai-key')
    }
  });
  if (!res.config.tools) res.config.tools = {};
  return res.config;
}

function cliFlags() {
  return {
    aiReport: flag('ai-report'), aiReview: flag('ai-review'),
    aiProvider: flag('ai-provider'), aiModel: flag('ai-model'),
    aiBaseUrl: flag('ai-base-url'), aiKey: flag('ai-key')
  };
}

function usage(code = 0) {
  logRaw(`moraa — .NET code review orchestrator

  moraa review <sourcePath> [options]   run the full pipeline (tools + built-ins, merged)
  moraa discover <sourcePath>           project shape + capability detection only
  moraa tools [sourcePath]              list adapters and whether each can run
  moraa native <sourcePath>             ONLY the built-in engine — no scanner, no AI, no network
  moraa supplychain <sourcePath>        ONLY the NuGet supply-chain analyzer
  moraa binary <sourcePath>             ONLY the assembly (bin/*.dll) review path
  moraa config                          which integrations are configured (values redacted)
  moraa baseline create <sourcePath>    freeze current findings as the review baseline
  moraa init <sourcePath>               write a starter moraa.config.json

Review options
  --out <dir>        output folder, relative to sourcePath   (default .moraa-review)
  --only a,b         run only these sources (adapters + native/supplychain/binary)
  --skip a,b         skip these sources
  --fail-on <sev>    exit 1 if a finding at or above this severity exists (CRITICAL|HIGH|MEDIUM|LOW)
  --no-consolidate  disable rule-family consolidation (default: one finding per rule)
  --obsidian <dir>   mirror the Obsidian vault to this folder after the review
  --format <list>    projections to write, comma-separated from
                     vault,json,sarif,md,excel — or "all" (default: all)
  --no-color         disable ANSI colour (also automatic: NO_COLOR, or output is not a terminal)
  --config <path>    explicit moraa.config.json (overrides the default search order)

Built-in sources (run by default inside review; no external tool required)
  native             the built-in engine: XML config + C# + manifest checks driven by the
                     279-case .NET catalog; undecided cases become explicit manual-review items
  supplychain        NuGet supply-chain: dependency confusion, feed/credential misconfig,
                     pinning/lockfile integrity, restore-time execution surface
  binary             deployed-assembly review: PE/ECMA-335 metadata, debug builds, binding
                     redirects, embedded secrets (redacted), optional decompiler

PR/diff mode
  --diff <base>      restrict the reported findings to files changed vs <base>.
                     Uses merge-base semantics: base...HEAD, i.e. only what this branch
                     introduced (pass --diff-two-dot for exact-tree base..HEAD).
  --diff-two-dot     with --diff: use base..HEAD instead of the default base...HEAD
  --diff-context     with --diff: also report findings whose additionalLocations touch a
                     changed file (catches sink-here/source-there flows the tool did emit)
  --fail-on-new <sev>  with --diff or baseline: exit 1 when a NEW finding at or above this
                     severity is introduced (CRITICAL|HIGH|MEDIUM|LOW|INFO)

Baseline mode
  moraa baseline create <sourcePath> [--suppress "<findingId>=<why>[;expires=YYYY-MM-DD]"]
                     freezes data/report.json findings into data/baseline.json. Later reviews
                     classify NEW / EXISTING / FIXED against it; NEW leads the summary and
                     --fail-on-new gates on it. Suppressions REQUIRE a justification; expired
                     ones are reported back as findings.

AI modes — both OFF by default; nothing AI-related runs unless you enable one
  --ai-report        post-process the ALREADY-written report: enrich each finding's own
                     Markdown page with an AI narrative, in place, idempotently
  --ai-review        direct AI code review; findings enter the correlation as tool "ai-review"
                     and never override any tool finding
  --ai-provider <name>  anthropic | openai | zai | local | none | auto (default auto)
  --ai-model <id>    model override for both modes
  --ai-base-url <url>  required for --ai-provider local (OpenAI-compatible endpoint)
  --ai-key <secret>  LAST RESORT — argv is visible in process listings. Prefer the
                     environment: MORAA_AI_API_KEY / ANTHROPIC_API_KEY / OPENAI_API_KEY / ZAI_API_KEY

Secrets: keys are read from the environment or moraa.config.json (gitignored), never printed,
never written into any report. \`moraa config\` shows what is configured, redacted to last 4.
`);
  process.exit(code);
}

async function cmdDiscover(sourcePath) {
  const p = discover(sourcePath);
  log(`\n${p.name}  [${p.stack}]`);
  log(`  solution     ${p.solution || '—'}`);
  log(`  projects     ${p.counts.projects} (${p.counts.testProjects} test)`);
  log(`  config files ${p.counts.configFiles}`);
  log(`  flags        packages.config=${p.flags.anyPackagesConfig} nonSdk=${p.flags.anyNonSdk} ` +
    `tests=${p.flags.hasTests} lockfile=${p.flags.hasLockFile} analyzers=${p.flags.hasAnalyzers} ` +
    `ci=${p.flags.hasCI} git=${p.flags.isGitRepo}`);
  log('\n  capabilities');
  for (const [k, v] of Object.entries(p.capabilities)) {
    log(`    ${v.supported ? 'YES' : 'NO '}  ${k}`);
    log(`          ${v.reason}`);
    if (!v.supported && v.alternative) log(`          -> ${v.alternative}`);
  }
  const df = discoveryFindings(p);
  if (df.length) {
    log(`\n  ${df.length} finding(s) established by discovery alone:`);
    df.forEach(f => log(`    ${f.severity.padEnd(8)} ${f.title}`));
  }
  return p;
}

async function cmdTools(sourcePath) {
  const adapters = loadAdapters();
  const project = sourcePath ? discover(sourcePath) : { stack: 'unknown' };
  const ctx = {
    sourcePath: sourcePath || repoRoot, outPath: path.join(repoRoot, '.moraa-tmp'),
    project, config: loadConfig(sourcePath || repoRoot), env: process.env, log: () => {}
  };
  log(`\n${adapters.length} adapter(s)\n`);
  for (const a of adapters) {
    let d;
    try { d = await a.detect(ctx); } catch (e) { d = { available: false, reason: 'detect() threw: ' + e.message }; }
    log(`  ${d.available ? 'READY      ' : 'UNAVAILABLE'}  ${a.id.padEnd(18)} ${a.kind.padEnd(11)} ${d.version || ''}`);
    if (!d.available) {
      log(`               ${d.reason || ''}`);
      if (d.command) log(`               enable: ${d.command}`);
    }
  }
  const builtIns = [
    ['native', NATIVE], ['supplychain', SUPPLY], ['binary', BINARY]
  ];
  log(`\nbuilt-in source(s) — no external tool required\n`);
  for (const [id, mod] of builtIns) {
    let d;
    try { d = await mod.detect(ctx); } catch (e) { d = { available: false, reason: 'detect() threw: ' + e.message }; }
    log(`  ${d.available ? 'READY      ' : 'UNAVAILABLE'}  ${id.padEnd(18)} ${String(mod.kind).padEnd(11)} ${d.version || ''}`);
    if (!d.available) log(`               ${d.reason || ''}`);
  }
}

/**
 * Run the built-in sources (native, supplychain, binary). All three need no external tool;
 * each returns a contract-valid RunResult and degrades to NOT_APPLICABLE / FAILED as data.
 */
async function runBuiltIns(sourcePath, outPath, project, config, filters) {
  const results = [];
  const want = id => (!filters.only || filters.only.includes(id)) &&
    !filters.skip.includes(id) && ((config.tools[id] || {}).enabled !== false);

  if (want('native')) {
    const t0 = Date.now();
    const r = await NATIVE.analyze(sourcePath, { outPath, stack: project.stack, log });
    r.kind = 'sast';
    r.durationMs = r.durationMs || (Date.now() - t0);
    results.push(r);
  }
  if (want('supplychain')) {
    const r = await SUPPLY.analyze(sourcePath, { outPath });
    r.kind = 'dependency';
    results.push(r);
  }
  if (want('binary')) {
    const r = BINARY.analyze(sourcePath, { outPath });
    r.kind = 'sast';
    results.push(r);
  }
  return results;
}

async function cmdReview(sourcePath) {
  if (!fs.existsSync(sourcePath)) { console.error(`source path not found: ${sourcePath}`); process.exit(2); }

  // --diff takes a value; a bare `--diff` (or one followed by another flag) makes flag()
  // return `true`. Treat that as a usage error rather than a ref literally named "true".
  const diffBase = flag('diff', null);
  if (diffBase === true) {
    console.error('--diff requires a base ref, e.g. moraa review . --diff origin/main');
    process.exit(2);
  }
  const SEVERITIES = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'];
  const diffTwoDot = flag('diff-two-dot', false) !== false;
  const diffContext = flag('diff-context', false) !== false;
  const failOnNew = flag('fail-on-new', null);
  if (failOnNew === true) {
    console.error('--fail-on-new requires a severity: CRITICAL|HIGH|MEDIUM|LOW|INFO');
    process.exit(2);
  }
  if (failOnNew && !SEVERITIES.includes(String(failOnNew).toUpperCase())) {
    console.error(`--fail-on-new: unknown severity "${failOnNew}" (use CRITICAL|HIGH|MEDIUM|LOW|INFO)`);
    process.exit(2);
  }
  if ((diffTwoDot || diffContext) && !diffBase) {
    console.error('--diff-two-dot / --diff-context require --diff <base>');
    process.exit(2);
  }

  const outDir = flag('out', '.moraa-review');
  const outPath = path.join(sourcePath, outDir);
  const only = flag('only') ? String(flag('only')).split(',').map(s => s.trim()) : null;
  const skip = flag('skip') ? String(flag('skip')).split(',').map(s => s.trim()) : [];
  const config = loadConfig(sourcePath);
  const FORMAT_KEYS = ['vault', 'json', 'sarif', 'md', 'excel'];
  const formatRaw = String(flag('format', 'all') === true ? 'all' : flag('format', 'all'));
  const format = formatRaw.split(',').map(s => s.trim().toLowerCase()).filter(Boolean);
  const unknownFmt = format.filter(f => f !== 'all' && !FORMAT_KEYS.includes(f));
  if (unknownFmt.length) {
    console.error(`--format: unknown projection(s) "${unknownFmt.join(', ')}" (use all|${FORMAT_KEYS.join(',')})`);
    process.exit(2);
  }
  const F = k => format.includes('all') || format.includes(k);

  log(`\nmoraa review\n  source: ${sourcePath}\n  output: ${outPath}\n`);

  // ---- 1. discover
  log(`[1/6] discovering project shape`);
  const project = discover(sourcePath);
  log(`      ${project.counts.projects} project(s), stack=${project.stack}, ` +
    `tests=${project.flags.hasTests}, packages.config=${project.flags.anyPackagesConfig}`);
  fs.mkdirSync(path.join(outPath, 'raw'), { recursive: true });

  const ctx = {
    sourcePath, outPath, project, config, env: process.env,
    flags: cliFlags(), log: (...a) => logRaw(...a)
  };

  // ---- 2. run adapters
  const adapters = loadAdapters()
    .filter(a => !only || only.includes(a.id))
    .filter(a => !skip.includes(a.id))
    .filter(a => (config.tools[a.id] || {}).enabled !== false);

  log(`[2/6] running ${adapters.length} external adapter(s)`);
  const runResults = [];
  for (const a of adapters) {
    let r;
    const t0 = Date.now();
    try {
      r = await a.run(ctx);
    } catch (e) {
      // An adapter throwing is itself a finding about the adapter, not a crash of the review.
      r = C.failed(a.id, `adapter threw: ${e.message}`, { durationMs: Date.now() - t0 });
    }
    const problems = C.validateRunResult(r, a.id);
    if (problems.length) {
      console.error(`      ${a.id}: contract violation — ${problems[0]}`);
      r = C.failed(a.id, `adapter returned a contract-invalid result: ${problems[0]}`);
    }
    r.kind = a.kind;
    runResults.push(r);
    const n = (r.findings || []).length;
    log(`      ${String(r.status).padEnd(14)} ${a.id.padEnd(18)} ${n} finding(s)` +
      (r.status !== 'EXECUTED' ? `  — ${String(r.notes || '').slice(0, 80)}` : ''));
  }

  // ---- 2b. built-in sources (native, supplychain, binary) — merged into the SAME pipeline
  log(`[3/6] running built-in source(s)`);
  const builtInResults = await runBuiltIns(sourcePath, outPath, project, config, { only, skip });
  for (const r of builtInResults) {
    const problems = C.validateRunResult(r, r.tool);
    if (problems.length) {
      console.error(`      ${r.tool}: contract violation — ${problems[0]}`);
      continue; // a contract-invalid built-in result never enters the canonical set
    }
    runResults.push(r);
    const n = (r.findings || []).length;
    log(`      ${String(r.status).padEnd(14)} ${r.tool.padEnd(18)} ${n} finding(s)` +
      (r.status !== 'EXECUTED' ? `  — ${String(r.notes || '').slice(0, 80)}` : ''));
  }
  if (!builtInResults.length) log('      (none selected)');

  // ---- 3. gather + discovery findings
  log('[4/6] normalising');
  const raw = [];
  for (const r of runResults) for (const f of r.findings || []) raw.push(f);
  const dFindings = discoveryFindings(project);
  dFindings.forEach(f => raw.push(f));
  runResults.push({
    status: 'EXECUTED', tool: 'discover', kind: 'build', exitCode: 0,
    findings: dFindings, command: 'moraa discover (read-only inspection)',
    notes: `Repository inspection established ${dFindings.length} finding(s) with no external tool.`,
    limitations: 'Inspection only: reads project shape and configuration, executes nothing.'
  });
  log(`      ${raw.length} raw finding(s) from ${runResults.length} source(s)`);

  // ---- 4. correlate
  log('[5/6] correlating and deduplicating');
  const toolsThatRan = runResults.filter(r => r.status === 'EXECUTED').map(r => r.tool);
  let { findings, stats } = correlate(raw, { toolsThatRan });
  log(`      ${stats.canonicalFindings} canonical (merged ${stats.mergedAway}), ` +
    `${stats.multiToolConfirmed} confirmed by >1 tool`);

  // ---- 4a. separate the coverage checklist from the actionable findings.
  //
  // The native engine emits one MANUAL_REVIEW item per catalog case it could not decide
  // mechanically. Those are deliberately QUESTIONS, not defects (see src/native/finding.js),
  // and keeping them is the honest coverage model. Leaving them INSIDE the findings array,
  // however, made every count meaningless and -- worse -- put hundreds of locationless
  // "(project)" results into report.sarif, where a code-scanning UI raises each one as a
  // real alert. They travel alongside the findings from here on, never inside them.
  //
  // This runs BEFORE consolidation on purpose: folding manual-review items into rule
  // families first would bury the distinction this split exists to draw.
  const isManualReview = f => (f.detection && f.detection.class === 'MANUAL_REVIEW') ||
    (f.sources || []).some(sc => (sc.status === 'NOT_AUTOMATED'));
  const manualReview = findings.filter(isManualReview);
  findings = findings.filter(f => !isManualReview(f));
  stats.actionableFindings = findings.length;
  stats.manualReviewItems = manualReview.length;
  if (manualReview.length) {
    log(`      ${findings.length} actionable finding(s); ` +
      `${manualReview.length} catalog case(s) not mechanically decided (manual-review queue)`);
  }

  // rule-family consolidation: one finding per tool+rule, rest become additionalLocations
  if (flag('no-consolidate', false) !== true) {
    const c = consolidate(findings, { maxLocations: 500 });
    findings = c.findings;
    stats.consolidatedAway = c.stats.consolidatedAway;
    log(`      consolidated to ${findings.length} rule families (folded ${stats.consolidatedAway} repeat locations)`);
  }

  // ---- 4b. diff partition (AFTER correlate: filter what is reported, never what is scanned)
  let diffInfo = null;
  if (diffBase) {
    const mergeBase = !diffTwoDot;
    const changed = changedFiles(diffBase, { cwd: sourcePath, mergeBase });
    const p = partitionFindings(findings, changed, { context: diffContext });
    findings = p.inDiff; // the reported set; vault/report.json/report.sarif get only these
    diffInfo = {
      base: diffBase,
      range: resolveDiffRange(diffBase, mergeBase).join(' '),
      mergeBase,
      changedFiles: changed.size,
      inDiff: p.inDiff.length,
      contextual: p.contextual.length,
      outOfDiff: p.outOfDiff.length,
      context: diffContext
    };
    log(`      diff base ${diffBase} (${diffInfo.range}): ${changed.size} changed file(s) -> ` +
      `${p.inDiff.length} in diff, ${p.contextual.length} contextual, ${p.outOfDiff.length} outside`);
    log('      adapters saw the whole tree; only the reported set is restricted to the diff');
  }

  // ---- 4c. baseline classification (when a baseline exists)
  const baselinePath = path.join(outPath, 'data', 'baseline.json');
  let classification = null;
  if (fs.existsSync(baselinePath)) {
    try {
      const baseline = JSON.parse(fs.readFileSync(baselinePath, 'utf8'));
      // Classify the REAL findings array: the baseline/suppression annotations are part of
      // what the report should carry forward, not throwaway copies.
      classification = BASELINE.classify(findings, baseline);
      log(`      baseline: ${classification.summary.newCount} NEW, ` +
        `${classification.summary.existingCount} existing, ` +
        `${classification.summary.fixedCount} fixed` +
        (classification.summary.expiredCount
          ? `, ${classification.summary.expiredCount} EXPIRED suppression(s)` : ''));
    } catch (e) {
      console.error(`      baseline present but unusable (${e.message}); continuing unclassified`);
    }
  }

  // ---- 5. project
  log('[6/6] writing report');
  let root = outPath, written = [];
  if (F('vault')) {
    const v = writeVault({ sourcePath, outDir, findings, runResults, stats, project });
    root = v.root; written = v.written;

    // The manual-review queue is coverage, not findings, so it gets its own document rather
    // than one vault note per item. Without this the vault would silently imply that the
    // cases nothing examined were examined and found clean.
    if (manualReview.length) {
      const byCat = new Map();
      for (const f of manualReview) {
        const k = f.category || 'uncategorised';
        if (!byCat.has(k)) byCat.set(k, []);
        byCat.get(k).push(f);
      }
      const lines = [
        '# Manual review queue',
        '',
        `${manualReview.length} catalog case(s) could not be decided mechanically in this run.`,
        '',
        'These are **questions, not defects**. Nothing here claims the codebase is clean, and',
        'nothing here claims a defect exists — each line is a case no automated check reached.',
        'They are kept out of the findings count and out of report.sarif for exactly that reason.',
        ''
      ];
      for (const k of [...byCat.keys()].sort()) {
        lines.push(`## ${k} (${byCat.get(k).length})`, '');
        for (const f of byCat.get(k)) {
          lines.push(`- **${(f.tests && f.tests[0]) || '-'}** — ${f.title.replace(/^Manual review: /, '')}`);
          if (f.recommendation) lines.push(`  - ${String(f.recommendation).replace(/\s+/g, ' ').trim()}`);
        }
        lines.push('');
      }
      const qf = path.join(root, 'Manual-Review-Queue.md');
      fs.writeFileSync(qf, lines.join('\n'));
      written.push(qf);
    }
  }

  // --obsidian <dir>: mirror the Obsidian vault to an external folder
  const obsidianTarget = flag('obsidian', null);
  if (F('vault') && obsidianTarget && obsidianTarget !== true) {
    try {
      fs.cpSync(root, path.resolve(obsidianTarget), { recursive: true });
      log(`      obsidian mirror: ${root} -> ${path.resolve(obsidianTarget)}`);
    } catch (e) {
      log(`      obsidian mirror FAILED: ${e.message} (review output unaffected)`);
    }
  }

  const summary = {
    generatedAt: new Date().toISOString(),
    source: sourcePath,
    project: {
      name: project.name, stack: project.stack, solution: project.solution,
      counts: project.counts, flags: project.flags, capabilities: project.capabilities
    },
    totals: SEVERITIES.reduce((m, s) =>
      (m[s.toLowerCase()] = findings.filter(f => f.severity === s).length, m), { all: findings.length }),
    correlation: stats,
    ...(diffInfo ? { diff: diffInfo } : {}),
    ...(classification ? {
      baseline: {
        path: path.relative(sourcePath, baselinePath).replace(/\\/g, '/'),
        ...classification.summary
      }
    } : {}),
    catalogCoverage: (() => {
      // union of built-in coverage records: how many catalog cases SOMETHING decided
      const byCase = new Map();
      for (const r of runResults) {
        for (const rec of r.catalogCoverage || []) {
          const cur = byCase.get(rec.caseId) || { outcome: 'not-applicable' };
          if (rec.outcome === 'checked' || cur.outcome !== 'checked') {
            if (rec.outcome === 'checked') cur.outcome = 'checked';
            else if (rec.outcome === 'manual-review' && cur.outcome === 'not-applicable') cur.outcome = 'manual-review';
          }
          byCase.set(rec.caseId, cur);
        }
      }
      const vals = [...byCase.values()];
      return {
        total: vals.length,
        checked: vals.filter(v => v.outcome === 'checked').length,
        manualReview: vals.filter(v => v.outcome === 'manual-review').length
      };
    })(),
    tools: runResults.map(r => ({
      tool: r.tool, status: r.status, version: r.version, exitCode: r.exitCode,
      findings: (r.findings || []).length, command: r.command, notes: r.notes,
      limitations: r.limitations
    }))
  };

  // baseline classification leads the summary with NEW when one exists
  const headline = classification
    ? `  NEW ${classification.summary.newCount}` +
      `  | existing ${classification.summary.existingCount}` +
      `  | fixed ${classification.summary.fixedCount}` +
      (classification.summary.expiredCount ? `  | EXPIRED suppressions ${classification.summary.expiredCount}` : '')
    : null;

  if (F('json')) {
    fs.mkdirSync(path.join(root, 'data'), { recursive: true });
    fs.writeFileSync(path.join(root, 'data', 'report.json'),
      JSON.stringify({
        summary, findings, manualReview,
        ...(classification ? {
          baselineClassification: {
            new: classification.new.map(f => f.findingId),
            existing: classification.existing.map(f => f.findingId),
            fixed: classification.fixed
          }
        } : {})
      }, null, 2));
  }
  if (F('sarif')) {
    fs.mkdirSync(path.join(root, 'data'), { recursive: true });
    fs.writeFileSync(path.join(root, 'data', 'report.sarif'), JSON.stringify(toSarif(findings), null, 2));  // actionable only: manual-review items are not alerts
  }
  let excelPath = null;
  if (F('excel')) {
    excelPath = writeExcel(root, { findings, runResults, stats });
    // Parse-back proof on every write: the file is verified before the run claims success.
    const v = verifyExcel(fs.readFileSync(excelPath, 'utf8'));
    if (!v.ok) console.error(`      WARNING: Excel parse-back failed (${v.errors[0]}) — data/report.excel.xml is suspect`);
  }
  if (F('md')) {
    writeMarkdown(root, { findings, summary, project, stats });
  }

  const filesWritten = (F('vault') ? written.length : 0) +
    (F('json') ? 1 : 0) + (F('sarif') ? 1 : 0) + (F('md') ? 1 : 0) + (F('excel') ? 1 : 0);
  log(`\n  wrote ${filesWritten} file(s) to ${root}`);
  if (F('vault')) log(`  start at ${path.join(outDir, 'README.md')}`);
  if (excelPath) log(`  Excel: ${path.relative(sourcePath, excelPath).replace(/\\/g, '/')} (SpreadsheetML 2003 — opens in Excel/LibreOffice)`);

  // severity line, coloured by severity when colour is on
  // INFO is included so the severities add up to the findings total; omitting it made the
  // line silently disagree with the count reported two lines earlier.
  const sevCounts = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'].map(s =>
    [s, findings.filter(f => f.severity === s).length]);
  log('');
  log('  ' + sevCounts.map(([s, n]) =>
    (n ? paint.severity(`${s} ${n}`) : paint.dim(`${s} ${n}`))).join(paint.dim('  |  ')));
  if (headline) { log(''); log(paint.bold(headline)); }

  const notRun = runResults.filter(r => r.status !== 'EXECUTED');
  if (notRun.length) {
    log(`\n  ${notRun.length} source(s) did not run: ${notRun.map(r => r.tool).join(', ')}`);
    log('  Findings absent from this report may simply never have been looked for.');
  }

  // ---- 6. AI mode "report": post-process the ALREADY-written markdown, in place
  const aiFlagVal = flag('ai-report', false);
  const aiReportRequested = (aiFlagVal === true ||
      (typeof aiFlagVal === 'string' && !['off', 'false', '0', 'no'].includes(aiFlagVal.toLowerCase()))) ||
    (config.ai && config.ai.report && config.ai.report.enabled === true);
  if (aiReportRequested) {
    log('\n[ai-report] enriching findings pages in place (opt-in mode)');
    const res = await aiReviewAdapter.runReport({
      reportDir: outPath, sourcePath, config, env: process.env,
      flags: ctx.flags, log: (...a) => logRaw(...a)
    });
    if (res.ok) {
      log(`      enriched ${res.enriched.length}, unchanged ${res.unchanged.length}` +
        (res.failedFindings && res.failedFindings.length ? `, FAILED ${res.failedFindings.length}` : '') +
        (res.noPage && res.noPage.length ? `, no page for ${res.noPage.length}` : ''));
    } else if (res.skipped) {
      log(`      skipped: ${res.reason}`);
    } else {
      console.error(`      ai-report failed: ${res.error}` +
        (res.enrichedSoFar && res.enrichedSoFar.length
          ? ` (files already enriched keep their AI blocks: ${res.enrichedSoFar.join(', ')})` : ''));
    }
  }

  const failOn = flag('fail-on');
  if (failOn) {
    const order = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'];
    const cut = order.indexOf(String(failOn).toUpperCase());
    if (cut >= 0 && findings.some(f => order.indexOf(f.severity) <= cut)) {
      console.error(`\nFAIL: findings at or above ${failOn}`);
      process.exit(1);
    }
  }

  // --fail-on-new gates on the DIFF set (inDiff) when diffing, or on the baseline NEW set
  // when a baseline exists. Pre-existing findings never gate a PR in either mode.
  if (failOnNew && diffInfo) {
    const order = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'];
    const cut = order.indexOf(String(failOnNew).toUpperCase());
    const offenders = findings.filter(f => order.indexOf(f.severity) <= cut);
    if (offenders.length) {
      console.error(`\nFAIL: ${offenders.length} finding(s) at or above ${failOnNew} in the diff ` +
        `set (base ${diffInfo.base}, ${diffInfo.range}, ${diffInfo.changedFiles} changed file(s)):`);
      offenders.slice(0, 10).forEach(f => console.error(`  ${f.severity.padEnd(8)} ${f.findingId}  ${f.location.file}`));
      process.exit(1);
    }
  }
  if (failOnNew && classification) {
    const g = BASELINE.gate(classification, failOnNew);
    if (g && g.fail) {
      console.error(`\n${g.message}:`);
      g.offenders.slice(0, 10).forEach(f =>
        console.error(`  ${String(f.severity || '').padEnd(8)} ${f.findingId || f.title || ''}  ${f.location ? f.location.file : f.file || ''}`));
      process.exit(1);
    }
  }
}

/**
 * moraa install [tool...] [--yes]
 *
 * Shows which scanners are missing and exactly how this machine would install each one, then
 * stops. Installing software changes the user system, so it happens only with an explicit
 * --yes; the plan is printed either way, so nothing ever runs unseen.
 */
function cmdInstall(names, doIt) {
  const p = INSTALL.plan(names);
  logRaw("");
  log("  platform   " + p.platform.label + " (" + p.platform.arch + ")");
  log("  managers   " + (p.managers.length ? p.managers.join(", ") : "(none detected on PATH)"));
  logRaw("");

  if (p.unknown.length) {
    console.error("  unknown tool(s): " + p.unknown.join(", "));
    console.error("  known: " + Object.keys(INSTALL.RECIPES).join(", "));
  }

  const missing = p.items.filter(i => !i.installed);
  const installable = missing.filter(i => i.argv);
  const manualOnly = missing.filter(i => !i.argv);

  for (const it of p.items) {
    const state = it.installed ? paint.status("INSTALLED") : paint.dim("MISSING  ");
    log("  " + state + "  " + it.name);
    if (it.installed) continue;
    log(paint.dim("             " + it.why));
    if (it.command) {
      log("             " + it.command + (it.privileged ? "   (needs sudo)" : ""));
    } else {
      log(paint.dim("             no package manager here provides it - install manually: " + it.manual));
    }
  }
  logRaw("");

  // Every requested name was unrecognised, so there is nothing to report on. Falling through
  // here would print "every supported scanner is already on PATH" -- a confident claim about
  // a set the user never asked about, and simply untrue.
  if (p.unknown.length && !p.items.length) {
    console.error("  nothing to do: no recognised tool was named.");
    process.exitCode = 2;
    return;
  }

  if (!missing.length) { log("  every supported scanner is already on PATH."); return; }

  if (!doIt) {
    log("  " + installable.length + " tool(s) can be installed here" +
      (manualOnly.length ? ", " + manualOnly.length + " need a manual download" : "") + ".");
    log("  nothing has been installed. Re-run with --yes to execute the commands above:");
    log("    moraa install --yes" + (names && names.length ? " " + names.join(" ") : ""));
    return;
  }

  if (!installable.length) { log("  nothing here can be installed automatically."); return; }

  log("  installing " + installable.length + " tool(s). Each is attempted independently.");
  logRaw("");
  const results = INSTALL.execute(p, { log: log });
  logRaw("");
  for (const r of results) {
    log("  " + (r.ok ? paint.status("OK") : paint.severity("FAILED")) + "  " + r.name + " - " + r.detail);
  }
  const failed = results.filter(r => !r.ok);
  logRaw("");
  log("  " + (results.length - failed.length) + " of " + results.length + " installed. " +
    "Run: moraa tools <path>   to confirm the pipeline now sees them.");
  if (failed.length) process.exitCode = 1;
}

function toSarif(findings) {
  const level = s => ({ CRITICAL: 'error', HIGH: 'error', MEDIUM: 'warning', LOW: 'note', INFO: 'note' }[s] || 'note');
  return {
    $schema: 'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json',
    version: '2.1.0',
    runs: [{
      tool: {
        driver: {
          name: 'dotnet-codereview-framework', version: '2.0.0',
          informationUri: 'https://github.com/Amrkadry/dotnet-codereview-framework',
          rules: findings.map(f => ({
            id: f.findingId,
            shortDescription: { text: f.title },
            fullDescription: { text: f.problem || f.title },
            help: { text: f.recommendation || '', markdown: `**Impact**\n\n${f.impact || ''}\n\n**Fix**\n\n${f.recommendation || ''}` },
            defaultConfiguration: { level: level(f.severity) },
            properties: {
              tags: ['moraa', f.category].concat(f.cwe || []).concat(f.owasp || []).filter(Boolean),
              'security-severity': f.cvss ? String(f.cvss.score) : undefined,
              precision: ({ CONFIRMED: 'very-high', LIKELY: 'high', POSSIBLE: 'medium', UNVERIFIED: 'low' })[f.confidence]
            }
          }))
        }
      },
      results: findings.map(f => ({
        ruleId: f.findingId, level: level(f.severity),
        message: { text: `${f.title}${f.impact ? ' — ' + String(f.impact).split('. ')[0] + '.' : ''}` },
        locations: [{
          physicalLocation: {
            artifactLocation: { uri: String(f.location.file).replace(/\\/g, '/') },
            region: { startLine: f.location.startLine || 1, endLine: f.location.endLine || f.location.startLine || 1 }
          }
        }],
        partialFingerprints: { moraaFindingId: f.findingId },
        properties: {
          confidence: f.confidence, status: f.status,
          sources: (f.sources || []).map(s => `${s.tool}:${s.status}`)
        }
      }))
    }]
  };
}

function cmdInit(sourcePath) {
  const p = path.join(sourcePath, 'moraa.config.json');
  if (fs.existsSync(p)) { console.error(`${p} already exists`); process.exit(2); }
  const cfgTemplate = {
    $schema: './moraa.config.schema.json',
    schema: 2,
    outDir: '.moraa-review',
    failOn: null,
    // ONE file for every integration setting. Keys MAY live here (gitignore this file first!)
    // but the environment is preferred: MORAA_AI_API_KEY / ANTHROPIC_API_KEY / OPENAI_API_KEY /
    // ZAI_API_KEY / SNYK_TOKEN / SONAR_TOKEN. `moraa config` verifies without revealing values.
    keys: { anthropic: null, openai: null, zai: null, local: null, snyk: null, sonar: null },
    endpoints: { sonarqube: { hostUrl: null, projectKey: null } },
    ai: {
      provider: 'auto', model: null, baseUrl: null,
      // MODE 1 — post-process the produced report, editing each finding's page in place.
      report: { enabled: false, severityThreshold: 'LOW', contextLines: 4, maxFindings: 50 },
      // MODE 2 — direct AI code review as one more tool. Never overrides a tool finding.
      review: { enabled: false, maxFiles: 12, maxBytesPerFile: 60000 }
    },
    tools: {
      trivy: { enabled: true },
      snyk: { enabled: true },
      'osv-scanner': { enabled: true },
      'dependency-check': { enabled: false },
      gitleaks: { enabled: true, config: 'rules/gitleaks/dotnet-config.toml' },
      semgrep: { enabled: true, config: 'rules/semgrep/dotnet-moraa.yaml' },
      sonarqube: { enabled: false, projectKey: 'my-project', hostUrl: 'http://localhost:9000' },
      native: { enabled: true },
      supplychain: { enabled: true },
      binary: { enabled: true }
    }
  };
  fs.writeFileSync(p, JSON.stringify(cfgTemplate, null, 2));
  logRaw(`wrote ${p}`);
  logRaw('Review it, then run:  moraa review ' + sourcePath);
  logRaw('If you put real keys in this file, add "moraa.config.json" to .gitignore FIRST.');
}

// ---------------------------------------------------------------- baseline / config / single-lane

function cmdBaseline(action, sourcePath) {
  const outPath = path.join(sourcePath, flag('out', '.moraa-review'));
  const reportFile = path.join(outPath, 'data', 'report.json');
  const baselineFile = path.join(outPath, 'data', 'baseline.json');

  if (action === 'create') {
    if (!fs.existsSync(reportFile)) {
      console.error(`no ${path.relative(sourcePath, reportFile) || 'data/report.json'} under ${outPath}.\n` +
        'Run `moraa review ' + sourcePath + '` first — a baseline freezes a REAL finding set, not an intention.');
      process.exit(2);
    }
    const rep = JSON.parse(fs.readFileSync(reportFile, 'utf8'));
    const suppressed = {};
    const raw = flag('suppress');
    if (raw && raw !== true) {
      for (const spec of String(raw).split('|')) {
        const m = spec.match(/^\s*([\w-]+)\s*=\s*([^;]+)(?:;\s*expires\s*=\s*([^;\s]+))?\s*$/);
        if (!m) {
          console.error(`--suppress: bad spec "${spec}" (use "<findingId>=<justification>[;expires=YYYY-MM-DD]", ` +
            'pipe-separate several)');
          process.exit(2);
        }
        suppressed[m[1]] = { justification: m[2], ...(m[3] ? { expires: m[3] } : {}) };
      }
    }
    let baseline;
    try {
      baseline = BASELINE.create(rep.findings || [], { suppressed });
    } catch (e) {
      console.error('baseline create failed: ' + e.message);
      process.exit(2);
    }
    fs.mkdirSync(path.dirname(baselineFile), { recursive: true });
    fs.writeFileSync(baselineFile, JSON.stringify(baseline, null, 2));
    logRaw(`baseline written: ${baselineFile}`);
    logRaw(`  ${baseline.count} finding(s) frozen at ${baseline.createdAt}`);
    const nSupp = baseline.entries.filter(e => e.suppressed).length;
    if (nSupp) logRaw(`  ${nSupp} suppressed (each with a recorded justification` +
      `${baseline.entries.some(e => e.suppressed && e.suppressed.expires) ? ' and expiry' : ''})`);
    logRaw('Later `moraa review ' + sourcePath + '` runs will classify NEW / EXISTING / FIXED against it.');
    return;
  }

  if (action === 'show') {
    if (!fs.existsSync(baselineFile)) {
      console.error(`no baseline at ${baselineFile} — run \`moraa baseline create ${sourcePath}\``);
      process.exit(2);
    }
    const b = JSON.parse(fs.readFileSync(baselineFile, 'utf8'));
    logRaw(`baseline: ${b.createdAt}, ${b.count} finding(s)`);
    for (const e of b.entries.slice(0, 50)) {
      logRaw(`  ${String(e.severity).padEnd(8)} ${e.findingId || '(id n/a)'}  ${e.file}` +
        (e.suppressed ? `  [SUPPRESSED: ${String(e.suppressed.justification).slice(0, 60)}` +
          `${e.suppressed.expires ? '; expires ' + e.suppressed.expires : ''}]` : ''));
    }
    if (b.count > 50) logRaw(`  … ${b.count - 50} more`);
    return;
  }

  console.error('usage: moraa baseline create|show <sourcePath>');
  process.exit(2);
}

async function cmdSingleLane(id, mod, sourcePath, sync = false) {
  if (!fs.existsSync(sourcePath)) { console.error(`source path not found: ${sourcePath}`); process.exit(2); }
  const outPath = path.join(sourcePath, flag('out', '.moraa-review'));
  log(`\nmoraa ${id} — ${sourcePath}\n`);
  let r;
  if (sync) r = mod.analyze(sourcePath, { outPath });
  else r = await mod.analyze(sourcePath, { outPath, log: (...a) => logRaw(...a) });
  const problems = C.validateRunResult(r, r.tool);
  if (problems.length) { console.error(`contract violation: ${problems[0]}`); process.exit(1); }
  log(`  ${paint.status(String(r.status))}  ${r.tool} ${r.version || ''}  ` +
    `${(r.findings || []).length} finding(s)  (${r.durationMs || 0}ms)`);
  if (r.notes) log('\n  ' + String(r.notes).replace(/\n/g, '\n  '));
  if (r.limitations) log(paint.dim('\n  Limitations. ' + r.limitations));
  const real = (r.findings || []).filter(f => f.severity !== 'INFO');
  if (real.length) {
    log(`\n  findings (non-manual-review):`);
    for (const f of real.slice(0, 30)) {
      log(`    ${paint.severity(f.severity.padEnd(8))} ${f.confidence.padEnd(9)} ` +
        `${f.title.slice(0, 76)}`);
      log(`    ${' '.repeat(8 + 10)} ${paint.dim(`${f.location.file}${f.location.startLine ? ':' + f.location.startLine : ''}`)}`);
    }
    if (real.length > 30) log(`    … ${real.length - 30} more`);
  }
  // INFO is included so the severities add up to the findings total; omitting it made the
  // line silently disagree with the count reported two lines earlier.
  const sevCounts = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'].map(s =>
    [s, (r.findings || []).filter(f => f.severity === s).length]);
  log('\n  ' + sevCounts.map(([s, n]) =>
    (n ? paint.severity(`${s} ${n}`) : paint.dim(`${s} ${n}`))).join(paint.dim('  |  ')));
  if (r.catalogCoverage) {
    const checked = r.catalogCoverage.filter(c => c.outcome === 'checked').length;
    log(paint.dim(`\n  catalog coverage: ${checked} of ${r.catalogCoverage.length} applicable case(s) ` +
      `decided by checks; the rest are listed as explicit manual-review items`));
  }
  // write the single-lane result in the standard formats so it is usable in CI
  if (flag('write', false) === true) {
    fs.mkdirSync(path.join(outPath, 'raw'), { recursive: true });
    fs.writeFileSync(path.join(outPath, 'raw', `${id}.json`), JSON.stringify(r, null, 2));
    log(`\n  wrote ${path.join(flag('out', '.moraa-review'), 'raw', id + '.json')}`);
  }
}

(async () => {
  try {
    switch (cmd) {
      case 'review': if (!argv[1]) usage(2); await cmdReview(sourceArg(argv[1])); break;
      case 'discover': if (!argv[1]) usage(2); await cmdDiscover(sourceArg(argv[1])); break;
      case 'tools': await cmdTools(argv[1] ? sourceArg(argv[1]) : null); break;
      case 'install': {
        const asked = argv.slice(1).filter(a => a.charAt(0) !== "-");
        cmdInstall(asked, flag("yes", false) === true);
        break;
      }
      case 'native': if (!argv[1]) usage(2); await cmdSingleLane('native', NATIVE, sourceArg(argv[1])); break;
      case 'supplychain': if (!argv[1]) usage(2); await cmdSingleLane('supplychain', SUPPLY, sourceArg(argv[1])); break;
      case 'binary': if (!argv[1]) usage(2); await cmdSingleLane('binary', BINARY, sourceArg(argv[1]), true); break;
      case 'config': {
        const report = cfg.checkConfig({
          configPath: flag('config', undefined) === true ? undefined : flag('config', undefined),
          sourcePath: argv[1] ? sourceArg(argv[1]) : undefined,
          env: process.env, flags: cliFlags()
        });
        logRaw(cfg.printCheck(report));
        break;
      }
      case 'baseline':
        if (!argv[1] || !argv[2]) { console.error('usage: moraa baseline create|show <sourcePath>'); process.exit(2); }
        cmdBaseline(argv[1], sourceArg(argv[2]));
        break;
      case 'init': if (!argv[1]) usage(2); cmdInit(sourceArg(argv[1])); break;
      case '-h': case '--help': case 'help': case undefined: usage(0); break;
      default: console.error(`unknown command: ${cmd}`); usage(2);
    }
  } catch (e) {
    console.error('\nmoraa failed: ' + e.message);
    if (process.env.MORAA_DEBUG) console.error(e.stack);
    process.exit(1);
  }
})();
