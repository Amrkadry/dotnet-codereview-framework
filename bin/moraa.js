#!/usr/bin/env node
'use strict';
/**
 * moraa — .NET code review orchestrator.
 *
 *   moraa review <sourcePath> [--out .moraa-review] [--only trivy,snyk] [--skip ai-review]
 *   moraa discover <sourcePath>          project shape + capability detection, no scanning
 *   moraa tools                          list adapters and whether each can run here
 *   moraa init <sourcePath>              write a starter moraa.config.json
 *
 * Pipeline: discover -> detect capabilities -> run adapters -> normalise -> correlate/dedup
 *           -> project into an Obsidian-style vault inside the source tree + JSON + SARIF.
 */

const fs = require('fs');
const path = require('path');

const repoRoot = path.resolve(__dirname, '..');
const C = require(path.join(repoRoot, 'src/core/adapter-contract'));
const { discover, discoveryFindings } = require(path.join(repoRoot, 'src/discover/project'));
const { correlate } = require(path.join(repoRoot, 'src/correlate/merge'));
const { writeVault } = require(path.join(repoRoot, 'src/report/vault'));

const argv = process.argv.slice(2);
const cmd = argv[0];
const flag = (name, def) => {
  const i = argv.indexOf('--' + name);
  return i >= 0 ? (argv[i + 1] && !argv[i + 1].startsWith('--') ? argv[i + 1] : true) : def;
};
const log = (...a) => console.log(...a);

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

function loadConfig(sourcePath) {
  const candidates = [
    path.join(sourcePath, 'moraa.config.json'),
    path.join(repoRoot, 'moraa.config.json')
  ];
  for (const c of candidates) {
    if (fs.existsSync(c)) {
      try { return Object.assign({ _path: c }, JSON.parse(fs.readFileSync(c, 'utf8'))); }
      catch (e) { console.error(`config ${c} is not valid JSON: ${e.message}`); process.exit(2); }
    }
  }
  return { tools: {} };
}

function usage(code = 0) {
  log(`moraa — .NET code review orchestrator

  moraa review <sourcePath> [options]   run the full pipeline
  moraa discover <sourcePath>           project shape + capability detection only
  moraa tools [sourcePath]              list adapters and whether each can run
  moraa init <sourcePath>               write a starter moraa.config.json

Options
  --out <dir>        output folder, relative to sourcePath   (default .moraa-review)
  --only a,b         run only these adapters
  --skip a,b         skip these adapters
  --fail-on <sev>    exit 1 if a finding at or above this severity exists (CRITICAL|HIGH|MEDIUM|LOW)

API keys are read from the environment only, never from config or argv:
  ANTHROPIC_API_KEY | OPENAI_API_KEY | ZAI_API_KEY   (for the ai-review adapter)
  SNYK_TOKEN | SONAR_TOKEN | SONAR_HOST_URL
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
}

async function cmdReview(sourcePath) {
  if (!fs.existsSync(sourcePath)) { console.error(`source path not found: ${sourcePath}`); process.exit(2); }

  const outDir = flag('out', '.moraa-review');
  const outPath = path.join(sourcePath, outDir);
  const only = flag('only') ? String(flag('only')).split(',').map(s => s.trim()) : null;
  const skip = flag('skip') ? String(flag('skip')).split(',').map(s => s.trim()) : [];
  const config = loadConfig(sourcePath);

  log(`\nmoraa review\n  source: ${sourcePath}\n  output: ${outPath}\n`);

  // ---- 1. discover
  log('[1/5] discovering project shape');
  const project = discover(sourcePath);
  log(`      ${project.counts.projects} project(s), stack=${project.stack}, ` +
    `tests=${project.flags.hasTests}, packages.config=${project.flags.anyPackagesConfig}`);
  fs.mkdirSync(path.join(outPath, 'raw'), { recursive: true });

  const ctx = { sourcePath, outPath, project, config, env: process.env, log };

  // ---- 2. run adapters
  const adapters = loadAdapters()
    .filter(a => !only || only.includes(a.id))
    .filter(a => !skip.includes(a.id))
    .filter(a => (config.tools[a.id] || {}).enabled !== false);

  log(`[2/5] running ${adapters.length} adapter(s)`);
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

  // ---- 3. gather + discovery findings
  log('[3/5] normalising');
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
  log('[4/5] correlating and deduplicating');
  const toolsThatRan = runResults.filter(r => r.status === 'EXECUTED').map(r => r.tool);
  const { findings, stats } = correlate(raw, { toolsThatRan });
  log(`      ${stats.canonicalFindings} canonical (merged ${stats.mergedAway}), ` +
    `${stats.multiToolConfirmed} confirmed by >1 tool`);

  // ---- 5. project
  log('[5/5] writing report');
  const { root, written } = writeVault({ sourcePath, outDir, findings, runResults, stats, project });

  const summary = {
    generatedAt: new Date().toISOString(),
    source: sourcePath,
    project: {
      name: project.name, stack: project.stack, solution: project.solution,
      counts: project.counts, flags: project.flags, capabilities: project.capabilities
    },
    totals: ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'].reduce((m, s) =>
      (m[s.toLowerCase()] = findings.filter(f => f.severity === s).length, m), { all: findings.length }),
    correlation: stats,
    tools: runResults.map(r => ({
      tool: r.tool, status: r.status, version: r.version, exitCode: r.exitCode,
      findings: (r.findings || []).length, command: r.command, notes: r.notes,
      limitations: r.limitations
    }))
  };
  fs.writeFileSync(path.join(root, 'data', 'report.json'),
    JSON.stringify({ summary, findings }, null, 2));
  fs.writeFileSync(path.join(root, 'data', 'report.sarif'), JSON.stringify(toSarif(findings), null, 2));

  log(`\n  wrote ${written.length + 2} file(s) to ${root}`);
  log(`  start at ${path.join(outDir, 'README.md')}\n`);
  log('  ' + ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].map(s =>
    `${s} ${findings.filter(f => f.severity === s).length}`).join('  |  '));

  const notRun = runResults.filter(r => r.status !== 'EXECUTED');
  if (notRun.length) {
    log(`\n  ${notRun.length} tool(s) did not run: ${notRun.map(r => r.tool).join(', ')}`);
    log('  Findings absent from this report may simply never have been looked for.');
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
  const cfg = {
    $schema: './moraa.config.schema.json',
    outDir: '.moraa-review',
    tools: {
      trivy: { enabled: true },
      snyk: { enabled: true },
      'osv-scanner': { enabled: true },
      'dependency-check': { enabled: false },
      gitleaks: { enabled: true, config: 'rules/gitleaks/dotnet-config.toml' },
      semgrep: { enabled: true, config: 'rules/semgrep/dotnet-moraa.yaml' },
      sonarqube: { enabled: false, projectKey: 'my-project', hostUrl: 'http://localhost:9000' },
      'ai-review': {
        enabled: false,
        _comment: 'OPT-IN: enabling this transmits source code to a third-party API. ' +
          'The key is read from ANTHROPIC_API_KEY / OPENAI_API_KEY / ZAI_API_KEY only.',
        model: 'claude-sonnet-5', maxFiles: 12, maxBytesPerFile: 60000
      }
    },
    failOn: null
  };
  fs.writeFileSync(p, JSON.stringify(cfg, null, 2));
  log(`wrote ${p}`);
  log('Review it, then run:  moraa review ' + sourcePath);
}

(async () => {
  try {
    switch (cmd) {
      case 'review': if (!argv[1]) usage(2); await cmdReview(path.resolve(argv[1])); break;
      case 'discover': if (!argv[1]) usage(2); await cmdDiscover(path.resolve(argv[1])); break;
      case 'tools': await cmdTools(argv[1] ? path.resolve(argv[1]) : null); break;
      case 'init': if (!argv[1]) usage(2); cmdInit(path.resolve(argv[1])); break;
      case '-h': case '--help': case 'help': case undefined: usage(0); break;
      default: console.error(`unknown command: ${cmd}`); usage(2);
    }
  } catch (e) {
    console.error('\nmoraa failed: ' + e.message);
    if (process.env.MORAA_DEBUG) console.error(e.stack);
    process.exit(1);
  }
})();
