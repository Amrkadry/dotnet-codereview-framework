#!/usr/bin/env node
// dotnet-codereview-framework — tools/selfcheck.js
// Author: Amr Kadry (github.com/Amrkadry) · MIT License
'use strict';
/**
 * Whole-framework self check.
 *
 * One command that proves the framework is internally consistent and that every delegated or
 * hand-written part actually works. This is the gate to run before committing, and the gate CI
 * runs. It exits non-zero on the first hard failure.
 *
 *   node tools/selfcheck.js
 */
const { execFileSync } = require('child_process');
const fs = require('fs');
const path = require('path');

const root = path.resolve(__dirname, '..');
const results = [];
let hardFail = 0;

function check(name, fn, { soft = false } = {}) {
  let status = 'PASS', detail = '';
  try {
    detail = fn() || '';
  } catch (e) {
    status = soft ? 'WARN' : 'FAIL';
    detail = String(e.message).split('\n')[0].slice(0, 160);
    if (!soft) hardFail++;
  }
  results.push([status, name, detail]);
}

const node = (script, args = []) =>
  execFileSync(process.execPath, [path.join(root, script), ...args],
    { cwd: root, encoding: 'utf8', stdio: 'pipe' });

// ------------------------------------------------------------------ structure
check('repo structure', () => {
  const required = [
    'bin/moraa.js', 'package.json', 'README.md', 'LICENSE',
    'schema/finding.schema.json',
    'src/core/adapter-contract.js', 'src/normalize/sarif.js',
    'src/correlate/merge.js', 'src/report/vault.js', 'src/discover/project.js',
    'catalog/dotnet-test-cases.json', 'catalog/dotnet-test-cases-advanced.json',
    'rules/gitleaks/dotnet-config.toml', 'rules/semgrep/dotnet-moraa.yaml',
    'ci/github-actions.yml'
  ];
  const missing = required.filter(f => !fs.existsSync(path.join(root, f)));
  if (missing.length) throw new Error('missing: ' + missing.join(', '));
  return `${required.length} required paths present`;
});

// ------------------------------------------------------------------ JSON validity
check('all JSON parses', () => {
  const bad = [];
  const walk = d => {
    for (const e of fs.readdirSync(d, { withFileTypes: true })) {
      if (e.isDirectory()) {
        if (/^(node_modules|\.git|\.moraa-tmp|\.moraa-review)$/.test(e.name)) continue;
        walk(path.join(d, e.name));
      } else if (e.name.endsWith('.json')) {
        const p = path.join(d, e.name);
        try { JSON.parse(fs.readFileSync(p, 'utf8')); }
        catch (err) { bad.push(path.relative(root, p)); }
      }
    }
  };
  walk(root);
  if (bad.length) throw new Error('invalid JSON: ' + bad.join(', '));
  return 'every .json file parses';
});

// ------------------------------------------------------------------ modules load
check('core modules load', () => {
  const mods = ['src/core/adapter-contract', 'src/normalize/sarif', 'src/correlate/merge',
    'src/report/vault', 'src/discover/project'];
  mods.forEach(m => require(path.join(root, m)));
  return `${mods.length} modules load cleanly`;
});

// ------------------------------------------------------------------ adapters
check('adapter contract tests', () => {
  const out = node('tools/test-adapters.js');
  const m = out.match(/(\d+) pass, (\d+) partial, (\d+) fail/);
  if (!m) throw new Error('could not parse harness output');
  if (Number(m[3]) > 0) throw new Error(`${m[3]} adapter(s) failed the contract`);
  return `${m[1]} pass, ${m[2]} partial (unfixtured)`;
});

// ------------------------------------------------------------------ catalog
check('correlation and dedup', () => {
  const out = node('tools/test-correlation.js');
  if (!/all correlation tests passed/.test(out)) throw new Error('correlation tests did not all pass');
  const m = out.match(/(\d+) in -> (\d+) out, merged (\d+)/);
  return m ? `${m[1]} raw -> ${m[2]} canonical (merged ${m[3]}), cross-tool equivalence works`
    : 'all correlation tests passed';
});

check('catalog coverage audit', () => {
  const out = node('tools/audit-coverage.js');
  const t = out.match(/test cases\s*:\s*(\d+)/);
  const g = out.match(/gaps\s*:\s*(\d+)/);
  if (!t) throw new Error('audit produced no case count');
  if (g && Number(g[1]) > 0) throw new Error(`${g[1]} known coverage gap(s)`);
  return `${t[1]} test cases, 0 known gaps`;
});

check('finding <-> test cross-references', () => {
  const out = node('tools/validate-crossrefs.js', ['reviews/example']);
  if (!/OK:/.test(out)) throw new Error('cross-reference check did not report OK');
  return 'all references resolve both ways';
});

check('canonical projection', () => {
  node('tools/project-findings.js', ['reviews/example']);
  const p = path.join(root, 'reviews/example/report.sarif');
  const s = JSON.parse(fs.readFileSync(p, 'utf8'));
  if (s.version !== '2.1.0') throw new Error('SARIF version is not 2.1.0');
  if (!s.runs[0].results.length) throw new Error('SARIF has no results');
  return `SARIF 2.1.0, ${s.runs[0].results.length} results`;
});

// ------------------------------------------------------------------ CLI end-to-end
check('CLI: moraa tools', () => {
  const out = execFileSync(process.execPath, [path.join(root, 'bin/moraa.js'), 'tools'],
    { cwd: root, encoding: 'utf8' });
  if (!/adapter\(s\)/.test(out)) throw new Error('unexpected output');
  return (out.match(/adapter\(s\)/) ? out.match(/(\d+) adapter\(s\)/)[1] : '?') + ' adapters enumerated';
});

check('CLI: end-to-end review on a synthetic project', () => {
  const tmp = path.join(root, '.moraa-tmp', 'SelfCheckApp');
  fs.rmSync(tmp, { recursive: true, force: true });
  fs.mkdirSync(path.join(tmp, 'App'), { recursive: true });
  fs.writeFileSync(path.join(tmp, 'App.sln'),
    'Project("{FAE04EC0-301F-11D3-BF4B-00C04F79EFBC}") = "App", "App\\App.csproj", "{1}"\nEndProject\n');
  fs.writeFileSync(path.join(tmp, 'App', 'App.csproj'),
    '<Project ToolsVersion="15.0"><PropertyGroup><TargetFrameworkVersion>v4.8</TargetFrameworkVersion></PropertyGroup>' +
    '<Import Project="$(VSToolsPath)\\WebApplications\\Microsoft.WebApplication.targets" /></Project>');
  fs.writeFileSync(path.join(tmp, 'App', 'packages.config'),
    '<?xml version="1.0"?><packages><package id="Newtonsoft.Json" version="11.0.1" /></packages>');

  execFileSync(process.execPath, [path.join(root, 'bin/moraa.js'), 'review', tmp],
    { cwd: root, encoding: 'utf8', stdio: 'pipe' });

  const vault = path.join(tmp, '.moraa-review');
  const must = ['README.md', '00-Executive-Summary.md', '01-Findings.md', '02-Tool-Results.md',
    '03-Dependencies-Security.md', 'data/report.json', 'data/report.sarif'];
  const missing = must.filter(f => !fs.existsSync(path.join(vault, f)));
  if (missing.length) throw new Error('vault missing: ' + missing.join(', '));

  const rep = JSON.parse(fs.readFileSync(path.join(vault, 'data/report.json'), 'utf8'));
  if (!rep.findings.length) throw new Error('review produced no findings on a project that has several');

  // The honesty requirement: an empty dependency queue must explain itself.
  // With the OSV adapter the queue may legitimately be non-empty — real advisories
  // are then the explanation; the honesty line is required only when nothing ran.
  const dep = fs.readFileSync(path.join(vault, '03-Dependencies-Security.md'), 'utf8');
  const depQueueFilled = rep.findings.some(f => (f.advisories || []).length || f.category === 'dependency');
  if (!depQueueFilled && !/capability gap|scanner did run/.test(dep))
    throw new Error('empty dependency queue does not explain itself');

  fs.rmSync(tmp, { recursive: true, force: true });
  return `${rep.findings.length} findings, vault + JSON + SARIF written into the source path`;
});

// ------------------------------------------------------------------ hygiene
check('no secrets in the repo (own ruleset)', () => {
  let gl;
  try {
    gl = execFileSync('gitleaks', ['version'], { encoding: 'utf8' }).trim();
  } catch { return 'SKIPPED — gitleaks not installed'; }
  try {
    // --source '.' with cwd=root so reported paths are RELATIVE and therefore match the
    // fingerprints recorded in .gitleaksignore. An absolute --source yields absolute paths,
    // which silently never match and produce a permanent false warning.
    execFileSync('gitleaks', ['detect', '--source', '.', '--no-git', '--redact', '--no-banner',
      '--config', 'rules/gitleaks/dotnet-config.toml',
      '--gitleaks-ignore-path', '.gitleaksignore'],
      { cwd: root, encoding: 'utf8', stdio: 'pipe' });
    return `clean (gitleaks ${gl})`;
  } catch (e) {
    throw new Error('secret scan reported findings — inspect before committing');
  }
}, { soft: true });

check('no API keys referenced outside env', () => {
  const bad = [];
  const walk = d => {
    for (const e of fs.readdirSync(d, { withFileTypes: true })) {
      if (e.isDirectory()) {
        if (/^(node_modules|\.git|\.moraa-tmp|\.moraa-review)$/.test(e.name)) continue;
        walk(path.join(d, e.name));
      } else if (/\.(js|json|md)$/.test(e.name)) {
        const p = path.join(d, e.name);
        const t = fs.readFileSync(p, 'utf8');
        // A literal key assigned in source would be a real problem.
        if (/(sk-ant-[A-Za-z0-9]{20,}|sk-[A-Za-z0-9]{32,})/.test(t)) bad.push(path.relative(root, p));
      }
    }
  };
  walk(root);
  if (bad.length) throw new Error('possible literal API key in: ' + bad.join(', '));
  return 'keys are read from environment only';
});

// ------------------------------------------------------------------ report
const w = Math.max(...results.map(r => r[1].length));
console.log('dotnet-codereview-framework — self check\n');
for (const [status, name, detail] of results) {
  console.log(`  ${status.padEnd(5)}  ${name.padEnd(w)}  ${detail}`);
}
const pass = results.filter(r => r[0] === 'PASS').length;
const warn = results.filter(r => r[0] === 'WARN').length;
const fail = results.filter(r => r[0] === 'FAIL').length;
console.log(`\n  ${pass} pass, ${warn} warn, ${fail} fail`);

if (hardFail) { console.error('\nSELF CHECK FAILED'); process.exit(1); }
console.log('\nSELF CHECK PASSED');
