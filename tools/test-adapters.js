#!/usr/bin/env node
// dotnet-codereview-framework — tools/test-adapters.js
// Author: Amr Kadry (github.com/Amrkadry) · MIT License
'use strict';
/**
 * Adapter contract test harness.
 *
 * Verifies every module in src/adapters/ against the contract in src/core/adapter-contract.js,
 * WITHOUT needing the real tool installed. Each adapter is checked for:
 *
 *   1. shape        — required exports, correct types
 *   2. detect()     — returns {available, ...} and never throws
 *   3. parse()      — is pure, and produces contract-valid findings from a fixture
 *   4. robustness   — parse() survives empty string, '{}', null and malformed JSON
 *   5. honesty      — parse() of empty tool output yields ZERO findings (no invention)
 *
 * A fixture is a real (or realistically shaped) tool output at
 * fixtures/<adapter-id>.json. Without a fixture, only 1, 2 and 4 run and the adapter is
 * reported as PARTIAL — which is deliberately visible, because an unfixtured parser is unproven.
 *
 *   node tools/test-adapters.js           # test all
 *   node tools/test-adapters.js trivy     # test one
 */
const fs = require('fs');
const path = require('path');
const C = require('../src/core/adapter-contract');

const repoRoot = path.resolve(__dirname, '..');
const adapterDir = path.join(repoRoot, 'src', 'adapters');
const fixtureDir = path.join(repoRoot, 'fixtures');
const only = process.argv.slice(2).find(a => !a.startsWith('--')); // flags like --strict are not adapter selectors

if (!fs.existsSync(adapterDir)) {
  console.error('no src/adapters directory'); process.exit(2);
}

const files = fs.readdirSync(adapterDir)
  .filter(f => f.endsWith('.js'))
  .filter(f => !only || f === `${only}.js`);

if (!files.length) { console.error('no adapters found'); process.exit(2); }

const ctx = {
  sourcePath: repoRoot,
  outPath: path.join(repoRoot, '.moraa-tmp'),
  project: { stack: 'framework', solution: 'Example.sln', projects: [], hasPackagesConfig: true },
  config: { tools: {} },
  env: {},
  log: () => {}
};

let pass = 0, partial = 0, fail = 0;
const rows = [];

for (const file of files) {
  const id = file.replace(/\.js$/, '');
  const problems = [];
  let mod;

  try {
    mod = require(path.join(adapterDir, file));
  } catch (e) {
    rows.push([id, 'FAIL', 'module failed to load: ' + e.message]);
    fail++; continue;
  }

  // 1. shape
  problems.push(...C.validateAdapter(mod, file));
  if (mod.id && mod.id !== id) problems.push(`${file}: id "${mod.id}" must match filename "${id}"`);

  // 2. detect()
  if (typeof mod.detect === 'function') {
    try {
      const d = mod.detect(ctx);
      const res = (d && typeof d.then === 'function') ? null : d;
      if (res && typeof res.available !== 'boolean')
        problems.push(`${file}: detect() must return { available: boolean }`);
    } catch (e) {
      problems.push(`${file}: detect() threw: ${e.message}`);
    }
  }

  // 4. robustness — a parser must never throw on junk; it should return [].
  if (typeof mod.parse === 'function') {
    for (const junk of ['', '{}', '[]', null, undefined, '{not json', '{"runs":[]}']) {
      try {
        const r = mod.parse(junk, ctx);
        if (!Array.isArray(r)) problems.push(`${file}: parse(${JSON.stringify(junk)}) must return an array`);
        else if (r.length) problems.push(`${file}: parse(${JSON.stringify(junk)}) invented ${r.length} finding(s) from empty input`);
      } catch (e) {
        problems.push(`${file}: parse(${JSON.stringify(junk)}) threw instead of returning []: ${e.message}`);
      }
    }
  }

  // 3. fixture
  const fx = path.join(fixtureDir, `${id}.json`);
  let fixtured = false, produced = 0;
  if (fs.existsSync(fx) && typeof mod.parse === 'function') {
    fixtured = true;
    try {
      const raw = fs.readFileSync(fx, 'utf8');
      const found = mod.parse(raw, ctx);
      if (!Array.isArray(found)) {
        problems.push(`${file}: parse(fixture) did not return an array`);
      } else {
        produced = found.length;
        if (!found.length) problems.push(`${file}: fixture produced 0 findings — the parser is not reading the fixture`);
        found.forEach((f, i) => problems.push(...C.validateFinding(f, `${id} fixture[${i}]`)));
        // purity: parsing twice must give identical output
        const again = JSON.stringify(mod.parse(raw, ctx));
        if (again !== JSON.stringify(found)) problems.push(`${file}: parse() is not pure — two calls differ`);
      }
    } catch (e) {
      problems.push(`${file}: parse(fixture) threw: ${e.message}`);
    }
  }

  if (problems.length) { fail++; rows.push([id, 'FAIL', problems.slice(0, 6).join(' | ')]); }
  else if (!fixtured) { partial++; rows.push([id, 'PARTIAL', 'no fixtures/' + id + '.json — parser unproven']); }
  else { pass++; rows.push([id, 'PASS', `${produced} findings from fixture, contract-valid`]); }
}

const w = Math.max(...rows.map(r => r[0].length), 8);
console.log('adapter contract tests\n');
for (const [id, status, note] of rows) {
  const mark = status === 'PASS' ? 'PASS   ' : status === 'PARTIAL' ? 'PARTIAL' : 'FAIL   ';
  console.log(`  ${mark}  ${id.padEnd(w)}  ${note}`);
}
console.log(`\n${pass} pass, ${partial} partial, ${fail} fail (of ${rows.length})`);

if (fail) {
  console.error('\nFAILED: adapters must satisfy the contract before they are wired into the pipeline.');
  process.exit(1);
}
if (partial && process.argv.includes('--strict')) {
  console.error('\nSTRICT: every adapter needs a fixture.');
  process.exit(1);
}
