#!/usr/bin/env node
// dotnet-codereview-framework — tools/validate-crossrefs.js
// Author: Amr Kadry (github.com/Amrkadry) · MIT License
/**
 * Cross-reference integrity between a review's canonical findings and the GENERIC
 * .NET test-case catalog (catalog/dotnet-test-cases.json).
 *
 * Findings reference catalog ids (A-001, B-003, E-012, ...) rather than bespoke test ids,
 * so one shared library of .NET test cases serves every review. A review may additionally
 * supply reviews/<id>/test-catalog.json for application-specific cases; ids from both are
 * accepted.
 *
 *   node tools/validate-crossrefs.js reviews/example
 */
'use strict';
const fs = require('fs');
const path = require('path');

const dir = process.argv[2];
if (!dir) { console.error('usage: validate-crossrefs.js <reviewDir>'); process.exit(2); }

const repoRoot = path.resolve(__dirname, '..');

// ---------------------------------------------------------------- load catalogs
// Every catalog/*.json is merged, so adding a catalog file extends coverage without
// touching this tool. Base catalog = categories A-R; advanced = S-Z.
const catalogDir = path.join(repoRoot, 'catalog');
const catalogFiles = fs.readdirSync(catalogDir).filter(f => f.endsWith('.json')).sort();
const catalogs = catalogFiles.map(f =>
  JSON.parse(fs.readFileSync(path.join(catalogDir, f), 'utf8')));

const generic = {
  categories: Object.assign({}, ...catalogs.map(c => c.categories)),
  tests: catalogs.flatMap(c => c.tests)
};
const genericTests = generic.tests;

let localTests = [];
const localPath = path.join(dir, 'test-catalog.json');
if (fs.existsSync(localPath)) {
  localTests = JSON.parse(fs.readFileSync(localPath, 'utf8')).tests || [];
}

const testById = new Map(genericTests.concat(localTests).map(t => [t.id, t]));

// ---------------------------------------------------------------- load findings
const findings = fs.readdirSync(dir)
  .filter(f => /^findings.*\.json$/.test(f))
  .flatMap(f => JSON.parse(fs.readFileSync(path.join(dir, f), 'utf8')).findings || []);

const problems = [];
const warnings = [];

// 1. every referenced test id must resolve in the generic or local catalog
for (const f of findings) {
  for (const t of f.tests || []) {
    if (!testById.has(t)) problems.push(`finding ${f.findingId} references unknown test id "${t}"`);
  }
}

// 2. catalog structural integrity
const seenTest = new Set();
const validCats = Object.keys(generic.categories);
for (const t of genericTests) {
  if (seenTest.has(t.id)) problems.push(`duplicate catalog test id ${t.id}`);
  seenTest.add(t.id);
  if (!validCats.includes(t.category)) problems.push(`test ${t.id}: unknown category "${t.category}"`);
  for (const req of ['title', 'lookFor', 'expected', 'stack', 'type', 'priority', 'automatable']) {
    if (!t[req]) problems.push(`test ${t.id}: missing required field "${req}"`);
  }
  if (!['framework', 'core', 'both'].includes(t.stack))
    problems.push(`test ${t.id}: invalid stack "${t.stack}"`);
  if (!['DETERMINISTIC', 'AI_ASSISTED', 'DYNAMIC', 'MANUAL'].includes(t.automatable))
    problems.push(`test ${t.id}: invalid automatable "${t.automatable}"`);
}

// 3. findings with no mapped test (warning, not an error)
const untested = findings.filter(f => !(f.tests || []).length).map(f => f.findingId);
if (untested.length) warnings.push(`findings with no mapped test: ${untested.join(', ')}`);

// 4. security findings should map to at least one security-category test
const secCats = ['A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'M', 'N', 'Q'];
for (const f of findings.filter(x => x.category === 'security' && (x.tests || []).length)) {
  const cats = f.tests.map(t => (testById.get(t) || {}).category);
  if (!cats.some(c => secCats.includes(c)))
    warnings.push(`security finding ${f.findingId} maps to no security-category test`);
}

// ---------------------------------------------------------------- report
const byCat = genericTests.reduce((m, t) => (m[t.category] = (m[t.category] || 0) + 1, m), {});
const byAuto = genericTests.reduce((m, t) => (m[t.automatable] = (m[t.automatable] || 0) + 1, m), {});
const byStack = genericTests.reduce((m, t) => (m[t.stack] = (m[t.stack] || 0) + 1, m), {});

console.log(`generic catalog: ${genericTests.length} test cases across ${Object.keys(byCat).length} categories`);
if (localTests.length) console.log(`review-local catalog: ${localTests.length} test cases`);
console.log(`review findings: ${findings.length}`);

console.log('\nby category:');
Object.keys(generic.categories).sort().forEach(c =>
  console.log(`  ${c}  ${String(byCat[c] || 0).padStart(3)}  ${generic.categories[c]}`));

console.log('\nby automatability:');
Object.entries(byAuto).sort((a, b) => b[1] - a[1])
  .forEach(([k, v]) => console.log(`  ${String(v).padStart(3)}  ${k}`));

console.log('\nby stack:');
Object.entries(byStack).sort((a, b) => b[1] - a[1])
  .forEach(([k, v]) => console.log(`  ${String(v).padStart(3)}  ${k}`));

if (warnings.length) {
  console.log('\nwarnings:');
  warnings.forEach(w => console.log('  - ' + w));
}
if (problems.length) {
  console.error(`\nCROSS-REFERENCE ERRORS (${problems.length}):`);
  problems.forEach(p => console.error('  - ' + p));
  process.exit(1);
}
console.log('\nOK: catalog is structurally valid and every finding reference resolves.');
