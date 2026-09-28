#!/usr/bin/env node
// Summarise a gitleaks JSON report: counts by rule and by file, plus redacted samples.
// Usage: node summarize-gitleaks.js <report.json>
const fs = require('fs');
const path = process.argv[2];
if (!path) { console.error('usage: summarize-gitleaks.js <report.json>'); process.exit(2); }

let findings;
try {
  const raw = fs.readFileSync(path, 'utf8').trim();
  findings = raw === '' ? [] : JSON.parse(raw);
} catch (e) {
  console.error('could not read/parse report:', e.message);
  process.exit(1);
}

const tally = (arr, key) => arr.reduce((m, x) => (m[x[key]] = (m[x[key]] || 0) + 1, m), {});
const show = (obj, limit) => Object.entries(obj)
  .sort((a, b) => b[1] - a[1])
  .slice(0, limit || 50)
  .forEach(([k, v]) => console.log('  ' + String(v).padStart(4) + '  ' + k));

console.log('TOTAL FINDINGS: ' + findings.length);
if (!findings.length) process.exit(0);

console.log('\n--- by rule ---');
show(tally(findings, 'RuleID'));

console.log('\n--- by file (top 12) ---');
const byFile = findings.reduce((m, x) => {
  const base = String(x.File).split(/[\\/]/).slice(-2).join('/');
  m[base] = (m[base] || 0) + 1; return m;
}, {});
show(byFile, 12);

console.log('\n--- samples (redacted) ---');
findings.slice(0, 12).forEach(x => {
  const base = String(x.File).split(/[\\/]/).pop();
  console.log('  ' + x.RuleID + ' @ ' + base + ':' + x.StartLine + '  match=' + String(x.Match || '').slice(0, 70).replace(/\s+/g, ' '));
});
