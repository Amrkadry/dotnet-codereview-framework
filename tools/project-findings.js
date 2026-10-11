#!/usr/bin/env node
// dotnet-codereview-framework — tools/project-findings.js
// Author: Amr Kadry (github.com/Amrkadry) · MIT License
/**
 * dotnet-moraa-codereviewer — canonical projection engine.
 *
 * The canonical JSON is the SINGLE SOURCE OF TRUTH. Every other view is generated
 * from it and may never contain a fact that is absent from it.
 *
 *   reviews/<id>/findings-*.json
 *             |
 *             +--> report.json     (merged canonical, machine-readable)
 *             +--> report.sarif    (SARIF 2.1.0 -> GitHub/GitLab/Azure code scanning)
 *             +--> reports/*.md    (human views: exec, security, deps, tests, config...)
 *
 * Usage:  node tools/project-findings.js reviews/example
 */
'use strict';
const fs = require('fs');
const path = require('path');

const reviewDir = process.argv[2];
if (!reviewDir) { console.error('usage: project-findings.js <reviewDir>'); process.exit(2); }

const repoRoot = path.resolve(__dirname, '..');
const outDir = path.join(repoRoot, 'reports');
fs.mkdirSync(outDir, { recursive: true });

// ---------------------------------------------------------------- load + merge
const parts = fs.readdirSync(reviewDir)
  .filter(f => /^findings.*\.json$/.test(f))
  .sort();

let findings = [];
let reviewMeta = {};
for (const f of parts) {
  const doc = JSON.parse(fs.readFileSync(path.join(reviewDir, f), 'utf8'));
  reviewMeta = Object.assign({}, doc.review, reviewMeta);
  findings = findings.concat(doc.findings || []);
}

// ------------------------------------------------------- integrity checks
const errors = [];
const seen = new Set();
for (const f of findings) {
  if (seen.has(f.findingId)) errors.push(`duplicate findingId: ${f.findingId}`);
  seen.add(f.findingId);
  if (!f.sources || !f.sources.length) errors.push(`${f.findingId}: no sources`);
  if (f.cvss && f.cvss.vector && !/^CVSS:3\.1\//.test(f.cvss.vector))
    errors.push(`${f.findingId}: malformed CVSS vector`);
  // A finding may not claim CVSS for a non-scoreable category.
  const nonScoreable = ['architecture', 'testing', 'process'];
  if (f.cvss && nonScoreable.includes(f.category))
    errors.push(`${f.findingId}: category '${f.category}' must have cvss=null`);
  if ((f.status === 'FALSE_POSITIVE' || f.status === 'ACCEPTED_RISK') && !f.suppression)
    errors.push(`${f.findingId}: ${f.status} requires a suppression block with an expiry`);
}
if (errors.length) {
  console.error('CANONICAL INTEGRITY ERRORS:');
  errors.forEach(e => console.error('  - ' + e));
  process.exitCode = 1;
}

// ------------------------------------------------------------------ ordering
const SEV = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3, INFO: 4 };
const CONF = { CONFIRMED: 0, LIKELY: 1, POSSIBLE: 2, UNVERIFIED: 3 };
const score = f => (f.cvss && f.cvss.score) || 0;
findings.sort((a, b) =>
  SEV[a.severity] - SEV[b.severity] ||
  score(b) - score(a) ||
  CONF[a.confidence] - CONF[b.confidence] ||
  a.findingId.localeCompare(b.findingId));

// --------------------------------------------------------------- report.json
const bySeverity = s => findings.filter(f => f.severity === s);
const summary = {
  review: reviewMeta,
  generatedAt: new Date().toISOString().slice(0, 10),
  totals: {
    all: findings.length,
    critical: bySeverity('CRITICAL').length,
    high: bySeverity('HIGH').length,
    medium: bySeverity('MEDIUM').length,
    low: bySeverity('LOW').length,
    info: bySeverity('INFO').length
  },
  byCategory: findings.reduce((m, f) => (m[f.category] = (m[f.category] || 0) + 1, m), {}),
  byConfidence: findings.reduce((m, f) => (m[f.confidence] = (m[f.confidence] || 0) + 1, m), {}),
  cvss: {
    scored: findings.filter(f => f.cvss).length,
    notApplicable: findings.filter(f => !f.cvss).length,
    max: findings.reduce((m, f) => Math.max(m, score(f)), 0)
  },
  // Two INDEPENDENT queues: an old package is not a vulnerability.
  dependencyQueues: {
    security: findings.filter(f => f.category === 'dependency' && f.cvss).map(f => f.findingId),
    maintenance: findings.filter(f => f.category === 'dependency' && !f.cvss).map(f => f.findingId)
  },
  environmentDependent: findings
    .filter(f => f.verification && f.verification.environmentDependent)
    .map(f => ({ id: f.findingId, openQuestion: (f.verification || {}).openQuestion || null })),
  corrections: findings
    .filter(f => f.verification && ['CORRECTED', 'STRENGTHENED', 'CLARIFIED', 'WITHDRAWN'].includes(f.verification.outcome))
    .map(f => ({ id: f.findingId, outcome: f.verification.outcome }))
};
fs.writeFileSync(path.join(reviewDir, 'report.json'),
  JSON.stringify({ summary, findings }, null, 2));

// -------------------------------------------------------------- report.sarif
const sarifLevel = s => ({ CRITICAL: 'error', HIGH: 'error', MEDIUM: 'warning', LOW: 'note', INFO: 'note' }[s] || 'note');
const rules = findings.map(f => ({
  id: f.findingId,
  name: f.findingId.replace(/-/g, ''),
  shortDescription: { text: f.title },
  fullDescription: { text: f.problem || f.title },
  help: { text: f.recommendation || '', markdown: '**Impact**\n\n' + (f.impact || '') + '\n\n**Recommendation**\n\n' + (f.recommendation || '') },
  properties: {
    tags: ['moraa', f.category, f.subcategory].concat(f.cwe || []).concat(f.owasp || []).filter(Boolean),
    'security-severity': f.cvss ? String(f.cvss.score) : undefined,
    precision: ({ CONFIRMED: 'very-high', LIKELY: 'high', POSSIBLE: 'medium', UNVERIFIED: 'low' })[f.confidence]
  },
  defaultConfiguration: { level: sarifLevel(f.severity) }
}));

const results = findings.map(f => ({
  ruleId: f.findingId,
  level: sarifLevel(f.severity),
  message: { text: f.title + ' — ' + (f.impact || '').split('. ')[0] + '.' },
  locations: [{
    physicalLocation: {
      artifactLocation: { uri: f.location.file.replace(/\\/g, '/') },
      region: { startLine: f.location.startLine || 1, endLine: f.location.endLine || f.location.startLine || 1 }
    }
  }],
  relatedLocations: (f.location.additionalLocations || []).map((l, i) => ({
    id: i,
    physicalLocation: {
      artifactLocation: { uri: String(l.file).replace(/\\/g, '/') },
      region: { startLine: l.startLine || 1 }
    },
    message: { text: l.note || '' }
  })),
  partialFingerprints: { moraaFindingId: f.findingId },
  properties: {
    confidence: f.confidence,
    status: f.status,
    priority: f.priority,
    sources: (f.sources || []).map(s => s.tool + ':' + s.status)
  }
}));

fs.writeFileSync(path.join(reviewDir, 'report.sarif'), JSON.stringify({
  $schema: 'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json',
  version: '2.1.0',
  runs: [{
    tool: { driver: { name: 'dotnet-moraa-codereviewer', version: '1.0.0', informationUri: 'https://moraa.dev', rules } },
    results
  }]
}, null, 2));

// ---------------------------------------------------------------- md helpers
const mdTable = (headers, rows) =>
  '| ' + headers.join(' | ') + ' |\n' +
  '|' + headers.map(() => '---').join('|') + '|\n' +
  rows.map(r => '| ' + r.join(' | ') + ' |').join('\n') + '\n';

const cvssCell = f => f.cvss ? `${f.cvss.score} (${f.cvss.severity})` : 'N/A';
const esc = s => String(s == null ? '' : s).replace(/\|/g, '\\|').replace(/\n+/g, ' ');
const firstSentence = s => { const t = String(s || ''); const i = t.indexOf('. '); return i > 0 ? t.slice(0, i + 1) : t; };

const write = (name, body) => {
  fs.writeFileSync(path.join(outDir, name), body);
  console.log('  wrote reports/' + name);
};

// -------------------------------------------------- 02-security-findings.md
const secCats = ['security'];
const sec = findings.filter(f => secCats.includes(f.category));
let body = '# Security Findings\n\n*Generated from the canonical JSON. Do not edit by hand.*\n\n';
for (const sevName of ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']) {
  const g = sec.filter(f => f.severity === sevName);
  if (!g.length) continue;
  body += `## ${sevName}\n\n`;
  for (const f of g) {
    body += `### ${f.findingId} — ${f.title}\n\n`;
    body += mdTable(['Field', 'Value'], [
      ['Severity', f.severity], ['CVSS', cvssCell(f)],
      ['CVSS Vector', f.cvss ? '`' + f.cvss.vector + '`' : 'N/A'],
      ['Confidence', f.confidence], ['CWE', (f.cwe || []).join(', ') || '—'],
      ['OWASP', (f.owasp || []).join(', ') || '—'],
      ['Location', '`' + f.location.file + (f.location.startLine ? ':' + f.location.startLine : '') + '`'],
      ['Priority', f.priority || '—'], ['Effort', f.effort || '—'], ['Status', f.status]
    ]);
    if (f.severityRationale) body += `\n> [!note] Severity vs CVSS\n> ${f.severityRationale}\n`;
    body += `\n**Problem.** ${f.problem}\n\n**Impact.** ${f.impact}\n\n`;
    if (f.attackScenario) body += `**Attack / failure scenario.** ${f.attackScenario}\n\n`;
    if (f.rootCause) body += `**Root cause.** ${f.rootCause}\n\n`;
    body += '**Evidence**\n\n```' + (f.evidence.language || 'csharp') + '\n' + f.evidence.snippet + '\n```\n\n';
    if (f.evidence.toolOutput) body += '**Tool output**\n\n```text\n' + f.evidence.toolOutput + '\n```\n\n';
    body += `**Recommendation.** ${f.recommendation}\n\n`;
    if (f.correctedCode) body += '**Corrected code**\n\n```csharp\n' + f.correctedCode + '\n```\n\n';
    if (f.tests) body += `**Required tests:** ${f.tests.join(', ')}\n\n`;
    if (f.regressionTest) body += `**Regression test.** ${f.regressionTest}\n\n`;
    if (f.detection) body += `**Detection (${f.detection.class}):** ` +
      (f.detection.rules || []).map(r => `${r.engine}/${r.ruleId} [${r.status}]`).join(', ') + '\n\n';
    body += `**Sources:** ` + (f.sources || []).map(s => `${s.tool} → ${s.status}`).join('; ') + '\n\n';
    if (f.verification) body += `**Verification.** ${f.verification.disproofAttempt || f.verification.method} → **${f.verification.outcome}**\n\n`;
    body += '---\n\n';
  }
}
write('02-security-findings.md', body);

// ------------------------------------------------- 05-outdated-dependencies.md
const depMaint = findings.filter(f => f.category === 'dependency' && !f.cvss);
const depSec = findings.filter(f => f.category === 'dependency' && f.cvss);
body = '# Dependencies — Two Independent Queues\n\n' +
  '*An outdated package is **not** automatically a vulnerability, and a current package can still ' +
  'carry one. These queues are tracked separately and must never be merged into a single count.*\n\n' +
  '## Queue A — SECURITY (confirmed advisory against the exact version in use)\n\n';
body += depSec.length
  ? mdTable(['ID', 'Title', 'CVSS', 'Status'], depSec.map(f => [f.findingId, esc(f.title), cvssCell(f), f.status]))
  : '**Empty.** No exploitable advisory was confirmed against the exact versions present.\n\n' +
    '> [!warning] Absence of evidence, not evidence of absence\n' +
    '> No vulnerable-package scanner could be executed on this project shape — see `DEP-AUDIT-001`. ' +
    'This queue being empty reflects a missing capability, not a clean result.\n';
body += '\n## Queue B — MAINTENANCE (outdated, EOL, deprecated, duplicated, licence)\n\n';
body += mdTable(['ID', 'Title', 'CVSS', 'Severity', 'Status'],
  depMaint.map(f => [f.findingId, esc(f.title), 'N/A', f.severity, f.status]));
body += '\n' + depMaint.map(f => `### ${f.findingId}\n\n${f.impact}\n\n**Recommendation.** ${f.recommendation}\n`).join('\n');
write('05-outdated-dependencies.md', body);

// ---------------------------------------------------------- 06-test-gaps.md
body = '# Test Coverage Gaps\n\n';
const testFindings = findings.filter(f => f.category === 'testing');
body += testFindings.map(f => `## ${f.findingId} — ${f.title}\n\n${f.impact}\n\n`).join('');
body += '## Required tests by finding\n\n';
body += mdTable(['Finding', 'Severity', 'Required tests', 'Regression test'],
  findings.filter(f => (f.tests || []).length)
    .map(f => [f.findingId, f.severity, (f.tests || []).join(', '), esc(firstSentence(f.regressionTest))]));
write('06-test-gaps.md', body);

// -------------------------------------------------------- 07-configuration.md
const cfg = findings.filter(f => f.category === 'configuration');
body = '# Configuration Findings\n\n' + mdTable(
  ['ID', 'Title', 'Severity', 'CVSS', 'File', 'Status'],
  cfg.map(f => [f.findingId, esc(f.title), f.severity, cvssCell(f), '`' + f.location.file + '`', f.status]));
body += '\n' + cfg.map(f => `## ${f.findingId} — ${f.title}\n\n**Problem.** ${f.problem}\n\n**Impact.** ${f.impact}\n\n**Recommendation.** ${f.recommendation}\n`).join('\n');
write('07-configuration.md', body);

// --------------------------------------------------- 13-remediation-plan.md
body = '# Remediation Roadmap\n\n*Ordered by priority, then CVSS, then confidence.*\n\n';
for (const p of ['P0', 'P1', 'P2', 'P3']) {
  const g = findings.filter(f => f.priority === p);
  if (!g.length) continue;
  const label = { P0: 'Immediate security risk', P1: 'High-risk security/reliability', P2: 'Important technical debt', P3: 'Improvement' }[p];
  body += `## ${p} — ${label}\n\n` + mdTable(
    ['ID', 'Title', 'Severity', 'CVSS', 'Effort', 'Reason'],
    g.map(f => [f.findingId, esc(f.title), f.severity, cvssCell(f), f.effort || '—', esc(firstSentence(f.impact))]));
  body += '\n';
}
write('13-remediation-plan.md', body);

// ------------------------------------------------------- 01-executive-summary.md
const overall = summary.totals.critical > 0 ? 'CRITICAL' : summary.totals.high > 0 ? 'HIGH' : 'MEDIUM';
body = `# Executive Summary\n\n**Overall risk: ${overall}**\n\n` + mdTable(
  ['Metric', 'Value'],
  [['Total findings', summary.totals.all],
   ['Critical', summary.totals.critical], ['High', summary.totals.high],
   ['Medium', summary.totals.medium], ['Low', summary.totals.low],
   ['CVSS-scored', summary.cvss.scored], ['CVSS N/A (by design)', summary.cvss.notApplicable],
   ['Highest CVSS', summary.cvss.max],
   ['Dependency SECURITY queue', summary.dependencyQueues.security.length],
   ['Dependency MAINTENANCE queue', summary.dependencyQueues.maintenance.length],
   ['Environment-dependent (unresolved)', summary.environmentDependent.length]]);
body += '\n## Top remediation priorities\n\n' + mdTable(
  ['#', 'ID', 'Title', 'Severity', 'CVSS'],
  findings.slice(0, 10).map((f, i) => [i + 1, f.findingId, esc(f.title), f.severity, cvssCell(f)]));
body += '\n## Findings corrected during validation\n\n' +
  '*Reasoning that was wrong in an earlier iteration and was fixed. Recorded because a review that ' +
  'never corrects itself is not being checked.*\n\n' +
  mdTable(['ID', 'Outcome'], summary.corrections.map(c => [c.id, c.outcome]));
body += '\n## Still environment-dependent\n\n' +
  mdTable(['ID', 'Open question'], summary.environmentDependent.map(e => [e.id, esc(e.openQuestion) || '—']));
write('01-executive-summary.md', body);

// ------------------------------- generic category reports (single source of truth)
const categoryReports = [
  ['03-code-quality.md', 'Code Quality Findings', ['code-quality']],
  ['04-dependencies-vulnerabilities.md', 'Dependency Vulnerabilities (SECURITY queue)', ['dependency'], f => !!f.cvss],
  ['08-architecture.md', 'Architecture Findings', ['architecture']],
  ['09-performance.md', 'Performance Findings', ['performance']],
  ['10-reliability.md', 'Reliability Findings', ['reliability']],
  ['14-deployment-and-process.md', 'Deployment and Process Findings', ['deployment', 'process']],
  ['15-observability.md', 'Observability Findings', ['observability']]
];

for (const [file, title, cats, extra] of categoryReports) {
  let g = findings.filter(f => cats.includes(f.category));
  if (extra) g = g.filter(extra);
  let b = `# ${title}\n\n*Generated from the canonical JSON. Do not edit by hand.*\n\n`;
  if (!g.length) {
    b += '**No findings in this category.**\n\n';
    if (file.startsWith('04-')) {
      b += '> [!warning] This emptiness is a capability gap, not a clean result\n' +
           '> No vulnerable-package scanner could be executed on this project shape — see `DEP-AUDIT-001`.\n' +
           '> An empty SECURITY queue here means the scan did not run, **not** that no vulnerable\n' +
           '> dependency exists. The MAINTENANCE queue is in `05-outdated-dependencies.md`.\n';
    }
  } else {
    b += mdTable(['ID', 'Title', 'Severity', 'CVSS', 'Confidence', 'Location', 'Status'],
      g.map(f => [f.findingId, esc(f.title), f.severity, cvssCell(f), f.confidence,
                  '`' + f.location.file + (f.location.startLine ? ':' + f.location.startLine : '') + '`', f.status]));
    b += '\n';
    for (const f of g) {
      b += `## ${f.findingId} — ${f.title}\n\n`;
      if (f.severityRationale) b += `> [!note] Severity vs CVSS\n> ${f.severityRationale}\n\n`;
      b += `**Problem.** ${f.problem}\n\n**Impact.** ${f.impact}\n\n`;
      if (f.rootCause) b += `**Root cause.** ${f.rootCause}\n\n`;
      b += '**Evidence**\n\n```' + (f.evidence.language || 'csharp') + '\n' + f.evidence.snippet + '\n```\n\n';
      if (f.evidence.toolOutput) b += '**Tool output**\n\n```text\n' + f.evidence.toolOutput + '\n```\n\n';
      b += `**Recommendation.** ${f.recommendation}\n\n`;
      if (f.correctedCode) b += '**Corrected code**\n\n```csharp\n' + f.correctedCode + '\n```\n\n';
      if (f.tests) b += `**Required tests:** ${f.tests.join(', ')}\n\n`;
      b += `**Sources:** ` + (f.sources || []).map(s => `${s.tool} → ${s.status}`).join('; ') + '\n\n';
      if (f.verification) b += `**Verification.** ${f.verification.disproofAttempt || f.verification.method} → **${f.verification.outcome}**\n\n`;
      b += '---\n\n';
    }
  }
  write(file, b);
}

console.log(`\nprojected ${findings.length} findings from ${parts.length} canonical parts`);
console.log(`  ${reviewDir}/report.json`);
console.log(`  ${reviewDir}/report.sarif`);
if (errors.length) console.log(`\n${errors.length} integrity error(s) — see above`);
