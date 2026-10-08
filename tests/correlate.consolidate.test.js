// dotnet-codereview-framework — tests/correlate.consolidate.test.js
// Author: Amr Kadry (github.com/Amrkadry) · MIT License
'use strict';
/**
 * Tests for rule-family consolidation (the coarse pass after correlate()).
 * Contract:
 *   - same tool + same rule across files/lines -> ONE finding, rest as additionalLocations
 *   - primary keeps the strongest severity and confidence
 *   - sources union survives (cross-tool corroboration inside a family)
 *   - dependency advisories and INFO manual-review items are NEVER consolidated
 *   - --no-consolidate equivalent: singleton families pass through unchanged
 */
const test = require('node:test');
const assert = require('assert');
const { consolidate } = require('../src/correlate/merge');

function f(tool, rule, file, line, severity = 'MEDIUM', confidence = 'POSSIBLE') {
  return {
    title: `${rule} somewhere`,
    category: 'security',
    subcategory: rule,
    severity, confidence,
    cvss: null,
    cwe: ['CWE-000'],
    location: { file, startLine: line },
    evidence: { snippet: 'x', language: 'csharp', toolOutput: `${tool} ${rule}` },
    detection: { class: 'DETERMINISTIC', rules: [{ engine: tool, ruleId: rule, status: 'ALERT' }] },
    sources: [{ tool, status: 'REPORTED', sourceFindingId: rule }],
    problem: 'p', impact: 'i', recommendation: 'r',
  };
}

test('same rule across files folds into one finding with additionalLocations', () => {
  const input = [
    f('sonarqube', 'S1481', 'a.cs', 10),
    f('sonarqube', 'S1481', 'b.cs', 20),
    f('sonarqube', 'S1481', 'c.cs', 30),
  ];
  const { findings, stats } = consolidate(input);
  assert.equal(findings.length, 1);
  assert.equal(stats.consolidatedAway, 2);
  assert.equal(findings[0].location.file, 'a.cs');
  assert.equal(findings[0].location.additionalLocations.length, 2);
  assert.equal(findings[0].consolidated.locations, 3);
});

test('primary keeps the strongest severity and confidence', () => {
  const input = [
    f('native', 'cs-ssh-hostkey', 'a.cs', 10, 'MEDIUM', 'POSSIBLE'),
    f('native', 'cs-ssh-hostkey', 'b.cs', 20, 'HIGH', 'LIKELY'),
  ];
  const { findings } = consolidate(input);
  assert.equal(findings.length, 1);
  assert.equal(findings[0].severity, 'HIGH');
  assert.equal(findings[0].confidence, 'LIKELY');
});

test('different rules never merge, dependency advisories never merge', () => {
  const input = [
    f('sonarqube', 'S1481', 'a.cs', 1),
    f('sonarqube', 'S3776', 'a.cs', 2),
    { ...f('osv', 'GHSA-xxxx', 'packages.config', 3), category: 'dependency',
      advisories: ['GHSA-xxxx'], package: { name: 'P', installed: '1.0.0' } },
    { ...f('osv', 'GHSA-yyyy', 'packages.config', 4), category: 'dependency',
      advisories: ['GHSA-yyyy'], package: { name: 'Q', installed: '1.0.0' } },
  ];
  const { findings, stats } = consolidate(input);
  assert.equal(findings.length, 4);
  assert.equal(stats.consolidatedAway, 0);
});

test('INFO manual-review items pass through untouched', () => {
  const info = { ...f('native', 'manual', 'a.cs', 1), severity: 'INFO' };
  const { findings, stats } = consolidate([info]);
  assert.equal(findings.length, 1);
  assert.equal(stats.consolidatedAway, 0);
  assert.equal(findings[0].consolidated, undefined);
});

test('singleton families pass through without consolidation metadata', () => {
  const input = [f('native', 'cs-ssh-hostkey', 'a.cs', 10)];
  const { findings } = consolidate(input);
  assert.equal(findings.length, 1);
  assert.equal(findings[0].consolidated, undefined);
  assert.equal(findings[0].location.additionalLocations, undefined);
});
