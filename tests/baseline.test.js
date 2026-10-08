// dotnet-codereview-framework — tests/baseline.test.js
// Author: Amr Kadry (github.com/Amrkadry) · MIT License
'use strict';
/**
 * Baseline tests (src/baseline/index.js).
 *
 * The two properties the whole feature rests on:
 *   1. FINGERPRINTS SURVIVE DRIFT. The fingerprint is rule + file + whitespace-normalised
 *      snippet — NOT the line number. Proof by simulation: create a baseline, insert blank
 *      lines above a finding, re-run: the finding is still EXISTING, not NEW.
 *   2. SUPPRESSIONS ARE ACCOUNTABLE. No justification -> error. An expired suppression does
 *      not suppress — the finding returns to OPEN and the expiry is reported so the
 *      acceptance comes back for a human decision.
 */
const { test, describe } = require('node:test');
const assert = require('node:assert/strict');

const B = require('../src/baseline');

const mkFinding = (id, title, file, line, snippet, severity = 'HIGH') => ({
  findingId: id, title, severity,
  category: 'security', subcategory: 'C-001',
  confidence: 'POSSIBLE',
  location: { file, startLine: line, endLine: line },
  evidence: { snippet, language: 'csharp' },
  problem: 'p', impact: 'i', recommendation: 'r',
  sources: [{ tool: 'native', status: 'REPORTED' }],
  status: 'OPEN', tests: ['C-001']
});

describe('fingerprint', () => {
  test('stable across whitespace drift and line shifts, sensitive to content', () => {
    const f1 = mkFinding('SEC-INJ-001', 'SQL injection', 'a/Bad.cs', 10, 'var c = new SqlCommand("SELECT " + q, null);');
    const f2 = mkFinding('SEC-INJ-002', 'SQL injection', 'a\\Bad.cs', 55, // line moved, backslashes, blank lines
      '\n\n   var c = new SqlCommand("SELECT " + q,   null);\n\n');
    assert.equal(B.fingerprint(f1), B.fingerprint(f2), 'formatting-only change produced a NEW fingerprint');

    const f3 = mkFinding('SEC-INJ-003', 'SQL injection', 'a/Bad.cs', 10, 'var c = new SqlCommand("SELECT " + x, null);');
    assert.notEqual(B.fingerprint(f1), B.fingerprint(f3), 'different code must not collide');

    const f4 = mkFinding('SEC-INJ-004', 'SQL injection', 'a/Other.cs', 10, 'var c = new SqlCommand("SELECT " + q, null);');
    assert.notEqual(B.fingerprint(f1), B.fingerprint(f4), 'different file must not collide');
  });

  test('the rule identity is the subcategory, not the sequence-derived findingId', () => {
    // Same defect, renumbered between runs because other findings shifted the order.
    const a = mkFinding('SEC-INJ-007', 'SQL injection', 'a/Bad.cs', 10, 'var c = x;');
    const b = mkFinding('SEC-INJ-001', 'SQL injection', 'a/Bad.cs', 10, 'var c = x;');
    assert.equal(B.fingerprint(a), B.fingerprint(b), 'renumbering broke the fingerprint');
  });
});

describe('create + classify', () => {
  const set1 = () => [
    mkFinding('SEC-INJ-001', 'SQL concat', 'a.cs', 10, 'bad + worse'),
    mkFinding('CFG-GEN-001', 'debug on', 'Web.config', 4, '<compilation debug="true" />', 'MEDIUM'),
    mkFinding('SEC-GEN-009', 'temp', 'old.cs', 3, 'legacy', 'LOW')
  ];

  test('new / existing / fixed classification', () => {
    const baseline = B.create(set1());
    const later = [
      set1()[0],                                       // unchanged -> EXISTING
      set1()[1],                                       // unchanged -> EXISTING
      mkFinding('SEC-GEN-100', 'brand new', 'new.cs', 1, 'fresh badness', 'CRITICAL')
      // set1()[2] is gone -> FIXED
    ];
    const c = B.classify(later, baseline);
    assert.equal(c.summary.newCount, 1);
    assert.equal(c.summary.existingCount, 2);
    assert.equal(c.summary.fixedCount, 1);
    assert.equal(c.new[0].findingId, 'SEC-GEN-100');
    assert.equal(c.fixed[0].findingId, 'SEC-GEN-009');
    assert.equal(c.existing[0].baseline.state, 'EXISTING');
  });

  test('drift survival end-to-end: blank lines inserted above a finding stay EXISTING', () => {
    const baseline = B.create(set1());
    const drifted = [
      mkFinding('SEC-INJ-050', 'SQL concat', 'a.cs', 14, // line moved 10 -> 14
        '\n\n\n\nbad + worse'),
      set1()[1]
    ];
    const c = B.classify(drifted, baseline);
    assert.equal(c.summary.newCount, 0, 'formatting drift must not manufacture NEW findings');
    assert.equal(c.summary.existingCount, 2);
    assert.equal(c.summary.fixedCount, 1);
  });
});

describe('suppressions', () => {
  test('require a justification', () => {
    const f = mkFinding('SEC-INJ-001', 'SQL concat', 'a.cs', 10, 'bad');
    assert.throws(() => B.create([f], { suppressed: { 'SEC-INJ-001': { justification: '   ' } } }),
      /justification/);
    assert.throws(() => B.create([f], { suppressed: { 'SEC-INJ-001': {} } }), /justification/);
  });

  test('validate the expiry date', () => {
    const f = mkFinding('SEC-INJ-001', 'SQL concat', 'a.cs', 10, 'bad');
    assert.throws(() => B.create([f], { suppressed: { 'SEC-INJ-001': { justification: 'ok', expires: 'not-a-date' } } }),
      /not a date/);
  });

  test('unknown findingId in suppressed map fails loudly', () => {
    const f = mkFinding('SEC-INJ-001', 'SQL concat', 'a.cs', 10, 'bad');
    assert.throws(() => B.create([f], { suppressed: { 'SEC-INJ-999': { justification: 'typo' } } }),
      /not present/);
  });

  test('active suppression marks the finding SUPPRESSED and records why', () => {
    const f = mkFinding('SEC-INJ-001', 'SQL concat', 'a.cs', 10, 'bad');
    const future = new Date(Date.now() + 30 * 864e5).toISOString();
    const baseline = B.create([f], { suppressed: { 'SEC-INJ-001': { justification: 'vendor patch pending', expires: future } } });
    const c = B.classify([mkFinding('SEC-INJ-001', 'SQL concat', 'a.cs', 10, 'bad')], baseline);
    assert.equal(c.summary.expiredCount, 0);
    assert.equal(c.existing[0].status, 'SUPPRESSED');
    assert.equal(c.existing[0].suppression.justification, 'vendor patch pending');
    assert.equal(c.existing[0].suppression.expires, future);
  });

  test('EXPIRED suppression: finding returns to OPEN and the expiry is reported', () => {
    const f = mkFinding('SEC-INJ-001', 'SQL concat', 'a.cs', 10, 'bad');
    const past = new Date(Date.now() - 864e5).toISOString();
    const baseline = B.create([f], { suppressed: { 'SEC-INJ-001': { justification: 'time-boxed acceptance', expires: past } } });
    const c = B.classify([mkFinding('SEC-INJ-001', 'SQL concat', 'a.cs', 10, 'bad')], baseline);
    assert.equal(c.summary.expiredCount, 1);
    assert.equal(c.existing[0].status, 'OPEN', 'an expired suppression must not keep suppressing');
    assert.equal(c.existing[0].suppression.active, false);
    assert.equal(c.existing[0].suppression.expired, true);
  });

  test('a suppression without expiry never expires', () => {
    const f = mkFinding('SEC-INJ-001', 'SQL concat', 'a.cs', 10, 'bad');
    const baseline = B.create([f], { suppressed: { 'SEC-INJ-001': { justification: 'documented decision' } } });
    const c = B.classify([f], baseline);
    assert.equal(c.summary.expiredCount, 0);
    assert.equal(c.existing[0].status, 'SUPPRESSED');
  });
});

describe('gate', () => {
  test('NEW findings at or above the threshold fail; below pass', () => {
    const baseline = B.create([mkFinding('A', 'old', 'o.cs', 1, 'old')]);
    const cls = B.classify([
      mkFinding('B', 'new high', 'n.cs', 1, 'new bad', 'HIGH'),
      mkFinding('C', 'new low', 'n2.cs', 1, 'minor', 'LOW')
    ], baseline);
    const gHigh = B.gate(cls, 'HIGH');
    assert.equal(gHigh.fail, true);
    assert.equal(gHigh.offenders.length, 1);
    assert.equal(B.gate(cls, 'MEDIUM').fail, true);
    assert.equal(B.gate(cls, 'LOW').fail, true);
  });

  test('expired suppressions always gate, regardless of threshold', () => {
    const f = mkFinding('SEC-INJ-001', 'SQL concat', 'a.cs', 10, 'bad', 'LOW');
    const past = new Date(Date.now() - 864e5).toISOString();
    const baseline = B.create([f], { suppressed: { 'SEC-INJ-001': { justification: 'x', expires: past } } });
    const cls = B.classify([f], baseline);
    const g = B.gate(cls, 'INFO');
    assert.equal(g.fail, true, 'an overdue acceptance must come back even at the loosest gate');
    assert.ok(/expired/i.test(g.message));
  });

  test('clean classification passes any threshold', () => {
    const baseline = B.create([mkFinding('A', 'old', 'o.cs', 1, 'old')]);
    const cls = B.classify([mkFinding('A', 'old', 'o.cs', 1, 'old')], baseline);
    assert.deepEqual(B.gate(cls, 'CRITICAL'), { fail: false, threshold: 'CRITICAL' });
  });

  test('rejects an unknown severity', () => {
    const baseline = B.create([]);
    const cls = B.classify([], baseline);
    assert.throws(() => B.gate(cls, 'APOCALYPTIC'), /unknown severity/);
  });
});
