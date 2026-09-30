'use strict';
/**
 * Unit tests for src/normalize/sarif.js (fromSarif).
 *
 * The normaliser's two design rules are "never invent" and "severity from the tool's own
 * signals, in priority order". Every fixture here pins one rule: absent data must stay absent,
 * tool severity signals must win in the documented order, and malformed input must fail loudly
 * (throw) or honestly ([]) — never silently fabricate findings.
 */
const { test, describe } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { fromSarif, severityFromCvss, LEVEL_TO_SEVERITY } = require('../src/normalize/sarif');

const dir = path.join(__dirname, 'fixtures', 'sarif');
const load = name => JSON.parse(fs.readFileSync(path.join(dir, name), 'utf8'));
const run = name => fromSarif(load(name), { toolId: 'toolx', toolKind: 'sast' });

describe('fromSarif: malformed and empty input', () => {
  test('an empty runs array yields no findings', () => {
    assert.deepEqual(fromSarif({ version: '2.1.0', runs: [] }), []);
    assert.deepEqual(run('empty-runs.json'), []);
  });

  test('a run with no results key yields no findings', () => {
    assert.deepEqual(run('no-results.json'), []);
  });

  test('unparseable JSON throws rather than yielding a silent empty result', () => {
    assert.throws(() => fromSarif('not json'), SyntaxError);
  });

  test('null, non-SARIF objects and a non-array runs field return [] without throwing', () => {
    assert.deepEqual(fromSarif(null), []);
    assert.deepEqual(fromSarif({}), []);
    assert.deepEqual(fromSarif({ runs: 'nope' }), []);
  });
});

describe('fromSarif: locations', () => {
  test('missing physicalLocation degrades to "(unknown)" without crashing', () => {
    const findings = run('missing-location.json');
    assert.equal(findings.length, 2);
    for (const f of findings) {
      assert.equal(f.location.file, '(unknown)');
      assert.equal(f.location.startLine, undefined);
    }
  });

  test('confidence differs between a present-but-empty location entry and no locations at all', () => {
    const [emptyEntry, noLocations] = run('missing-location.json');
    assert.equal(emptyEntry.confidence, 'LIKELY',
      'locations:[{}] counts as a concrete location -> LIKELY');
    assert.equal(noLocations.confidence, 'POSSIBLE',
      'no locations array -> POSSIBLE');
  });

  test('file:/// URIs, %20 escapes and backslashes are decoded and normalised', () => {
    const [fileUri, escaped, backslashes] = run('file-uris.json');
    assert.equal(fileUri.location.file, 'C:/x/Web.config');
    assert.equal(escaped.location.file, 'My Project/Code Behind.aspx.cs');
    assert.equal(backslashes.location.file, 'SampleApp/Services/Http.cs');
  });
});

describe('fromSarif: runs and rule metadata', () => {
  test('findings from ALL runs in one file are returned, count is the sum', () => {
    const findings = run('multi-run.json');
    assert.equal(findings.length, 3, '1 semgrep result + 2 codeql results');
    const rules = new Set(findings.map(f => f.subcategory));
    assert.ok(rules.has('moraa-dotnet-disable-cert-validation'), 'run 1 present');
    assert.ok(rules.has('cs/sql-injection'), 'run 2 present');
  });

  test('a result whose rule has no metadata still produces a finding, nothing fabricated', () => {
    const [f] = run('absent-rule.json');
    assert.ok(f, 'a finding must still be produced');
    assert.equal(f.title, 'The tool emitted a rule it never declared in metadata.',
      'title falls back to the message text');
    assert.equal(f.impact, '', 'impact must stay empty rather than be invented');
    assert.equal(f.subcategory, 'UNDECLARED-RULE');
    assert.equal(f.severity, 'MEDIUM', 'no signal at all -> conservative MEDIUM default');
    assert.equal(f.cvss, null, 'no CVSS may be fabricated');
  });
});

describe('fromSarif: severity precedence', () => {
  test('security-severity 9.1 outranks level note and yields a CRITICAL CVSS-backed finding', () => {
    const findings = run('severity-precedence.json');
    const f = findings.find(x => x.subcategory === 'R-SECSEV');
    assert.equal(f.severity, 'CRITICAL');
    assert.ok(f.cvss, 'a real score must materialise a cvss block');
    assert.equal(f.cvss.score, 9.1);
    assert.equal(f.cvss.version, '3.1');
    assert.equal(f.cvss.severity, 'CRITICAL');
    assert.equal(f.cvss.vector, null,
      'no vector was supplied, so none may be asserted — the note must say so');
  });

  test('with no security-severity, level maps error->HIGH, warning->MEDIUM, note->LOW', () => {
    const findings = run('severity-precedence.json');
    const byRule = Object.fromEntries(findings.map(f => [f.subcategory, f]));
    assert.equal(byRule['R-ERROR'].severity, 'HIGH');
    assert.equal(byRule['R-WARNING'].severity, 'MEDIUM');
    assert.equal(byRule['R-NOTE'].severity, 'LOW');
    for (const r of ['R-ERROR', 'R-WARNING', 'R-NOTE']) {
      assert.equal(byRule[r].cvss, null, `${r} has no score, so no cvss block may exist`);
    }
  });

  test('LEVEL_TO_SEVERITY and severityFromCvss exports behave as the adapter contract expects', () => {
    assert.deepEqual(LEVEL_TO_SEVERITY, { error: 'HIGH', warning: 'MEDIUM', note: 'LOW', none: 'INFO' });
    assert.equal(severityFromCvss(9.1), 'CRITICAL');
    assert.equal(severityFromCvss(7.4), 'HIGH');
    assert.equal(severityFromCvss(5.3), 'MEDIUM');
    assert.equal(severityFromCvss(1.2), 'LOW');
    assert.equal(severityFromCvss(0), 'INFO');
  });
});

describe('fromSarif: suppression and CWE', () => {
  test('a non-empty suppressions array marks the finding FALSE_POSITIVE, not OPEN', () => {
    const [f] = run('suppressed.json');
    assert.equal(f.status, 'FALSE_POSITIVE');
  });

  test('CWE ids are extracted from rule tags and normalised to CWE-<number>', () => {
    const [withCwe, withoutCwe] = run('cwe-tags.json');
    assert.deepEqual(withCwe.cwe, ['CWE-295']);
    assert.equal(withoutCwe.cwe, undefined, 'no CWE in the rule must stay absent, not be invented');
  });
});
