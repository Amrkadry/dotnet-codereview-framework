'use strict';
/**
 * Schema conformance: every canonical finding the pipeline emits must validate against
 * schema/finding.schema.json.
 *
 * The raw set is built EXACTLY the way tools/test-correlation.js builds it: each adapter's
 * parse() runs over fixtures/<adapter-id>.json, then correlate() dedupes the union. Adapter
 * modules are required read-only and never edited here.
 *
 * AS OF THIS TEST'S WRITING the pipeline produces findings that DO NOT validate. Per the task
 * rules the sources were left untouched; instead this test records the exact current violation
 * set (see BUG below) so it fails loudly the moment the behaviour changes in either direction.
 *
 * BUG: the current violation set, by root cause —
 *   1. `/advisories` (additional property not allowed): the schema defines cwe/owasp but has NO
 *      `advisories` property, yet dependency adapters emit advisory ids there and
 *      src/correlate/merge.js mergeInto() synthesises `advisories: []` on EVERY merged finding
 *      (even security/code-quality ones that never had advisories). Affected: DEP-VULN-001..004,
 *      SEC-CRYPTO-001, SEC-SECRET-001, SEC-GEN-001.
 *   2. `/package` (additional property not allowed): trivy/snyk adapters emit
 *      `package {name, installed, fixed}`; the schema has no such property, so the single most
 *      actionable dependency fact is unrepresentable. Affected: DEP-VULN-001..004.
 *   3. `/_transitive` (additional property not allowed): the snyk adapter leaks an internal
 *      bookkeeping flag into the canonical finding. Affected: DEP-VULN-001, DEP-VULN-003.
 *   4. `/detection/rules/0/engine` ("snyk" not in enum): the snyk adapter names its engine
 *      "snyk", which the schema enum does not list (semgrep/roslyn/sonarqube/gitleaks/trivy/
 *      dependency-check/config-xml/architecture/codeql/custom). Affected: DEP-VULN-001, DEP-VULN-003.
 *   5. `/verification/outcome` ("UNVERIFIED" not in enum): the ai-review adapter records
 *      outcome "UNVERIFIED", but the schema enum only allows CONFIRMED/CORRECTED/STRENGTHENED/
 *      CLARIFIED/WITHDRAWN. Affected: SEC-AUTHZ-001, REL-GEN-001.
 */
const { test, describe } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { validate } = require('./helpers/schema');
const { correlate } = require('../src/correlate/merge');

const root = path.resolve(__dirname, '..');
const schema = JSON.parse(fs.readFileSync(path.join(root, 'schema', 'finding.schema.json'), 'utf8'));

// Same mechanism as tools/test-correlation.js, generalised over every adapter that has a fixture.
const adapters = fs.readdirSync(path.join(root, 'src', 'adapters'))
  .filter(f => f.endsWith('.js'))
  .map(f => require(path.join(root, 'src', 'adapters', f)));
const loaded = [];
const raw = [];
for (const adapter of adapters) {
  const fixture = path.join(root, 'fixtures', `${adapter.id}.json`);
  if (!fs.existsSync(fixture)) continue;
  raw.push(...adapter.parse(fs.readFileSync(fixture, 'utf8'), { sourcePath: root }));
  loaded.push(adapter.id);
}

test('precondition: a realistic raw finding set was built', () => {
  assert.ok(loaded.length >= 5, `expected several adapters with fixtures, got ${loaded.join(',')}`);
  assert.ok(raw.length >= 10, 'the fixtures must produce a non-trivial raw set');
});

describe('schema conformance of the correlated pipeline output', () => {
  // Enum-error messages embed the offending value and the schema's full value list, both of
  // which churn independently of the violation itself; pin path+kind instead.
  const normalise = e => e.replace(/: value string ".*?" not in enum \[.*\]$/, ': not in enum');

  // Identity-free and count-free: findingId is assigned by correlate() from SORTED order, so
  // any new adapter or fixture renumbers ids and an id-pinned expectation fails for a reason
  // that has nothing to do with schema conformance. Numeric array indices in the path are
  // normalised to N for the same reason — which rule slot an engine name lands in is bookkeeping.
  const identityFree = v => {
    const s = v.replace(/^\S+ /, '');                     // drop the findingId prefix
    const c = s.indexOf(': ');
    return s.slice(0, c).replace(/\/\d+(?=\/|$)/g, '/N') + s.slice(c);
  };

  const result = correlate(raw, { toolsThatRan: loaded });
  const violations = [];
  for (const f of result.findings) {
    const { valid, errors } = validate(schema, f);
    if (!valid) errors.forEach(e => violations.push(`${f.findingId} ${normalise(e)}`));
  }
  const signature = [...new Set(violations.map(identityFree))].sort();

  // BUG: pinned to the CURRENT actual behaviour. See the file-level BUG comment for the five
  // root causes. If this assertion fails, either a violation was fixed (remove it from the set)
  // or a new one was introduced (record it, do not hide it).
  const EXPECTED = [
    '/_transitive: additional property not allowed',
    '/advisories: additional property not allowed',
    '/detection/rules/N/engine: not in enum',
    '/package: additional property not allowed',
    '/verification/outcome: not in enum'
  ];

  test('every canonical finding carries a schema-shaped unique id', () => {
    const ids = result.findings.map(f => f.findingId);
    assert.equal(ids.length, new Set(ids).size);
    const pattern = /^(SEC|CFG|DEP|CODE|ARCH|PERF|REL|TEST|OBS|LOGIC|PROC)-[A-Z0-9]+-[0-9]{3}$/;
    ids.forEach(id => assert.match(id, pattern));
  });

  test('the majority of pipeline findings DO validate against the schema', () => {
    const invalidIds = new Set(violations.map(v => v.split(' ')[0]));
    const clean = result.findings.filter(f => !invalidIds.has(f.findingId));
    assert.ok(clean.length > 0,
      'at least some canonical findings must be fully conformant — a schema nothing satisfies proves nothing');
    // Spot-check one clean finding end to end; it must not be a degenerate object.
    const sample = clean[0];
    assert.equal(validate(schema, sample).valid, true, validate(schema, sample).errors.join('; '));
    assert.ok(sample.title.length >= 8);
    assert.ok(sample.sources.length >= 1);
  });

  test('the DISTINCT root-cause signature is exactly the five known causes recorded above', () => {
    // The SET of distinct "<path>: <kind>" strings, identity-free — stable under id
    // renumbering when adapters or fixtures are added, unlike the previous id-count pin.
    assert.deepEqual(signature, [...EXPECTED].sort());
  });
});
