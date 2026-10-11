// dotnet-codereview-framework — tests/helpers.schema.test.js
// Author: Amr Kadry (github.com/Amrkadry) · MIT License
'use strict';
/**
 * The validator must actually REJECT. These tests prove every supported keyword both accepts a
 * valid value and rejects the corresponding violation — a validator that only accepted would be
 * worse than none, because it would lend false authority to non-conforming findings.
 */
const { test, describe } = require('node:test');
const assert = require('node:assert/strict');
const { validate } = require('./helpers/schema');

// A minimal finding-shaped schema carrying every keyword the real finding schema uses.
const FINDING = {
  $schema: 'https://json-schema.org/draft/2020-12/schema',
  $id: 'https://moraa.dev/schema/test',
  title: 'test finding',
  description: 'documentation, must be ignored',
  type: 'object',
  required: ['findingId', 'title', 'severity'],
  additionalProperties: false,
  properties: {
    findingId: { type: 'string', pattern: '^(SEC|DEP)-[A-Z]+-[0-9]{3}$' },
    title: { type: 'string', minLength: 8, maxLength: 120 },
    severity: { type: 'string', enum: ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'] },
    count: { type: 'integer', minimum: 0, maximum: 10 },
    score: { type: 'number', minimum: 0 },
    active: { type: 'boolean' },
    nothing: { type: 'null' },
    tags: { type: 'array', minItems: 1, items: { type: 'string' } },
    version: { const: '3.1' },
    cvss: {
      oneOf: [
        { type: 'null', description: 'N/A' },
        { type: 'object', required: ['version', 'score'], additionalProperties: false,
          properties: { version: { const: '3.1' }, score: { type: 'number', minimum: 0, maximum: 10 } } }
      ]
    },
    meta: { type: 'object', additionalProperties: false, properties: { author: { type: 'string' } } },
    // documentation-only keywords: present but NEVER enforced
    legacy: { type: 'string', format: 'date-time', examples: ['2024-01-01T00:00:00Z'], default: '' }
  }
};

const minimal = {
  findingId: 'SEC-TEST-001',
  title: 'A valid minimal finding',
  severity: 'HIGH'
};

describe('schema validator', () => {
  test('a valid minimal finding passes', () => {
    const r = validate(FINDING, minimal);
    assert.equal(r.valid, true, r.errors.join('; '));
    assert.deepEqual(r.errors, []);
  });

  test('an unknown extra property fails when additionalProperties is false', () => {
    const r = validate(FINDING, { ...minimal, notInTheSchema: true });
    assert.equal(r.valid, false);
    assert.ok(r.errors.some(e => e.includes('/notInTheSchema') && e.includes('additional property not allowed')));
  });

  test('a bad severity enum value fails and names the allowed values', () => {
    const r = validate(FINDING, { ...minimal, severity: 'CATASTROPHIC' });
    assert.equal(r.valid, false);
    assert.ok(r.errors.some(e => e.includes('/severity') && e.includes('"CRITICAL"')));
  });

  test('a findingId that violates the pattern fails', () => {
    const r = validate(FINDING, { ...minimal, findingId: 'sec-test-1' });
    assert.equal(r.valid, false);
    assert.ok(r.errors.some(e => e.includes('/findingId') && e.includes('does not match pattern')));
  });

  test('a missing required property fails and the error names that property', () => {
    const { title, ...withoutTitle } = minimal;
    const r = validate(FINDING, withoutTitle);
    assert.equal(r.valid, false);
    assert.ok(r.errors.some(e => e.includes('/title') && e.includes('required property missing')));
  });

  test('cvss: null passes (the schema oneOf allows null)', () => {
    const r = validate(FINDING, { ...minimal, cvss: null });
    assert.equal(r.valid, true, r.errors.join('; '));
  });

  test('an array whose item has the wrong type fails, with the item path', () => {
    const r = validate(FINDING, { ...minimal, tags: ['ok', 42] });
    assert.equal(r.valid, false);
    assert.ok(r.errors.some(e => e.includes('/tags/1') && e.includes('expected type string')));
  });

  test('exactly-one semantics of oneOf: an object with vector:null fails both branches', () => {
    const r = validate(FINDING, { ...minimal, cvss: { version: null, score: 5 } });
    assert.equal(r.valid, false);
    assert.ok(r.errors.some(e => e.includes('/cvss') && e.includes('oneOf')));
  });

  test('documentation keywords ($schema, $id, title, description, examples, default, format) are ignored', () => {
    const r = validate(FINDING, { ...minimal, legacy: 'not a date at all' });
    assert.equal(r.valid, true, 'format must not be enforced: ' + r.errors.join('; '));
  });

  test('minLength and maxLength are enforced on strings', () => {
    assert.equal(validate(FINDING, { ...minimal, title: 'short' }).valid, false);
    assert.equal(validate(FINDING, { ...minimal, title: 'x'.repeat(121) }).valid, false);
    assert.equal(validate(FINDING, { ...minimal, title: 'x'.repeat(120) }).valid, true);
  });

  test('minimum and maximum are enforced on numbers; integer rejects non-integers', () => {
    assert.equal(validate(FINDING, { ...minimal, count: -1 }).valid, false);
    assert.equal(validate(FINDING, { ...minimal, count: 11 }).valid, false);
    assert.equal(validate(FINDING, { ...minimal, count: 1.5 }).valid, false);
    assert.equal(validate(FINDING, { ...minimal, count: 3 }).valid, true);
    assert.equal(validate(FINDING, { ...minimal, score: -0.5 }).valid, false);
    assert.equal(validate(FINDING, { ...minimal, score: 7.4 }).valid, true);
  });

  test('const is enforced exactly', () => {
    assert.equal(validate(FINDING, { ...minimal, version: '3.0' }).valid, false);
    assert.equal(validate(FINDING, { ...minimal, version: '3.1' }).valid, true);
  });

  test('booleans and null types are checked', () => {
    assert.equal(validate(FINDING, { ...minimal, active: 'yes' }).valid, false);
    assert.equal(validate(FINDING, { ...minimal, nothing: 0 }).valid, false);
    assert.equal(validate(FINDING, { ...minimal, nothing: null }).valid, true);
  });

  test('minItems is enforced on arrays', () => {
    assert.equal(validate(FINDING, { ...minimal, tags: [] }).valid, false);
    assert.equal(validate(FINDING, { ...minimal, tags: ['one'] }).valid, true);
  });

  test('type mismatches report the offending path', () => {
    const r = validate(FINDING, { ...minimal, severity: 4 });
    assert.equal(r.valid, false);
    assert.ok(r.errors[0].includes('/severity'));
  });

  test('errors carry a JSON-pointer-ish path for nested objects and arrays', () => {
    const r = validate(FINDING, { ...minimal, meta: { author: 3 } });
    assert.equal(r.valid, false);
    assert.ok(r.errors.some(e => e.startsWith('/meta/author') && e.includes('expected type string')), r.errors.join('; '));

    // oneOf reports at the branch point itself (branch-internal paths stay private),
    // but a numeric violation inside the matching object branch still surfaces by path.
    const badScore = validate(FINDING, { ...minimal, cvss: { version: '3.1', score: 99 } });
    assert.equal(badScore.valid, false);
    assert.ok(badScore.errors.some(e => e.includes('/cvss')), badScore.errors.join('; '));
  });
});
