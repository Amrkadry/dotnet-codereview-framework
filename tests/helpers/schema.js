// dotnet-codereview-framework — tests/helpers/schema.js
// Author: Amr Kadry (github.com/Amrkadry) · MIT License
'use strict';
/**
 * Minimal JSON Schema validator — supports exactly the subset used by
 * schema/finding.schema.json, and nothing more.
 *
 * WHY hand-rolled: the framework has a hard zero-dependency rule, and the schema only uses
 * type / required / properties / additionalProperties:false / enum / const / pattern /
 * minLength / maxLength / minimum / maximum / items / minItems / oneOf. Everything else that
 * appears in the schema ($schema, $id, title, description, examples, default, format) is
 * DOCUMENTATION and must be ignored here, not enforced.
 *
 * validate(schema, value) -> { valid: boolean, errors: string[] }
 * Each error is a human-readable string carrying the JSON-pointer-ish path of the offending
 * value, e.g. "/cvss/vector: does not match pattern ^CVSS:3\\.1/...".
 */

const TYPE_CHECKS = {
  string: v => typeof v === 'string',
  number: v => typeof v === 'number' && Number.isFinite(v),
  integer: v => typeof v === 'number' && Number.isInteger(v),
  object: v => v !== null && typeof v === 'object' && !Array.isArray(v),
  array: v => Array.isArray(v),
  boolean: v => typeof v === 'boolean',
  null: v => v === null
};

/** Deep equality used for enum/const membership (strict equality with object fallback). */
const same = (a, b) => a === b || JSON.stringify(a) === JSON.stringify(b);

const childPath = (path, key) => path + '/' + key;

function describe(v) {
  if (v === null) return 'null';
  if (Array.isArray(v)) return 'array';
  if (typeof v === 'string') {
    const s = v.length > 60 ? v.slice(0, 60) + '...' : v;
    return `string "${s}"`;
  }
  return typeof v;
}

/**
 * Core walker. `errors` is the collector to push human-readable failures onto;
 * passing a fresh array in is what makes oneOf branch probing isolated.
 */
function walk(s, v, at, errors) {
  if (s === undefined || s === null || typeof s !== 'object' || Array.isArray(s)) return;

  // `type` may be a single type name or an array of allowed names.
  if (s.type !== undefined) {
    const allowed = Array.isArray(s.type) ? s.type : [s.type];
    if (!allowed.some(t => (TYPE_CHECKS[t] || (() => true))(v))) {
      errors.push(`${at || '/'}: expected type ${allowed.join(' | ')}, got ${describe(v)}`);
      return; // further checks would only produce cascading noise
    }
  }

  if (s.enum !== undefined && !s.enum.some(e => same(e, v))) {
    errors.push(`${at || '/'}: value ${describe(v)} not in enum [${s.enum.map(e => JSON.stringify(e)).join(', ')}]`);
  }

  if (s.const !== undefined && !same(s.const, v)) {
    errors.push(`${at || '/'}: value ${describe(v)} does not equal const ${JSON.stringify(s.const)}`);
  }

  if (typeof v === 'string') {
    if (s.pattern !== undefined && !new RegExp(s.pattern).test(v)) {
      errors.push(`${at || '/'}: does not match pattern ${s.pattern}`);
    }
    if (s.minLength !== undefined && v.length < s.minLength) {
      errors.push(`${at || '/'}: length ${v.length} is less than minLength ${s.minLength}`);
    }
    if (s.maxLength !== undefined && v.length > s.maxLength) {
      errors.push(`${at || '/'}: length ${v.length} exceeds maxLength ${s.maxLength}`);
    }
  }

  if (typeof v === 'number' && Number.isFinite(v)) {
    if (s.minimum !== undefined && v < s.minimum) {
      errors.push(`${at || '/'}: ${v} is less than minimum ${s.minimum}`);
    }
    if (s.maximum !== undefined && v > s.maximum) {
      errors.push(`${at || '/'}: ${v} exceeds maximum ${s.maximum}`);
    }
  }

  // oneOf: EXACTLY one branch must validate. Each branch is probed with its own error
  // collector so branch-internal failures never leak into the reported errors.
  if (s.oneOf !== undefined) {
    const matches = s.oneOf.filter(branch => {
      const probe = [];
      walk(branch, v, at, probe);
      return probe.length === 0;
    });
    if (matches.length !== 1) {
      errors.push(`${at || '/'}: expected exactly one oneOf branch to match, ${matches.length} did`);
      return;
    }
  }

  if (v !== null && typeof v === 'object') {
    if (Array.isArray(v)) {
      if (s.minItems !== undefined && v.length < s.minItems) {
        errors.push(`${at || '/'}: array has ${v.length} item(s), fewer than minItems ${s.minItems}`);
      }
      if (s.items !== undefined) {
        if (Array.isArray(s.items)) {
          // tuple form (unused by the finding schema, supported for completeness)
          v.forEach((item, i) => { if (s.items[i]) walk(s.items[i], item, `${at}/${i}`, errors); });
        } else {
          v.forEach((item, i) => walk(s.items, item, `${at}/${i}`, errors));
        }
      }
    } else {
      // JSON has no `undefined`: a property whose value is undefined is treated as absent,
      // exactly as JSON.stringify treats it when the finding is projected. Adapters do emit
      // `note: undefined` style keys, and they must not be reported as schema violations.
      if (s.required !== undefined) {
        for (const r of s.required) {
          if (!(r in v) || v[r] === undefined) {
            errors.push(`${childPath(at, r)}: required property missing`);
          }
        }
      }
      if (s.properties !== undefined || s.additionalProperties === false) {
        const known = s.properties || {};
        for (const k of Object.keys(v)) {
          if (v[k] === undefined) continue;
          if (k in known) walk(known[k], v[k], childPath(at, k), errors);
          else if (s.additionalProperties === false) {
            errors.push(`${childPath(at, k)}: additional property not allowed`);
          }
        }
      }
    }
  }
}

/** Validate `value` against `schema`. Returns { valid, errors } with pointer-ish paths. */
function validate(schema, value) {
  const errors = [];
  walk(schema, value, '', errors);
  return { valid: errors.length === 0, errors };
}

module.exports = { validate };
