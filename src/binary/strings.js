'use strict';
/**
 * Embedded string surface — what the binary confesses without source.
 *
 * Reads the '#US' (user string) heap, which holds every string literal the compiler placed in
 * the assembly. When that heap is unavailable, falls back to a raw scan for printable ASCII and
 * UTF-16LE runs. Matches are scanned for connection strings, hardcoded credentials, API keys and
 * internal hostnames.
 *
 * REDACTION POLICY: the finding records enough to LOCATE the string (assembly, offset, structure
 * of the match, length of the secret) and never the secret value itself. Every emitted snippet
 * has values replaced with [REDACTED len=N] and `evidence.redacted: true`.
 */

const METADATA = require('./metadata');

// A string that is a good witness, not framework noise.
const NOISE = /^(?:system|microsoft|mscorlib|get_|set_|_|http:\/\/schemas\.|http:\/\/www\.w3\.org|http:\/\/tempuri|http:\/\/microsoft|urn:)/i;

const RULES = [
  {
    id: 'binary-connection-string',
    title: 'Connection string embedded in compiled assembly',
    confidence: 'LIKELY',
    severity: 'HIGH',
    cwe: ['CWE-798'],
    match: (s) => {
      const isCs = /(?:data\s*source|server|host)\s*=[^;]{1,120};\s*(?:initial\s*catalog|database)\s*=/i.test(s);
      if (!isCs) return null;
      const auth = /(?:user\s*id|uid|user|pwd|password)\s*=/i.test(s);
      return { embeddedCredentials: auth };
    }
  },
  {
    id: 'binary-credential-literal',
    title: 'Hardcoded credential pattern in compiled assembly',
    confidence: 'LIKELY',
    severity: 'HIGH',
    cwe: ['CWE-798'],
    match: (s) => /(?:password|passwd|pwd|apassword)\s*[=:]\s*\S{3,}/i.test(s) && !NOISE.test(s)
      ? { } : null
  },
  {
    id: 'binary-api-key-shape',
    title: 'API-key-shaped token in compiled assembly',
    confidence: 'LIKELY',
    severity: 'HIGH',
    cwe: ['CWE-798'],
    match: (s) => {
      const m = s.match(/(?:AKIA[0-9A-Z]{16}|sk-[A-Za-z0-9]{20,64}|ghp_[A-Za-z0-9]{36,40}|gho_[A-Za-z0-9]{36,40}|AIza[0-9A-Za-z_\-]{35}|xox[baprs]-[A-Za-z0-9\-]{10,60}|sgp_[A-Za-z0-9_]{20,60})/);
      return m ? { shape: m[0].slice(0, 3) } : null;
    }
  },
  {
    id: 'binary-internal-endpoint',
    title: 'Internal hostname or private address in compiled assembly',
    confidence: 'LIKELY',
    severity: 'MEDIUM',
    cwe: ['CWE-200'],
    match: (s) => {
      const m = s.match(/https?:\/\/([^\/\s:@]+(?::\d+)?)/i);
      if (!m) return null;
      const host = m[1];
      if (/\.(?:local|internal|corp|lan|intra|priv)(?::\d+)?$/i.test(host) ||
          /^(?:10\.|192\.168\.|172\.(?:1[6-9]|2\d|3[01])\.)/.test(host)) {
        return { host, class: 'private-address-or-internal-tld' };
      }
      if (/^https/i.test(s) && !host.includes('.') && !/localhost/i.test(host)) {
        return { host, class: 'single-label-host' };
      }
      return null;
    }
  }
];

const REDACTED = (n) => `[REDACTED len=${n}]`;
const MAX_VALUE = 4 * 1024;        // never decode more than 4KB of one string
const MAX_PER_RULE = 40;           // bound the noise an obfuscated or bloated binary can emit

/**
 * Redact a raw string for evidence display: mask credential values and key-shaped tokens,
 * keep structure (keys, host names, database names) so the finding is locatable.
 */
function redactForEvidence(raw, ruleId) {
  let out = raw.length > 300 ? raw.slice(0, 300) + ` …(+${raw.length - 300} chars)` : raw;
  if (ruleId === 'binary-api-key-shape') {
    out = out.replace(/(AKIA[0-9A-Z]{16}|sk-[A-Za-z0-9]{20,64}|ghp_[A-Za-z0-9]{36,40}|gho_[A-Za-z0-9]{36,40}|AIza[0-9A-Za-z_\-]{35}|xox[baprs]-[A-Za-z0-9\-]{10,60}|sgp_[A-Za-z0-9_]{20,60})/g,
      (m) => m.slice(0, 3) + REDACTED(m.length - 3));
  }
  // Mask the VALUE of credential-looking assignments; keep the key.
  out = out.replace(/((?:password|passwd|pwd|user\s*id|uid|user)\s*[=:]\s*)([^;]{1,200};?)/gi,
    (m, key, val) => key.trimEnd() + REDACTED(val.replace(/;$/, '').length) + (val.endsWith(';') ? ';' : ''));
  return { display: out, redacted: out !== (raw.length > 300 ? raw.slice(0, 300) + ` …(+${raw.length - 300} chars)` : raw) };
}

/**
 * Scan one decoded string against the rules. Returns [{ ruleId, rule, detail, evidence }].
 * Pure. Never throws.
 */
function scanString(raw) {
  if (!raw || raw.length < 6 || raw.length > MAX_VALUE || NOISE.test(raw)) return [];
  const hits = [];
  for (const rule of RULES) {
    const detail = rule.match(raw);
    if (detail) {
      const red = redactForEvidence(raw, rule.id);
      hits.push({ ruleId: rule.id, detail, display: red.display, redacted: red.redacted });
    }
  }
  return hits;
}

/**
 * Collect user strings from a parsed assembly and scan them.
 * `parsed` is the record returned by metadata.inspectAssemblyBuffer().
 * Returns per-rule hits with heap offsets for locating the string later.
 */
function scanAssemblyStrings(buf, parsed, opts = {}) {
  const hits = [];
  if (!parsed || !parsed.managed || !buf) return hits;

  let strings;
  if (parsed.userStringsHeap) {
    strings = METADATA.readUserStrings(buf, parsed.userStringsHeap, opts.maxUserStrings || 20000)
      .map(e => ({ heapOffset: e.index, value: e.value, origin: '#US heap' }));
  } else {
    // No #US heap (native image, satellite, or partial): fall back to raw readable runs so the
    // surface is still covered — labelled as lower precision.
    strings = rawReadableStrings(buf, opts.maxRawScanBytes || 32 * 1024 * 1024)
      .map(e => ({ heapOffset: e.offset, value: e.value, origin: 'raw scan' }));
  }

  const perRule = {};
  for (const s of strings) {
    for (const h of scanString(s.value)) {
      if ((perRule[h.ruleId] || 0) >= MAX_PER_RULE) continue;
      perRule[h.ruleId] = (perRule[h.ruleId] || 0) + 1;
      hits.push({
        assembly: parsed.assembly ? parsed.assembly.name : null,
        ruleId: h.ruleId,
        rule: RULES.find(r => r.id === h.ruleId),
        heapOffset: s.heapOffset,
        origin: s.origin,
        detail: h.detail,
        display: h.display,
        redacted: h.redacted
      });
    }
  }
  return hits;
}

/**
 * Fallback: printable ASCII runs and UTF-16LE runs of >= 8 characters. Lower precision than the
 * #US heap and labelled as such by callers.
 */
function rawReadableStrings(buf, maxBytes) {
  const out = [];
  const limit = Math.min(buf.length, maxBytes);
  let run = [], runStart = 0;
  const flush = () => {
    if (run.length >= 8) {
      try { out.push({ offset: runStart, value: Buffer.from(run).toString('ascii') }); } catch { /* skip */ }
    }
    run = [];
  };
  for (let i = 0; i < limit; i++) {
    const c = buf[i];
    if (c >= 0x20 && c < 0x7f) {
      if (!run.length) runStart = i;
      run.push(c);
      if (run.length > 2048) flush();
    } else flush();
  }
  flush();

  // UTF-16LE: low byte printable, high byte 0.
  const u16 = [];
  run = [];
  for (let i = 0; i + 1 < limit; i += 2) {
    const lo = buf[i], hi = buf[i + 1];
    if (hi === 0 && lo >= 0x20 && lo < 0x7f) {
      if (!run.length) runStart = i;
      run.push(lo);
      if (run.length > 2048) { if (run.length >= 8) u16.push({ offset: runStart, value: Buffer.from(run).toString('ascii') }); run = []; }
    } else {
      if (run.length >= 8) u16.push({ offset: runStart, value: Buffer.from(run).toString('ascii') });
      run = [];
    }
  }
  if (run.length >= 8) u16.push({ offset: runStart, value: Buffer.from(run).toString('ascii') });

  return out.concat(u16).slice(0, 50000);
}

module.exports = { RULES, scanString, redactForEvidence, scanAssemblyStrings, rawReadableStrings };
