'use strict';
/**
 * SECRETS DISCIPLINE — the only code allowed to touch a credential value.
 *
 * Three operations, in increasing strength:
 *
 *   redact(secret)  — display form of a KNOWN secret: last 4 characters only.
 *   scrub(text)     — pattern-based removal of credential-shaped strings from free text.
 *   guard(text)     — the last line of defence. Runs on EVERY output path this framework owns
 *                     (terminal logs, verbose/debug output, raw provider responses, and every
 *                     Markdown file the ai-report mode writes). It refuses to emit a value that
 *                     looks like a key: the value is replaced and a warning WITHOUT the value is
 *                     raised on stderr.
 *
 * Rules enforced elsewhere in this framework and assumed here:
 *   - Loading a config that contains a real key must not echo it, even in verbose/debug mode.
 *     (Callers must run any config dump through redactConfig() before printing.)
 *   - A warning about redaction names the PATH and the COUNT, never the value.
 */

const fs = require('fs');
const path = require('path');

/** Credential shapes we recognise. Kept conservative: over-matching mangles real content. */
const KEY_PATTERNS = [
  /sk-ant-[A-Za-z0-9_-]{8,}/g,                                   // Anthropic
  /sk-[A-Za-z0-9_-]{12,}/g,                                      // OpenAI-shaped / generic sk-
  /\b[0-9a-f]{32}\.[A-Za-z0-9]{16,}\b/g,                         // Snyk-style token
  /\bAKIA[0-9A-Z]{16}\b/g,                                       // AWS access key id
  /\b(?:ghp|gho|ghu|ghs)_[A-Za-z0-9]{20,}\b/g,                   // GitHub tokens
  /\bgithub_pat_[A-Za-z0-9_]{20,}\b/g,                           // GitHub fine-grained PAT
  /(Bearer\s+)[A-Za-z0-9._-]{16,}/gi,                            // Authorization headers
  /("(?:api[_-]?key|apikey|authorization|x-api-key|access[_-]?token|secret|token)"?\s*[:=]\s*")[^"]{8,}(")/gi,
  /((?:api[_-]?key|apikey|access[_-]?token|secret)\s*[=:]\s*)[A-Za-z0-9._-]{16,}/gi
];

/** Anything that is obviously a placeholder, not a real credential — never redacted. */
const PLACEHOLDER_RE = /^\s*(?:<[^>]*>|\$\{[^}]*\}|\.{3}|x+|REDACTED(?:\s*\*.*)?|YOUR[_A-Z-]*|CHANGE[_A-Z-]*|EXAMPLE[_A-Z-]*|set-[A-Za-z0-9_-]+)\s*$/i;

/** Does this string contain something credential-shaped? */
function isKeyShaped(s) {
  const t = String(s == null ? '' : s);
  return KEY_PATTERNS.some(re => (re.lastIndex = 0, re.test(t)));
}

/**
 * Display form of a KNOWN secret: fixed mask + last 4 characters.
 * `sk-test-ABCDEFGHIJKLMNOP` -> `****MNOP`. Short/empty secrets are fully masked.
 */
function redact(secret) {
  const s = String(secret == null ? '' : secret);
  if (!s) return '(not set)';
  if (PLACEHOLDER_RE.test(s)) return '(placeholder)';
  return '****' + s.slice(-4);
}

/** Pattern-based scrub of credential-shaped strings out of free text. */
function scrub(s) {
  let t = String(s == null ? '' : s);
  for (const re of KEY_PATTERNS) {
    re.lastIndex = 0;
    t = t.replace(re, (...args) => {
      const match = args[0];
      // Grouped shapes carry (match, labelGroup[, closingGroup], offset, string).
      // Groupless ones carry (match, offset, string) — offset is a NUMBER, never keep it.
      const p1 = typeof args[1] === 'string' ? args[1] : null;
      const p2 = typeof args[2] === 'string' ? args[2] : null;
      if (p1 !== null) return `${p1}***REDACTED***${p2 || ''}`;
      return isPlaceholderish(match) ? match : '***REDACTED***';
    });
  }
  return t;
}

function isPlaceholderish(token) {
  return PLACEHOLDER_RE.test(token) || /REDACTED/i.test(token);
}

/** Inspect + scrub. Returns { text, redacted } so callers can decide how to warn. */
function inspectGuard(text) {
  const before = String(text == null ? '' : text);
  const after = scrub(before);
  return { text: after, redacted: after !== before };
}

/**
 * THE GUARD. Scrubs credential-shaped values and warns on stderr — naming the label and the
 * fact of redaction, never the value. Use on every terminal/log path.
 */
function guard(text, label) {
  const { text: out, redacted } = inspectGuard(text);
  if (redacted) {
    process.stderr.write(`[moraa] guard: redacted credential-shaped content in ${label || 'output'}\n`);
  }
  return out;
}

/**
 * THE GUARD for file writes. Scrubs, then writes. Use for every file this framework writes that
 * can contain AI- or tool-derived free text (Markdown pages, raw provider responses).
 */
function guardedWriteFile(file, text, opts = {}) {
  const { text: clean, redacted } = inspectGuard(text);
  if (redacted && !opts.quiet) {
    process.stderr.write(`[moraa] guard: refused to write credential-shaped content to ${file}; redacted before write\n`);
  }
  fs.mkdirSync(path.dirname(file), { recursive: true });
  fs.writeFileSync(file, clean);
  return clean;
}

/**
 * Deep-copy a config object for DISPLAY. Every value sitting under a credential-named property,
 * or looking credential-shaped, is replaced by its redacted form. Verbose/debug printing of a
 * config must go through this — a real key must never be echoed at any log level.
 */
function redactConfig(cfg) {
  const SENSITIVE = /^(?:key|apikey|api[_-]?key|token|secret|password|authorization|creds?|credentials)$/i;
  const walk = (v, name) => {
    if (Array.isArray(v)) return v.map(x => walk(x, name));
    if (v && typeof v === 'object') {
      const out = {};
      for (const [k, val] of Object.entries(v)) {
        if (k === 'keys' && val && typeof val === 'object' && !Array.isArray(val)) {
          // The keys block is credential-bearing by POSITION: every string in it is a secret.
          out[k] = {};
          for (const [pk, pv] of Object.entries(val)) {
            out[k][pk] = (typeof pv === 'string' && pv && !PLACEHOLDER_RE.test(pv)) ? redact(pv)
              : Array.isArray(pv) || (pv && typeof pv === 'object') ? walk(pv, pk) : walk(pv, pk);
          }
          continue;
        }
        out[k] = SENSITIVE.test(k) ? (val == null ? null : (typeof val === 'string' ? redact(val) : walk(val, k))) : walk(val, k);
      }
      return out;
    }
    if (typeof v === 'string' && isKeyShaped(v)) return scrub(v);
    return v;
  };
  return walk(cfg, '');
}

module.exports = {
  KEY_PATTERNS, isKeyShaped, redact, scrub, guard, inspectGuard,
  guardedWriteFile, redactConfig
};
