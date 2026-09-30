'use strict';
/**
 * BASELINE — the memory between reviews.
 *
 * `moraa baseline create` freezes the current finding set; every later review classifies its
 * findings against it:
 *   NEW      — not in the baseline. This is what the PR introduced; the summary leads with it.
 *   EXISTING — fingerprint present. Known debt, deliberately not re-alarming every run.
 *   FIXED    — in the baseline but not found now. Either genuinely fixed, or the finder broke.
 *
 * FINGERPRINT (the design decision that makes this usable): SHA-256 over
 *   rule identity  (subcategory — the stable per-check id, NOT the sequence-derived findingId,
 *                   which renumbers whenever severity ordering shifts)
 * + file path      (normalised separators/case)
 * + surrounding snippet (whitespace-normalised: blank lines and indentation collapsed).
 * Line numbers are deliberately EXCLUDED — they drift on every edit above the finding and a
 * baseline that forgets findings after a reformat is worse than none. Whitespace is exactly
 * the change a "just formatting" commit makes, so it must not count as new debt. Proven by
 * tests/baseline.test.js: insert blank lines above a finding, re-run, still EXISTING.
 *
 * SUPPRESSIONS: a baseline entry may be suppressed with a REQUIRED justification and an
 * OPTIONAL expiry date. An expired suppression is not silently honoured — it is reported as a
 * finding, so time-boxed acceptances actually come back to be re-decided.
 */

const crypto = require('crypto');

const SCHEMA_VERSION = 1;

/** Normalise a snippet: strip blank lines, collapse runs of whitespace, trim. */
function normaliseSnippet(snippet) {
  return String(snippet || '')
    .split(/\r?\n/)
    .map(l => l.replace(/\s+/g, ' ').trim())
    .filter(l => l !== '')
    .join('\n');
}

const normPath = p => String(p || '').replace(/\\/g, '/').replace(/^\.\//, '').toLowerCase();

/**
 * The fingerprint of a canonical finding.
 * @param {object} f canonical finding (needs subcategory-or-title, location.file, evidence.snippet)
 */
function fingerprint(f) {
  const rule = f.subcategory || (f.detection && f.detection.rules && f.detection.rules[0] && f.detection.rules[0].ruleId) || f.title;
  const file = normPath(f.location && f.location.file);
  const snippet = normaliseSnippet(f.evidence && f.evidence.snippet);
  return crypto.createHash('sha256')
    .update(`${rule}\u0000${file}\u0000${snippet}`)
    .digest('hex');
}

/**
 * Build a baseline from a correlated finding set.
 * @param {object[]} findings canonical findings
 * @param {object} [opts] { suppressed: { [findingId]: { justification, expires } } }
 * @returns {object} the baseline document (JSON-serialisable)
 */
function create(findings, opts = {}) {
  const supp = opts.suppressed || {};
  const entries = findings.map(f => {
    const s = supp[f.findingId] || null;
    const entry = {
      fingerprint: fingerprint(f),
      findingId: f.findingId,
      title: f.title,
      severity: f.severity,
      file: normPath(f.location && f.location.file),
      firstSeen: new Date().toISOString()
    };
    if (s) {
      if (!s.justification || !String(s.justification).trim()) {
        throw new Error(`suppression of ${f.findingId} requires a non-empty justification — ` +
          'an unexplained suppression is indistinguishable from hiding the finding.');
      }
      entry.suppressed = { justification: String(s.justification).trim() };
      if (s.expires) {
        const d = new Date(s.expires);
        if (isNaN(d.getTime())) throw new Error(`suppression of ${f.findingId}: expires "${s.expires}" is not a date (use ISO 8601)`);
        entry.suppressed.expires = d.toISOString();
      }
    }
    return entry;
  });
  // A suppression naming a findingId that does not exist would silently do nothing — that is
  // how a reviewer ends up believing something is waived when it is not. Fail loudly instead.
  const known = new Set(entries.map(e => e.findingId));
  const unknown = Object.keys(supp).filter(id => !known.has(id));
  if (unknown.length) {
    throw new Error(`--suppress names findingId(s) not present in this report: ${unknown.join(', ')}. ` +
      'Use the finding id exactly as shown in data/report.json (e.g. SEC-INJ-001).');
  }
  return {
    schema: 'moraa.baseline.v' + SCHEMA_VERSION,
    createdAt: new Date().toISOString(),
    count: entries.length,
    entries
  };
}

/** Classify findings against a baseline. Pure: no I/O, no mutation of inputs. */
function classify(findings, baseline) {
  if (!baseline || !Array.isArray(baseline.entries)) {
    throw new Error('classify() needs a baseline document (run `moraa baseline create` first)');
  }
  const byFp = new Map(baseline.entries.map(e => [e.fingerprint, e]));
  const matched = new Set();

  const isNew = [], existing = [];
  const now = Date.now();
  for (const f of findings) {
    const fp = fingerprint(f);
    const entry = byFp.get(fp);
    if (!entry) { isNew.push(f); continue; }
    matched.add(fp);
    f.baseline = { state: 'EXISTING', firstSeen: entry.firstSeen };
    const expired = entry.suppressed && entry.suppressed.expires &&
      Date.parse(entry.suppressed.expires) <= now;
    if (entry.suppressed && !expired) {
      f.suppression = {
        active: true,
        justification: entry.suppressed.justification,
        expires: entry.suppressed.expires || null
      };
      f.status = 'SUPPRESSED';
    }
    if (entry.suppressed && expired) {
      // The acceptance ran out: the finding is back to OPEN and the expiry is surfaced so the
      // re-decision actually happens instead of aging silently into permanent acceptance.
      f.status = 'OPEN';
      f.suppression = { active: false, expired: true,
        justification: entry.suppressed.justification, expires: entry.suppressed.expires };
    }
    existing.push(f);
  }

  const fixed = baseline.entries
    .filter(e => !matched.has(e.fingerprint))
    .map(e => ({ fingerprint: e.fingerprint, findingId: e.findingId, title: e.title,
      severity: e.severity, file: e.file }));

  // Expired suppressions: surface them as finding-shaped records so the re-decision happens.
  const expired = [];
  for (const e of baseline.entries) {
    if (!e.suppressed || !e.suppressed.expires) continue;
    if (Date.parse(e.suppressed.expires) <= now && matched.has(e.fingerprint)) {
      expired.push(e);
    }
  }

  return { new: isNew, existing, fixed, expiredSuppressions: expired,
    summary: { newCount: isNew.length, existingCount: existing.length,
      fixedCount: fixed.length, expiredCount: expired.length } };
}

/**
 * The severity gate for baseline mode: NEW findings at/above the threshold block.
 * Expired suppressions always block (they are overdue acceptances).
 */
function gate(classification, threshold) {
  const order = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'];
  if (!threshold) return null;
  const cut = order.indexOf(String(threshold).toUpperCase());
  if (cut < 0) throw new Error(`unknown severity "${threshold}"`);
  const offenders = classification.new.filter(f => order.indexOf(f.severity) <= cut);
  if (offenders.length) {
    return { fail: true, offenders, threshold, message:
      `FAIL: ${offenders.length} NEW finding(s) at or above ${threshold} (baseline mode)` };
  }
  if (classification.expiredSuppressions.length) {
    return { fail: true, offenders: classification.expiredSuppressions, threshold, message:
      `FAIL: ${classification.expiredSuppressions.length} suppression(s) have expired and must be re-decided` };
  }
  return { fail: false, threshold };
}

module.exports = { fingerprint, normaliseSnippet, create, classify, gate, SCHEMA_VERSION };
