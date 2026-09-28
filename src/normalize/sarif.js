'use strict';
/**
 * SARIF 2.1.0 -> canonical finding normaliser.
 *
 * SARIF is the interchange format for most modern scanners (Trivy, Semgrep, gitleaks,
 * OWASP Dependency-Check, Snyk Code, CodeQL). Normalising it ONCE, well, is far safer than
 * hand-parsing each tool's bespoke JSON: there is a single place to get right and a single
 * place to fix.
 *
 * Design rules:
 *  - Never invent. A field absent from the SARIF is absent from the finding.
 *  - Severity comes from the tool's own signals in priority order:
 *      properties['security-severity'] (numeric, GitHub convention)
 *      -> properties.severity / properties.problem.severity
 *      -> result.level / rule.defaultConfiguration.level
 *  - security-severity is treated as a CVSS-like base score, which is the GitHub convention,
 *    but it is NOT presented as a CVSS vector unless the tool actually supplied one.
 */

const { normaliseSeverity, severityFromCvss } = require('../core/adapter-contract');

const LEVEL_TO_SEVERITY = { error: 'HIGH', warning: 'MEDIUM', note: 'LOW', none: 'INFO' };

/** Collect rule metadata from a run, handling both inline rules and extensions. */
function indexRules(run) {
  const idx = new Map();
  const add = rules => (rules || []).forEach(r => { if (r && r.id) idx.set(r.id, r); });
  if (run.tool && run.tool.driver) add(run.tool.driver.rules);
  ((run.tool && run.tool.extensions) || []).forEach(ext => add(ext.rules));
  return idx;
}

function text(o) {
  if (!o) return '';
  if (typeof o === 'string') return o;
  return o.text || o.markdown || '';
}

/** Best-effort physical location. */
function locationOf(result) {
  const locs = result.locations || [];
  const primary = locs[0] || {};
  const phys = primary.physicalLocation || {};
  const art = phys.artifactLocation || {};
  const region = phys.region || {};
  let file = art.uri || '';
  // SARIF uris are often file:// or relative with %20 escapes
  try { file = decodeURIComponent(file); } catch { /* keep raw */ }
  file = file.replace(/^file:\/\/\/?/, '').replace(/\\/g, '/');

  const additional = locs.slice(1).concat(result.relatedLocations || []).map(l => {
    const p = (l && l.physicalLocation) || {};
    const a = p.artifactLocation || {};
    let u = a.uri || '';
    try { u = decodeURIComponent(u); } catch { /* keep raw */ }
    return {
      file: u.replace(/^file:\/\/\/?/, '').replace(/\\/g, '/'),
      startLine: (p.region && p.region.startLine) || undefined,
      note: text(l && l.message) || undefined
    };
  }).filter(x => x.file);

  return {
    file: file || '(unknown)',
    startLine: region.startLine,
    endLine: region.endLine,
    additionalLocations: additional.length ? additional : undefined
  };
}

/** Snippet from the region, if the tool embedded one. */
function snippetOf(result) {
  const phys = ((result.locations || [])[0] || {}).physicalLocation || {};
  const r = phys.region || {};
  const s = (r.snippet && (r.snippet.text || r.snippet.rendered)) || '';
  return String(s).trim();
}

/** Pull CWE identifiers out of the many places tools hide them. */
function cwesOf(rule, result) {
  const out = new Set();
  const scan = v => {
    if (!v) return;
    if (Array.isArray(v)) return v.forEach(scan);
    const m = String(v).match(/CWE[-_ ]?(\d+)/gi);
    if (m) m.forEach(x => out.add('CWE-' + x.replace(/\D+/g, '')));
  };
  if (rule) {
    scan(rule.properties && rule.properties.tags);
    scan(rule.properties && rule.properties.cwe);
    scan(rule.id);
    scan(text(rule.shortDescription));
    (rule.relationships || []).forEach(rel => scan(rel.target && (rel.target.id || rel.target.guid)));
  }
  scan(result.properties && result.properties.cwe);
  scan(result.ruleId);
  return [...out];
}

/** CVE / advisory ids. */
function cvesOf(rule, result) {
  const out = new Set();
  const scan = v => {
    if (!v) return;
    if (Array.isArray(v)) return v.forEach(scan);
    const m = String(v).match(/(CVE-\d{4}-\d{4,7}|GHSA-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{4})/gi);
    if (m) m.forEach(x => out.add(x.toUpperCase().replace('GHSA', 'GHSA')));
  };
  scan(result.ruleId);
  if (rule) { scan(rule.id); scan(text(rule.shortDescription)); scan(rule.properties && rule.properties.tags); }
  scan(text(result.message));
  return [...out];
}

/**
 * Decide severity, and a CVSS block only when the tool really provided a score.
 * Returns { severity, cvss }
 */
function severityOf(rule, result) {
  const rp = (rule && rule.properties) || {};
  const pp = result.properties || {};

  // GitHub convention: a numeric security-severity is a CVSS-like base score.
  const secSev = pp['security-severity'] !== undefined ? pp['security-severity']
    : rp['security-severity'];
  const score = secSev !== undefined ? Number(secSev) : NaN;

  // A real vector, if the tool supplied one anywhere.
  const vector = pp.cvssV3_vector || pp.cvss_vector || rp.cvssV3_vector || rp.cvss_vector ||
    (typeof pp.cvss === 'string' && /^CVSS:3/.test(pp.cvss) ? pp.cvss : undefined);

  let severity;
  if (isFinite(score) && score > 0) {
    severity = severityFromCvss(score);
  } else {
    const raw = pp.severity || rp.severity || (rp.problem && rp.problem.severity);
    const level = result.level ||
      (rule && rule.defaultConfiguration && rule.defaultConfiguration.level);
    severity = raw ? normaliseSeverity(raw)
      : (LEVEL_TO_SEVERITY[String(level || '').toLowerCase()] || 'MEDIUM');
  }

  let cvss = null;
  if (isFinite(score) && score > 0) {
    cvss = {
      version: '3.1',
      score: Math.round(score * 10) / 10,
      vector: vector || null,
      severity: severityFromCvss(score),
      note: vector ? undefined
        : 'Score reported by the tool; no CVSS vector was supplied, so the vector is not asserted.'
    };
  }
  return { severity, cvss };
}

/** Map a SARIF precision/confidence hint onto the canonical confidence scale. */
function confidenceOf(rule, result) {
  const p = ((result.properties || {}).precision) ||
    ((rule && rule.properties) || {}).precision;
  const map = { 'very-high': 'CONFIRMED', high: 'LIKELY', medium: 'POSSIBLE', low: 'UNVERIFIED' };
  if (p && map[String(p).toLowerCase()]) return map[String(p).toLowerCase()];
  // A tool reporting a concrete location is at least LIKELY; without one, POSSIBLE.
  return (result.locations || []).length ? 'LIKELY' : 'POSSIBLE';
}

/** Choose a canonical category for a finding produced by a tool of a given kind. */
function categoryOf(toolKind, rule, result) {
  const tags = String((((rule || {}).properties || {}).tags || []).join(' ')).toLowerCase();
  if (toolKind === 'dependency') return 'dependency';
  if (toolKind === 'secret') return 'security';
  if (toolKind === 'config') return 'configuration';
  if (/security|cwe|owasp|injection|xss|crypto/.test(tags)) return 'security';
  if (/performance/.test(tags)) return 'performance';
  if (/maintainability|style|convention/.test(tags)) return 'code-quality';
  return toolKind === 'quality' ? 'code-quality' : 'security';
}

/**
 * Normalise a SARIF log into canonical findings.
 * @param {object|string} sarif  parsed SARIF or raw JSON string
 * @param {object} opts { toolId, toolKind, statusIfEmpty }
 */
function fromSarif(sarif, opts = {}) {
  const doc = typeof sarif === 'string' ? JSON.parse(sarif) : sarif;
  if (!doc || !Array.isArray(doc.runs)) return [];

  const toolId = opts.toolId || 'sarif';
  const toolKind = opts.toolKind || 'sast';
  const out = [];

  for (const run of doc.runs) {
    const rules = indexRules(run);
    const driver = (run.tool && run.tool.driver) || {};
    const toolVersion = driver.semanticVersion || driver.version || undefined;

    for (const result of run.results || []) {
      // Respect the tool's own suppression state rather than silently reporting it as open.
      const suppressed = (result.suppressions || []).length > 0;

      const rule = rules.get(result.ruleId) || null;
      const { severity, cvss } = severityOf(rule, result);
      const location = locationOf(result);
      const cwe = cwesOf(rule, result);
      const cves = cvesOf(rule, result);

      const title = text(result.message).split('\n')[0].trim() ||
        text(rule && rule.shortDescription) ||
        result.ruleId || 'Unnamed finding';

      out.push({
        // No findingId yet: the correlation engine assigns canonical ids after dedup.
        title: title.slice(0, 200),
        category: categoryOf(toolKind, rule, result),
        subcategory: result.ruleId || undefined,
        severity,
        confidence: confidenceOf(rule, result),
        cvss,
        cwe: cwe.length ? cwe : undefined,
        advisories: cves.length ? cves : undefined,
        location,
        evidence: {
          snippet: snippetOf(result),
          language: 'csharp',
          toolOutput: `${toolId}${toolVersion ? ' ' + toolVersion : ''} rule ${result.ruleId || '(none)'}` +
            (result.level ? ` level=${result.level}` : '')
        },
        problem: text(result.message) || text(rule && rule.fullDescription) ||
          text(rule && rule.shortDescription) || '',
        impact: '',          // tools rarely state impact; left empty rather than fabricated
        recommendation: text(rule && rule.help) ||
          text(rule && rule.fullDescription) || '',
        sources: [{
          tool: toolId,
          sourceFindingId: result.ruleId || undefined,
          status: 'REPORTED',
          note: result.partialFingerprints
            ? 'fingerprint: ' + Object.values(result.partialFingerprints)[0] : undefined
        }],
        status: suppressed ? 'FALSE_POSITIVE' : 'OPEN',
        _raw: {
          ruleId: result.ruleId,
          fingerprints: result.partialFingerprints || result.fingerprints || undefined,
          helpUri: (rule && rule.helpUri) || undefined
        }
      });
    }
  }
  return out;
}

module.exports = { fromSarif, severityFromCvss, LEVEL_TO_SEVERITY };
