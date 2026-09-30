'use strict';
/**
 * Canonical finding factory shared by every supply-chain check.
 *
 * Exists so the shape dictated by schema/finding.schema.json is written once: a check states
 * the rule id, the risk text, the location and the evidence, and this module assembles the
 * rest (category defaults, cvss null, sources, detection) exactly as the house adapters do.
 * Fields are omitted when absent so emitted JSON stays stable — no null-valued keys that
 * the schema's additionalProperties rules would still accept but no other adapter emits.
 */

const { validateFinding } = require('../core/adapter-contract');

/**
 * buildFinding(ruleId, o) -> canonical finding
 * Required in o: title, location { file, startLine? }, evidence { snippet, ... },
 *                problem, impact, recommendation.
 * Optional: severity, confidence, category, cwe, owasp, tests, engine, effort, priority,
 *           references, attackScenario, rootCause, severityRationale, additionalLocations,
 *           sourceNote.
 */
function buildFinding(ruleId, o) {
  const finding = {
    title: String(o.title || '').slice(0, 120),
    category: o.category || 'dependency',
    subcategory: ruleId,
    severity: o.severity || 'MEDIUM',
    confidence: o.confidence || 'CONFIRMED',
    cvss: null,   // no CVSS is asserted: nothing here is a scored advisory, and inventing a
                  // vector for a configuration state would be exactly the fabrication the
                  // framework forbids. Use severityRationale instead.
    cwe: o.cwe || undefined,
    owasp: o.owasp || undefined,
    location: { file: (o.location && o.location.file) || '(unknown)' },
    evidence: {
      snippet: String((o.evidence && o.evidence.snippet) || ''),
      language: (o.evidence && o.evidence.language) || 'text',
      redacted: !!(o.evidence && o.evidence.redacted)
    },
    // toolOutput is the machine-derived provenance line (feeds in play, redacted URLs,
    // nearest-well-known-id…) — attached only when a check supplied one, so emitted JSON is
    // stable and never carries an empty field.
    problem: o.problem || '',
    impact: o.impact || '',
    recommendation: o.recommendation || '',
    sources: [{
      tool: 'supplychain',
      sourceFindingId: ruleId,
      status: 'REPORTED',
      note: o.sourceNote || undefined
    }],
    status: 'OPEN',
    detection: {
      class: 'DETERMINISTIC',
      rules: [{ engine: o.engine || 'config-xml', ruleId, status: 'EXISTS' }]
    }
  };
  if (o.location && o.location.startLine) finding.location.startLine = o.location.startLine;
  if (o.location && o.location.endLine) finding.location.endLine = o.location.endLine;
  if (o.evidence && o.evidence.toolOutput) finding.evidence.toolOutput = String(o.evidence.toolOutput);
  if (o.additionalLocations && o.additionalLocations.length) {
    finding.location.additionalLocations = o.additionalLocations;
  }
  if (o.severityRationale) finding.severityRationale = o.severityRationale;
  if (o.attackScenario) finding.attackScenario = o.attackScenario;
  if (o.rootCause) finding.rootCause = o.rootCause;
  if (o.tests) finding.tests = o.tests;
  if (o.effort) finding.effort = o.effort;
  if (o.priority) finding.priority = o.priority;
  if (o.references) finding.references = o.references;
  return finding;
}

/** Run the contract's validator over a batch; returns the problem strings (empty = clean). */
function selfCheck(findings, where = 'supplychain') {
  const problems = [];
  (findings || []).forEach((f, i) =>
    validateFinding(f, `${where}[${i}]`).forEach(p => problems.push(p)));
  return problems;
}

module.exports = { buildFinding, selfCheck };
