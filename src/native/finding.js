// dotnet-codereview-framework — src/native/finding.js
// Author: Amr Kadry (github.com/Amrkadry) · MIT License
'use strict';
/**
 * Finding factory for the native engine.
 *
 * One place builds every native finding so the honesty rules cannot drift per check:
 *   - every finding quotes the matched source line(s) as evidence — never a paraphrase;
 *   - confidence states HOW the finding was established, and the check must declare it:
 *       CONFIRMED  — a configuration fact read from a file (debug="true" is in the XML);
 *       LIKELY     — a structural code fact (a dangerous API is called here);
 *       POSSIBLE   — a content-dependent heuristic (the concat MIGHT be safe internal input).
 *     A bare regex match is POSSIBLE, never more. Overclaiming confidence is how a native
 *     engine loses the right to be believed.
 *   - `tests` carries the catalog case ids the check implements, so every finding traces back
 *     to the shared .NET test-case catalog and the Coverage sheet stays mechanically truthful.
 */

const TOOL = 'native';

const SEVERITIES = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'];
const CONFIDENCES = ['CONFIRMED', 'LIKELY', 'POSSIBLE', 'UNVERIFIED'];

/** Map a catalog priority onto the canonical severity scale. */
function severityFromPriority(p) {
  const v = String(p || '').toLowerCase();
  if (v === 'critical') return 'CRITICAL';
  if (v === 'high') return 'HIGH';
  if (v === 'medium') return 'MEDIUM';
  if (v === 'low') return 'LOW';
  return 'MEDIUM';
}

/**
 * Build one canonical (pre-correlation) finding.
 * @param {object} spec
 *   title, category, severity, confidence, cwe[], caseId(s), file, startLine, endLine,
 *   snippet, language, problem, impact, recommendation, attackScenario, subcategory,
 *   additionalLocations, status
 */
function finding(spec) {
  for (const k of ['title', 'category', 'severity', 'confidence', 'file', 'problem', 'impact', 'recommendation']) {
    if (spec[k] === undefined) throw new Error(`native finding missing "${k}" (${spec.title || 'untitled'})`);
  }
  if (!SEVERITIES.includes(spec.severity)) throw new Error(`native: bad severity "${spec.severity}"`);
  if (!CONFIDENCES.includes(spec.confidence)) throw new Error(`native: bad confidence "${spec.confidence}"`);

  const cases = (Array.isArray(spec.caseIds) ? spec.caseIds : spec.caseId ? [spec.caseId] : [])
    .filter(Boolean);
  const srcNote = spec.possibleNote ||
    (spec.confidence === 'POSSIBLE'
      ? 'Pattern-based match with no dataflow or configuration proof: it may be safe depending on ' +
        'where the value originates. Read the quoted lines before acting.'
      : 'Established by the framework\u2019s built-in engine from the file content shown.');

  return {
    title: spec.title,
    category: spec.category,
    subcategory: spec.subcategory || (cases.length ? cases[0] : 'native'),
    severity: spec.severity,
    confidence: spec.confidence,
    cvss: null,
    cwe: spec.cwe || [],
    location: {
      file: String(spec.file).replace(/\\/g, '/'),
      startLine: spec.startLine,
      endLine: spec.endLine || spec.startLine,
      ...(spec.additionalLocations && spec.additionalLocations.length
        ? { additionalLocations: spec.additionalLocations } : {})
    },
    evidence: {
      snippet: String(spec.snippet == null ? '' : spec.snippet),
      language: spec.language || 'xml',
      toolOutput: `native check "${spec.check || spec.subcategory || cases[0] || ''}" matched here`
    },
    problem: spec.problem,
    impact: spec.impact,
    ...(spec.attackScenario ? { attackScenario: spec.attackScenario } : {}),
    recommendation: spec.recommendation,
    detection: {
      class: 'DETERMINISTIC',
      rules: [{ engine: 'native', ruleId: spec.check || (cases[0] || 'native'), status: 'ALERT' }]
    },
    sources: [{ tool: TOOL, status: 'REPORTED', note: srcNote }],
    status: spec.status || 'OPEN',
    tests: cases,
    verification: {
      method: spec.confidence === 'CONFIRMED'
        ? 'Read directly from the file quoted above — the fact is in the configuration itself.'
        : spec.confidence === 'LIKELY'
          ? 'The construct is present in the code; exploitation depends on values not visible statically.'
          : 'Heuristic match on source text; treat as a lead until confirmed by reading the code.'
    }
  };
}

/**
 * Manual-review item for a catalog case this engine cannot decide mechanically.
 * These are QUESTIONS, not defects: they are always INFO severity so they never gate CI,
 * and they exist so coverage is honest — the report must show what was NOT looked for,
 * not just what was found. Carrying the case's own checklist question is the point.
 */
function manualReview(cse, projectStack) {
  return {
    title: `Manual review: ${cse.title} (${cse.id})`,
    category: categoryFor(cse),
    subcategory: cse.id,
    severity: 'INFO',
    confidence: 'UNVERIFIED',
    cvss: null,
    cwe: cse.cwe && cse.cwe !== 'N/A' ? [cse.cwe] : [],
    location: { file: '(project)', startLine: undefined, endLine: undefined },
    evidence: {
      snippet: '',
      language: 'markdown',
      toolOutput: `catalog case ${cse.id} — no automated check decided it in this run`
    },
    problem: `Catalog case ${cse.id} (${categoryLetter(cse)}) was NOT mechanically decided: ` +
      `${cse.lookFor}.`,
    impact: cse.expected,
    recommendation: `Review by hand — ${cse.lookFor}. Pass condition: ${cse.expected}`,
    detection: {
      class: 'MANUAL_REVIEW',
      rules: [{ engine: 'native', ruleId: cse.id, status: 'NOT_AUTOMATED' }]
    },
    sources: [{
      tool: TOOL, status: 'REPORTED',
      note: `Checklist item from the shared catalog (priority: ${cse.priority}, ` +
        `stack: ${cse.stack}${projectStack && cse.stack !== 'both' ? '' : ''}). ` +
        'No finding above this line claims this case is clean — it is explicitly UNDECIDED.'
    }],
    status: 'OPEN',
    tests: [cse.id],
    verification: {
      method: 'None — emitted precisely because nothing examined it. That honesty is the coverage model.',
      outcome: 'UNVERIFIED'
    }
  };
}

function categoryLetter(cse) { return `category ${cse.category}`; }

const CATEGORY_BY_LETTER = {
  A: 'security', B: 'security', C: 'security', D: 'security', E: 'security', F: 'security',
  G: 'observability', H: 'configuration', I: 'security', J: 'security', K: 'security',
  L: 'security', M: 'security', N: 'configuration', O: 'dependency', P: 'performance',
  Q: 'security', R: 'code-quality', S: 'security', T: 'security', U: 'security', V: 'security',
  W: 'security', X: 'security', Y: 'security', Z: 'security'
};

function categoryFor(cse) { return CATEGORY_BY_LETTER[cse.category] || 'security'; }

module.exports = { finding, manualReview, severityFromPriority, TOOL, CATEGORY_BY_LETTER };
