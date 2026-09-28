'use strict';
/**
 * THE ADAPTER CONTRACT
 *
 * Every tool integration is an adapter module that exports this exact shape. The contract exists
 * so adapters can be written independently (including by a delegated model) and then verified
 * MECHANICALLY rather than by inspection — see tools/test-adapters.js.
 *
 * An adapter must be honest about what it did. It may never return findings it did not obtain from
 * real tool output, and it must distinguish "ran and found nothing" from "could not run".
 *
 * module.exports = {
 *   id:        'trivy',                       // stable, lowercase, matches the filename
 *   name:      'Trivy',                       // human label
 *   kind:      'dependency' | 'secret' | 'sast' | 'quality' | 'build' | 'config' | 'ai',
 *   stacks:    ['framework','core','both'],   // which .NET project shapes it supports
 *
 *   // Can this tool run here AT ALL? Never claim a clean result from a tool that cannot run.
 *   // Returns { available, version, reason, command }
 *   detect: async (ctx) => ({...}),
 *
 *   // Execute. MUST return a RunResult (see below). MUST NOT throw for tool failure —
 *   // a failed tool is data, not an exception.
 *   run: async (ctx) => ({...}),
 *
 *   // Parse raw output into canonical findings. Pure function, no I/O, no network.
 *   // Separated from run() so it is unit-testable against fixtures.
 *   parse: (raw, ctx) => [ ...canonicalFindings ],
 * }
 *
 * RunResult:
 * {
 *   status: 'EXECUTED' | 'FAILED' | 'NOT_AVAILABLE' | 'NOT_APPLICABLE' | 'UNVERIFIED',
 *   tool: 'trivy', version: '0.58.1',
 *   command: 'trivy fs --scanners vuln ...',   // exactly what ran, for reproducibility
 *   exitCode: 0,
 *   durationMs: 1234,
 *   rawPath: 'data/raw/trivy.json',            // where the untouched output was written
 *   findings: [ ...canonical ],                // [] is valid ONLY when status is EXECUTED
 *   notes: 'human-readable interpretation',
 *   limitations: 'what this run could NOT see'
 * }
 */

const STATUSES = ['EXECUTED', 'FAILED', 'NOT_AVAILABLE', 'NOT_APPLICABLE', 'UNVERIFIED'];
const KINDS = ['dependency', 'secret', 'sast', 'quality', 'build', 'config', 'ai'];
const SEVERITIES = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'];
const CONFIDENCES = ['CONFIRMED', 'LIKELY', 'POSSIBLE', 'UNVERIFIED'];
const CATEGORIES = ['security', 'code-quality', 'architecture', 'performance', 'reliability',
  'configuration', 'dependency', 'testing', 'deployment', 'observability', 'process'];
// Categories where a CVSS score is not a meaningful model.
const NON_SCOREABLE = ['architecture', 'testing', 'process'];

/** Validate an adapter module's shape. Returns an array of problem strings (empty = valid). */
function validateAdapter(mod, filename) {
  const p = [];
  const req = ['id', 'name', 'kind', 'stacks', 'detect', 'run', 'parse'];
  for (const k of req) if (mod[k] === undefined) p.push(`${filename}: missing export "${k}"`);
  if (mod.id && !/^[a-z0-9][a-z0-9-]*$/.test(mod.id)) p.push(`${filename}: id must be lowercase-kebab`);
  if (mod.kind && !KINDS.includes(mod.kind)) p.push(`${filename}: kind "${mod.kind}" not in ${KINDS.join('|')}`);
  if (mod.stacks && !Array.isArray(mod.stacks)) p.push(`${filename}: stacks must be an array`);
  for (const fn of ['detect', 'run', 'parse']) {
    if (mod[fn] !== undefined && typeof mod[fn] !== 'function') p.push(`${filename}: ${fn} must be a function`);
  }
  if (typeof mod.parse === 'function' && mod.parse.length < 1)
    p.push(`${filename}: parse must accept (raw, ctx)`);
  return p;
}

/** Validate a RunResult. Returns problem strings. */
function validateRunResult(r, toolId) {
  const p = [];
  if (!r || typeof r !== 'object') return [`${toolId}: run() returned no object`];
  if (!STATUSES.includes(r.status)) p.push(`${toolId}: invalid status "${r.status}"`);
  if (!Array.isArray(r.findings)) p.push(`${toolId}: findings must be an array`);
  if (r.status !== 'EXECUTED' && Array.isArray(r.findings) && r.findings.length)
    p.push(`${toolId}: status ${r.status} must not carry findings — a tool that did not run cannot report results`);
  if (r.status === 'EXECUTED' && r.exitCode === undefined)
    p.push(`${toolId}: EXECUTED requires exitCode`);
  if ((r.status === 'FAILED' || r.status === 'NOT_AVAILABLE') && !r.notes && !r.limitations)
    p.push(`${toolId}: ${r.status} requires notes explaining why (so a reader is never left to assume it was clean)`);
  if (r.command !== undefined && typeof r.command !== 'string')
    p.push(`${toolId}: command must be a string`);
  (r.findings || []).forEach((f, i) => validateFinding(f, `${toolId}[${i}]`).forEach(x => p.push(x)));
  return p;
}

/** Validate a canonical finding as produced by an adapter (pre-correlation). */
function validateFinding(f, where) {
  const p = [];
  if (!f || typeof f !== 'object') return [`${where}: not an object`];
  for (const k of ['title', 'category', 'severity', 'confidence', 'location', 'evidence', 'sources'])
    if (f[k] === undefined) p.push(`${where}: missing "${k}"`);
  if (f.category && !CATEGORIES.includes(f.category)) p.push(`${where}: bad category "${f.category}"`);
  if (f.severity && !SEVERITIES.includes(f.severity)) p.push(`${where}: bad severity "${f.severity}"`);
  if (f.confidence && !CONFIDENCES.includes(f.confidence)) p.push(`${where}: bad confidence "${f.confidence}"`);
  if (f.location && !f.location.file) p.push(`${where}: location.file required`);
  if (f.evidence && typeof f.evidence.snippet !== 'string') p.push(`${where}: evidence.snippet required (may be '')`);
  if (!Array.isArray(f.sources) || !f.sources.length) p.push(`${where}: sources[] required and non-empty`);
  if (f.cvss && NON_SCOREABLE.includes(f.category))
    p.push(`${where}: category "${f.category}" must have cvss null — CVSS is not a meaningful model for it`);
  if (f.cvss && f.cvss.vector && !/^CVSS:3\.1\/AV:[NALP]\/AC:[LH]\/PR:[NLH]\/UI:[NR]\/S:[UC]\/C:[NLH]\/I:[NLH]\/A:[NLH]$/.test(f.cvss.vector))
    p.push(`${where}: malformed CVSS v3.1 vector`);
  return p;
}

/** Normalise a tool severity string onto the canonical scale. */
function normaliseSeverity(s, fallback = 'MEDIUM') {
  if (!s) return fallback;
  const v = String(s).toUpperCase();
  if (['CRITICAL', 'BLOCKER'].includes(v)) return 'CRITICAL';
  if (['HIGH', 'ERROR', 'MAJOR'].includes(v)) return 'HIGH';
  if (['MEDIUM', 'MODERATE', 'WARNING', 'MINOR'].includes(v)) return 'MEDIUM';
  if (['LOW', 'NOTE', 'INFO', 'INFORMATIONAL'].includes(v)) return 'LOW';
  if (['NONE', 'UNKNOWN'].includes(v)) return 'INFO';
  return fallback;
}

/** Derive severity from a CVSS base score. */
function severityFromCvss(score) {
  const n = Number(score);
  if (!isFinite(n) || n <= 0) return 'INFO';
  if (n >= 9.0) return 'CRITICAL';
  if (n >= 7.0) return 'HIGH';
  if (n >= 4.0) return 'MEDIUM';
  return 'LOW';
}

/** Build a RunResult for a tool that cannot run, with the command needed to enable it. */
function notAvailable(toolId, reason, command) {
  return {
    status: 'NOT_AVAILABLE', tool: toolId, findings: [],
    notes: reason,
    limitations: `No results were obtained from ${toolId}. This is NOT a clean result.`,
    remediation: command ? `Install/enable with: ${command}` : undefined
  };
}

/** Build a RunResult for a tool that ran and failed. */
function failed(toolId, reason, opts = {}) {
  return Object.assign({
    status: 'FAILED', tool: toolId, findings: [],
    notes: reason,
    limitations: `${toolId} produced no analysis. Absence of findings here is absence of evidence.`
  }, opts);
}

module.exports = {
  STATUSES, KINDS, SEVERITIES, CONFIDENCES, CATEGORIES, NON_SCOREABLE,
  validateAdapter, validateRunResult, validateFinding,
  normaliseSeverity, severityFromCvss, notAvailable, failed
};
