'use strict';
/**
 * Correlation and deduplication.
 *
 * Multiple tools reporting ONE issue must produce ONE finding. Inflating the count by the number
 * of detectors is the single most common way a multi-tool report becomes untrustworthy.
 *
 * Correlation strategy, in decreasing confidence:
 *   1. advisory identity   — same CVE/GHSA + same package        (dependency findings)
 *   2. location identity   — same file + line window + same CWE  (code findings)
 *   3. rule equivalence    — same file + an equivalence-mapped rule pair
 *
 * When findings merge, we keep the STRONGEST evidence and record every contributing tool in
 * sources[], including tools that looked and did NOT report it. That asymmetry is the point:
 * agreement raises confidence, and a miss is information about the tool.
 */

const SEV_RANK = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3, INFO: 4 };
const CONF_RANK = { CONFIRMED: 0, LIKELY: 1, POSSIBLE: 2, UNVERIFIED: 3 };

/**
 * Rules from different tools that mean the same thing. Extend as tools are added.
 * Key is a canonical concept; values are tool-native rule ids.
 */
const RULE_EQUIVALENCE = [
  { concept: 'hardcoded-credentials', rules: ['S2068', 'dotnet-appsetting-secret', 'dotnet-connectionstring-password', 'generic-api-key', 'CWE-798', 'SCS0015', 'cs/hardcoded-credentials', 'cs/password-in-configuration'] },
  { concept: 'weak-cert-validation', rules: ['S4830', 'CA5359', 'moraa-dotnet-disable-cert-validation', 'CWE-295', 'SCS0004'] },
  { concept: 'static-iv', rules: ['S3329', 'CA5401', 'moraa-dotnet-static-zero-iv', 'CWE-329'] },
  { concept: 'regex-no-timeout', rules: ['S6444', 'MORAA0013', 'moraa-dotnet-regex-no-timeout', 'CWE-1333'] },
  { concept: 'permissive-cors', rules: ['S5122', 'moraa-dotnet-cors-reflected-origin', 'CWE-346', 'CWE-942'] },
  { concept: 'sql-injection', rules: ['S3649', 'CA2100', 'csharp.lang.security.sqli', 'CWE-89', 'SCS0002', 'cs/sql-injection'] },
  { concept: 'weak-hash', rules: ['S4790', 'CA5350', 'CA5351', 'CWE-327', 'CWE-328', 'SCS0006'] },
  { concept: 'unsafe-deserialization', rules: ['S5766', 'CA2300', 'CA2301', 'CA2302', 'CWE-502', 'SCS0028', 'cs/unsafe-deserialization'] },
  { concept: 'xxe', rules: ['S2755', 'CA3075', 'CWE-611', 'SCS0007'] },
  { concept: 'path-traversal', rules: ['S2083', 'CA3003', 'CWE-22', 'SCS0018', 'cs/path-injection'] },
  { concept: 'weak-random', rules: ['S2245', 'CA5394', 'CWE-338', 'SCS0005'] },
  { concept: 'cleartext-transmission', rules: ['S5332', 'CWE-319'] },
  { concept: 'shared-mutable-state', rules: ['S1450', 'MORAA0009', 'CWE-488'] },
  { concept: 'null-dereference', rules: ['S2259', 'CS8602', 'CWE-476'] },
  { concept: 'missing-authorization', rules: ['MORAA0002', 'moraa-dotnet-controller-missing-authorize', 'CWE-862'] },
  { concept: 'command-injection', rules: ['SCS0001', 'cs/command-line-injection', 'CA3006', 'S2076', 'CWE-78'] },
  { concept: 'xss', rules: ['SCS0029', 'cs/web/xss', 'CA3002', 'S5131', 'CWE-79'] },
  { concept: 'code-injection', rules: ['cs/code-injection', 'CWE-94'] },
  { concept: 'ldap-injection', rules: ['SCS0031', 'SCS0026', 'CA3005', 'S2078', 'CWE-90'] },
  { concept: 'xpath-injection', rules: ['SCS0003', 'CA3008', 'CWE-643'] },
  { concept: 'open-redirect', rules: ['SCS0027', 'CA3007', 'S5146', 'CWE-601'] },
  { concept: 'csrf', rules: ['SCS0016', 'S4502', 'CWE-352'] },
  { concept: 'weak-cipher', rules: ['SCS0010', 'SCS0013', 'CA5358', 'CWE-326'] }
];

const CONCEPT_OF = new Map();
RULE_EQUIVALENCE.forEach(({ concept, rules }) =>
  rules.forEach(r => CONCEPT_OF.set(String(r).toUpperCase(), concept)));

/** The concept a finding belongs to, if we can tell. */
function conceptOf(f) {
  const candidates = []
    .concat(f.subcategory || [])
    .concat((f.sources || []).map(s => s.sourceFindingId).filter(Boolean))
    .concat(f.cwe || []);
  for (const c of candidates) {
    const hit = CONCEPT_OF.get(String(c).toUpperCase());
    if (hit) return hit;
  }
  return null;
}

const norm = p => String(p || '').replace(/\\/g, '/').replace(/^\.\//, '').toLowerCase();

/** Line proximity window — tools disagree by a few lines on the same defect. */
const LINE_WINDOW = 4;

/** Keys a finding can be correlated on, strongest first. */
function keysOf(f) {
  const keys = [];
  const file = norm(f.location && f.location.file);
  const line = (f.location && f.location.startLine) || 0;

  // 1. advisory identity (dependency findings): CVE + package
  if (f.advisories && f.advisories.length) {
    const pkg = (f.package && f.package.name) || f.subcategory || '';
    f.advisories.forEach(a => keys.push(`adv:${String(a).toUpperCase()}:${String(pkg).toLowerCase()}`));
  }

  // 2. concept + file (+ line bucket) — survives differing rule ids
  const concept = conceptOf(f);
  if (concept && file) {
    keys.push(`concept:${concept}:${file}:${Math.floor(line / LINE_WINDOW)}`);
    // also a file-level key so tools that report the whole file still correlate
    keys.push(`conceptfile:${concept}:${file}`);
  }

  // 3. exact rule + location
  if (file && f.subcategory) keys.push(`rule:${String(f.subcategory).toUpperCase()}:${file}:${line}`);

  return keys;
}

/** Pick the better of two values by a rank map. */
const best = (a, b, rank) => (rank[a] ?? 99) <= (rank[b] ?? 99) ? a : b;

/** Merge b into a, keeping the strongest evidence. */
function mergeInto(a, b) {
  a.severity = best(a.severity, b.severity, SEV_RANK);
  a.confidence = best(a.confidence, b.confidence, CONF_RANK);

  // A dataflow path is evidence; losing it on merge would silently discard the reason the
  // finding is credible. Keep whichever side has one, and prefer the one with MORE steps when
  // both do — the longer path documents the taint route in more detail.
  if (b.dataflow && (!a.dataflow ||
      (b.dataflow.steps || []).length > (a.dataflow.steps || []).length)) {
    a.dataflow = b.dataflow;
  }

  // Prefer a real CVSS vector over a bare score; prefer the higher score otherwise.
  if (b.cvss && (!a.cvss || (b.cvss.vector && !a.cvss.vector) ||
      (b.cvss.score || 0) > (a.cvss.score || 0))) a.cvss = b.cvss;

  // Prefer the richer text.
  for (const k of ['problem', 'impact', 'recommendation', 'attackScenario', 'rootCause', 'correctedCode']) {
    if ((b[k] || '').length > (a[k] || '').length) a[k] = b[k];
  }
  if ((b.evidence?.snippet || '').length > (a.evidence?.snippet || '').length) {
    a.evidence.snippet = b.evidence.snippet;
  }
  // Tool output accumulates — every tool's own words are kept.
  if (b.evidence?.toolOutput) {
    a.evidence.toolOutput = [a.evidence.toolOutput, b.evidence.toolOutput].filter(Boolean).join('\n');
  }

  a.cwe = [...new Set([...(a.cwe || []), ...(b.cwe || [])])];
  a.owasp = [...new Set([...(a.owasp || []), ...(b.owasp || [])])];
  a.advisories = [...new Set([...(a.advisories || []), ...(b.advisories || [])])];
  a.tests = [...new Set([...(a.tests || []), ...(b.tests || [])])];

  // sources is the audit trail; never collapse it.
  const seen = new Set((a.sources || []).map(s => s.tool + '|' + (s.sourceFindingId || '')));
  (b.sources || []).forEach(s => {
    const k = s.tool + '|' + (s.sourceFindingId || '');
    if (!seen.has(k)) { a.sources.push(s); seen.add(k); }
  });

  a.correlation = a.correlation || {};
  a.correlation.mergedFrom = [...new Set([
    ...(a.correlation.mergedFrom || []),
    ...(b.correlation?.mergedFrom || []),
    ...(b.sources || []).map(s => `${s.tool}:${s.sourceFindingId || 'n/a'}`)
  ])];

  // Extra locations are additive context.
  if (b.location?.additionalLocations) {
    a.location.additionalLocations = [
      ...(a.location.additionalLocations || []),
      ...b.location.additionalLocations
    ];
  }
  // If either says suppressed, keep that state visible rather than silently reopening.
  if (b.status === 'FALSE_POSITIVE' && a.status === 'OPEN') a.status = 'FALSE_POSITIVE';
  return a;
}

/**
 * Correlate a flat list of adapter-produced findings.
 * @param {Array} findings
 * @param {object} opts { toolsThatRan: [toolId], idPrefixer: fn }
 * @returns {{findings: Array, stats: object}}
 */
function correlate(findings, opts = {}) {
  const index = new Map();   // key -> canonical finding
  const canonical = [];
  let merged = 0;

  for (const f of findings) {
    const keys = keysOf(f);
    let target = null;
    for (const k of keys) if (index.has(k)) { target = index.get(k); break; }

    if (target) {
      mergeInto(target, f);
      merged++;
      keys.forEach(k => { if (!index.has(k)) index.set(k, target); });
    } else {
      const copy = JSON.parse(JSON.stringify(f));
      copy.correlation = copy.correlation || {};
      canonical.push(copy);
      keys.forEach(k => index.set(k, copy));
    }
  }

  // Record tools that ran but did NOT report each finding. This is what makes a miss visible.
  const ran = opts.toolsThatRan || [];
  for (const f of canonical) {
    const reported = new Set((f.sources || []).map(s => s.tool));
    for (const t of ran) {
      if (!reported.has(t)) {
        f.sources.push({ tool: t, status: 'MISSED', note: 'ran on this codebase and did not report this finding' });
      }
    }
  }

  // Stable ordering: severity, then CVSS, then confidence, then location.
  canonical.sort((a, b) =>
    SEV_RANK[a.severity] - SEV_RANK[b.severity] ||
    ((b.cvss?.score || 0) - (a.cvss?.score || 0)) ||
    CONF_RANK[a.confidence] - CONF_RANK[b.confidence] ||
    norm(a.location.file).localeCompare(norm(b.location.file)) ||
    ((a.location.startLine || 0) - (b.location.startLine || 0)));

  // Assign canonical ids now that order is stable.
  const counters = {};
  const prefixFor = f => {
    if (f.category === 'dependency') return 'DEP-VULN';
    if (f.category === 'configuration') return 'CFG-GEN';
    if (f.category === 'code-quality') return 'CODE-QUAL';
    if (f.category === 'architecture') return 'ARCH-GEN';
    if (f.category === 'performance') return 'PERF-GEN';
    if (f.category === 'reliability') return 'REL-GEN';
    if (f.category === 'testing') return 'TEST-GEN';
    if (f.category === 'deployment') return 'DEP-PROC';
    if (f.category === 'process') return 'PROC-GEN';
    const c = conceptOf(f);
    if (c === 'hardcoded-credentials') return 'SEC-SECRET';
    if (c === 'missing-authorization') return 'SEC-AUTHZ';
    if (c === 'permissive-cors') return 'SEC-CORS';
    if (['static-iv', 'weak-hash', 'weak-random', 'weak-cert-validation', 'weak-cipher'].includes(c)) return 'SEC-CRYPTO';
    if (['sql-injection', 'xxe', 'unsafe-deserialization', 'command-injection', 'xss',
         'code-injection', 'ldap-injection', 'xpath-injection'].includes(c)) return 'SEC-INJ';
    if (c === 'path-traversal') return 'SEC-FILE';
    return 'SEC-GEN';
  };
  for (const f of canonical) {
    const pre = prefixFor(f);
    counters[pre] = (counters[pre] || 0) + 1;
    f.findingId = `${pre}-${String(counters[pre]).padStart(3, '0')}`;
    delete f._raw;
  }

  return {
    findings: canonical,
    stats: {
      inputFindings: findings.length,
      canonicalFindings: canonical.length,
      mergedAway: merged,
      dedupRatio: findings.length ? +(merged / findings.length).toFixed(3) : 0,
      multiToolConfirmed: canonical.filter(f =>
        (f.sources || []).filter(s => s.status === 'REPORTED').length > 1).length
    }
  };
}

module.exports = { correlate, RULE_EQUIVALENCE, conceptOf, keysOf, mergeInto };
