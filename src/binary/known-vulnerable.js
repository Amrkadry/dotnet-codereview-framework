'use strict';
/**
 * Offline known-vulnerable managed-assembly table.
 *
 * This is a CURATED, static table — deliberately small, deliberately high-confidence. It is not
 * an advisory feed and makes no claim to completeness; it exists because on a deployed-bins-only
 * engagement there is no manifest for a scanner to read, yet the AssemblyRef table still pins
 * exact dependency versions. Version-vs-advisory matching here is a fact; REACHABILITY is not
 * asserted by this module and the emitted findings say so.
 *
 * Extend this table only with entries where the vulnerable range and fix version are certain.
 * `fixed` is the first assembly version at which the advisory no longer applies (NuGet package
 * versions and assembly versions usually agree for these libraries; where they diverge, use the
 * ASSEMBLY version — that is what the metadata table carries).
 */

const ENTRIES = [
  {
    name: 'newtonsoft.json',
    displayName: 'Newtonsoft.Json',
    fixed: [13, 0, 0, 1],
    fixedLabel: '13.0.0.1',
    cve: 'CVE-2024-21907',
    severity: 'HIGH',
    summary: 'Improper handling of high nesting depth in Json.NET can cause stack exhaustion ' +
      '(denial of service) when processing hostile JSON.',
    url: 'https://nvd.nist.gov/vuln/detail/CVE-2024-21907'
  },
  {
    name: 'log4net',
    displayName: 'log4net',
    fixed: [2, 0, 10, 0],
    fixedLabel: '2.0.10',
    cve: 'CVE-2018-1285',
    severity: 'HIGH',
    summary: 'XXE in log4net serializers (affects 1.2.0 - 2.0.9): a hostile configuration or ' +
      'log message can be parsed by a vulnerable XML parser.',
    url: 'https://nvd.nist.gov/vuln/detail/CVE-2018-1285'
  },
  {
    name: 'icsharpcode.sharpziplib',
    displayName: 'ICSharpCode.SharpZipLib',
    fixed: [1, 0, 0, 0],
    fixedLabel: '1.0.0',
    cve: 'CVE-2018-1002204',
    severity: 'HIGH',
    summary: 'Path traversal when extracting attacker-controlled archives (Zip Slip); fixed in 1.0.0.',
    url: 'https://nvd.nist.gov/vuln/detail/CVE-2018-1002204'
  }
];

/** '4.7.2.1' -> [4,7,2,1]; tolerant of 2- and 3-part versions. Returns null on junk. */
function parseVersion(v) {
  if (!v || typeof v !== 'string') return null;
  const parts = v.trim().split('.').map(p => /^\d+$/.test(p) ? Number(p) : null);
  if (parts.some(p => p === null) || !parts.length || parts.length > 4) return null;
  while (parts.length < 4) parts.push(0);
  return parts;
}

/** Numeric four-part comparison: -1 / 0 / 1. Non-parseable inputs compare as null. */
function compareVersions(a, b) {
  const pa = parseVersion(a), pb = parseVersion(b);
  if (!pa || !pb) return null;
  for (let i = 0; i < 4; i++) {
    if (pa[i] !== pb[i]) return pa[i] < pb[i] ? -1 : 1;
  }
  return 0;
}

/**
 * Match one reference (name + version) against the table.
 * Returns the matching ENTRIES[] row or null. Pure.
 */
function checkReference(name, version) {
  if (!name || !version) return null;
  const entry = ENTRIES.find(e => e.name === String(name).toLowerCase());
  if (!entry) return null;
  return compareVersions(version, entry.fixedLabel) < 0 ? entry : null;
}

/** Is a given version itself in a known-vulnerable range (used to escalate redirects)? */
function isVulnerable(name, version) {
  return checkReference(name, version) !== null;
}

module.exports = { ENTRIES, checkReference, isVulnerable, compareVersions, parseVersion };
