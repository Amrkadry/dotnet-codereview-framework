// dotnet-codereview-framework — src/supplychain/checks/name-risk.js
// Author: Amr Kadry (github.com/Amrkadry) · MIT License
'use strict';
/**
 * CHECK 4 — package-name risk heuristics (typosquat-shaped ids).
 *
 * Compares every declared or locked package id against a curated list of well-known .NET
 * package ids (src/supplychain/package-names.js) using an in-code Levenshtein distance, and
 * flags NEAR-MISSES ONLY: edit distance 1 on reasonably sized names, distance 2 only on long
 * compound names, plus ids containing characters outside the NuGet id alphabet (homoglyph-
 * shaped). Everything here is LOW severity and POSSIBLE confidence by construction — the
 * analyzer has no registry access, so it CANNOT know whether a name is squatted; it can only
 * say "this looks shaped like a mistake or a squat, a human must confirm". A false
 * typosquat accusation is worse than a miss, and the wording below is written to be survivable
 * for the accused package too.
 */

const { buildFinding } = require('../finding');
const { classifyName } = require('../package-names');

const MAX_REPORT = 20;   // safety valve against a pathological tree flooding the report

function nameRisk(inv) {
  // Unique ids across manifests (what developers asked for) AND lockfile entries (what
  // transitively restores — exactly where a squat can hide from the manifest).
  const seen = new Map();   // lowercase id -> { id, file, line, snippet, origin }
  const add = (id, file, line, snippet, origin) => {
    const key = String(id || '').trim().toLowerCase();
    if (!key || seen.has(key)) return;
    seen.set(key, { id: String(id).trim(), file, line, snippet, origin });
  };
  for (const p of inv.projects)
    for (const r of p.model.packageRefs)
      add(r.id, p.file, r.versionLine || r.line, r.snippet, 'PackageReference');
  for (const pc of inv.packagesConfig)
    for (const p of pc.model.packages)
      add(p.id, pc.file, p.line, p.snippet, 'packages.config');
  for (const cp of inv.centralProps)
    for (const v of cp.model.versions)
      add(v.id, cp.file, v.line, v.snippet, 'Directory.Packages.props');
  for (const lf of inv.lockfiles)
    for (const e of lf.model.entries)
      add(e.id, lf.file, e.line, `"${e.id}"`, 'packages.lock.json');

  const out = [];
  for (const entry of seen.values()) {
    if (out.length >= MAX_REPORT) break;
    const c = classifyName(entry.id);
    if (!c.flagged) continue;
    out.push(buildFinding('nuget-package-name-risk', {
      title: `Package id "${entry.id}" ${c.reason || 'looks like a near-miss of a well-known package'}`,
      severity: 'LOW',
      confidence: 'POSSIBLE',
      cwe: ['CWE-1357'],
      owasp: ['A08:2021'],
      location: { file: entry.file, startLine: entry.line || 1 },
      evidence: {
        snippet: entry.snippet || `"${entry.id}"`,
        language: entry.origin === 'packages.lock.json' ? 'json' : 'xml',
        toolOutput: c.nearest
          ? `nearest well-known id: "${c.nearest}" (edit distance ${c.distance}); ` +
            'match is shape-based only'
          : 'shape-based check only; no registry was consulted'
      },
      problem: `The id is not one of the analyzer's curated well-known ids and ${c.reason}. ` +
        'This is a SHAPE signal — typosquats deliberately resemble famous names — but plenty of ' +
        'legitimate packages sit near famous ones too.',
      impact: 'If this IS a typosquat, restoring it executes attacker code with build privileges. ' +
        'If it is not, this finding is a false accusation. A HUMAN MUST CONFIRM which it is — the ' +
        'analyzer cannot decide this offline.',
      recommendation: 'Confirm the exact id, letter by letter and character by character, against ' +
        'the package you actually intended at https://www.nuget.org/packages/<id>, check the owner/publisher ' +
        'and download history there, and verify the intended dependency is not simply a misspelling. ' +
        'Do not remediate by accusation; do verify before the next restore.',
      tests: ['O-004'],
      effort: 'TRIVIAL',
      priority: 'P3',
      engine: 'custom',
      sourceNote: 'curated well-known list compiled into the analyzer; no download statistics are ' +
        'implied and no registry was queried'
    }));
  }
  if (out.length >= MAX_REPORT) {
    // honesty about the cap rather than silent truncation
    out[out.length - 1].sources[0].note =
      'name-risk findings were capped at ' + MAX_REPORT + ' for this tree; more ids matched the heuristics';
  }
  return out;
}

module.exports = { nameRisk };
