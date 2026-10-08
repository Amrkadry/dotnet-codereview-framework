// dotnet-codereview-framework — src/report/vault.js
// Author: Amr Kadry (github.com/Amrkadry) · MIT License
'use strict';
/**
 * Obsidian-style review vault writer.
 *
 * Writes the human-readable review INTO THE SOURCE TREE, at <sourcePath>/<outDir>, so the review
 * travels with the code it describes. Default outDir is `.moraa-review`.
 *
 * Layout (wikilinks work in Obsidian, and plain Markdown links work on GitHub):
 *
 *   <source>/.moraa-review/
 *     README.md                      entry point / map of content
 *     00-Executive-Summary.md
 *     01-Findings.md                 master table, grouped by severity
 *     02-Tool-Results.md             what ran, what failed, what was never available
 *     03-Dependencies-Security.md    SECURITY queue (confirmed advisories)
 *     04-Dependencies-Maintenance.md MAINTENANCE queue (outdated / EOL / duplicated)
 *     05-Test-Coverage.md            required tests per finding, mapped to the catalog
 *     06-Configuration.md
 *     07-Correlation-and-Dedup.md    which tools agreed, which missed
 *     08-Remediation-Roadmap.md      P0..P3
 *     Findings/<ID> <slug>.md        one page per finding
 *     data/report.json               canonical machine output
 *     data/report.sarif              SARIF 2.1.0 for CI code scanning
 *     data/raw/*                     untouched tool output
 *
 * IMPORTANT: this writer never invents content. Empty sections say they are empty and say why.
 */

const fs = require('fs');
const path = require('path');

const SEV_ICON = { CRITICAL: '🔴', HIGH: '🟠', MEDIUM: '🟡', LOW: '🔵', INFO: '⚪' };
const SEV_ORDER = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'];

const esc = s => String(s == null ? '' : s).replace(/\|/g, '\\|').replace(/\r?\n+/g, ' ').trim();
const slug = s => String(s).replace(/[^A-Za-z0-9 ]+/g, '').replace(/\s+/g, ' ').trim().slice(0, 70);
const firstSentence = s => {
  const t = String(s || '').trim();
  const i = t.search(/\.\s/);
  return i > 0 ? t.slice(0, i + 1) : t;
};

function table(headers, rows) {
  if (!rows.length) return '_None._\n';
  return '| ' + headers.join(' | ') + ' |\n' +
    '|' + headers.map(() => '---').join('|') + '|\n' +
    rows.map(r => '| ' + r.join(' | ') + ' |').join('\n') + '\n';
}

function fm(tags, extra = {}) {
  const lines = ['---', `tags: [${tags.join(', ')}]`, `created: ${new Date().toISOString().slice(0, 10)}`];
  Object.entries(extra).forEach(([k, v]) => lines.push(`${k}: ${v}`));
  lines.push('---', '');
  return lines.join('\n');
}

const cvssCell = f => f.cvss ? `${f.cvss.score} (${f.cvss.severity})` : 'N/A';

/** Tools that reported vs missed a finding. */
function toolSplit(f) {
  const rep = (f.sources || []).filter(s => s.status === 'REPORTED').map(s => s.tool);
  const missed = (f.sources || []).filter(s => s.status === 'MISSED').map(s => s.tool);
  const fn = (f.sources || []).filter(s => s.status === 'FALSE_NEGATIVE').map(s => s.tool);
  return { rep, missed, fn };
}

// ---------------------------------------------------------------- finding page
function findingPage(f) {
  const { rep, missed, fn } = toolSplit(f);
  let b = fm(['moraa', 'finding', String(f.severity).toLowerCase(), f.category],
    { parent: '"[[01-Findings]]"' });

  b += `# ${f.findingId} — ${f.title}\n\n`;
  b += table(['Field', 'Value'], [
    ['**Severity**', `${SEV_ICON[f.severity] || ''} ${f.severity}`],
    ['**CVSS**', f.cvss ? `${f.cvss.score} (${f.cvss.severity})` : 'N/A — not a meaningful model for this finding type'],
    ['**CVSS Vector**', f.cvss && f.cvss.vector ? '`' + f.cvss.vector + '`' : 'not supplied'],
    ['**Confidence**', f.confidence],
    ['**Category**', f.category + (f.subcategory ? ` / \`${f.subcategory}\`` : '')],
    ['**CWE**', (f.cwe || []).join(', ') || '—'],
    ['**OWASP**', (f.owasp || []).join(', ') || '—'],
    ['**Advisories**', (f.advisories || []).join(', ') || '—'],
    ['**Location**', '`' + f.location.file + (f.location.startLine ? ':' + f.location.startLine : '') + '`'],
    ['**Priority / Effort**', `${f.priority || '—'} / ${f.effort || '—'}`],
    ['**Status**', f.status || 'OPEN']
  ]);

  if (f.severityRationale) {
    b += `\n> [!note] Severity differs from the CVSS base severity\n> ${f.severityRationale}\n`;
  }

  if (rep.length > 1) {
    b += `\n> [!check] Confirmed independently by ${rep.length} tools\n> ${rep.join(', ')}\n`;
  }
  if (fn.length) {
    b += `\n> [!warning] A tool looked and reported nothing (false negative)\n> ${fn.join(', ')} — a confident zero from a tool is a claim to verify, not a result.\n`;
  }

  if (f.package) {
    b += '\n## Package\n\n' + table(['Package', 'Installed', 'Fixed in'],
      [[`\`${f.package.name}\``, f.package.installed || '—',
        f.package.fixed ? `\`${f.package.fixed}\`` : '**no fix published**']]);
  }

  if (f.problem) b += `\n## Problem\n\n${f.problem}\n`;
  if (f.impact) b += `\n## Impact\n\n${f.impact}\n`;
  if (f.attackScenario) b += `\n## Attack / failure scenario\n\n${f.attackScenario}\n`;
  if (f.rootCause) b += `\n## Root cause\n\n${f.rootCause}\n`;

  if (f.evidence && (f.evidence.snippet || f.evidence.toolOutput)) {
    b += '\n## Evidence\n\n';
    if (f.evidence.snippet) {
      b += '```' + (f.evidence.language || 'csharp') + '\n' + f.evidence.snippet + '\n```\n';
      if (f.evidence.redacted) b += '\n*Secret material redacted by the adapter.*\n';
    }
    if (f.evidence.toolOutput) b += '\n**Tool output**\n\n```text\n' + f.evidence.toolOutput + '\n```\n';
  }

  if ((f.location.additionalLocations || []).length) {
    b += '\n## Other affected locations\n\n' + table(['File', 'Line', 'Note'],
      f.location.additionalLocations.slice(0, 40)
        .map(l => ['`' + l.file + '`', l.startLine || '—', esc(l.note) || '—']));
  }

  if (f.recommendation) b += `\n## Recommendation\n\n${f.recommendation}\n`;
  if (f.correctedCode) b += '\n## Corrected code\n\n```csharp\n' + f.correctedCode + '\n```\n';

  if ((f.tests || []).length) {
    b += `\n## Required tests\n\n${f.tests.map(t => '`' + t + '`').join(' · ')}\n`;
    b += '\nCatalog ids, from `catalog/dotnet-test-cases*.json`.\n';
  }
  if (f.regressionTest) b += `\n## Regression test\n\n${f.regressionTest}\n`;

  b += '\n## Detection\n\n';
  if (f.detection) {
    b += `Class: **${f.detection.class}**\n\n`;
    if ((f.detection.rules || []).length) {
      b += table(['Engine', 'Rule', 'Status'],
        f.detection.rules.map(r => [r.engine, '`' + r.ruleId + '`', r.status]));
    }
  } else b += '_Not classified._\n';

  b += '\n## Sources\n\n' + table(['Tool', 'Status', 'Note'],
    (f.sources || []).map(s => [s.tool, s.status, esc(s.note) || '—']));
  if (missed.length) {
    b += `\n${missed.length} tool(s) ran and did not report this: ${missed.join(', ')}.\n`;
  }

  if (f.verification) {
    b += '\n## Verification\n\n';
    if (f.verification.method) b += `**Method.** ${f.verification.method}\n\n`;
    if (f.verification.disproofAttempt) b += `**Attempt to disprove.** ${f.verification.disproofAttempt}\n\n`;
    if (f.verification.outcome) b += `**Outcome.** ${f.verification.outcome}\n\n`;
    if (f.verification.openQuestion) b += `> [!question] Unresolved\n> ${f.verification.openQuestion}\n`;
  }

  if ((f.references || []).length) {
    b += '\n## References\n\n' + f.references.map(r => `- ${r}`).join('\n') + '\n';
  }

  const rel = (f.correlation && f.correlation.relatedTo) || [];
  if (rel.length) b += '\n## Related\n\n' + rel.map(r => `[[${r}]]`).join(' · ') + '\n';

  return b;
}

// ---------------------------------------------------------------- main writer
/**
 * @param {object} args
 *   sourcePath, outDir, findings, runResults, stats, project, catalogStats, config
 */
function writeVault(args) {
  const { sourcePath, findings = [], runResults = [], stats = {}, project = {} } = args;
  const outDir = args.outDir || '.moraa-review';
  const root = path.join(sourcePath, outDir);

  fs.mkdirSync(path.join(root, 'Findings'), { recursive: true });
  fs.mkdirSync(path.join(root, 'data', 'raw'), { recursive: true });

  const written = [];
  const put = (rel, body) => {
    const p = path.join(root, rel);
    fs.mkdirSync(path.dirname(p), { recursive: true });
    fs.writeFileSync(p, body);
    written.push(rel);
  };

  const by = s => findings.filter(f => f.severity === s);
  const counts = SEV_ORDER.reduce((m, s) => (m[s] = by(s).length, m), {});
  const overall = counts.CRITICAL ? 'CRITICAL' : counts.HIGH ? 'HIGH' : counts.MEDIUM ? 'MEDIUM' : 'LOW';

  const nameOf = f => `${f.findingId} ${slug(f.title)}`;

  // ---------- finding pages ----------
  const pageNames = new Set();
  for (const f of findings) {
    const rel = path.join('Findings', `${nameOf(f)}.md`);
    put(rel, findingPage(f));
    pageNames.add(path.basename(rel));
  }

  // Prune generated pages from earlier runs. Without this the folder accumulates every
  // finding the project has ever had, so a reader sees fixed and withdrawn findings
  // presented exactly like current ones — the report stops describing the code as it is.
  // Scoped deliberately: only files matching the generated "<FINDING-ID> <title>.md" shape
  // are removed, so hand-written notes dropped into the folder are left untouched.
  const GENERATED_PAGE = /^[A-Z]+(-[A-Z0-9]+)+-\d{3} .+\.md$/;
  try {
    for (const name of fs.readdirSync(path.join(root, 'Findings'))) {
      if (pageNames.has(name)) continue;
      if (!GENERATED_PAGE.test(name)) continue;
      try { fs.unlinkSync(path.join(root, 'Findings', name)); } catch { /* leave it */ }
    }
  } catch { /* no Findings dir yet */ }

  // ---------- 01-Findings ----------
  let b = fm(['moraa', 'findings', 'moc'], { parent: '"[[README]]"' });
  b += '# Findings\n\n';
  b += table(['Severity', 'Count'], SEV_ORDER.filter(s => counts[s])
    .map(s => [`${SEV_ICON[s]} ${s}`, counts[s]]).concat([['**Total**', `**${findings.length}**`]]));

  if (!findings.length) {
    b += '\n> [!warning] No findings does not mean no problems\n' +
      '> Check [[02-Tool-Results]] first. If tools failed or were unavailable, this page is empty\n' +
      '> because nothing looked — not because nothing is wrong.\n';
  }

  for (const s of SEV_ORDER) {
    const g = by(s);
    if (!g.length) continue;
    b += `\n## ${SEV_ICON[s]} ${s}\n\n`;
    b += table(['ID', 'Finding', 'CVSS', 'Conf.', 'Location', 'Tools', 'Status'],
      g.map(f => {
        const { rep } = toolSplit(f);
        return [
          f.findingId,
          `[[${nameOf(f)}\\|${esc(f.title).slice(0, 80)}]]`,
          cvssCell(f), f.confidence,
          '`' + esc(f.location.file).split('/').slice(-2).join('/') +
            (f.location.startLine ? ':' + f.location.startLine : '') + '`',
          rep.length > 1 ? `**${rep.length}** (${rep.join(', ')})` : (rep[0] || '—'),
          f.status || 'OPEN'
        ];
      }));
  }
  put('01-Findings.md', b);

  // ---------- 00-Executive-Summary ----------
  b = fm(['moraa', 'summary'], { parent: '"[[README]]"' });
  b += `# Executive Summary\n\n**Overall risk: ${overall}**\n\n`;
  b += table(['Metric', 'Value'], [
    ['Findings', findings.length],
    ...SEV_ORDER.filter(s => counts[s]).map(s => [s, counts[s]]),
    ['CVSS-scored', findings.filter(f => f.cvss).length],
    ['CVSS N/A by design', findings.filter(f => !f.cvss).length],
    ['Highest CVSS', findings.reduce((m, f) => Math.max(m, (f.cvss && f.cvss.score) || 0), 0) || '—'],
    ['Confirmed by >1 tool', stats.multiToolConfirmed ?? '—'],
    ['Raw tool findings before dedup', stats.inputFindings ?? '—'],
    ['Merged away as duplicates', stats.mergedAway ?? '—'],
    ['Tools executed', runResults.filter(r => r.status === 'EXECUTED').length],
    ['Tools failed / unavailable', runResults.filter(r => r.status !== 'EXECUTED').length]
  ]);

  const notRun = runResults.filter(r => r.status !== 'EXECUTED');
  if (notRun.length) {
    b += '\n> [!warning] Coverage gaps — read before trusting any "clean" result\n';
    notRun.forEach(r => { b += `> - **${r.tool}** (${r.status}): ${esc(r.notes || 'no reason recorded')}\n`; });
    b += '> \n> An empty result from a tool that never ran is absence of evidence, not evidence of absence.\n';
  }

  const top = findings.slice(0, 10);
  if (top.length) {
    b += '\n## Top priorities\n\n' + table(['#', 'ID', 'Finding', 'Severity', 'CVSS'],
      top.map((f, i) => [i + 1, `[[${nameOf(f)}\\|${f.findingId}]]`, esc(f.title).slice(0, 70), f.severity, cvssCell(f)]));
  }
  b += '\n## Where to go next\n\n- [[01-Findings]] — every finding\n- [[02-Tool-Results]] — what actually ran\n' +
    '- [[08-Remediation-Roadmap]] — ordered plan\n';
  put('00-Executive-Summary.md', b);

  // ---------- 02-Tool-Results ----------
  b = fm(['moraa', 'tools'], { parent: '"[[README]]"' });
  b += '# Tool Results\n\n*Every tool the pipeline attempted, with its real exit code and command. ' +
    'A tool that did not run is reported as such rather than as a clean pass.*\n\n';
  b += table(['Tool', 'Status', 'Version', 'Exit', 'Findings', 'Duration'],
    runResults.map(r => [r.tool, `**${r.status}**`, r.version || '—',
      r.exitCode === undefined ? '—' : r.exitCode,
      (r.findings || []).length, r.durationMs ? `${(r.durationMs / 1000).toFixed(1)}s` : '—']));

  for (const r of runResults) {
    b += `\n## ${r.tool} — ${r.status}\n\n`;
    if (r.command) b += '```bash\n' + r.command + '\n```\n\n';
    if (r.notes) b += `${r.notes}\n\n`;
    if (r.limitations) b += `**Limitations.** ${r.limitations}\n\n`;
    if (r.remediation) b += `**To enable.** \`${r.remediation}\`\n\n`;
    if (r.rawPath) b += `Raw output: \`${path.basename(r.rawPath)}\` in \`data/raw/\`\n\n`;
  }
  put('02-Tool-Results.md', b);

  // ---------- 03 / 04 dependency queues ----------
  const depSec = findings.filter(f => f.category === 'dependency' && (f.advisories || []).length);
  const depMaint = findings.filter(f => f.category === 'dependency' && !(f.advisories || []).length);
  const depToolRan = runResults.some(r => r.kind === 'dependency' && r.status === 'EXECUTED') ||
    runResults.some(r => ['trivy', 'snyk', 'osv-scanner', 'dependency-check'].includes(r.tool) && r.status === 'EXECUTED');

  b = fm(['moraa', 'dependencies', 'security'], { parent: '"[[README]]"' });
  b += '# Dependencies — SECURITY queue\n\n' +
    '*Confirmed advisories against the exact versions in use. Kept separate from the maintenance ' +
    'queue, because an outdated package is not automatically a vulnerability and a current package ' +
    'can still carry one.*\n\n';
  if (depSec.length) {
    b += table(['ID', 'Package', 'Installed', 'Fixed in', 'Advisory', 'CVSS', 'Severity'],
      depSec.map(f => [`[[${nameOf(f)}\\|${f.findingId}]]`,
        '`' + ((f.package && f.package.name) || '—') + '`',
        (f.package && f.package.installed) || '—',
        (f.package && f.package.fixed) ? '`' + f.package.fixed + '`' : '**none**',
        (f.advisories || []).slice(0, 2).join(', '), cvssCell(f), f.severity]));
    const noFix = depSec.filter(f => f.package && !f.package.fixed);
    if (noFix.length) {
      b += `\n> [!warning] ${noFix.length} advisory(ies) have NO published fix\n` +
        '> These cannot be resolved by upgrading. Assess reachability, then mitigate or replace.\n';
    }
  } else if (!depToolRan) {
    b += '**Empty — and that is a capability gap, not a clean result.**\n\n' +
      '> [!danger] No dependency scanner completed\n' +
      '> See [[02-Tool-Results]]. On `packages.config` projects `dotnet list package --vulnerable`\n' +
      '> cannot run at all, so a manifest-reading scanner (Trivy, OSV-Scanner, Dependency-Check)\n' +
      '> is required. Until one runs, the vulnerability status of the dependencies is UNKNOWN.\n';
  } else {
    b += '**Empty, and a scanner did run** — no advisory matched the pinned versions.\n';
  }
  put('03-Dependencies-Security.md', b);

  b = fm(['moraa', 'dependencies', 'maintenance'], { parent: '"[[README]]"' });
  b += '# Dependencies — MAINTENANCE queue\n\n' +
    '*Outdated, end-of-life, deprecated, duplicated or licence-restricted. CVSS is deliberately N/A ' +
    'for everything here: the scoring model does not apply to currency.*\n\n';
  b += depMaint.length
    ? table(['ID', 'Finding', 'Severity', 'Location'],
      depMaint.map(f => [`[[${nameOf(f)}\\|${f.findingId}]]`, esc(f.title).slice(0, 80), f.severity, '`' + f.location.file + '`']))
    : '_No maintenance findings recorded._\n';
  put('04-Dependencies-Maintenance.md', b);

  // ---------- 05-Test-Coverage ----------
  b = fm(['moraa', 'tests'], { parent: '"[[README]]"' });
  b += '# Test Coverage\n\n*Tests required to close each finding, keyed to the shared .NET test-case catalog.*\n\n';
  const withTests = findings.filter(f => (f.tests || []).length);
  b += table(['Finding', 'Severity', 'Catalog test cases', 'Regression test'],
    withTests.map(f => [`[[${nameOf(f)}\\|${f.findingId}]]`, f.severity,
      (f.tests || []).map(t => '`' + t + '`').join(' '), esc(firstSentence(f.regressionTest)) || '—']));
  const noTests = findings.filter(f => !(f.tests || []).length);
  if (noTests.length) {
    b += `\n## Findings with no mapped test case (${noTests.length})\n\n` +
      'These need a catalog id assigned before remediation, or the fix cannot be regression-tested.\n\n' +
      table(['ID', 'Finding'], noTests.map(f => [f.findingId, esc(f.title).slice(0, 90)]));
  }
  put('05-Test-Coverage.md', b);

  // ---------- 06-Configuration ----------
  const cfg = findings.filter(f => f.category === 'configuration');
  b = fm(['moraa', 'configuration'], { parent: '"[[README]]"' });
  b += '# Configuration Findings\n\n' +
    '*Configuration is the blind spot of compiled-code analysers: they analyse IL, so they never read ' +
    '`Web.config` or `appsettings.json` at all.*\n\n';
  b += cfg.length
    ? table(['ID', 'Finding', 'Severity', 'File'],
      cfg.map(f => [`[[${nameOf(f)}\\|${f.findingId}]]`, esc(f.title).slice(0, 80), f.severity, '`' + f.location.file + '`']))
    : '_No configuration findings recorded._\n';
  put('06-Configuration.md', b);

  // ---------- 07-Correlation ----------
  b = fm(['moraa', 'correlation'], { parent: '"[[README]]"' });
  b += '# Correlation and Deduplication\n\n' +
    '*Multiple tools reporting one issue produce ONE finding. Inflating the count by the number of ' +
    'detectors is how a multi-tool report loses credibility.*\n\n';
  b += table(['Metric', 'Value'], [
    ['Raw findings from all tools', stats.inputFindings ?? '—'],
    ['Canonical findings after dedup', stats.canonicalFindings ?? findings.length],
    ['Merged away as duplicates', stats.mergedAway ?? '—'],
    ['Dedup ratio', stats.dedupRatio ?? '—'],
    ['Confirmed by more than one tool', stats.multiToolConfirmed ?? '—']
  ]);
  const multi = findings.filter(f => toolSplit(f).rep.length > 1);
  if (multi.length) {
    b += '\n## Independently confirmed by multiple tools\n\n' +
      '*Agreement raises confidence.*\n\n' +
      table(['ID', 'Finding', 'Reported by'],
        multi.map(f => [`[[${nameOf(f)}\\|${f.findingId}]]`, esc(f.title).slice(0, 70), toolSplit(f).rep.join(', ')]));
  }
  const fns = findings.filter(f => toolSplit(f).fn.length);
  if (fns.length) {
    b += '\n## Tool false negatives\n\n*A tool looked here and reported nothing.*\n\n' +
      table(['ID', 'Finding', 'Missed by'],
        fns.map(f => [`[[${nameOf(f)}\\|${f.findingId}]]`, esc(f.title).slice(0, 70), toolSplit(f).fn.join(', ')]));
  }
  put('07-Correlation-and-Dedup.md', b);

  // ---------- 08-Remediation-Roadmap ----------
  b = fm(['moraa', 'roadmap'], { parent: '"[[README]]"' });
  b += '# Remediation Roadmap\n\n';
  const prio = { P0: 'Immediate security risk', P1: 'High-risk security or reliability', P2: 'Important technical debt', P3: 'Improvement' };
  const assigned = f => f.priority || (f.severity === 'CRITICAL' ? 'P0' : f.severity === 'HIGH' ? 'P1' : f.severity === 'MEDIUM' ? 'P2' : 'P3');
  for (const p of ['P0', 'P1', 'P2', 'P3']) {
    const g = findings.filter(f => assigned(f) === p);
    if (!g.length) continue;
    b += `\n## ${p} — ${prio[p]}\n\n` + table(['ID', 'Finding', 'Severity', 'CVSS', 'Effort', 'Why now'],
      g.map(f => [`[[${nameOf(f)}\\|${f.findingId}]]`, esc(f.title).slice(0, 65), f.severity,
        cvssCell(f), f.effort || '—', esc(firstSentence(f.impact)).slice(0, 110) || '—']));
  }
  put('08-Remediation-Roadmap.md', b);

  // ---------- README ----------
  b = fm(['moraa', 'moc'], {});
  b += `# Code Review — ${project.name || path.basename(sourcePath)}\n\n`;
  b += `> Generated by **dotnet-codereview-framework** on ${new Date().toISOString().slice(0, 10)}.\n` +
    '> Regenerate with `moraa review` — do not edit these files by hand, they are projections of\n' +
    '> `data/report.json`.\n\n';
  b += table(['', ''], [
    ['**Overall risk**', `**${overall}**`],
    ['Findings', `${findings.length} (${SEV_ORDER.filter(s => counts[s]).map(s => `${counts[s]} ${s.toLowerCase()}`).join(', ') || 'none'})`],
    ['Stack', project.stack || 'unknown'],
    ['Solution', project.solution ? '`' + project.solution + '`' : '—'],
    ['Projects', (project.projects || []).length || '—'],
    ['Tools executed', `${runResults.filter(r => r.status === 'EXECUTED').length} of ${runResults.length}`]
  ]);

  b += '\n## Pages\n\n' +
    '| Page | What it answers |\n|---|---|\n' +
    '| [[00-Executive-Summary]] | What is the overall risk and what do I fix first? |\n' +
    '| [[01-Findings]] | Every finding, grouped by severity |\n' +
    '| [[02-Tool-Results]] | What actually ran? What failed? What never looked? |\n' +
    '| [[03-Dependencies-Security]] | Which dependencies have real advisories? |\n' +
    '| [[04-Dependencies-Maintenance]] | Which are merely old, EOL or duplicated? |\n' +
    '| [[05-Test-Coverage]] | What tests must exist to close each finding? |\n' +
    '| [[06-Configuration]] | What is wrong in config, which analysers never read? |\n' +
    '| [[07-Correlation-and-Dedup]] | Which tools agreed, and which missed things? |\n' +
    '| [[08-Remediation-Roadmap]] | In what order should this be fixed? |\n';

  b += '\n## Machine-readable output\n\n' +
    '| File | Use |\n|---|---|\n' +
    '| `data/report.json` | canonical source of truth; every page above is generated from it |\n' +
    '| `data/report.sarif` | upload to GitHub/GitLab/Azure code scanning |\n' +
    '| `data/raw/` | untouched tool output, for reproducing any claim |\n';

  if (notRun.length) {
    b += '\n> [!warning] Read this before treating anything as clean\n' +
      `> ${notRun.length} tool(s) did not run: ${notRun.map(r => r.tool).join(', ')}.\n` +
      '> See [[02-Tool-Results]] for why, and what each would have covered.\n';
  }

  b += '\n> [!danger] Handling\n' +
    '> This folder may quote credentials, internal hostnames and unremediated vulnerabilities.\n' +
    '> Treat it as confidential. Add it to `.gitignore` unless your repository is private.\n';

  put('README.md', b);

  return { root, written };
}

module.exports = { writeVault, findingPage };
