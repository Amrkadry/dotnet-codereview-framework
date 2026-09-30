'use strict';
/**
 * Native checks over project manifests: *.csproj / *.vbproj / *.fsproj, packages.config,
 * global.json. These are project FACTS, so findings here are CONFIRMED.
 *
 * End-of-life decisions are computed from a dated table, not hardcoded booleans: what counts
 * as EOL changes over time, and a tool that freezes "supported" into its source rots silently.
 * The table below carries Microsoft's published end-of-support dates; the checks compare
 * against the wall clock at run time.
 */

const { finding } = require('../finding');
const { lineOf, redactSecrets } = require('./web-config');

/** Microsoft .NET end-of-support dates (target framework moniker -> EOL date, inclusive). */
const EOL_TARGETS = {
  // .NET Framework (windows-only, but supported status still varies)
  'v2.0': '2011-07-12', 'v3.0': '2011-07-12', 'v3.5': '2029-01-09', // 3.5 SP1: long-term, keep out of EOL until MS says
  'v4.0': '2016-01-12', 'v4.5': '2016-01-12', 'v4.5.1': '2016-01-12', 'v4.5.2': '2022-04-26',
  'v4.6': '2022-04-26', 'v4.6.1': '2022-04-26',
  // .NET Core / .NET
  'netcoreapp1.0': '2019-06-27', 'netcoreapp1.1': '2019-06-27',
  'netcoreapp2.0': '2018-10-01', 'netcoreapp2.1': '2021-08-21', 'netcoreapp2.2': '2019-12-23',
  'netcoreapp3.0': '2020-03-03', 'netcoreapp3.1': '2022-12-13',
  'net5.0': '2022-05-10', 'net6.0': '2024-11-12', 'net7.0': '2024-05-14', 'net8.0': '2026-11-10',
  'net9.0': '2026-05-12'
};

const isEol = tfm => {
  const eol = EOL_TARGETS[String(tfm).toLowerCase()];
  if (!eol) return false;
  return Date.now() >= Date.parse(eol + 'T23:59:59Z');
};

/** Each check: { id, caseIds, run(ctx) }. ctx: {relPath, text, lines, emit, stack}. */
const CHECKS = [
  {
    id: 'manifest-eol-tfm',
    caseIds: ['O-005'],
    run(ctx) {
      const found = [];
      const re = /(?:<TargetFramework(?:Version|s)?\s*>\s*([^<\s]+)\s*<|TargetFramework\s*=\s*"([^"]+)")/gi;
      let m;
      while ((m = re.exec(ctx.text)) !== null) {
        const tfm = m[1] || m[2];
        if (tfm && isEol(tfm) && !found.includes(tfm)) found.push(tfm);
      }
      if (!found.length) return;
      const line = lineOf(ctx.lines, ctx.text.search(/<TargetFramework|TargetFramework\s*=/i));
      ctx.emit(finding({
        check: this.id, caseIds: this.caseIds, confidence: 'CONFIRMED', severity: 'HIGH',
        category: 'dependency', cwe: ['CWE-1104'], language: 'xml',
        title: `Runtime target past end of support: ${found.join(', ')}`,
        file: ctx.relPath, startLine: line,
        snippet: redactSecrets(ctx.lines[line - 1]),
        problem: 'The project targets ' + found.join(', ') + ', which reached end of support on ' +
          found.map(t => EOL_TARGETS[String(t).toLowerCase()]).join(' / ') +
          '. Security patches are no longer produced for it.',
        impact: 'Every vulnerability disclosed after the EOL date is permanent: no fix exists and ' +
          'none is coming. Compliance frameworks (PCI DSS 4.0, ISO 27001 controls) fail this state.',
        recommendation: 'Upgrade to a supported target (.NET Framework 4.8 for the legacy stack, ' +
          'the current .NET LTS otherwise) and re-run the full review against the upgraded build.'
      }));
    }
  },
  {
    id: 'manifest-floating-version',
    caseIds: ['O-003'],
    run(ctx) {
      const hits = [];
      const re1 = /<package\s+id="([^"]+)"\s+version="([^"]*[\s*][^"]*|[^"]*"[^"]*)"/gi; // packages.config wildcard
      let m;
      while ((m = /<package\s+[^>]*version\s*=\s*"[^"]*[\s*][^"]*"/gi.exec(ctx.text)) !== null) hits.push(m[0]);
      const re2 = /<PackageReference\s+[^>]*Version\s*=\s*"[^"]*[\s*][^"]*"/gi;
      while ((m = re2.exec(ctx.text)) !== null) hits.push(m[0]);
      // Floating transitive pins in packages.config: version="" (empty) is resolved by restore.
      while ((m = /<package\s+[^>]*version\s*=\s*""\s*\/?>/gi.exec(ctx.text)) !== null) hits.push(m[0]);
      if (!hits.length) return;
      const line = lineOf(ctx.lines, ctx.text.indexOf(hits[0]));
      ctx.emit(finding({
        check: this.id, caseIds: this.caseIds, confidence: 'CONFIRMED', severity: 'MEDIUM',
        category: 'dependency', cwe: ['CWE-1357'], language: 'xml',
        title: `Floating package version${hits.length > 1 ? 's' : ''} (${hits.length} reference(s))`,
        file: ctx.relPath, startLine: line,
        snippet: redactSecrets(hits.slice(0, 3).join('\n')),
        problem: 'Package references use wildcard or empty versions, so the build resolves ' +
          'whatever satisfies the range at restore time — today\u2019s build and next month\u2019s ' +
          'are different binaries.',
        impact: 'An attacker who publishes a malicious higher version inside the range is ' +
          'automatically pulled in (typo-squatting / dependency confusion amplifier); incident ' +
          'reproduction becomes guesswork because the version is not recorded.',
        recommendation: 'Pin exact versions and commit packages.lock.json with ' +
          'RestorePackagesWithLockFile, so restore is reproducible and dependency substitution is visible in review.'
      }));
    }
  },
  {
    id: 'manifest-unsafe-blocks',
    caseIds: [],
    run(ctx) {
      const m = ctx.text.match(/<AllowUnsafeBlocks\s*>\s*true\s*</i);
      if (!m) return;
      const line = lineOf(ctx.lines, m.index);
      ctx.emit(finding({
        check: this.id, caseIds: this.caseIds, confidence: 'CONFIRMED', severity: 'LOW',
        category: 'code-quality', cwe: [], language: 'xml',
        title: 'AllowUnsafeBlocks enabled',
        file: ctx.relPath, startLine: line,
        snippet: ctx.lines[line - 1],
        problem: 'The project compiles unsafe (pointer) code.',
        impact: 'Memory-safety guarantees stop at every unsafe block: buffer overruns and ' +
          'type-confusion become possible exactly where reviewers are least used to looking. ' +
          'This is a survey flag, not a defect: unsafe code can be correct.',
        recommendation: 'Inventory the unsafe blocks (grep "unsafe") and confirm each is ' +
          'bounded, checked and covered by tests; remove any that are vestigial.',
        possibleNote: 'Deliberately unmapped: no catalog case covers AllowUnsafeBlocks; recorded for completeness.'
      }));
    }
  },
  {
    id: 'manifest-no-lockfile-note',
    caseIds: [],
    run(ctx) { /* covered project-wide in index.js (O-003) — needs global knowledge, not per-file */ }
  }
];

module.exports = { CHECKS, EOL_TARGETS, isEol };
