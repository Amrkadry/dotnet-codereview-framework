// dotnet-codereview-framework — tests/correlate.merge.test.js
// Author: Amr Kadry (github.com/Amrkadry) · MIT License
'use strict';
/**
 * Unit tests for src/correlate/merge.js.
 *
 * Correlation is the mechanism that keeps a multi-tool report honest: one issue reported by N
 * tools must be ONE finding, tools that ran and missed must be visible as MISSED, and the merge
 * must keep the strongest evidence while losing no attribution. Each test below pins one of
 * those guarantees, using hand-built findings so a regression here cannot be blamed on adapters.
 */
const { test, describe } = require('node:test');
const assert = require('node:assert/strict');
const { correlate, RULE_EQUIVALENCE, conceptOf, keysOf, mergeInto } = require('../src/correlate/merge');
const { finding } = require('./helpers/finding');

// Rule id pairs drawn from the real equivalence table, so tests track the shipped config.
const CERT_RULES = RULE_EQUIVALENCE.find(r => r.concept === 'weak-cert-validation').rules;
const SONAR_CERT = CERT_RULES[0];            // S4830
const SEMGREP_CERT = CERT_RULES[2];          // moraa-dotnet-disable-cert-validation

const sonarCert = (file, line) => finding({
  title: 'Enable server certificate validation',
  subcategory: SONAR_CERT,
  location: { file, startLine: line },
  sources: [{ tool: 'sonarqube', sourceFindingId: SONAR_CERT, status: 'REPORTED' }]
});
const semgrepCert = (file, line) => finding({
  title: 'TLS certificate validation disabled process-wide',
  subcategory: SEMGREP_CERT,
  location: { file, startLine: line },
  sources: [{ tool: 'semgrep', sourceFindingId: SEMGREP_CERT, status: 'REPORTED' }]
});

describe('correlate: dedup', () => {
  test('a. same finding from two tools dedupes to one', () => {
    const res = correlate(
      [sonarCert('SampleApp/Services/Http.cs', 42), semgrepCert('SampleApp/Services/Http.cs', 42)],
      { toolsThatRan: ['sonarqube', 'semgrep'] });

    assert.equal(res.findings.length, 1);
    assert.equal(res.stats.canonicalFindings, 1);
    assert.equal(res.stats.mergedAway, 1);
    assert.equal(res.stats.inputFindings, 2);

    const f = res.findings[0];
    const tools = new Set(f.sources.filter(s => s.status === 'REPORTED').map(s => s.tool));
    assert.ok(tools.has('sonarqube'), 'sonarqube must be REPORTED');
    assert.ok(tools.has('semgrep'), 'semgrep must be REPORTED');
  });

  test('b. a tool that ran but did not report is attributed as MISSED, not silent', () => {
    const res = correlate(
      [sonarCert('SampleApp/Services/Http.cs', 42), semgrepCert('SampleApp/Services/Http.cs', 42)],
      { toolsThatRan: ['sonarqube', 'semgrep', 'trivy'] });

    const f = res.findings[0];
    const trivySources = f.sources.filter(s => s.tool === 'trivy');
    assert.equal(trivySources.length, 1, 'exactly one trivy attribution');
    assert.equal(trivySources[0].status, 'MISSED');
    assert.ok(!trivySources.some(s => s.status === 'REPORTED'),
      'trivy must NOT appear as REPORTED on a finding it never made');
    assert.equal(res.stats.multiToolConfirmed, 1,
      'two tools agreeing must count the finding as multiToolConfirmed');
  });

  test('c. severity/confidence reconciliation keeps the STRONGEST, in either merge order', () => {
    const low = () => finding({ severity: 'MEDIUM', subcategory: 'X1',
      sources: [{ tool: 'tool-a', sourceFindingId: 'X1', status: 'REPORTED' }] });
    const high = () => finding({ severity: 'HIGH', subcategory: 'Y1',
      sources: [{ tool: 'tool-b', sourceFindingId: 'Y1', status: 'REPORTED' }] });
    // distinct concept-free rule ids + distinct files, so ONLY mergeInto is under test
    const a = mergeInto(low(), { ...high(), location: { file: 'other.cs' } });
    const b = mergeInto(high(), { ...low(), location: { file: 'other.cs' } });
    assert.equal(a.severity, 'HIGH', 'MEDIUM merged into HIGH stays HIGH');
    assert.equal(b.severity, 'HIGH', 'HIGH merged into MEDIUM becomes HIGH — order-independent');

    const confirmed = () => finding({ confidence: 'CONFIRMED' });
    const possible = () => finding({ confidence: 'POSSIBLE' });
    const c = mergeInto(possible(), confirmed());
    const d = mergeInto(confirmed(), possible());
    assert.equal(c.confidence, 'CONFIRMED');
    assert.equal(d.confidence, 'CONFIRMED', 'order-independent for confidence too');
  });

  test('d. near-miss findings in one file DO merge despite the line window', () => {
    // BUG: keysOf() emits a file-level `conceptfile:{concept}:{file}` key in ADDITION to the
    // line-bucketed `concept:{concept}:{file}:{floor(line/4)}` key. Because both findings share
    // a concept and a file, the file-level key matches regardless of line, so findings 4000
    // lines apart collapse into one canonical finding. The documented line window (LINE_WINDOW
    // = 4) is therefore defeated for any rule pair in RULE_EQUIVALENCE; the bucketed key alone
    // would have kept them apart (the rule-key test below proves that mechanism still works).
    const far1 = sonarCert('SampleApp/Services/Http.cs', 100);
    const far2 = semgrepCert('SampleApp/Services/Http.cs', 5000);
    assert.notEqual(Math.floor(100 / 4), Math.floor(5000 / 4), 'precondition: different line buckets');

    const res = correlate([far1, far2]);
    assert.equal(res.findings.length, 1, 'CURRENT ACTUAL BEHAVIOUR: they merge via the file-level key');
    assert.equal(res.stats.mergedAway, 1);

    // Contrast: with NO equivalence-mapped concept, the line-bucketed rule key is the only
    // key, and the window behaves as documented — far-apart findings stay separate.
    const noConcept = (line) => finding({
      subcategory: 'ENTIRELY-UNMAPPED-RULE',
      location: { file: 'SampleApp/Services/Http.cs', startLine: line },
      sources: [{ tool: 'tool-a', sourceFindingId: 'ENTIRELY-UNMAPPED-RULE', status: 'REPORTED' }]
    });
    const separated = correlate([noConcept(100), noConcept(5000)]);
    assert.equal(separated.findings.length, 2, 'no concept -> rule+line key keeps them apart');
  });

  test('d2. different files with the same rule must never merge', () => {
    const res = correlate([
      sonarCert('SampleApp/Services/Http.cs', 42),
      sonarCert('SampleApp/Services/Other.cs', 42)
    ]);
    assert.equal(res.findings.length, 2, 'file identity must be respected');
    assert.deepEqual(res.findings.map(f => f.location.file).sort(),
      ['SampleApp/Services/Http.cs', 'SampleApp/Services/Other.cs']);
  });

  test('e. advisory identity: same CVE + same package merges; same CVE + other package does not', () => {
    const vuln = (pkg, file) => finding({
      category: 'dependency',
      advisories: ['CVE-2024-0057'],
      package: { name: pkg, installed: '1.0.0', fixed: null },
      location: { file, startLine: undefined },
      sources: [{ tool: 'trivy', sourceFindingId: 'CVE-2024-0057', status: 'REPORTED' }]
    });
    // Distinct files and lines, so the ONLY key the two share is adv:cve:package.
    const sameAdvisory = correlate([
      vuln('Microsoft.Data.SqlClient', 'ExampleApp/packages.config'),
      { ...vuln('Microsoft.Data.SqlClient', 'SampleApp/packages.config') }
    ]);
    assert.equal(sameAdvisory.findings.length, 1, 'same CVE + same package is the same defect');
    assert.equal(sameAdvisory.stats.mergedAway, 1);
    assert.deepEqual(sameAdvisory.findings[0].advisories, ['CVE-2024-0057'], 'advisories deduped');

    const differentPackage = correlate([
      vuln('Microsoft.Data.SqlClient', 'ExampleApp/packages.config'),
      vuln('Legacy.Parser', 'ExampleApp/other.config')
    ]);
    assert.equal(differentPackage.findings.length, 2, 'same CVE on a DIFFERENT package is a separate defect');
  });

  test('f. canonical ids are unique, schema-shaped, and follow the category->prefix mapping', () => {
    const res = correlate([
      // dependency -> DEP-VULN
      finding({
        category: 'dependency', advisories: ['CVE-2024-0057'],
        package: { name: 'Microsoft.Data.SqlClient', installed: '5.1.0', fixed: null },
        location: { file: 'ExampleApp/packages.config' },
        sources: [{ tool: 'trivy', sourceFindingId: 'CVE-2024-0057', status: 'REPORTED' }]
      }),
      // hardcoded-credentials concept -> SEC-SECRET (category security, rule from the map)
      finding({
        subcategory: 'S2068', cwe: ['CWE-798'],
        location: { file: 'SampleApp/Web.config', startLine: 12 },
        sources: [{ tool: 'sonarqube', sourceFindingId: 'S2068', status: 'REPORTED' }]
      }),
      // unmapped configuration finding -> CFG-GEN
      finding({
        category: 'configuration', subcategory: 'custom-config-rule',
        location: { file: 'appsettings.json' },
        sources: [{ tool: 'tool-a', sourceFindingId: 'custom-config-rule', status: 'REPORTED' }]
      })
    ]);

    const ids = res.findings.map(f => f.findingId);
    assert.equal(ids.length, new Set(ids).size, 'ids must be unique');
    const pattern = /^(SEC|CFG|DEP|CODE|ARCH|PERF|REL|TEST|OBS|LOGIC|PROC)-[A-Z0-9]+-[0-9]{3}$/;
    ids.forEach(id => assert.match(id, pattern, `id ${id} must match the schema pattern`));

    const byPrefix = Object.fromEntries(res.findings.map(f => [f.findingId.split('-').slice(0, 2).join('-'), f]));
    assert.match(byPrefix['DEP-VULN'].findingId, /^DEP-VULN-\d{3}$/, 'dependency -> DEP-VULN');
    assert.equal(byPrefix['DEP-VULN'].category, 'dependency');
    assert.match(byPrefix['SEC-SECRET'].findingId, /^SEC-SECRET-\d{3}$/, 'hardcoded-credentials -> SEC-SECRET');
    assert.equal(conceptOf(byPrefix['SEC-SECRET']), 'hardcoded-credentials');
    assert.match(byPrefix['CFG-GEN'].findingId, /^CFG-GEN-\d{3}$/);
  });

  test('g. output is sorted CRITICAL before HIGH before LOW regardless of input order', () => {
    const mk = (sev, rule, file) => finding({
      severity: sev, subcategory: rule, location: { file, startLine: 1 },
      sources: [{ tool: 'tool-a', sourceFindingId: rule, status: 'REPORTED' }]
    });
    const res = correlate([
      mk('LOW', 'U-LOW', 'a.cs'),
      mk('CRITICAL', 'U-CRIT', 'b.cs'),
      mk('HIGH', 'U-HIGH', 'c.cs')
    ]);
    assert.deepEqual(res.findings.map(f => f.severity), ['CRITICAL', 'HIGH', 'LOW']);
  });

  test('h. sources are never collapsed: every distinct (tool, sourceFindingId) pair survives', () => {
    const inputs = [
      sonarCert('SampleApp/Services/Http.cs', 42),          // merges with semgrepCert
      semgrepCert('SampleApp/Services/Http.cs', 42),
      finding({ location: { file: 'x.cs' }, sources: [{ tool: 'tool-c', sourceFindingId: 'C-1', status: 'REPORTED' }] }),
      finding({ location: { file: 'y.cs' }, sources: [{ tool: 'tool-d', sourceFindingId: 'D-1', status: 'REPORTED' }] })
    ];
    const inPairs = new Set(inputs.flatMap(f => f.sources.map(s => `${s.tool}|${s.sourceFindingId}`)));

    // No toolsThatRan here: MISSED attributions would pollute the REPORTED accounting.
    const res = correlate(inputs);
    const reported = res.findings.flatMap(f => f.sources.filter(s => s.status === 'REPORTED'));
    const outPairs = new Set(reported.map(s => `${s.tool}|${s.sourceFindingId}`));

    assert.equal(reported.length, inPairs.size,
      `${inPairs.size} distinct reported pairs in -> ${reported.length} out`);
    assert.equal(outPairs.size, inPairs.size, 'no pair may be duplicated or dropped');
    for (const p of inPairs) assert.ok(outPairs.has(p), `pair ${p} must survive the merge`);
  });

  test('stats.dedupRatio reflects merged/input', () => {
    const res = correlate(
      [sonarCert('a.cs', 42), semgrepCert('a.cs', 42), finding({ location: { file: 'z.cs' } })]);
    assert.equal(res.stats.inputFindings, 3);
    assert.equal(res.stats.canonicalFindings, 2);
    assert.equal(res.stats.mergedAway, 1);
    assert.equal(res.stats.dedupRatio, +(1 / 3).toFixed(3));
  });
});

describe('mergeInto unit behaviour', () => {
  test('merging b into a records provenance in correlation.mergedFrom', () => {
    const a = sonarCert('a.cs', 42);
    const b = semgrepCert('a.cs', 42);
    const merged = mergeInto(a, b);
    assert.ok(merged.correlation.mergedFrom.some(x => x.startsWith('semgrep:')),
      'mergedFrom must name the merged-away source');
    assert.equal(merged.sources.length, 2, 'both sources kept');
  });

  test('cwe and owasp accumulate without duplicates', () => {
    const a = finding({ cwe: ['CWE-295'], owasp: ['A02:2021'] });
    const b = finding({ cwe: ['CWE-295', 'CWE-798'], owasp: ['A02:2021', 'A05:2021'] });
    const m = mergeInto(a, b);
    assert.deepEqual(m.cwe, ['CWE-295', 'CWE-798']);
    assert.deepEqual(m.owasp, ['A02:2021', 'A05:2021']);
  });

  test('a FALSE_POSITIVE state from either side is kept visible', () => {
    const open = finding({ status: 'OPEN' });
    const dismissed = finding({ status: 'FALSE_POSITIVE' });
    assert.equal(mergeInto(open, dismissed).status, 'FALSE_POSITIVE');
    assert.equal(mergeInto(dismissed, open).status, 'FALSE_POSITIVE');
  });

  test('toolOutput accumulates rather than being overwritten', () => {
    const a = finding({ evidence: { snippet: '', language: 'text', toolOutput: 'tool-a says X' } });
    const b = finding({ evidence: { snippet: '', language: 'text', toolOutput: 'tool-b says Y' } });
    const m = mergeInto(a, b);
    assert.ok(m.evidence.toolOutput.includes('tool-a says X'));
    assert.ok(m.evidence.toolOutput.includes('tool-b says Y'));
  });

  test('keysOf: equivalence-mapped rules map to a shared concept, unmapped rules do not', () => {
    const mapped = keysOf(sonarCert('a.cs', 42));
    assert.ok(mapped.some(k => k.startsWith('concept:weak-cert-validation:')),
      'S4830 must carry a weak-cert-validation concept key: ' + JSON.stringify(mapped));
    const unmapped = keysOf(finding({ subcategory: 'UNMAPPED-RULE' }));
    assert.ok(!unmapped.some(k => k.startsWith('concept:')), JSON.stringify(unmapped));
  });
});
