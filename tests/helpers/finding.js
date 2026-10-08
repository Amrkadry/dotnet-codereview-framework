// dotnet-codereview-framework — tests/helpers/finding.js
// Author: Amr Kadry (github.com/Amrkadry) · MIT License
'use strict';
/**
 * Factory for hand-built canonical findings used in correlation tests.
 *
 * Correlation tests need minimal but VALID-shaped findings; the factory defaults keep each test
 * focused on the one dimension it varies (concept, location, advisories, severity...). Defaults
 * are deliberately free of correlation-meaningful ids (no CWE, no mapped rule ids) so a test
 * only merges when the dimension under test says it must.
 */

/**
 * Build one canonical finding. `overrides` is merged shallowly, so nested objects
 * (location, evidence, sources) must be supplied whole.
 */
function finding(overrides = {}) {
  return Object.assign({
    title: 'Synthetic test finding',
    category: 'security',
    severity: 'MEDIUM',
    confidence: 'LIKELY',
    cvss: null,
    location: { file: 'src/Synthetic.cs', startLine: 10 },
    evidence: { snippet: 'var x = 1;', language: 'csharp', toolOutput: 'test factory' },
    problem: 'A synthetic problem for tests.',
    impact: '',
    recommendation: '',
    sources: [{ tool: 'tool-a', sourceFindingId: 'RULE-A', status: 'REPORTED' }],
    status: 'OPEN'
  }, overrides);
}

module.exports = { finding };
