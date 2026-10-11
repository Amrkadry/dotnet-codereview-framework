// dotnet-codereview-framework — tests/excel.test.js
// Author: Amr Kadry (github.com/Amrkadry) · MIT License
'use strict';
/**
 * Excel output tests (src/report/excel.js).
 *
 * The format decision is SpreadsheetML 2003 (zero dependencies; rationale in the module
 * header). The proof demanded of it: the written file PARSES BACK through the strict
 * verifier, cell-for-cell, INCLUDING hostile content (< > & " ' + XML-illegal control
 * characters), and the verifier actually rejects malformed XML (negative controls — a
 * verifier that cannot fail is decoration, not verification).
 */
const { test, describe } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

const E = require('../src/report/excel');

const HOSTILE = 'SELECT * FROM t WHERE a = "<script>&amp; it\'s \x07 \x1F bad>> & raw';
const findings = [
  {
    findingId: 'SEC-INJ-001', severity: 'CRITICAL', title: HOSTILE, category: 'security',
    subcategory: 'C-001', cwe: ['CWE-89'], cvss: { score: 9.1, severity: 'Critical', vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H' },
    location: { file: 'a/b&c.cs', startLine: 9 }, confidence: 'POSSIBLE', status: 'OPEN',
    recommendation: HOSTILE,
    sources: [{ tool: 'native', status: 'REPORTED' }, { tool: 'semgrep', status: 'MISSED' }],
    tests: ['C-001']
  },
  {
    findingId: 'CFG-GEN-001', severity: 'MEDIUM', title: 'plain', category: 'configuration',
    cwe: ['CWE-11'], location: { file: 'Web.config', startLine: 4 }, confidence: 'CONFIRMED',
    status: 'OPEN', recommendation: 'r',
    sources: [{ tool: 'native', status: 'REPORTED' }], tests: ['N-006']
  }
];
const runResults = [
  { tool: 'native', status: 'EXECUTED', catalogCoverage: [
    { caseId: 'C-001', stack: 'both', outcome: 'checked', tool: 'native' },
    { caseId: 'A-001', stack: 'both', outcome: 'manual-review', tool: 'native' },
    { caseId: 'Z-009', stack: 'both', outcome: 'not-applicable', tool: 'native' }
  ] },
  { tool: 'semgrep', status: 'EXECUTED' }
];
const stats = { inputFindings: 5, canonicalFindings: 2, mergedAway: 3, multiToolConfirmed: 0 };

describe('buildWorkbook + verify: the parse-back proof', () => {
  test('workbook parses back to the same three sheets and cells', () => {
    const xml = E.buildWorkbook({ findings, runResults, stats });
    const v = E.verify(xml);
    assert.equal(v.ok, true, 'parse-back errors: ' + JSON.stringify(v.errors));
    assert.deepEqual(v.sheets.map(s => s.name), ['Summary', 'Findings', 'Coverage']);

    const summary = v.sheets[0];
    assert.ok(summary.rows.some(r => r[0] === 'Total findings' && r[1] === String(findings.length)));

    const f = v.sheets[1];
    assert.equal(f.rows.length, findings.length + 1, 'header + one row per finding');
    const row1 = f.rows[1];
    const expectedTitle = E.stripIllegal(HOSTILE);   // control chars are stripped BY DESIGN
    assert.equal(row1[0], 'SEC-INJ-001');
    assert.equal(row1[1], 'CRITICAL');
    assert.equal(row1[2], expectedTitle, 'hostile title did not round-trip');
    assert.equal(row1[4], '9.1');
    assert.equal(row1[5], 'a/b&c.cs');
    assert.equal(row1[7], 'native');
    assert.equal(row1[8], 'semgrep');

    const cov = v.sheets[2];
    const byCase = Object.fromEntries(cov.rows.slice(1).map(r => [r[0], r[2]]));
    assert.equal(byCase['C-001'], 'covered');
    assert.equal(byCase['A-001'], 'not covered');   // manual-review is undecided, NOT covered
    assert.equal(byCase['Z-009'], 'not covered');   // not applicable is not covered either
  });

  test('XML-illegal control characters are stripped, legal text intact', () => {
    const xml = E.buildWorkbook({ findings, runResults, stats });
    const v = E.verify(xml);
    const title = v.sheets[1].rows[1][2];
    assert.ok(!/[\u0000-\u0008\u000B\u000C\u000E-\u001F]/.test(title), 'control character survived into XML');
    assert.ok(title.includes('<script>'), 'escaped markup must round-trip as text');
    assert.ok(title.includes('& raw'), 'escaped ampersand must round-trip');
  });

  test('writeExcel writes a file that re-reads and verifies', () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'moraa-excel-'));
    try {
      const p = E.writeExcel(dir, { findings, runResults, stats });
      assert.equal(path.basename(p), 'report.excel.xml');
      const back = E.verify(fs.readFileSync(p, 'utf8'));
      assert.equal(back.ok, true);
      assert.equal(back.sheets.length, 3);
      // and the mso-application PI is present so Excel claims the file on open
      assert.ok(/\uFEFF?<?xml/.test(fs.readFileSync(p, 'utf8').slice(0, 60)));
      assert.ok(/mso-application progid="Excel\.Sheet"/.test(fs.readFileSync(p, 'utf8')));
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });
});

describe('verify() negative controls: it must be able to fail', () => {
  test('mismatched close tag rejected', () => {
    const v = E.verify('<Workbook><Worksheet ss:Name="x"><Table><Row><Cell>' +
      '<Data ss:Type="String">un</Workbook>');
    assert.equal(v.ok, false);
    assert.ok(v.errors.length >= 1);
  });

  test('unclosed element rejected', () => {
    const v = E.verify('<Workbook><Worksheet ss:Name="x"><Table><Row><Cell>' +
      '<Data ss:Type="String">o');
    assert.equal(v.ok, false);
  });

  test('bare ampersand in text rejected', () => {
    const v = E.verify('<Workbook><Worksheet ss:Name="x"><Table><Row><Cell>' +
      '<Data ss:Type="String">a & b</Data></Cell></Row></Table></Worksheet>');
    assert.equal(v.ok, false);
    assert.ok(v.errors.some(e => /entity/.test(e)));
  });

  test('valid workbook with entity escapes accepted', () => {
    const v = E.verify('<Workbook><Worksheet ss:Name="x"><Table><Row><Cell>' +
      '<Data ss:Type="String">a &amp; b &lt;c&gt;</Data></Cell></Row></Table></Worksheet></Workbook>');
    assert.equal(v.ok, true);
    assert.equal(v.sheets[0].rows[0][0], 'a & b <c>');
  });
});
