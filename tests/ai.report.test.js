// dotnet-codereview-framework — tests/ai.report.test.js
// Author: Amr Kadry (github.com/Amrkadry) · MIT License
'use strict';
/**
 * AI mode "report" tests (src/adapters/ai-review.js runReport).
 *
 * Mode 1 post-processes an ALREADY-PRODUCED report and enriches each finding's own Markdown
 * page IN PLACE. The contract under test:
 *   - OFF by default: with the mode disabled, nothing runs, nothing is written;
 *   - IDEMPOTENT: the AI-authored block is wrapped in stable markers and REPLACED on re-run —
 *     proven here with a STUBBED model by running twice and diffing: the second run must be
 *     byte-identical and must not touch the file;
 *   - the canonical data/report.json is NEVER modified by this mode;
 *   - disagreement from the model is rendered as recorded-unresolved, never as a verdict.
 * No network is used anywhere in this file: ctx.aiCall injects the model.
 */
const { test, describe, before, after } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

const ai = require('../src/adapters/ai-review');

const root = path.resolve(__dirname, '..');

let workdir;      // the "reviewed project"
let reportDir;    // <workdir>/.moraa-review

const FINDING = {
  findingId: 'SEC-INJ-001', title: 'SQL command built with string concatenation',
  severity: 'CRITICAL', confidence: 'POSSIBLE', category: 'security', subcategory: 'C-001',
  cwe: ['CWE-89'],
  location: { file: 'Controllers/Bad.cs', startLine: 8, endLine: 8 },
  evidence: { snippet: 'var cmd = new SqlCommand("SELECT * FROM U WHERE N = \'" + q + "\'", null);', language: 'csharp' },
  problem: 'concat', impact: 'sqli', recommendation: 'parameterise',
  sources: [{ tool: 'native', status: 'REPORTED' }],
  status: 'OPEN', tests: ['C-001']
};

// Config that satisfies the config layer for tests: a local OpenAI-compatible endpoint
// (key-optional). It is NEVER dialled — every call goes through the injected aiCall stub.
const STUBCFG = { ai: { provider: 'local', baseUrl: 'http://127.0.0.1:9' } };

const NARRATIVE = {
  explanation: 'The query text is concatenated from user input.',
  risk: 'An attacker can append SQL through the q parameter.',
  fix: 'Use cmd.Parameters.AddWithValue("@q", q).',
  disagreement: null
};

before(() => {
  workdir = fs.mkdtempSync(path.join(os.tmpdir(), 'moraa-ai-report-'));
  fs.mkdirSync(path.join(workdir, 'Controllers'), { recursive: true });
  fs.writeFileSync(path.join(workdir, 'Controllers', 'Bad.cs'),
    'using System.Data.SqlClient;\npublic class Bad {\n  var cmd = new SqlCommand("SELECT * FROM U WHERE N = \'" + q + "\'", null);\n}\n');
  reportDir = path.join(workdir, '.moraa-review');
  fs.mkdirSync(path.join(reportDir, 'Findings'), { recursive: true });
  fs.mkdirSync(path.join(reportDir, 'data'), { recursive: true });
  fs.writeFileSync(path.join(reportDir, 'data', 'report.json'),
    JSON.stringify({ summary: {}, findings: [FINDING] }));
  fs.writeFileSync(path.join(reportDir, 'Findings', 'SEC-INJ-001 sql-concat.md'),
    `# SEC-INJ-001 — SQL command built with string concatenation\n\n` +
    `| Field | Value |\n|---|---|\n| Severity | CRITICAL |\n\n` +
    `## Problem\n\nconcat\n`);
});

after(() => { fs.rmSync(workdir, { recursive: true, force: true }); });

const page = () => path.join(reportDir, 'Findings', 'SEC-INJ-001 sql-concat.md');

describe('mode "report"', () => {
  test('is skipped when disabled (the default) — nothing runs, nothing is written', async () => {
    const beforeBytes = fs.readFileSync(page(), 'utf8');
    const r = await ai.runReport({ reportDir, sourcePath: workdir, env: {}, flags: {}, log: () => {} });
    assert.equal(r.skipped, true);
    assert.equal(r.ok, false);
    assert.equal(fs.readFileSync(page(), 'utf8'), beforeBytes, 'a disabled mode must not touch files');
  });

  test('enriches the finding page in place with a marked, replaceable block', async () => {
    let calls = 0;
    const r = await ai.runReport({
      reportDir, sourcePath: workdir, config: STUBCFG, env: {}, flags: { aiReport: true },
      log: () => {},
      aiCall: async () => { calls++; return JSON.stringify(NARRATIVE); }
    });
    assert.equal(r.ok, true, 'runReport failed: ' + JSON.stringify(r));
    assert.deepEqual(r.enriched, ['SEC-INJ-001']);
    assert.equal(calls, 1, 'model called once per finding');

    const md = fs.readFileSync(page(), 'utf8');
    assert.ok(md.includes('## Problem'), 'original content must survive');
    assert.ok(md.includes(ai.MARK + ' START id=SEC-INJ-001'), 'marker block missing');
    assert.ok(md.includes('Use cmd.Parameters.AddWithValue'), 'narrative content missing');
    assert.ok(/No tool is authoritative, including the AI/.test(md), 'governing rule must be visible');
    // canonical JSON untouched by this mode
    const canonical = JSON.parse(fs.readFileSync(path.join(reportDir, 'data', 'report.json'), 'utf8'));
    assert.equal(canonical.findings[0].status, 'OPEN', 'canonical record must not be edited by mode "report"');
  });

  test('IDEMPOTENT: a second identical run changes nothing (byte-for-byte)', async () => {
    const before = fs.readFileSync(page(), 'utf8');
    const r = await ai.runReport({
      reportDir, sourcePath: workdir, config: STUBCFG, env: {}, flags: { aiReport: true },
      log: () => {},
      aiCall: async () => JSON.stringify(NARRATIVE)
    });
    assert.equal(r.ok, true);
    assert.deepEqual(r.unchanged, ['SEC-INJ-001'], 'second run should classify the page as unchanged');
    assert.deepEqual(r.enriched, []);
    assert.equal(fs.readFileSync(page(), 'utf8'), before, 'second run modified the file');
  });

  test('a CHANGED model reply REPLACES the block (never appends, never nests)', async () => {
    const before = fs.readFileSync(page(), 'utf8');
    const blocksBefore = (before.match(new RegExp(ai.MARK + ' START', 'g')) || []).length;
    assert.equal(blocksBefore, 1, 'sanity: exactly one block before');
    const r = await ai.runReport({
      reportDir, sourcePath: workdir, config: STUBCFG, env: {}, flags: { aiReport: true },
      log: () => {},
      aiCall: async () => JSON.stringify({ ...NARRATIVE, fix: 'Use a parameterised command — updated guidance.' })
    });
    assert.equal(r.ok, true);
    assert.deepEqual(r.enriched, ['SEC-INJ-001']);
    const after = fs.readFileSync(page(), 'utf8');
    const blocksAfter = (after.match(new RegExp(ai.MARK + ' START', 'g')) || []).length;
    assert.equal(blocksAfter, 1, 're-run must REPLACE the block, not add a second');
    assert.ok(after.includes('updated guidance'));
    assert.ok(after.includes('## Problem'), 'non-AI content preserved on replace');
  });

  test('model disagreement is rendered recorded-unresolved, never applied', async () => {
    await ai.runReport({
      reportDir, sourcePath: workdir, config: STUBCFG, env: {}, flags: { aiReport: true },
      log: () => {},
      aiCall: async () => JSON.stringify({ ...NARRATIVE, disagreement: 'This endpoint is internal-only; severity looks overstated.' })
    });
    const md = fs.readFileSync(page(), 'utf8');
    assert.ok(/Disagreement.*UNRESOLVED/i.test(md), 'disagreement section missing');
    assert.ok(md.includes('internal-only'), 'disagreement text missing');
    // and the finding's own record was still not edited:
    const canonical = JSON.parse(fs.readFileSync(path.join(reportDir, 'data', 'report.json'), 'utf8'));
    assert.equal(canonical.findings[0].severity, 'CRITICAL', 'AI disagreement must not change the record');
  });

  test('fails soft when there is no canonical report to post-process', async () => {
    const r = await ai.runReport({
      reportDir: path.join(workdir, 'no-such-dir'), sourcePath: workdir,
      config: STUBCFG, env: {}, flags: { aiReport: true }, log: () => {}, aiCall: async () => '{}'
    });
    assert.equal(r.ok, false);
    assert.ok(!r.skipped, 'a missing report is an error, not a skip');
    assert.ok(/report\.json|review first/i.test(r.error), 'error should name report.json: ' + r.error);
  });

  test('crossCheck: AI findings never override tool findings — disagreement is recorded', () => {
    const aiFindings = [{
      title: 'disputed', category: 'security', severity: 'LOW', confidence: 'POSSIBLE',
      location: { file: 'Controllers/Bad.cs', startLine: 8 },
      evidence: { snippet: 'x' }, sources: [{ tool: 'ai-review', status: 'REPORTED' }],
      cwe: ['CWE-89']
    }];
    const prior = [JSON.parse(JSON.stringify(FINDING))];   // tool says CRITICAL at same spot
    const { findings, disagreements, agreements } = ai.crossCheck(aiFindings, prior, ['native']);
    assert.equal(disagreements, 1);
    assert.equal(agreements, 0);
    assert.equal(findings[0].severity, 'LOW', 'AI severity must remain the AI\u2019s own (never edited)');
    const contradicted = (findings[0].sources || []).find(s => s.status === 'CONTRADICTED');
    assert.ok(contradicted, 'disagreement must be recorded on the finding');
    assert.ok(/RECORDED, NOT resolved/.test(contradicted.note));
    // and the tool finding is untouched:
    assert.equal(prior[0].severity, 'CRITICAL');
  });
});
