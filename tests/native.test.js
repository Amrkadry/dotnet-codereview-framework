'use strict';
/**
 * Native engine tests (src/native/*).
 *
 * The fixture project plants REAL defects with known line numbers, then asserts the engine
 * finds them with the required fields (file, line, snippet evidence, confidence, remediation,
 * catalog ids) — and that the false-positive discipline holds: the same pattern inside Tests/
 * produces nothing, commented-out code produces nothing, and the skip list is REPORTED rather
 * than hidden. Empty/irrelevant directories return zero findings, never throw.
 */
const { test, describe, before, after } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

const NATIVE = require('../src/native');

const root = path.resolve(__dirname, '..');

let fx;
before(() => {
  fx = fs.mkdtempSync(path.join(os.tmpdir(), 'moraa-native-test-'));
  fs.mkdirSync(path.join(fx, 'Controllers'));
  fs.mkdirSync(path.join(fx, 'Tests'));
  fs.writeFileSync(path.join(fx, 'Web.config'), `<?xml version="1.0"?>
<configuration>
  <system.web>
    <compilation debug="true" targetFramework="4.7.2" />
    <customErrors mode="Off" />
    <machineKey validation="SHA1" validationKey="SHORT" decryptionKey="AB" />
  </system.web>
  <connectionStrings>
    <add name="Db" connectionString="Server=sql01;User Id=sa;Password=Sup3rS3cret!" />
  </connectionStrings>
</configuration>
`);
  fs.writeFileSync(path.join(fx, 'Controllers', 'BadController.cs'), `using System;
using System.Data.SqlClient;
using System.Web.Mvc;
namespace App.Controllers {
  public class BadController : Controller {
    [HttpPost]
    public ActionResult Search(string q) {
      var cmd = new SqlCommand("SELECT * FROM U WHERE N = '" + q + "'", null);
      Response.Write(Request["msg"]);
      return View();
    }
  }
}
`);
  // The SAME patterns inside Tests/ and inside a comment must produce NOTHING.
  fs.writeFileSync(path.join(fx, 'Tests', 'Skipped.cs'), `public class Skipped {
  public void T() {
    // var cmd = new SqlCommand("SELECT * FROM U WHERE N = '" + q + "'", null);
    var cmd2 = new SqlCommand("SELECT * FROM U WHERE N = '" + q + "'", null);
  }
}
`);
  // appsettings with a live-looking secret
  fs.writeFileSync(path.join(fx, 'appsettings.json'),
    '{ "Api": { "ClientSecret": "live-value-9876", "Timeout": 30 } }');
});

after(() => { fs.rmSync(fx, { recursive: true, force: true }); });

const real = r => (r.findings || []).filter(f => f.severity !== 'INFO');

describe('native engine: real findings', () => {
  test('finds planted defects with full required fields', async () => {
    const r = await NATIVE.analyze(fx);
    assert.equal(r.status, 'EXECUTED');
    const found = real(r);
    assert.ok(found.length >= 6, `expected >=6 real findings, got ${found.length}`);

    for (const f of found) {
      assert.ok(f.title, 'title');
      assert.ok(f.location && f.location.file, 'location.file');
      assert.ok(['CONFIRMED', 'LIKELY', 'POSSIBLE'].includes(f.confidence), `confidence ${f.confidence}`);
      assert.ok(typeof f.evidence.snippet === 'string', 'evidence.snippet');
      assert.ok(f.problem && f.impact && f.recommendation, 'problem/impact/recommendation');
      assert.ok((f.sources || []).some(s => s.tool === 'native'), 'source tool native');
    }
    const titles = found.map(f => f.title);
    assert.ok(titles.some(t => /Debug compilation/.test(t)), 'debug=true finding');
    assert.ok(titles.some(t => /customErrors/.test(t)), 'customErrors finding');
    assert.ok(titles.some(t => /machineKey/.test(t)), 'machineKey finding');
    assert.ok(titles.some(t => /connection string/i.test(t)), 'cleartext connection string finding');
    assert.ok(titles.some(t => /concatenation/.test(t)), 'SQL concat finding');
    assert.ok(titles.some(t => /Response\.Write/.test(t)), 'Response.Write finding');
  });

  test('findings carry catalog case ids that exist in the catalog', async () => {
    const r = await NATIVE.analyze(fx);
    const catalogIds = new Set();
    for (const f of fs.readdirSync(path.join(root, 'catalog'))) {
      const c = JSON.parse(fs.readFileSync(path.join(root, 'catalog', f), 'utf8'));
      (c.tests || []).forEach(t => catalogIds.add(t.id));
    }
    for (const f of real(r)) {
      for (const id of f.tests || []) assert.ok(catalogIds.has(id), `case id ${id} not in catalog`);
    }
  });

  test('secrets are redacted in evidence snippets', async () => {
    const r = await NATIVE.analyze(fx);
    for (const f of r.findings) {
      const s = f.evidence && f.evidence.snippet || '';
      assert.ok(!s.includes('Sup3rS3cret!'), 'connection string password leaked into evidence');
      assert.ok(!s.includes('live-value-9876'), 'appsettings secret leaked into evidence');
    }
  });

  test('line numbers point at the planted defect', async () => {
    const r = await NATIVE.analyze(fx);
    const sql = real(r).find(f => /concatenation/.test(f.title));
    assert.equal(sql.location.file, 'Controllers/BadController.cs');
    assert.equal(sql.location.startLine, 8);
    assert.ok(sql.evidence.snippet.includes("SELECT * FROM U"));
  });

  test('POSSIBLE-confidence findings say what that means', async () => {
    const r = await NATIVE.analyze(fx);
    for (const f of real(r).filter(x => x.confidence === 'POSSIBLE')) {
      assert.ok(/pattern|lead|may|MIGHT|cannot/i.test(f.sources[0].note + f.problem),
        `POSSIBLE finding should not overclaim: ${f.title}`);
    }
  });
});

describe('native engine: false-positive discipline', () => {
  test('Tests/ is skipped, and the skip list is reported', async () => {
    const r = await NATIVE.analyze(fx);
    for (const f of real(r)) {
      assert.ok(!/^Tests\//.test(f.location.file), `finding leaked from Tests/: ${f.location.file}`);
    }
    assert.ok(/Tests\//.test(r.notes), 'skip list not visible in notes');
  });

  test('commented-out code produces no finding', async () => {
    const r = await NATIVE.analyze(fx);
    const commented = real(r).filter(f => f.location.file === 'Tests/Skipped.cs');
    assert.equal(commented.length, 0, 'Tests/ skip should make this moot, but if reached: comment matching leaked');
    // independent proof on the stripper itself:
    const { stripComments: sc } = require('../src/native/checks/csharp');
    const masked = sc(['// var cmd = new SqlCommand("a" + q, null);', 'var x = 1; /* c */']);
    assert.ok(!/SqlCommand/.test(masked[0]), 'line comment not stripped');
    assert.ok(!/c \*\//.test(masked[1]), 'block comment not stripped');
    assert.ok(/var x = 1;/.test(masked[1]), 'live code damaged by comment stripping');
  });

  test('a directory with no .NET surface returns zero findings, never throws', async () => {
    const empty = fs.mkdtempSync(path.join(os.tmpdir(), 'moraa-native-empty-'));
    try {
      const r = await NATIVE.analyze(empty);
      assert.equal(r.status, 'NOT_APPLICABLE');
      assert.equal(r.findings.length, 0);
    } finally {
      fs.rmSync(empty, { recursive: true, force: true });
    }
  });

  test('a nonexistent path returns FAILED (data, not a crash)', async () => {
    const r = await NATIVE.analyze(path.join(fx, 'does-not-exist'));
    assert.equal(r.status, 'FAILED');
    assert.equal(r.findings.length, 0);
    assert.ok(r.notes, 'FAILED must explain itself');
  });
});

describe('native engine: catalog coverage honesty', () => {
  test('every applicable catalog case is accounted for: checked or manual-review', async () => {
    const r = await NATIVE.analyze(fx);
    assert.ok(Array.isArray(r.catalogCoverage) && r.catalogCoverage.length >= 279,
      'coverage must cover the full catalog');
    for (const c of r.catalogCoverage) {
      assert.ok(['checked', 'manual-review', 'not-applicable'].includes(c.outcome), `outcome ${c.outcome}`);
      assert.equal(c.tool, 'native');
    }
    const checked = new Set(r.catalogCoverage.filter(c => c.outcome === 'checked').map(c => c.caseId));
    // the checks that fired must appear as checked coverage
    for (const f of real(r)) for (const id of f.tests || []) assert.ok(checked.has(id), `${id} fired but not marked checked`);
  });

  test('manual-review items are INFO, carry the checklist question, and never gate', async () => {
    const r = await NATIVE.analyze(fx);
    const manual = r.findings.filter(f => f.severity === 'INFO');
    assert.ok(manual.length > 100, 'undecided cases must surface as manual-review items');
    for (const m of manual) {
      assert.ok(/Catalog case [A-Z]-\d+/.test(m.problem), 'manual item names its catalog case');
      assert.ok(m.recommendation.length > 10, 'manual item carries the checklist question');
      assert.equal(m.confidence, 'UNVERIFIED');
    }
  });

  test('noManualReview option suppresses the INFO items but keeps the coverage records', async () => {
    const r = await NATIVE.analyze(fx, { noManualReview: true });
    assert.equal(r.findings.filter(f => f.severity === 'INFO').length, 0);
    assert.ok(r.catalogCoverage.filter(c => c.outcome === 'manual-review').length > 100,
      'coverage records must survive even when the findings are suppressed');
  });
});

describe('native engine: contract', () => {
  test('adapter surface validates and detect() is always available', async () => {
    const C = require('../src/core/adapter-contract');
    const problems = C.validateAdapter(NATIVE, 'native.js');
    assert.deepEqual(problems, []);
    const d = await NATIVE.detect({});
    assert.equal(d.available, true);
  });

  test('run() result passes validateRunResult', async () => {
    const C = require('../src/core/adapter-contract');
    const r = await NATIVE.run({ sourcePath: fx, outPath: path.join(fx, '.moraa-review'),
      project: { stack: 'unknown' }, log: () => {} });
    // manual-review findings lack a location line but the contract only requires location.file
    const problems = C.validateRunResult(r, 'native');
    assert.deepEqual(problems, []);
  });

  test('parse() round-trips raw output', async () => {
    const r = await NATIVE.analyze(fx);
    const again = NATIVE.parse(JSON.stringify({ findings: r.findings }));
    assert.equal(again.length, r.findings.length);
    assert.deepEqual(NATIVE.parse('not json'), []);
    assert.deepEqual(NATIVE.parse(null), []);
  });
});
