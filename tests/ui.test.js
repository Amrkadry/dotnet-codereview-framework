// dotnet-codereview-framework — tests/ui.test.js
// Author: Amr Kadry (github.com/Amrkadry) · MIT License
'use strict';
/**
 * Terminal UI tests (src/ui/index.js).
 *
 * The load-bearing property: colour is presentation, never data. Piped/redirected output must
 * contain ZERO escape bytes (CI logs and greppers must never meet \x1b), NO_COLOR must win over
 * everything, FORCE_COLOR must force colour through a pipe, and TERM=dumb must disable it.
 */
const { test, describe } = require('node:test');
const assert = require('node:assert/strict');
const { execFileSync } = require('node:child_process');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

const UI = require('../src/ui');
const root = path.resolve(__dirname, '..');

const ttyStream = { isTTY: true };
const pipeStream = { isTTY: false };

describe('colorEnabled precedence', () => {
  test('non-TTY means no colour', () => {
    assert.equal(UI.colorEnabled(pipeStream, {}), false);
    assert.equal(UI.colorEnabled(undefined, {}), false);
  });

  test('TTY gets colour', () => {
    assert.equal(UI.colorEnabled(ttyStream, {}), true);
  });

  test('NO_COLOR wins over everything, even FORCE_COLOR and TTY', () => {
    assert.equal(UI.colorEnabled(ttyStream, { NO_COLOR: '1' }), false);
    assert.equal(UI.colorEnabled(ttyStream, { NO_COLOR: '' }), true, 'empty NO_COLOR is not a claim');
    assert.equal(UI.colorEnabled(ttyStream, { NO_COLOR: '1', FORCE_COLOR: '1' }), false);
  });

  test('FORCE_COLOR forces colour through a pipe; FORCE_COLOR=0 disables on a TTY', () => {
    assert.equal(UI.colorEnabled(pipeStream, { FORCE_COLOR: '1' }), true);
    assert.equal(UI.colorEnabled(pipeStream, { FORCE_COLOR: 'yes' }), true);
    assert.equal(UI.colorEnabled(ttyStream, { FORCE_COLOR: '0' }), false);
  });

  test('TERM=dumb disables colour on a TTY', () => {
    assert.equal(UI.colorEnabled(ttyStream, { TERM: 'dumb' }), false);
  });
});

describe('paintFor', () => {
  test('non-TTY painters are identities: zero escape bytes', () => {
    const p = UI.paintFor(pipeStream, {});
    for (const fn of [p.bold, p.dim, p.red, p.green, p.yellow, p.blue, p.gray]) {
      assert.equal(fn('hello'), 'hello');
    }
    assert.equal(p.severity('CRITICAL'), 'CRITICAL');
    assert.equal(p.status('EXECUTED'), 'EXECUTED');
  });

  test('FORCE_COLOR painters emit ANSI', () => {
    const p = UI.paintFor(pipeStream, { FORCE_COLOR: '1' });
    assert.ok(p.red('x').includes('\x1b[31m'));
    assert.ok(p.severity('CRITICAL').includes('\x1b['));
    assert.ok(p.severity('CRITICAL').includes('CRITICAL'));
  });

  test('summaryTable and progressLine honour the same switch', () => {
    const findings = [
      { severity: 'CRITICAL' }, { severity: 'HIGH' }, { severity: 'INFO' }
    ];
    const quiet = UI.summaryTable(UI.paintFor(pipeStream, {}), findings).join('\n');
    assert.ok(!quiet.includes(UI.ESC), 'summary table emitted escapes on a pipe');
    const loud = UI.summaryTable(UI.paintFor(pipeStream, { FORCE_COLOR: '1' }), findings).join('\n');
    assert.ok(loud.includes(UI.ESC), 'summary table without colour under FORCE_COLOR');

    const line = UI.progressLine(UI.paintFor(pipeStream, {}), 'EXECUTED', 'native', 'ok');
    assert.ok(!line.includes(UI.ESC));
    const lineLoud = UI.progressLine(UI.paintFor(pipeStream, { FORCE_COLOR: '1' }), 'EXECUTED', 'native', 'ok');
    assert.ok(lineLoud.includes(UI.ESC));
  });
});

describe('end-to-end: the CLI piped is byte-clean', () => {
  // `moraa native` on a tiny planted fixture — a command whose output actually paints severity.
  const makeFx = () => {
    const d = fs.mkdtempSync(path.join(os.tmpdir(), 'moraa-ui-'));
    fs.writeFileSync(path.join(d, 'Web.config'),
      '<configuration><system.web><compilation debug="true" /></system.web></configuration>');
    return d;
  };

  test('moraa native output through a pipe contains zero escape bytes', () => {
    const fx = makeFx();
    try {
      const out = execFileSync(process.execPath,
        [path.join(root, 'bin/moraa.js'), 'native', fx],
        { encoding: 'utf8', env: Object.assign({}, process.env, { FORCE_COLOR: '' }) });
      assert.ok(!out.includes('\x1b'), 'piped CLI output carried ANSI escapes');
      assert.ok(/CRITICAL|MEDIUM/.test(out), 'expected a severity line in native output');
    } finally {
      fs.rmSync(fx, { recursive: true, force: true });
    }
  });

  test('FORCE_COLOR=1 through a pipe DOES colour (explicit override)', () => {
    const fx2 = makeFx();
    try {
      const out = execFileSync(process.execPath,
        [path.join(root, 'bin/moraa.js'), 'native', fx2],
        { encoding: 'utf8', env: Object.assign({}, process.env, { FORCE_COLOR: '1' }) });
      assert.ok(out.includes('\x1b'), 'FORCE_COLOR=1 did not force colour');
    } finally {
      fs.rmSync(fx2, { recursive: true, force: true });
    }
  });
});
