'use strict';
/**
 * Tests for the terminal layout primitives (boxes, bars, truncation, tool rows).
 *
 * The invariant that matters is the same one the colour tests defend, extended to glyphs: a
 * piped or CI-captured run must contain zero ANSI escape bytes AND no box-drawing characters,
 * because that output is read by grep, CI log viewers and this framework's own self-check.
 * Padding is the other thing worth pinning — it is computed on PRINTABLE width, so a coloured
 * cell must occupy the same number of columns as an uncoloured one, or every frame skews.
 */
const { test, describe } = require('node:test');
const assert = require('node:assert/strict');

const UI = require('../src/ui');

const pipe = { isTTY: false, columns: 92 };
const tty = { isTTY: true, columns: 92 };

const plain = UI.paintFor(pipe, {});
const loud = UI.paintFor(pipe, { FORCE_COLOR: '1' });

/** Box-drawing characters that must never reach a pipe. */
const UNICODE_FRAME = /[─-╿█░✔✖○⚠]/;

describe('glyph selection follows the colour decision', () => {
  test('a pipe gets ASCII glyphs, a terminal gets Unicode', () => {
    assert.equal(UI.glyphsFor(false, {}).v, '|');
    assert.equal(UI.glyphsFor(true, {}).v, '│');
  });

  test('MORAA_ASCII forces ASCII even on a terminal', () => {
    assert.equal(UI.glyphsFor(true, { MORAA_ASCII: '1' }).v, '|');
    // '0' and '' are not a claim, exactly as with the colour variables.
    assert.equal(UI.glyphsFor(true, { MORAA_ASCII: '0' }).v, '│');
    assert.equal(UI.glyphsFor(true, { MORAA_ASCII: '' }).v, '│');
  });

  test('paintFor hands its painter set a matching glyph set', () => {
    assert.equal(UI.paintFor(pipe, {}).glyphs.v, '|');
    assert.equal(UI.paintFor(tty, {}).glyphs.v, '│');
  });
});

describe('piped output is byte-clean and frame-clean', () => {
  const findings = [
    { severity: 'CRITICAL', title: 'a', location: { file: 'x.cs', startLine: 1 } },
    { severity: 'LOW', title: 'b', location: { file: 'y.cs', startLine: 2 } }
  ];

  test('every layout primitive is escape-free and ASCII-framed on a pipe', () => {
    const blocks = [
      UI.banner(plain, { title: 'moraa', subtitle: 'x', version: 'v1', stream: pipe }),
      UI.box(plain, 'title', ['one', 'two'], 60),
      UI.severityChart(plain, { CRITICAL: 2, HIGH: 0, MEDIUM: 1, LOW: 0, INFO: 0 }, pipe),
      UI.topFindings(plain, findings, { stream: pipe }),
      UI.sourceRow(plain, { tool: 't', status: 'EXECUTED', findings: [], durationMs: 5 }, pipe),
      [UI.phase(plain, 1, 6, 'step', 12, pipe)],
      [UI.rule(plain, 60, 'section')],
      [UI.detail(plain, 'leaf')],
      [UI.kv(plain, 'label', 'value')]
    ];
    for (const lines of blocks) {
      const text = lines.join('\n');
      assert.ok(!text.includes(UI.ESC), 'ANSI escape reached a pipe: ' + JSON.stringify(text.slice(0, 60)));
      assert.ok(!UNICODE_FRAME.test(text), 'box glyph reached a pipe: ' + JSON.stringify(text.slice(0, 60)));
    }
  });

  test('FORCE_COLOR turns colour back on without changing the column count', () => {
    const a = UI.box(plain, null, ['cell'], 40);
    const b = UI.box(loud, null, [loud.severity('CRITICAL')], 40);
    assert.ok(b.join('').includes(UI.ESC), 'FORCE_COLOR produced no colour');
    // Padding is computed on printable width, so both frames are the same width.
    assert.equal(UI.visibleLength(a[1]), UI.visibleLength(b[1]));
  });
});

describe('visibleLength and padVisible ignore ANSI', () => {
  test('colour costs no columns', () => {
    assert.equal(UI.visibleLength(loud.red('abc')), 3);
    assert.equal(UI.visibleLength('abc'), 3);
  });

  test('padding a coloured cell yields the same printable width as a plain one', () => {
    assert.equal(UI.visibleLength(UI.padVisible(loud.red('ab'), 10)), 10);
    assert.equal(UI.visibleLength(UI.padVisible('ab', 10)), 10);
  });

  test('a cell wider than its column is never silently clipped by padding', () => {
    assert.equal(UI.padVisible('abcdef', 3), 'abcdef');
  });

  test('right alignment puts the fill on the left', () => {
    assert.equal(UI.padVisible('7', 4, 'right'), '   7');
  });
});

describe('truncation', () => {
  test('text is cut on the right and marked, so a cut is visible', () => {
    const t = UI.truncText('abcdefghij', 5);
    assert.equal(t.length, 5);
    assert.ok(t.endsWith('…'), 'a truncated title must show it was truncated');
  });

  test('text that fits is returned untouched', () => {
    assert.equal(UI.truncText('abc', 10), 'abc');
  });

  test('a path is cut on the LEFT, keeping the file name and line', () => {
    const p = UI.truncPath('src/a/very/deep/tree/Thing.cs:42', 14);
    assert.equal(p.length, 14);
    assert.ok(p.endsWith('Thing.cs:42'), 'the navigable end of a path must survive: ' + p);
    assert.ok(p.startsWith('…'));
  });

  test('a path that fits is returned untouched', () => {
    assert.equal(UI.truncPath('a.cs:1', 20), 'a.cs:1');
  });
});

describe('duration', () => {
  test('scales units and never prints a bare number', () => {
    assert.equal(UI.duration(5), '5ms');
    assert.equal(UI.duration(1500), '1.5s');
    assert.equal(UI.duration(125000), '2m5s');
  });

  test('absent timings render as empty, not as zero', () => {
    assert.equal(UI.duration(undefined), '');
    assert.equal(UI.duration(null), '');
    assert.equal(UI.duration('nonsense'), '');
  });
});

describe('sourceRow tells the truth about what ran', () => {
  test('a tool that never ran shows no duration', () => {
    const row = UI.sourceRow(plain,
      { tool: 'semgrep', status: 'NOT_AVAILABLE', findings: [], durationMs: 0, notes: 'not installed' },
      pipe).join('\n');
    assert.ok(row.includes('not run'));
    assert.ok(!/\b0ms\b/.test(row), '"0ms" next to "not run" implies it ran and finished instantly');
    assert.ok(row.includes('not installed'), 'the reason is the point of the row');
  });

  test('a tool that ran and found nothing says clean, not zero findings', () => {
    const row = UI.sourceRow(plain,
      { tool: 'trivy', status: 'EXECUTED', findings: [], durationMs: 1200 }, pipe).join('\n');
    assert.ok(row.includes('clean'));
    assert.ok(row.includes('1.2s'));
  });

  test('singular and plural finding counts are both correct', () => {
    const one = UI.sourceRow(plain,
      { tool: 'gitleaks', status: 'EXECUTED', findings: [{}], durationMs: 1 }, pipe).join('');
    const many = UI.sourceRow(plain,
      { tool: 'gitleaks', status: 'EXECUTED', findings: [{}, {}], durationMs: 1 }, pipe).join('');
    assert.ok(/1 finding\b/.test(one) && !/1 findings/.test(one));
    assert.ok(/2 findings/.test(many));
  });
});

describe('severityChart', () => {
  test('empty severities are kept, so clean cannot be confused with partial', () => {
    const lines = UI.severityChart(plain, { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0 }, pipe);
    const text = lines.join('\n');
    for (const s of UI.SEV_ORDER) assert.ok(text.includes(s), s + ' row was dropped');
  });

  test('the largest count gets the longest bar', () => {
    const lines = UI.severityChart(plain, { CRITICAL: 1, HIGH: 50, MEDIUM: 0, LOW: 0, INFO: 0 }, pipe);
    const bars = lines.map(l => (l.match(/#/g) || []).length);
    assert.ok(Math.max(...bars) > 0, 'no bar was drawn at all');
    const crit = (lines.find(l => l.includes('CRITICAL')).match(/#/g) || []).length;
    const high = (lines.find(l => l.includes('HIGH')).match(/#/g) || []).length;
    assert.ok(high > crit, 'the bars do not reflect the counts');
  });

  test('a non-zero count always draws at least one cell', () => {
    const lines = UI.severityChart(plain, { CRITICAL: 1, HIGH: 999, MEDIUM: 0, LOW: 0, INFO: 0 }, pipe);
    const crit = (lines.find(l => l.includes('CRITICAL')).match(/#/g) || []).length;
    assert.ok(crit >= 1, 'a real finding rounded away to an empty bar');
  });
});

describe('topFindings', () => {
  const mk = (sev, n) => ({
    severity: sev, title: sev + ' thing',
    location: { file: 'f.cs', startLine: 1, additionalLocations: new Array(n || 0) }
  });

  test('orders most severe first regardless of input order', () => {
    const lines = UI.topFindings(plain, [mk('LOW'), mk('CRITICAL'), mk('MEDIUM')], { stream: pipe });
    const text = lines.join('\n');
    assert.ok(text.indexOf('CRITICAL') < text.indexOf('MEDIUM'));
    assert.ok(text.indexOf('MEDIUM') < text.indexOf('LOW'));
  });

  test('consolidated families disclose how many other locations exist', () => {
    const text = UI.topFindings(plain, [mk('HIGH', 22)], { stream: pipe }).join('\n');
    assert.ok(text.includes('(+22 more locations)'));
  });

  test('a single extra location is singular', () => {
    const text = UI.topFindings(plain, [mk('HIGH', 1)], { stream: pipe }).join('\n');
    assert.ok(text.includes('(+1 more location)'));
  });

  test('the limit is reported rather than silently applied', () => {
    const many = new Array(14).fill(0).map(() => mk('HIGH'));
    const text = UI.topFindings(plain, many, { limit: 10, stream: pipe }).join('\n');
    assert.ok(/4 further finding\(s\) in the report/.test(text));
  });

  test('an empty set renders nothing at all', () => {
    assert.deepEqual(UI.topFindings(plain, [], { stream: pipe }), []);
  });
});

describe('termWidth', () => {
  test('clamps absurd terminals into a readable range', () => {
    assert.equal(UI.termWidth({ columns: 20 }), 48);
    assert.equal(UI.termWidth({ columns: 400 }), 100);
  });

  test('falls back when the stream reports no width', () => {
    assert.equal(UI.termWidth({}), 76);
    assert.equal(UI.termWidth(undefined), 76);
  });
});
