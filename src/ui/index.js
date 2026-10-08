// dotnet-codereview-framework — src/ui/index.js
// Author: Amr Kadry (github.com/Amrkadry) · MIT License
'use strict';
/**
 * TERMINAL UI — severity colour, progress lines, boxes, bars and the final summary.
 *
 * THE RULE THAT MATTERS MOST: colour is presentation, never data. A piped, redirected or
 * CI-captured run must contain ZERO ANSI escape bytes, because the output is parsed by things
 * (CI logs, grep, the framework's own selfcheck) that should never meet an escape sequence.
 * Order of precedence, checked in this exact order:
 *   1. NO_COLOR (any value, per https://no-color.org)        -> colour OFF
 *   2. FORCE_COLOR ('0' off, any other non-empty value on)   -> overrides TTY detection
 *   3. stream.isTTY                                          -> colour only on a terminal
 *   4. TERM=dumb                                             -> colour OFF
 *
 * The same rule is extended to BOX-DRAWING. Box characters are ordinary text rather than
 * escapes, so they would survive a pipe and clutter a CI log or a grep. The glyph set
 * therefore follows the colour decision: a real terminal gets rounded Unicode frames, a pipe
 * gets ASCII. MORAA_ASCII=1 forces ASCII on a terminal too, for old consoles and odd code pages.
 */

const SEV_ORDER = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'];

const ANSI = {
  red: 41, bold: 1, dim: 2, reset: 22
};

/** Should colour be used on this stream, given this environment? Pure decision, no I/O. */
function colorEnabled(stream, env) {
  const e = env || process.env;
  if (e && e.NO_COLOR !== undefined && e.NO_COLOR !== '') return false;
  if (e && e.FORCE_COLOR !== undefined && e.FORCE_COLOR !== '') return e.FORCE_COLOR !== '0';
  if (!stream || !stream.isTTY) return false;
  if (e && (e.TERM === 'dumb' || e.TERM === '')) return false;
  return true;
}

/** Unicode frames for a terminal, ASCII for anything that might be parsed. */
const GLYPHS = {
  unicode: {
    tl: '╭', tr: '╮', bl: '╰', br: '╯',
    h: '─', v: '│',
    bar: '█', barEmpty: '░',
    ok: '✔', fail: '✖', skip: '○', warn: '⚠', info: '•',
    tree: '└', treeMid: '├', arrow: '→', dot: '·'
  },
  ascii: {
    tl: '+', tr: '+', bl: '+', br: '+',
    h: '-', v: '|',
    bar: '#', barEmpty: '.',
    ok: 'ok', fail: 'XX', skip: '--', warn: '!!', info: '*',
    tree: '\\-', treeMid: '|-', arrow: '->', dot: '-'
  }
};

function glyphsFor(on, env) {
  const e = env || process.env;
  if (e && e.MORAA_ASCII !== undefined && e.MORAA_ASCII !== '' && e.MORAA_ASCII !== '0') {
    return GLYPHS.ascii;
  }
  return on ? GLYPHS.unicode : GLYPHS.ascii;
}

/** Printable width: ANSI sequences occupy no columns, so they must not count toward padding. */
function visibleLength(s) {
  return String(s).replace(/\x1b\[[0-9;]*m/g, '').length;
}

/** Pad to a column width measured in PRINTABLE characters, not bytes. */
function padVisible(s, width, align) {
  const len = visibleLength(s);
  if (len >= width) return String(s);
  const fill = ' '.repeat(width - len);
  return align === 'right' ? fill + String(s) : String(s) + fill;
}

/**
 * Build the colour function set for one output stream.
 * All functions are identities when colour is off — callers never branch on colour.
 */
function paintFor(stream, env) {
  const on = colorEnabled(stream, env);
  const wrap = code => s => on ? `\x1b[${code}m${s}\x1b[0m` : String(s);
  return {
    enabled: on,
    glyphs: glyphsFor(on, env),
    bold: wrap(ANSI.bold),
    dim: wrap(ANSI.dim),
    red: wrap(31),
    green: wrap(32),
    yellow: wrap(33),
    blue: wrap(34),
    magenta: wrap(35),
    cyan: wrap(36),
    gray: wrap(90),
    brightRed: wrap(91),
    brightGreen: wrap(92),
    brightCyan: wrap(96),
    white: wrap(97),
    bgRed: wrap(ANSI.red),
    severity(s) {
      switch (String(s).toUpperCase()) {
        case 'CRITICAL': return wrap('1;97;41')(String(s));
        case 'HIGH': return wrap('1;31')(String(s));
        case 'MEDIUM': return wrap('33')(String(s));
        case 'LOW': return wrap('34')(String(s));
        default: return wrap(ANSI.dim)(String(s));
      }
    },
    status(status) {
      switch (String(status)) {
        case 'EXECUTED': return wrap(32)(String(status));
        case 'FAILED': return wrap('1;31')(String(status));
        case 'NOT_AVAILABLE':
        case 'NOT_APPLICABLE': return wrap(33)(String(status));
        default: return wrap(ANSI.dim)(String(status));
      }
    }
  };
}

/** One progress line: status padded, tool id padded, note truncated. Colour-aware. */
function progressLine(paint, status, id, note, width = 14) {
  const st = String(status || '').padEnd(width);
  const tool = String(id || '').padEnd(18);
  const text = `${st} ${tool}${note ? ' ' + String(note) : ''}`;
  const colorOf = { EXECUTED: paint.green, FAILED: paint.red, NOT_AVAILABLE: paint.yellow, NOT_APPLICABLE: paint.yellow };
  const c = colorOf[status];
  return c ? c(text) : paint.dim(text);
}

// ---------------------------------------------------------------------------------------------
// Layout primitives
// ---------------------------------------------------------------------------------------------

/** Terminal width, clamped so a report stays readable in a very wide or very narrow window. */
function termWidth(stream, fallback = 78) {
  const w = stream && stream.columns ? stream.columns : fallback;
  return Math.max(48, Math.min(w - 2, 100));
}

/** A horizontal rule, optionally carrying a title. */
function rule(paint, width, title) {
  const g = paint.glyphs;
  if (!title) return paint.dim('  ' + g.h.repeat(width));
  const label = ' ' + title + ' ';
  const dashes = Math.max(0, width - label.length - 2);
  return '  ' + paint.dim(g.h.repeat(2)) + paint.bold(label) + paint.dim(g.h.repeat(dashes));
}

/**
 * A framed box. `lines` may already be coloured; padding is computed on printable width so
 * colour never shifts the right-hand border.
 */
function box(paint, title, lines, width) {
  const g = paint.glyphs;
  const inner = width - 2;
  const out = [];
  const top = title
    ? g.tl + g.h + ' ' + title + ' ' + g.h.repeat(Math.max(0, inner - title.length - 3)) + g.tr
    : g.tl + g.h.repeat(inner) + g.tr;
  out.push('  ' + paint.dim(top));
  for (const l of lines) {
    out.push('  ' + paint.dim(g.v) + ' ' + padVisible(l, inner - 2) + ' ' + paint.dim(g.v));
  }
  out.push('  ' + paint.dim(g.bl + g.h.repeat(inner) + g.br));
  return out;
}

/** The run banner. Deliberately quiet: one line of identity, not ASCII art. */
function banner(paint, { title, subtitle, version, stream }) {
  const width = termWidth(stream);
  const g = paint.glyphs;
  const left = paint.bold(paint.brightCyan(title)) +
    (subtitle ? paint.dim('  ' + g.dot + '  ') + paint.white(subtitle) : '');
  const right = version ? paint.dim(version) : '';
  const gap = Math.max(1, (width - 4) - visibleLength(left) - visibleLength(right));
  return box(paint, null, [left + ' '.repeat(gap) + right], width);
}

/** Aligned "label   value" pairs for the run header. */
function kv(paint, label, value, labelWidth = 9) {
  return '  ' + paint.dim(String(label).padEnd(labelWidth)) + ' ' + String(value);
}

/** Human duration: ms under a second, else seconds with one decimal. */
function duration(ms) {
  if (ms === undefined || ms === null) return '';
  const n = Number(ms);
  if (!isFinite(n)) return '';
  if (n < 1000) return `${Math.round(n)}ms`;
  if (n < 60000) return `${(n / 1000).toFixed(1)}s`;
  return `${Math.floor(n / 60000)}m${Math.round((n % 60000) / 1000)}s`;
}

/**
 * A phase heading: "[3/6] running built-in sources .............. 1.2s".
 * The leader dots line the timings up without needing a table.
 */
function phase(paint, n, total, title, ms, stream) {
  const width = termWidth(stream);
  const head = `[${n}/${total}] `;
  const time = ms === undefined || ms === null ? '' : duration(ms);
  const used = head.length + String(title).length + (time ? time.length + 1 : 0);
  const dots = Math.max(1, width - used - 4);
  return '  ' + paint.dim(head) + paint.bold(String(title)) + ' ' +
    paint.dim('.'.repeat(dots)) + (time ? ' ' + paint.cyan(time) : '');
}

/** An indented detail under a phase, drawn as a tree branch. */
function detail(paint, text, last = true) {
  const g = paint.glyphs;
  return '        ' + paint.dim(last ? g.tree : g.treeMid) + ' ' + text;
}

/** Glyph + colour for a source's outcome. */
function statusGlyph(paint, status) {
  const g = paint.glyphs;
  switch (String(status)) {
    case 'EXECUTED': return paint.green(g.ok);
    case 'FAILED': return paint.red(g.fail);
    case 'NOT_AVAILABLE': return paint.yellow(g.skip);
    case 'NOT_APPLICABLE': return paint.dim(g.skip);
    default: return paint.dim(g.info);
  }
}

/**
 * One row in the sources table: glyph, tool, finding count, timing, and the reason when a
 * source did not run. The reason IS the row's purpose — a tool that reported nothing because
 * it never ran is not a clean result, and the output has to say which of the two it was.
 */
function sourceRow(paint, r, stream) {
  const width = termWidth(stream);
  const n = (r.findings || []).length;
  const ran = r.status === 'EXECUTED';
  const count = ran
    ? (n ? paint.bold(String(n)) + paint.dim(n === 1 ? ' finding' : ' findings') : paint.green('clean'))
    : paint.dim('not run');
  const lines = ['  ' + statusGlyph(paint, r.status) + ' ' +
    padVisible(paint.white(r.tool), 20) + padVisible(count, 18) +
    paint.dim(duration(r.durationMs))];
  if (!ran && r.notes) {
    const room = Math.max(24, width - 10);
    lines.push('      ' + paint.dim(String(r.notes).replace(/\s+/g, ' ').slice(0, room)));
  }
  return lines;
}

function colorBar(paint, severity, bar) {
  switch (severity) {
    case 'CRITICAL': return paint.brightRed(bar);
    case 'HIGH': return paint.red(bar);
    case 'MEDIUM': return paint.yellow(bar);
    case 'LOW': return paint.blue(bar);
    default: return paint.dim(bar);
  }
}

/**
 * Horizontal bar chart of findings by severity. Empty severities are KEPT and dimmed rather
 * than dropped: "HIGH 0" is a result worth seeing, and a chart that silently omits the empty
 * rows makes a clean run indistinguishable from a partial one.
 */
function severityChart(paint, counts, stream, title = 'findings by severity') {
  const width = termWidth(stream);
  const g = paint.glyphs;
  const max = Math.max(1, ...SEV_ORDER.map(s => counts[s] || 0));
  const barRoom = Math.max(10, width - 28);
  const lines = [];
  for (const s of SEV_ORDER) {
    const n = counts[s] || 0;
    const filled = n ? Math.max(1, Math.round((n / max) * barRoom)) : 0;
    const bar = n
      ? colorBar(paint, s, g.bar.repeat(filled)) + paint.dim(g.barEmpty.repeat(barRoom - filled))
      : paint.dim(g.barEmpty.repeat(barRoom));
    lines.push(padVisible(n ? paint.severity(s) : paint.dim(s), 10) +
      padVisible(n ? paint.bold(String(n)) : paint.dim('0'), 5, 'right') + '  ' + bar);
  }
  return box(paint, title, lines, width);
}

/**
 * The findings worth reading first: most severe first, with location and how many other
 * places the same rule fired, so a consolidated family does not look like a single hit.
 */
function topFindings(paint, findings, opts = {}) {
  const { limit = 12, stream } = opts;
  const width = termWidth(stream);
  const order = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3, INFO: 4 };
  const rank = f => (order[f.severity] === undefined ? 9 : order[f.severity]);
  const ranked = findings.slice().sort((a, b) => rank(a) - rank(b));
  const shown = ranked.slice(0, limit);
  if (!shown.length) return [];
  const g = paint.glyphs;
  const lines = [];
  for (const f of shown) {
    const extra = ((f.location && f.location.additionalLocations) || []).length;
    const titleRoom = Math.max(20, width - 20);
    lines.push('  ' + padVisible(paint.severity(f.severity), 10) + ' ' +
      paint.white(String(f.title || '').slice(0, titleRoom)));
    const loc = f.location || {};
    const where = (loc.file || '(project)') + (loc.startLine ? ':' + loc.startLine : '');
    lines.push('             ' + paint.dim(g.arrow + ' ' + where) +
      (extra ? paint.dim(`  (+${extra} more location${extra === 1 ? '' : 's'})`) : ''));
  }
  if (ranked.length > shown.length) {
    lines.push('');
    lines.push('  ' + paint.dim(`${ranked.length - shown.length} further finding(s) in the report`));
  }
  return lines;
}

/** Final summary table (text). Returns lines; caller prints them. */
function summaryTable(paint, findings, { tools = [], notRun = [], extra = [] } = {}) {
  const lines = [];
  const counts = SEV_ORDER.map(s => [s, findings.filter(f => f.severity === s).length]);
  const W = 10;
  const head = '  ' + counts.map(([s]) => s.padEnd(W)).join('');
  const vals = '  ' + counts.map(([, n]) =>
    (String(n).padEnd(W))).join('');
  lines.push(paint.bold('  findings by severity'));
  lines.push(paint.dim(head));
  lines.push(counts.map(([s, n]) => n > 0 ? paint.severity(String(n).padEnd(W)) : paint.dim(String(n).padEnd(W))).join('').replace(/^/, '  '));
  void vals;
  if (tools.length) {
    lines.push('');
    lines.push(paint.bold('  sources'));
    for (const r of tools) {
      lines.push('  ' + progressLine(paint, r.status, r.tool, r.note || ''));
    }
  }
  if (notRun.length) {
    lines.push('');
    lines.push(paint.yellow(`  ${notRun.length} source(s) did not run: ${notRun.map(r => r.tool).join(', ')}`));
    lines.push(paint.dim('  Findings absent from this report may simply never have been looked for.'));
  }
  for (const e of extra) lines.push(e);
  return lines;
}

/** Stamp used by tests: if a string contains ESC it was coloured. */
const ESC = '\x1b';

module.exports = {
  colorEnabled, paintFor, progressLine, summaryTable, SEV_ORDER, ESC,
  // layout primitives
  termWidth, visibleLength, padVisible, rule, box, banner, kv, duration,
  phase, detail, statusGlyph, sourceRow, severityChart, topFindings, glyphsFor
};
