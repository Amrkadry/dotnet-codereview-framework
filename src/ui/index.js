'use strict';
/**
 * TERMINAL UI — severity colour, progress lines, final summary table.
 *
 * THE RULE THAT MATTERS MOST: colour is presentation, never data. A piped, redirected or
 * CI-captured run must contain ZERO ANSI escape bytes, because the output is parsed by things
 * (CI logs, grep, the framework's own selfcheck) that should never meet an escape sequence.
 * Order of precedence, checked in this exact order:
 *   1. NO_COLOR (any value, per https://no-color.org)        -> colour OFF
 *   2. FORCE_COLOR ('0' off, any other non-empty value on)   -> overrides TTY detection
 *   3. stream.isTTY                                          -> colour only on a terminal
 *   4. TERM=dumb                                             -> colour OFF
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

/**
 * Build the colour function set for one output stream.
 * All functions are identities when colour is off — callers never branch on colour.
 */
function paintFor(stream, env) {
  const on = colorEnabled(stream, env);
  const wrap = code => s => on ? `\x1b[${code}m${s}\x1b[0m` : String(s);
  return {
    enabled: on,
    bold: wrap(ANSI.bold),
    dim: wrap(ANSI.dim),
    red: wrap(31),
    green: wrap(32),
    yellow: wrap(33),
    blue: wrap(34),
    gray: wrap(90),
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

module.exports = { colorEnabled, paintFor, progressLine, summaryTable, SEV_ORDER, ESC };
