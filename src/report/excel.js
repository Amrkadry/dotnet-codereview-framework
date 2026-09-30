'use strict';
/**
 * EXCEL OUTPUT — SpreadsheetML 2003 (XML), written with ZERO dependencies.
 *
 * FORMAT DECISION (recorded here because it was a deliberate trade-off):
 *   A real .xlsx is a ZIP container with a multi-part OOXML package inside. Producing one
 *   without a dependency means shipping a zip writer, which is the single most fragile piece
 *   of hand-rolled code in this repo's threat model. SpreadsheetML 2003 is the alternative
 *   Excel has opened natively since Office 2002: a single XML document (`.xml`, with the
 *   `mso-application` processing instruction so Excel claims it on double-click). It needs no
 *   library, and its well-formedness is checkable with a parser small enough to review by eye.
 *   LibreOffice, Excel (desktop + Microsoft 365) and Numbers all open it. If a strict .xlsx is
 *   ever required, that is the day a dependency (exceljs) is justified — not before.
 *
 * THREE SHEETS, per the merged-report contract:
 *   Summary  — counts by severity, tool and category + the honesty counters (what ran).
 *   Findings — id, severity, CWE, CVSS, file, line, found-by, missed-by, confidence, status,
 *              remediation.
 *   Coverage — every catalog case and whether it was covered (and by which tool). Fed by the
 *              native engine's `catalogCoverage` records and each finding's `tests[]` ids, so
 *              a case is 'covered' when SOMETHING actually decided it — never by assumption.
 *
 * ESCAPING: findings quote source code, which is full of < > & " and occasionally control
 * characters. Every cell goes through escCell(): XML entities plus the removal of characters
 * illegal in XML 1.0 (the ones Excel rejects the whole file over). Snippets with hostile
 * content round-trip — proven by tests/excel.test.js, which parses the file back with the
 * strict verifier below and compares cell-for-cell.
 */

const fs = require('fs');
const path = require('path');

const NS = 'urn:schemas-microsoft-com:office:spreadsheet';
const SS = 'urn:schemas-microsoft-com:office:spreadsheet';
const O = 'urn:schemas-microsoft-com:office:office';
const X = 'urn:schemas-microsoft-com:office:excel';

const SEV_ORDER = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'];

/** Characters illegal in XML 1.0 entirely (Excel refuses the file), plus tab/newline normalisation. */
function stripIllegal(s) {
  // eslint-disable-next-line no-control-regex
  return String(s == null ? '' : s)
    .replace(/[\u0000-\u0008\u000B\u000C\u000E-\u001F\uFFFE\uFFFF]/g, '')
    .replace(/\r\n?/g, '\n');
}

function escCell(v) {
  return stripIllegal(v)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&apos;');
}

/** ss:Name rules: <=31 chars, no : \ / ? * [ ]. */
const sheetName = s => String(s).replace(/[:\\/?*[\]]/g, '-').slice(0, 31);

function cell(v, styleId) {
  const t = typeof v === 'number' && isFinite(v) ? 'Number' : 'String';
  const text = t === 'Number' ? String(v) : escCell(v);
  return `   <Cell${styleId ? ` ss:StyleID="${styleId}"` : ''}><Data ss:Type="${t}">${text}</Data></Cell>`;
}

function row(cells, styleId) {
  return `  <Row${styleId ? ` ss:StyleID="${styleId}"` : ''}>\n${cells.map(c =>
    typeof c === 'object' && c !== null && 'v' in c ? cell(c.v, c.s) : cell(c)).join('\n')}\n  </Row>`;
}

function worksheet(name, rows) {
  return ` <Worksheet ss:Name="${escCell(sheetName(name))}">\n` +
    `  <Table>\n${rows.join('\n')}\n  </Table>\n </Worksheet>`;
}

const STYLES = ` <Styles>
  <Style ss:ID="header">
   <Font ss:Bold="1"/>
   <Interior ss:Color="#D9E2F3" ss:Pattern="Solid"/>
  </Style>
  <Style ss:ID="critical"><Font ss:Bold="1" ss:Color="#9C0006"/><Interior ss:Color="#FFC7CE" ss:Pattern="Solid"/></Style>
  <Style ss:ID="high"><Font ss:Color="#9C5700"/><Interior ss:Color="#FFEB9C" ss:Pattern="Solid"/></Style>
  <Style ss:ID="medium"><Interior ss:Color="#FFFBDE" ss:Pattern="Solid"/></Style>
  <Style ss:ID="info"><Font ss:Color="#4472C4"/></Style>
 </Styles>`;

const sevStyle = s => ({ CRITICAL: 'critical', HIGH: 'high', MEDIUM: 'medium', INFO: 'info' }[s] || null);

// ---------------------------------------------------------------- sheet builders

function summarySheet(findings, runResults, stats) {
  const rows = [row([{ v: 'moraa review — summary', s: 'header' }])];
  rows.push(row(['Generated', new Date().toISOString()]));
  rows.push(row(['Total findings', findings.length]));
  rows.push(row(['', '']));

  rows.push(row([{ v: 'By severity', s: 'header' }]));
  for (const s of SEV_ORDER) {
    const n = findings.filter(f => f.severity === s).length;
    if (n) rows.push(row([s, n]));
  }
  rows.push(row(['', '']));

  rows.push(row([{ v: 'By tool (reported / missed)', s: 'header' }]));
  const toolStat = new Map();
  for (const f of findings) {
    for (const src of f.sources || []) {
      const cur = toolStat.get(src.tool) || { reported: 0, missed: 0 };
      if (src.status === 'REPORTED') cur.reported++;
      if (src.status === 'MISSED') cur.missed++;
      toolStat.set(src.tool, cur);
    }
  }
  for (const r of runResults || []) {
    if (!toolStat.has(r.tool)) toolStat.set(r.tool, { reported: 0, missed: 0, status: r.status });
  }
  for (const [tool, t] of [...toolStat.entries()].sort()) {
    rows.push(row([tool, t.reported, t.missed, t.status || '']));
  }
  rows.push(row(['', '']));

  rows.push(row([{ v: 'By category', s: 'header' }]));
  const catStat = new Map();
  for (const f of findings) catStat.set(f.category, (catStat.get(f.category) || 0) + 1);
  for (const [c, n] of [...catStat.entries()].sort((a, b) => b[1] - a[1])) rows.push(row([c, n]));
  rows.push(row(['', '']));

  if (stats) {
    rows.push(row([{ v: 'Correlation', s: 'header' }]));
    rows.push(row(['Raw findings before dedup', stats.inputFindings]));
    rows.push(row(['Canonical findings', stats.canonicalFindings]));
    rows.push(row(['Merged away as duplicates', stats.mergedAway]));
    rows.push(row(['Confirmed by >1 tool', stats.multiToolConfirmed]));
  }
  return worksheet('Summary', rows);
}

function findingsSheet(findings) {
  const rows = [row([{ v: 'ID', s: 'header' }, { v: 'Severity', s: 'header' }, { v: 'Title', s: 'header' },
    { v: 'CWE', s: 'header' }, { v: 'CVSS', s: 'header' }, { v: 'File', s: 'header' }, { v: 'Line', s: 'header' },
    { v: 'Found by', s: 'header' }, { v: 'Missed by', s: 'header' }, { v: 'Confidence', s: 'header' },
    { v: 'Status', s: 'header' }, { v: 'Remediation', s: 'header' }])];
  for (const f of findings) {
    const found = (f.sources || []).filter(s => s.status === 'REPORTED').map(s => s.tool).join(', ');
    const missed = (f.sources || []).filter(s => s.status === 'MISSED').map(s => s.tool).join(', ');
    rows.push(row([
      { v: f.findingId || '', s: sevStyle(f.severity) },
      { v: f.severity, s: sevStyle(f.severity) },
      f.title,
      (f.cwe || []).join(', '),
      f.cvss ? f.cvss.score : '',
      f.location && f.location.file ? f.location.file : '',
      f.location && f.location.startLine ? f.location.startLine : '',
      found,
      missed,
      f.confidence || '',
      f.status || 'OPEN',
      (f.recommendation || '').slice(0, 1000)
    ]));
  }
  return worksheet('Findings', rows);
}

function coverageSheet(findings, runResults) {
  const rows = [row([{ v: 'Catalog case', s: 'header' }, { v: 'Stack', s: 'header' },
    { v: 'Coverage', s: 'header' }, { v: 'Decided by', s: 'header' }, { v: 'Finding id(s)', s: 'header' }])];

  // caseId -> { coverage records, finding ids whose tests[] claim it }
  const cases = new Map();
  for (const r of runResults || []) {
    for (const rec of r.catalogCoverage || []) {
      const cur = cases.get(rec.caseId) || { stack: rec.stack, by: new Set(), findingIds: new Set() };
      cur.by.add(rec.tool + (rec.outcome ? ':' + rec.outcome : ''));
      cases.set(rec.caseId, cur);
    }
  }
  for (const f of findings) {
    for (const t of f.tests || []) {
      const cur = cases.get(t) || { stack: '', by: new Set(), findingIds: new Set() };
      cur.by.add('finding-evidence');
      cur.findingIds.add(f.findingId || '(pre-correlation)');
      cases.set(t, cur);
    }
  }
  if (!cases.size) rows.push(row(['(no catalog coverage data in this run)', '', 'not covered', '', '']));
  for (const [caseId, c] of [...cases.entries()].sort()) {
    const covered = [...c.by].some(b => /:checked$|finding-evidence/.test(b));
    rows.push(row([
      caseId, c.stack || '',
      covered ? 'covered' : 'not covered',
      [...c.by].sort().join(', '),
      [...c.findingIds].sort().join(', ')
    ]));
  }
  return worksheet('Coverage', rows);
}

// ---------------------------------------------------------------- assembly

/**
 * Build the workbook XML.
 * @param {object} args { findings, runResults, stats }
 * @returns {string} the SpreadsheetML document
 */
function buildWorkbook(args) {
  const { findings = [], runResults = [], stats } = args;
  return `<?xml version="1.0"?>
<?mso-application progid="Excel.Sheet"?>
<Workbook xmlns="${NS}" xmlns:ss="${SS}" xmlns:o="${O}" xmlns:x="${X}">
${STYLES}
${summarySheet(findings, runResults, stats)}
${findingsSheet(findings)}
${coverageSheet(findings, runResults)}
</Workbook>
`;
}

/**
 * Write data/report.excel.xml under the report directory.
 * @returns {string} the absolute path written
 */
function writeExcel(reportDir, args) {
  const p = path.join(reportDir, 'data', 'report.excel.xml');
  fs.mkdirSync(path.dirname(p), { recursive: true });
  fs.writeFileSync(p, buildWorkbook(args));
  return p;
}

// ---------------------------------------------------------------- parse-back verifier
//
// A STRICT but small XML parser: enough to prove well-formedness (tag balance, quoting,
// entity validity) and to walk Worksheet/Table/Row/Cell/Data for structural assertions.
// This is the parse-back half of "generate AND verify it opens" — the file is not trusted
// because we wrote it; it is trusted because it re-parses to the same shape.

function verify(xmlString) {
  const s = String(xmlString);
  const errors = [];
  const sheets = [];
  const stack = [];             // open elements: {name, cells, rows, text, ssName, type}
  let i = 0;
  const openOf = name => {
    for (let k = stack.length - 1; k >= 0; k--) if (stack[k].name === name) return stack[k];
    return null;
  };

  /** Text runs only legally appear inside <Data>; anything else is structural text we flag. */
  const pushText = text => {
    const top = stack[stack.length - 1];
    if (top && top.name === 'Data') top.text += text;
    else if (text.trim() !== '') errors.push(`text outside <Data> at ~${i}: ${JSON.stringify(text.trim().slice(0, 40))}`);
  };

  while (i < s.length) {
    if (s[i] !== '<') {
      const next = s.indexOf('<', i);
      const text = s.slice(i, next < 0 ? s.length : next);
      // only &-entities are legal escapes
      if (/&(?!amp;|lt;|gt;|quot;|apos;|#\d+;|#x[0-9a-fA-F]+;)/.test(text)) {
        errors.push(`bare or unknown entity in text at ~${i}: ${JSON.stringify(text.slice(0, 40))}`);
      }
      pushText(text.replace(/&lt;/g, '<').replace(/&gt;/g, '>').replace(/&quot;/g, '"')
        .replace(/&apos;/g, "'").replace(/&amp;/g, '&'));
      i = next < 0 ? s.length : next;
      continue;
    }
    if (s.startsWith('<?', i)) {
      const end = s.indexOf('?>', i);
      if (end < 0) { errors.push('unterminated processing instruction'); break; }
      i = end + 2; continue;
    }
    if (s.startsWith('<!--', i)) {
      const end = s.indexOf('-->', i);
      if (end < 0) { errors.push('unterminated comment'); break; }
      i = end + 3; continue;
    }
    const tagEnd = s.indexOf('>', i);
    if (tagEnd < 0) { errors.push('unterminated tag'); break; }
    let rawTag = s.slice(i + 1, tagEnd);
    i = tagEnd + 1;
    let selfClose = false;
    if (rawTag.endsWith('/')) { selfClose = true; rawTag = rawTag.slice(0, -1); }
    const isClosing = rawTag.startsWith('/');
    if (isClosing) rawTag = rawTag.slice(1);
    const nameMatch = rawTag.match(/^[\w.:-]+/);
    if (!nameMatch) { errors.push(`malformed tag near offset ${i}: ${JSON.stringify(rawTag.slice(0, 30))}`); break; }
    const name = nameMatch[0];

    // attribute sanity: every = is followed by a quoted value, nothing legal in between
    const attrText = rawTag.slice(name.length);
    const attrRe = /([\w:.-]+)\s*=\s*("([^"]*)"|'([^']*)')/g;
    let consumed = 0, am;
    while ((am = attrRe.exec(attrText)) !== null) {
      if (attrText.slice(consumed, am.index).trim() !== '') {
        errors.push(`unquoted attribute text near ${JSON.stringify(attrText.slice(consumed, am.index + am[0].length).slice(0, 40))}`);
      }
      consumed = am.index + am[0].length;
    }
    if (attrText.slice(consumed).trim() !== '') {
      errors.push(`malformed attribute(s) in <${name}>: ${JSON.stringify(attrText.slice(consumed).slice(0, 40))}`);
    }

    if (isClosing) {
      const closing = name;
      const top = stack.pop();
      if (!top || top.name !== closing) {
        errors.push(`mismatched close </${closing}> (open: ${top ? top.name : 'none'})`);
        break;
      }
      if (closing === 'Cell') {
        const rowEl = openOf('Row'), tbl = openOf('Table'), ws = openOf('Worksheet');
        if (!rowEl || !tbl || !ws) { errors.push('Cell outside Row/Table/Worksheet'); break; }
        const dataChild = top.dataText == null ? '' : top.dataText;
        rowEl.cells.push({ data: dataChild, type: top.dataType || 'String' });
      } else if (closing === 'Data') {
        const cellEl = openOf('Cell');
        if (!cellEl) { errors.push('Data outside Cell'); break; }
        cellEl.dataText = top.text;
        cellEl.dataType = top.type;
      } else if (closing === 'Row') {
        const tbl = openOf('Table'), ws = openOf('Worksheet');
        if (!tbl || !ws) { errors.push('Row outside Table/Worksheet'); break; }
        tbl.rows.push({ cells: top.cells });
      } else if (closing === 'Table') {
        const ws = openOf('Worksheet');
        if (!ws) { errors.push('Table outside Worksheet'); break; }
        ws.rows = top.rows;
      } else if (closing === 'Worksheet') {
        sheets.push({ name: top.ssName || '', rows: top.rows || [] });
      }
      continue;
    }

    // opening tag
    const el = { name, cells: [], rows: [], text: '' };
    const ssName = attrText.match(/ss:Name\s*=\s*"([^"]*)"/);
    const ssType = attrText.match(/ss:Type\s*=\s*"([^"]*)"/);
    if (ssName) el.ssName = ssName[1];
    if (ssType) el.type = ssType[1];
    stack.push(el);
    if (selfClose) {
      stack.pop();
      if (name === 'Cell') {
        const rowEl = openOf('Row');
        if (!rowEl) { errors.push('self-closed Cell outside Row'); break; }
        rowEl.cells.push({ data: '', type: 'String' });
      }
    } else if (name === 'Data') {
      el.text = '';
    }
  }
  if (stack.length) errors.push(`unclosed element(s): ${stack.map(x => x.name).join(', ')}`);
  if (!sheets.length) errors.push('no Worksheet elements parsed');

  return {
    ok: errors.length === 0,
    errors,
    sheets: sheets.map(w => ({
      name: w.name,
      rowCount: w.rows.length,
      rows: w.rows.map(r => r.cells.map(c => c.data))
    }))
  };
}

module.exports = { buildWorkbook, writeExcel, verify, escCell, stripIllegal, sheetName };
