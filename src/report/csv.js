'use strict';
/**
 * CSV projection — one row per finding, with every location flattened.
 *
 * Built for the spreadsheet side of a review: import into Excel/Sheets, or feed the
 * title+snippet columns into any downstream workflow. Same canonical data as
 * report.json; nothing is summarized away.
 *
 * Columns: id, severity, confidence, category, cwe, title, file, line, tools,
 *          confirmed_by, problem, recommendation, snippet
 * Tools columns list every contributing tool ("native+sonarqube+gitleaks").
 */

const fs = require('fs');

const csvField = (v) => {
  const s = String(v == null ? '' : v);
  return /[",\r\n]/.test(s) ? '"' + s.replace(/"/g, '""') + '"' : s;
};

function writeCsv({ outPath, findings }) {
  const header = 'id,severity,confidence,category,cwe,title,file,line,tools,confirmed_by,problem,recommendation,snippet';
  const rows = [header];

  for (const f of findings) {
    const cwe = (f.cwe || []).join(' ');
    const tools = [...new Set((f.sources || []).map(s => s.tool))].join('+');
    const reported = (f.sources || []).filter(s => s.status === 'REPORTED').map(s => s.tool);
    const confirmedBy = reported.length > 1 ? reported.join('+') : '';
    const snippet = ((f.evidence && f.evidence.snippet) || '').replace(/\r/g, '');
    const base = {
      id: f.findingId,
      severity: f.severity,
      confidence: f.confidence,
      category: f.category,
      cwe,
      title: f.title,
      tools,
      confirmedBy,
      problem: f.problem || '',
      recommendation: f.recommendation || '',
    };

    // primary location first, then consolidated extras — every location is a row
    const locations = [{ file: f.location.file, startLine: f.location.startLine }]
      .concat(f.location.additionalLocations || []);
    locations.forEach((loc, i) => {
      rows.push([
        base.id, base.severity, base.confidence, base.category, base.cwe, base.title,
        loc.file, loc.startLine || '', base.tools, base.confirmedBy,
        i === 0 ? base.problem : `${base.problem} (additional location ${i + 1} of ${locations.length})`,
        i === 0 ? base.recommendation : '',
        i === 0 ? snippet : '',
      ].map(csvField).join(','));
    });
  }

  fs.writeFileSync(outPath, rows.join('\r\n') + '\r\n', 'utf8');
  return findings.reduce((n, f) =>
    n + 1 + ((f.location && f.location.additionalLocations) || []).length, 0);
}

module.exports = { writeCsv };
