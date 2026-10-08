# 40 — Excel output

`data/report.excel.xml` — the risk-register format, written on every `review` (or alone with
`--format excel`):

```bash
node bin/moraa.js review /src/MyApp --format excel
```

## The format decision: SpreadsheetML 2003, zero dependencies

A real `.xlsx` is a ZIP container with a multi-part OOXML package inside; producing one without a
dependency means hand-rolling a zip writer — the most fragile thing this repo could ship.
**SpreadsheetML 2003** is the alternative Excel has opened natively since Office 2002: ONE XML
document with a `<?mso-application progid="Excel.Sheet"?>` processing instruction, so desktop Excel,
Microsoft 365 and LibreOffice all open it directly (double-click works; Excel may note the
extension is `.xml` — the content is a workbook). It costs zero dependencies, and its
well-formedness is checkable by a parser small enough to review by eye — which matters, because
the framework's rule is that output is *verified*, not assumed.

If a strict `.xlsx` is ever contractually required, that is the day one dependency (exceljs) is
justified — not before.

## The three sheets

| Sheet | Contents |
|---|---|
| **Summary** | Totals by severity, by tool (reported **and missed** — the honesty counters), by category, plus the correlation stats (raw → canonical, merged away, multi-tool confirmed). |
| **Findings** | id, severity, title, CWE, CVSS, file, line, **found by**, **missed by**, confidence, status, remediation — one row per canonical finding, severity-coloured. |
| **Coverage** | Every catalog case that any source reported coverage for, and whether it was **covered** (decided by a check or claimed by a finding) or **not covered** (manual-review / not applicable — which are undecided, not clean). Fed by the native engine's `catalogCoverage` records and each finding's `tests[]` ids. |

## Verification is part of the write

Every write is followed by a parse-back: the file is re-read and pushed through a strict XML
verifier (tag balance, attribute quoting, entity validity, Worksheet/Table/Row/Cell structure) and
the structure is compared to what was written. The verifier is itself tested against malformed
input — negative controls — because a verifier that cannot fail is decoration. A failed parse-back
prints a WARNING naming the file as suspect; it does not silently claim success.

Hostile content is the normal case: findings quote source code full of `< > & " '`. Every cell is
entity-escaped and XML-illegal control characters are stripped before serialisation; the round-trip
of such content through the verifier is pinned by tests.

## Compatibility notes

- Open directly in Excel (desktop/Microsoft 365) or LibreOffice Calc. Google Sheets imports it via
  File → Import.
- The file is plain UTF-8 XML — diff-able and grep-able, unlike a binary `.xlsx`.
- For CI consumption prefer `data/report.json` or `data/report.sarif`; the workbook is for humans.
