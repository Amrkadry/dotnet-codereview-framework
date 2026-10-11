# Reporting

## What

The three synchronized representations — Markdown for humans, JSON for machines, SARIF for CI — all projected from the canonical findings.

## Why

Hand-authored parallel reports drift. When the exec summary and the security report disagree on a count, the whole document loses authority.

## How

`node tools/project-findings.js reviews/<id>`. It merges canonical parts, validates integrity, sorts, and writes `report.json`, `report.sarif` and the Markdown views. Generated files carry a do-not-edit notice.

## What To Test

Projection is deterministic; SARIF validates against the 2.1.0 schema; counts in the exec summary equal counts in the canonical JSON.

## What Can Be Automated

All projection, plus the integrity gate that refuses to emit an inconsistent report.

## What Requires Manual Review

The narrative framing in the executive summary — which findings to lead with, and why.

## Common Failure Modes

Editing a generated report. Inflating counts by reporting the same vulnerability once per detecting tool.

## Example

Reference run: 31 findings from 6 canonical parts → `report.json`, a valid SARIF 2.1.0 (31 rules, 31 results, `security-severity` populated) and 6 Markdown views, with zero integrity errors. Multi-tool detections stay single findings via `correlation.mergedFrom`.

## Remediation

Never author a report directly; add a CI check that generated reports are unmodified.

---

Part of [dotnet-moraa-codereviewer](../README.md). See also [methodology](01-methodology.md), [CVSS](30-cvss.md), [false positives](31-false-positives.md), [AI review](32-ai-review.md).
