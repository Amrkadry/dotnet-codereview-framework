# Test Gap Analysis

## What

Identifying untested code, branches, security controls, endpoints, exception paths and configuration — not just reporting a coverage percentage.

## Why

Coverage measures lines executed, not risks covered. A 70%-covered codebase can have zero authorization tests.

## How

Cross-reference each endpoint, each security control and each `catch` block against existing tests. Emit a gap table with risk and priority. Every canonical finding carries `tests[]` and `regressionTest`, so the gap list derives from the findings automatically.

## What To Test

That the gap report itself is regenerated each run and that closing a finding removes its gap entry.

## What Can Be Automated

Endpoint enumeration, branch coverage, and the finding→required-test mapping (`reports/06-test-gaps.md` is generated).

## What Requires Manual Review

Risk ranking of each gap.

## Common Failure Modes

Reporting "0% coverage" as a metric without converting it into a prioritised, actionable gap list.

## Example

Reference run: coverage is 0% because no tests exist, so the gap list is the full set of `regressionTest` entries across all 31 findings — generated into `reports/06-test-gaps.md` rather than hand-written.

## Remediation

Work the generated gap table in priority order, starting with the authorization matrix.

---

Part of [dotnet-moraa-codereviewer](../README.md). See also [methodology](01-methodology.md), [CVSS](30-cvss.md), [false positives](31-false-positives.md), [AI review](32-ai-review.md).
