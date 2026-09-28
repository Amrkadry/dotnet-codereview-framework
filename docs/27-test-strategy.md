# Test Strategy

## What

The test pyramid for a legacy .NET application, and the order in which to build it when starting from zero.

## Why

Remediating security findings without tests risks trading a security defect for a behavioural one. Tests are a prerequisite for safe remediation, not a follow-up.

## How

Start with characterisation tests around the highest-risk logic (the core calculation logic), then security integration tests (401/403 per route), then unit tests for new code. Add a test project targeting the same framework; xUnit works on net48.

## What To Test

Order by risk: authorization matrix, authentication edge cases, core calculation correctness under hostile and culture-variant input, then everything else.

## What Can Be Automated

Execution, coverage measurement, and a coverage floor applied to new code only.

## What Requires Manual Review

What "correct" means for a lending decision — this is the specification the tests encode, and it must come from the business.

## Common Failure Modes

Chasing a global coverage number on a legacy base instead of covering risk. Writing only happy-path tests.

## Example

Reference run: the solution had **one project and no test framework** (`TEST-COV-001`, HIGH). All 31 findings are currently un-regression-testable, and the fail-to-zero calculation defect, the always-false role claim and the culture-dependent numeric formatting are each exactly what one unit test would have caught.

## Remediation

Add the test project; seed it with the `regressionTest` from each P0/P1 finding; set a floor on new code; make the test run a blocking gate.

---

Part of [dotnet-moraa-codereviewer](../README.md). See also [methodology](01-methodology.md), [CVSS](30-cvss.md), [false positives](31-false-positives.md), [AI review](32-ai-review.md).
