# Build and Test Verification

## What

Proving the code compiles and the tests run, with exit codes captured, before believing any analysis of it.

## Why

Analyzers that need compilation produce nothing useful on a broken build. A green build with no analyzers is also a false comfort worth naming.

## How

Legacy: `nuget restore` + `MSBuild.exe Sln -t:Build`. SDK: `dotnet restore`/`build`/`test`. Always record COMMAND, PURPOSE, RESULT, EXIT CODE, OUTPUT, INTERPRETATION, and use the vocabulary EXECUTED / FAILED / NOT AVAILABLE / NOT APPLICABLE / UNVERIFIED.

## What To Test

Build from a clean tree; build in Release (not just Debug), because Release is what transforms configuration; assert the test run executed a non-zero number of tests.

## What Can Be Automated

Everything, including the distinction between "tests passed" and "no tests exist" — these must never render identically.

## What Requires Manual Review

Deciding whether a build warning is benign. The reference run's leftover Sonar-targets warning was; a missing analyzer package would not be.

## Common Failure Modes

Reporting `dotnet test` as passing when zero tests ran. Building only Debug and missing that the Release transform is the only thing neutralising `debug="true"`.

## Example

Reference run: MSBuild exit 0, `YourApp -> YourApp\bin\YourApp.dll`. `dotnet test` → NOT APPLICABLE, because the solution has one project and no test framework (`TEST-COV-001`).

## Remediation

Make build and test blocking CI gates; fail the pipeline when the executed-test count is zero.

---

Part of [dotnet-moraa-codereviewer](../README.md). See also [methodology](01-methodology.md), [CVSS](30-cvss.md), [false positives](31-false-positives.md), [AI review](32-ai-review.md).
