# CI/CD

## What

The pipeline that makes every other recommendation enforceable: restore, build, test, analyzers, secret scan, dependency scan, SARIF upload.

## Why

Almost every remediation in a review ends "wire this into CI". Without a pipeline, none of them is actionable.

## How

Define blocking gates in order of cost: build, analyzers, tests, secret scan, dependency scan. Upload SARIF so findings appear in code review rather than a report nobody opens.

## What To Test

Pipeline self-test: introduce a secret, a vulnerable package and a failing test, and confirm each independently fails the build.

## What Can Be Automated

By definition, all of it.

## What Requires Manual Review

Which gates block versus warn during adoption, so a legacy codebase is not made undeliverable on day one.

## Common Failure Modes

Running scanners without `--exit-code`/`--failOnCVSS`, so they report and nothing happens. Using stock secret-scanner rules on .NET and getting a green light that means nothing.

## Example

Reference run: no `.github/`, no `azure-pipelines.yml`, no `.gitlab-ci.yml`, no `Jenkinsfile`, no `Dockerfile`, no `.git`. The recommended pipeline is in `ci/` and deliberately uses the custom gitleaks ruleset, because the stock one returns zero on this repository.

## Remediation

Adopt `ci/github-actions.yml`; start gates as warnings on legacy code and blocking on new code; upload SARIF.

---

Part of [dotnet-moraa-codereviewer](../README.md). See also [methodology](01-methodology.md), [CVSS](30-cvss.md), [false positives](31-false-positives.md), [AI review](32-ai-review.md).
