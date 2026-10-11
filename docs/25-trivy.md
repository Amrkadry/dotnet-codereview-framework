# Trivy

## What

Filesystem, dependency, secret, licence and container scanning — useful for .NET precisely because it does not need project evaluation.

## Why

Trivy reads manifests directly, so it works on `packages.config` projects where `dotnet list package --vulnerable` fails outright.

## How

`trivy fs --scanners vuln,secret,license --format sarif -o trivy.sarif .` and, if containerised, `trivy image <tag>`. Gate with `--exit-code 1 --severity HIGH,CRITICAL`.

## What To Test

That the scanner produced a non-empty report; that a known-vulnerable test package is detected; that the gate fails as configured.

## What Can Be Automated

All of it, including SARIF upload.

## What Requires Manual Review

Exploitability of each advisory in this application, and licence-policy decisions.

## Common Failure Modes

Running without `--exit-code`, so the pipeline stays green. Assuming a clean result when the manifest was not recognised.

## Example

Reference run: Trivy was **NOT AVAILABLE** (not installed), and this is stated rather than glossed. It is the recommended remedy for `DEP-AUDIT-001` because it reads `packages.config` without needing the VS web targets.

## Remediation

Install Trivy and add it as the dependency and secret gate; combine with the .NET gitleaks ruleset, since Trivy's secret rules share the high-entropy bias.

---

Part of [dotnet-moraa-codereviewer](../README.md). See also [methodology](01-methodology.md), [CVSS](30-cvss.md), [false positives](31-false-positives.md), [AI review](32-ai-review.md).
