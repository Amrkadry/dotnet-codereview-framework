# Deployment

## What

How the artifact is produced and released: transforms, packaging, artifact contents and repeatability.

## Why

Several findings are only safe because a transform is applied. If releases are manual, that safety is an assumption rather than a control.

## How

Inspect each transform and the *built* output, not just source. Check whether build artifacts, IDE state and analyser output ship alongside source. Confirm the package is produced by a pipeline.

## What To Test

Assert the packaged config contains no `debug` attribute and no secrets; assert the artifact excludes `bin/`, `obj/`, `.vs/`.

## What Can Be Automated

Package content assertions, and diffing base configuration against the transformed result.

## What Requires Manual Review

Whether the documented release process is the one actually used.

## Common Failure Modes

Reviewing source configuration and never opening the built package. Hand-built releases that skip the transform.

## Example

Reference run: inspecting the build output proved the secrets and `DisableSSLValidation=true` reach deployment (`obj/Release/Package/PackageTmp/Web.config`, `bin/YourApp.dll.config`). It also showed `bin/`, `obj/`, `.vs/` and `.sonarqube/` shipped with the source, and no pipeline existed (`PROC-CICD-001`).

## Remediation

Build releases only from a pipeline; add `.gitignore` for build and IDE output; assert package contents as a gate.

---

Part of [dotnet-moraa-codereviewer](../README.md). See also [methodology](01-methodology.md), [CVSS](30-cvss.md), [false positives](31-false-positives.md), [AI review](32-ai-review.md).
