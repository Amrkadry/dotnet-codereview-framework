# Project Discovery

## What

Inventory of solution, projects, target frameworks, project style (SDK vs non-SDK), entry points, configuration, CI/CD, containers and version control.

## Why

Project shape determines which tools can run at all. Discovering `packages.config` + non-SDK early prevents reporting a clean dependency audit that never happened.

## How

Parse `.sln` for `^Project(`; read each `.csproj` for `TargetFramework(Version)`, `Import` of `Microsoft.WebApplication.targets`, and analyzer properties; check for `packages.config` vs `PackageReference`, `packages.lock.json`, `.editorconfig`, `Directory.Build.props`, `.github/`, `azure-pipelines.yml`, `Dockerfile`, `.git`.

## What To Test

That discovery correctly classifies a legacy web project, an SDK library and a test project; that a missing `.git` is reported rather than ignored.

## What Can Be Automated

All of it. Emit a machine-readable capability profile that gates later phases.

## What Requires Manual Review

Whether an absent pipeline genuinely does not exist or simply was not delivered with the source — the reference review could not settle this and said so.

## Common Failure Modes

Assuming one project; assuming `dotnet build` works; missing that `bin/`, `obj/` and `.vs/` were shipped with the source, which changes where secrets live.

## Example

Reference run: `grep -c '^Project(' YourApp.sln` → 1. No test project, no CI, no Dockerfile, no `.git`, no lockfile, no analyzers. Four findings came from this phase alone: `TEST-COV-001`, `DEP-AUDIT-001`, `CFG-BUILD-001`, `PROC-CICD-001`.

## Remediation

Record the capability profile in the report so readers know which conclusions rest on tools that could not run.

---

Part of [dotnet-moraa-codereviewer](../README.md). See also [methodology](01-methodology.md), [CVSS](30-cvss.md), [false positives](31-false-positives.md), [AI review](32-ai-review.md).
