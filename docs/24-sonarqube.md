# SonarQube

## What

Running and interpreting SonarQube for .NET, including its real strengths and its documented blind spots.

## Why

Sonar is valuable and widely trusted, which makes understanding what it does *not* find essential.

## How

.NET Framework requires the **MSBuild** scanner, not the CLI scanner: `SonarScanner.MSBuild.exe begin /k:<key>` → `msbuild /t:Rebuild` → `end`. Raw analyzer output also lands in `.sonarqube/out/0/Issues.json` and can be parsed directly without a server.

## What To Test

That the quality gate fails the build; that the scan covers every project; that new-code conditions are enforced.

## What Can Be Automated

Scan execution and gate enforcement. Parsing `Issues.json` offline is a useful fallback when no server is reachable.

## What Requires Manual Review

Triaging ~800 maintainability issues into what actually matters, and recognising which security classes Sonar cannot see.

## Common Failure Modes

Using the CLI scanner on .NET Framework and getting no C# analysis. Treating a passing Sonar gate as a security sign-off. Ignoring that Sonar analyses compiled code and therefore never reads `Web.config`.

## Example

Reference run: 840 issues across 51 rules — and **none of the four Critical security findings**. Genuine contributions: `S2068` (hard-coded credential), `S3329` (static IV), `S6444` ×13 (regex timeout), `S1450` (shared field). Blind: missing authorization, reflected CORS, disabled TLS validation, PII in logs, and everything in configuration.

## Remediation

Run Sonar for maintainability and as one corroborating security source; pair it with a secret scanner, a dependency scanner, configuration rules and manual authorization review.

---

Part of [dotnet-moraa-codereviewer](../README.md). See also [methodology](01-methodology.md), [CVSS](30-cvss.md), [false positives](31-false-positives.md), [AI review](32-ai-review.md).
