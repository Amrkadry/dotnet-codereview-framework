# GitLeaks

## What

Secret scanning, and the custom .NET ruleset that makes it actually work on ASP.NET Framework applications.

## Why

This is the framework's clearest evidence that a tool must be validated, not trusted. Stock gitleaks reported **zero** leaks on a repository containing four sets of live cleartext passwords.

## How

Always pass the .NET config: `gitleaks dir . --config rules/gitleaks/dotnet-config.toml --redact --report-format sarif --report-path gitleaks.sarif`. Use `--redact` always. Scan history with `gitleaks detect` when a `.git` directory exists.

## What To Test

A canary: commit a fake `<add key="TestPassword" value="Str0ng!" />` and assert the scan fails. Without a canary you cannot distinguish "clean" from "not looking".

## What Can Be Automated

Scanning and gating. Rule authoring is manual and must be maintained as a first-class asset.

## What Requires Manual Review

Rule tuning, and confirming each hit is a real secret rather than a placeholder.

## Common Failure Modes

Trusting the default ruleset on .NET. Scanning only the working tree when history exists. Forgetting `--redact` and writing secrets into CI logs. Using lookahead in a rule — Go's RE2 does not support it.

## Example

Reference run, measured: stock rules → 49.18 MB scanned, **0 findings** (false negative). `rules/gitleaks/dotnet-config.toml` → 5.08 MB scanned (allow-list excludes `packages/`, `bin/`, `obj/`), **17 findings**: 9 appSetting secrets, 5 commented credentials, 2 weak static keys, 1 connection-string password. Faster *and* more precise.

## Remediation

Adopt the .NET ruleset, add a canary, gate CI with `--exit-code 1`, and treat the ruleset as code that is reviewed and version-controlled.

---

Part of [dotnet-moraa-codereviewer](../README.md). See also [methodology](01-methodology.md), [CVSS](30-cvss.md), [false positives](31-false-positives.md), [AI review](32-ai-review.md).
