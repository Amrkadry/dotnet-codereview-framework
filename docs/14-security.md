# Security Review

## What

The cross-cutting pass over OWASP Top 10 plus .NET-specific classes: secrets, transport, crypto, logging, file handling, deserialization, SSRF, XXE and misconfiguration.

## Why

Class-by-class sweeps catch what endpoint-by-endpoint review misses, and they let negative results be recorded with their basis.

## How

Work the class list, and for each record either a finding or an explicit clean result with the evidence. Grep-driven starting points: `BinaryFormatter`, `TypeNameHandling`, `XmlDocument`/`XmlResolver`, `Process.Start`, `ServerCertificateValidationCallback`, `Aes`/`Rfc2898DeriveBytes`, `Path.Combine`, `HttpClient` with user-controlled URIs.

## What To Test

One negative test per class, so a regression re-opens visibly rather than silently.

## What Can Be Automated

Most sink detection. Not reachability, and not business impact.

## What Requires Manual Review

Chaining. Individually-medium findings can combine into a critical path, which no single rule sees.

## Common Failure Modes

Reporting sinks without reachability. Omitting clean classes, so a later reviewer cannot tell what was checked.

## Example

Reference run clean results, each with basis: no XXE (no `XmlDocument`/`XmlReader`; XML formatter explicitly cleared), no unsafe deserialization (no `BinaryFormatter`, Newtonsoft without `TypeNameHandling`), no command injection (no `Process.Start`), no SQL injection (EF6 + LINQ only). Chaining example: `SEC-CORS-001` + `SEC-AUTHZ-001` together turn an internal API into an internet-reachable one.

## Remediation

Fix by chain, not by individual severity: closing the perimeter findings first collapses several others.

---

Part of [dotnet-moraa-codereviewer](../README.md). See also [methodology](01-methodology.md), [CVSS](30-cvss.md), [false positives](31-false-positives.md), [AI review](32-ai-review.md).
