# Dependency Security

## What

The SECURITY queue: confirmed advisories against the exact versions in use, with exploitability assessed for this application.

## Why

This queue drives urgent patching. Mixing it with "outdated" destroys its signal.

## How

Run a scanner that can read the project shape. `dotnet list package --vulnerable` needs PackageReference; `packages.config` needs OWASP Dependency-Check or Trivy. Record CVE, CVSS, affected and fixed versions, and whether the vulnerable code path is reachable here.

## What To Test

A regression test per upgrade; a CI gate failing above a severity threshold; a meta-check that the scanner actually produced a report.

## What Can Be Automated

Entirely — provided capability detection picks a scanner that can read the manifest.

## What Requires Manual Review

Exploitability in context. A vulnerable parser that never receives untrusted input is a different risk from one that does.

## Common Failure Modes

Reporting an empty SECURITY queue when no scanner ran. Citing a CVE that does not apply to the pinned version. Fabricating CVE identifiers.

## Example

Reference run: the SECURITY queue is **empty, and the report says why** — `dotnet list package --vulnerable` failed and no alternative scanner was installed (`DEP-AUDIT-001`). Of five CVE identifiers cited in the delegated inventory, all five were verified real and correctly characterised as patched-or-hedged; none was fabricated.

## Remediation

Install a manifest-appropriate scanner and gate CI on it; never present an unrun scan as a clean result.

---

Part of [dotnet-moraa-codereviewer](../README.md). See also [methodology](01-methodology.md), [CVSS](30-cvss.md), [false positives](31-false-positives.md), [AI review](32-ai-review.md).
