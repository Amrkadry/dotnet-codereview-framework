# Outdated Dependencies

## What

The MAINTENANCE queue: outdated, EOL, deprecated, duplicated and licence-restricted packages. Strictly separate from the SECURITY queue.

## Why

An old package is not automatically a vulnerability, and a current package can still carry one. Conflating them produces both false urgency and false comfort.

## How

Inventory every package with current version, latest, target framework, age, EOL status, licence, and whether another package already provides the capability. Assign `cvss: null` — the scoring model is not meaningful here.

## What To Test

A regression test per upgrade, especially across breaking changes; a policy test asserting one library per capability.

## What Can Be Automated

Version currency, EOL and licence checks, and duplicate-capability detection.

## What Requires Manual Review

Breaking-change risk and upgrade sequencing.

## Common Failure Modes

Labelling a package vulnerable because it is old. Missing that two libraries provide the same capability, so a fix in one leaves the other exposed.

## Example

Reference run: 120 packages. Retired ADAL alongside its MSAL replacement; a ~2003 SQL helper (referenced but unused); **four** spreadsheet parsers; **two** SFTP stacks — and the host-key finding belonged to WinSCP, not the SSH.NET fork an earlier draft blamed; EPPlus 7.6.0 under a non-commercial licence, a legal exposure for a regulated product (`DEP-MAINT-001`, `cvss: null`).

## Remediation

One library per capability; remove retired packages; resolve the licence question; migrate to PackageReference so audits and lockfiles become possible.

---

Part of [dotnet-moraa-codereviewer](../README.md). See also [methodology](01-methodology.md), [CVSS](30-cvss.md), [false positives](31-false-positives.md), [AI review](32-ai-review.md).
