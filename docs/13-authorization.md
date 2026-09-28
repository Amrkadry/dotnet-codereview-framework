# Authorization

## What

Whether the populated principal is ever actually consulted: global default, per-endpoint roles, and per-object ownership.

## Why

Authentication without authorization is the most common critical finding in business APIs, and it is invisible to analyzers that reason file-by-file.

## How

Count `[Authorize]` against the number of controllers. Check for a global authorization filter. Trace each role claim back to its source and confirm the source is actually populated. For every endpoint taking an object id, find the ownership comparison.

## What To Test

Two-account matrix: A's token against B's object id must fail. No token must fail. Wrong role must fail. A valid id belonging to another branch must fail.

## What Can Be Automated

Controllers lacking `[Authorize]`/`[AllowAnonymous]`; absence of a global filter. Ownership-check *presence* can be approximated; correctness cannot.

## What Requires Manual Review

Whether the ownership comparison uses the right claim and the right field.

## Common Failure Modes

A role claim derived from a field that is never fetched, so it is permanently false. Trusting an id in the request body. Assuming network isolation is authorization.

## Example

Reference run: two distinct failures. `SEC-AUTHZ-001` — one `[Authorize]` across 20 controllers, no global filter, no ownership checks anywhere. `SEC-AUTHZ-002` — a privileged role was read from an entity attribute that was never included in the requested column set, so it always evaluated to false and was then compared against a differently-cased string. The root cause was a code comment falsely claiming the data-access helper retrieved all attributes.

## Remediation

Deny by default globally; fail closed when a role attribute is missing; verify ownership against a claim, never against a request field.

---

Part of [dotnet-moraa-codereviewer](../README.md). See also [methodology](01-methodology.md), [CVSS](30-cvss.md), [false positives](31-false-positives.md), [AI review](32-ai-review.md).
