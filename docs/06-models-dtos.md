# Models, DTOs and ViewModels

## What

Validation coverage, type strength, over-posting exposure and the mapping boundary between transport types and domain entities.

## Why

A DTO is where untrusted input becomes typed data. Weak or uneven validation here pushes the burden onto every downstream consumer.

## How

Enumerate public properties per DTO; measure how many carry a validation attribute; prefer `decimal`/`Guid`/`DateTime`/enums over `string`; verify binding cannot set server-controlled fields.

## What To Test

Null, empty, whitespace, boundary, over-long, wrong-type, extra unexpected properties, and culture-variant numeric/date input for every DTO reaching a decision path.

## What Can Be Automated

Validation coverage as a percentage, with a build-failing floor (proposed `moraa-arch-dto-validation-coverage`). Reflection over the DTO namespace is enough.

## What Requires Manual Review

Whether the permitted character set is right for the field — `^[\p{L}\p{M}'\-. ]+$` for a name is a judgement about real customer data, not a rule.

## Common Failure Modes

A single catch-all sanitiser applied by hand, so coverage silently drifts. Using `string` for money and dates. Denylists instead of allow-lists.

## Example

Reference run: roughly half of all `public string` DTO properties carried a validation attribute. The uncovered files were the largest and most sensitive — the three largest write-path DTOs. Coverage was *inverted* (`SEC-VAL-001`).

## Remediation

Replace the catch-all with per-field allow-list attributes, strengthen types, and gate coverage in CI.

---

Part of [dotnet-moraa-codereviewer](../README.md). See also [methodology](01-methodology.md), [CVSS](30-cvss.md), [false positives](31-false-positives.md), [AI review](32-ai-review.md).
