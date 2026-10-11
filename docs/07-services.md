# Services and Application Logic

## What

Review of service-layer behaviour: error handling, transaction boundaries, idempotency, determinism, and shared mutable state.

## Why

Business rules live here. A service that silently returns a default on failure converts a loud error into a wrong answer, which is worse.

## How

Look for `catch` blocks whose only action is to return `0`, `null` or `default`; for instance fields on types registered as singletons; for culture-sensitive formatting; for duplicated implementations of the same calculation.

## What To Test

Each failure mode explicitly: dependency throws, dependency times out, dependency returns malformed data. Assert the caller observes a failure rather than a plausible-looking default.

## What Can Be Automated

Fail-silent detection (`catch` → `return 0`) and singleton-mutable-state detection are both deterministic and high value.

## What Requires Manual Review

Whether returning a default is *correct* for the domain. In a financial calculation, a zero result is never a safe default — it is a decision.

## Common Failure Modes

Swallowing exceptions to keep a flow alive; duplicating a calculation so a fix lands in one copy only; storing per-request data on a shared instance.

## Example

Reference run: `EvaluateExpression` caught every exception and returned `0`, on a monetary calculation path; three divergent implementations of `ComputeLimit` existed (`LOGIC-DEC-001`, `ARCH-001`).

## Remediation

Return `T?` or throw; log the identifier of the failing rule; route to manual review. Collapse duplicated calculations into one audited path.

---

Part of [dotnet-moraa-codereviewer](../README.md). See also [methodology](01-methodology.md), [CVSS](30-cvss.md), [false positives](31-false-positives.md), [AI review](32-ai-review.md).
