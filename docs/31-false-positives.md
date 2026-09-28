# False Positives and Suppressions

## What

Lifecycle for findings that are wrong, accepted, or mitigated: status, suppression id, reason, owner, approver, expiry and review date.

## Why

Suppression is necessary and dangerous. Without an expiry it becomes permanent invisible risk.

## How

Set `status` to `FALSE_POSITIVE`, `ACCEPTED_RISK` or `MITIGATED` and attach a `suppression` block. `expiresOn` is **mandatory** — the projection fails the build on a suppression without one, so permanent silent suppression is structurally impossible.

## What To Test

A suppression without an expiry fails the build; an expired suppression re-surfaces the finding.

## What Can Be Automated

Expiry enforcement, re-surfacing, and reporting suppression counts per owner.

## What Requires Manual Review

Whether the stated reason is genuine, and whether the approver had the authority.

## Common Failure Modes

Blanket inline suppressions with no reason. Suppressing a finding because it is inconvenient rather than incorrect. Never revisiting.

## Example

A real tuned false positive from the reference run: `dotnet-commented-credential` used a bounded lazy match `.{0,600}?` after `<!--`, because Go's RE2 engine has no lookahead and the idiomatic `(?:(?!-->).)*?` was unavailable. The bounded match spanned out of a prose comment at `Web.config:8` into an unrelated live `<add>` element. Fix: require the comment body to consist of `<add>` elements. Findings went **18 → 17**, and the rule was corrected rather than the finding suppressed — which is always the better outcome.

## Remediation

Prefer fixing the rule over suppressing the finding; when suppressing, require reason, owner, approver and expiry; review expiries on a schedule.

---

Part of [dotnet-moraa-codereviewer](../README.md). See also [methodology](01-methodology.md), [CVSS](30-cvss.md), [false positives](31-false-positives.md), [AI review](32-ai-review.md).
