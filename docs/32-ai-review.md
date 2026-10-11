# AI-Assisted Review

## What

Where AI review genuinely adds value, where it must not be trusted, and how its output is labelled and validated.

## Why

AI review is complementary to deterministic tooling, not a replacement for it — and the reverse is equally true. The reference run produced hard evidence in both directions.

## How

Label every source in `sources[]` with the producing tool and a status. Require `verification.disproofAttempt` before a finding is considered validated. Never let an AI conclusion inherit a tool's authority, or vice versa.

## What To Test

That every finding names its sources; that AI-only findings are marked; that the validation pass records a disproof attempt for each.

## What Can Be Automated

Source labelling, schema enforcement, and flagging findings that lack a disproof attempt.

## What Requires Manual Review

Whether an AI-proposed mechanism is actually true. This is where the reference run found its own worst errors.

## Common Failure Modes

Accepting a confident AI mechanism without checking its premises. Assuming a tool's silence is a clean result. Assuming an AI review can substitute for a dependency scanner or a secret scanner.

## Example

Reference run, both directions. **AI/review found what tools missed:** SonarQube reported 840 issues and none of the four Critical security findings; all four came from manual review. **A tool's confident zero was simply wrong:** stock gitleaks reported "no leaks found" across 49.18 MB on a repository with four live credential sets. **And the AI was wrong too:** the CORS finding's original credential-theft mechanism was void (no cookies exist anywhere), the crypto finding's zero-IV defect was in a method with no callers, and the DoS impact was overstated ~35x. All three were corrected only because a disproof pass ran.

## Remediation

Run both. Label both. Validate both. Treat any finding without a recorded disproof attempt as unvalidated, regardless of which produced it.

---

Part of [dotnet-moraa-codereviewer](../README.md). See also [methodology](01-methodology.md), [CVSS](30-cvss.md), [false positives](31-false-positives.md), [AI review](32-ai-review.md).
