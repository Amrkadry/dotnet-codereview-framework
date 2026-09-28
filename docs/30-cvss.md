# CVSS Scoring

## What

When CVSS applies, when it must be `N/A`, and how business severity may legitimately differ from the base score.

## Why

Scoring everything makes the scores meaningless. Scoring nothing makes prioritisation impossible. The boundary has to be explicit and enforced.

## How

Score only where the model is meaningful: a vulnerability with an attacker, a vector and an impact. Set `cvss: null` for maintainability, architecture, testing, process and formatting findings — the projection enforces this for `architecture`, `testing` and `process`. Record `conditionalScore` separately when a score depends on an unverified precondition; never report it as the headline.

## What To Test

Schema negative tests: a CVSS attached to an architecture finding must fail the build; a malformed vector must fail.

## What Can Be Automated

Vector validation, score/severity consistency, and the category rule.

## What Requires Manual Review

Every metric choice, especially `AC` and `S`, and any divergence between CVSS severity and business severity.

## Common Failure Modes

Scoring a code smell because it sounds security-adjacent. Using the conditional worst-case score as the headline. Letting CVSS override business context in a regulated environment.

## Example

Reference run: 20 findings scored, **11 deliberately N/A**. Two documented divergences — `SEC-CRYPTO-001` is CVSS 7.4 HIGH (MITM needs `AC:H`) but business CRITICAL, because one flag disables certificate validation process-wide for core banking, CRM and the credit bureau; `SEC-CFG-001` is CVSS 8.8 but business CRITICAL. Each carries a written `severityRationale`. `SEC-AUTH-001` is scored 5.3 for its confirmed subset with a `conditionalScore` of 9.8 if the domain permits empty-password binds.

## Remediation

Require `severityRationale` whenever severity and CVSS severity differ; keep conditional scores in their own field; never merge the two dependency queues under one score.

---

Part of [dotnet-moraa-codereviewer](../README.md). See also [methodology](01-methodology.md), [CVSS](30-cvss.md), [false positives](31-false-positives.md), [AI review](32-ai-review.md).
