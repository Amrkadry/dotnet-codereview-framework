# Framework Architecture

## What

A canonical-JSON core with pluggable collectors (build, analyzers, scanners, AI) and pure projections (Markdown, JSON, SARIF).

## Why

If reports are authored directly, they drift apart and the numbers stop matching. Making the JSON authoritative means the security report, the exec summary and the SARIF cannot disagree.

## How

Collectors write `findings-*.json` parts. `project-findings.js` merges, validates, sorts (severity → CVSS → confidence → id) and emits views. Nothing downstream may add a fact.

## What To Test

Round-trip: projecting twice yields identical bytes. Schema negative tests: duplicate id, missing sources, malformed vector, CVSS on an architecture finding — each must fail the build.

## What Can Be Automated

The whole pipeline. It runs today: `node tools/project-findings.js reviews/example` produced 31 findings, `report.json`, a valid SARIF 2.1.0 file and six Markdown views with zero integrity errors.

## What Requires Manual Review

Authoring the canonical finding bodies — impact, root cause, corrected code. These are judgement, and the schema deliberately does not try to generate them.

## Common Failure Modes

Editing a generated report by hand (it will be overwritten). Adding a projection that invents a severity label not present in the canonical object.

## Example

Two independent dependency queues are a projection concern, not a data concern: `category=dependency` plus `cvss===null` selects the maintenance queue. No separate field is needed.

## Remediation

Add a CI step that runs the projection and fails if `git diff --exit-code reports/` is dirty, proving reports are generated rather than edited.

---

Part of [dotnet-moraa-codereviewer](../README.md). See also [methodology](01-methodology.md), [CVSS](30-cvss.md), [false positives](31-false-positives.md), [AI review](32-ai-review.md).
