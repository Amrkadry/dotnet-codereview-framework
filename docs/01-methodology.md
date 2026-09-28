# Review Methodology

## What

The eight-phase, evidence-first process: discovery, build/test verification, tool execution with capability detection, ingestion of prior outputs, normalization, correlation and dedup, adversarial validation, projection.

## Why

Reviews fail in two directions: they miss real issues, and they assert issues that are not real. Separating *finding* from *validating* addresses the second, which is the one that destroys a report's credibility. In the reference run, adversarial validation corrected 3 of 26 findings and strengthened 2.

## How

Each phase writes into the canonical JSON (`schema/finding.schema.json`). No phase edits a rendered report. `tools/project-findings.js` regenerates every view and fails on integrity violations.

## What To Test

That the projection is reproducible; that every finding has at least one `sources[]` entry; that no non-scoreable category carries a CVSS; that every FALSE_POSITIVE has an expiring suppression.

## What Can Be Automated

Discovery, build, tool execution, schema validation, correlation by location+rule, dedup, projection to Markdown/JSON/SARIF, and the integrity gate.

## What Requires Manual Review

Severity adjustment against business context, exploitability judgement, and the disproof attempt in Phase 7. A model can propose a disproof; a human decides whether the attempt was serious.

## Common Failure Modes

Trusting a tool's silence (stock gitleaks reported zero on a repo with four live credential sets). Trusting an AI's confident mechanism (the CORS finding's original credential-theft explanation was void). Inflating a latent sink into a live vulnerability.

## Example

Phase 7 applied to a path-traversal candidate: the sink was real, but the only caller passed a server-generated filename. Outcome: recorded as LOW/latent with `cvss: null`, not HIGH. See `SEC-FILE-002`.

## Remediation

Adopt phases 1-8 in order. Do not let Phase 8 run before Phase 7. Treat any finding lacking `verification.disproofAttempt` as unvalidated.

---

Part of [dotnet-moraa-codereviewer](../README.md). See also [methodology](01-methodology.md), [CVSS](30-cvss.md), [false positives](31-false-positives.md), [AI review](32-ai-review.md).
