# Observability

## What

Health checks, metrics, tracing, alerting and the ability to reconstruct a request end to end.

## Why

Findings are only actionable if the system can show whether they are being exploited. A review that cannot answer "would we see this?" is incomplete.

## How

Check for a health endpoint, request metrics, a propagated correlation/trace id, and alerts on authentication failure rate, 5xx rate and memory pressure.

## What To Test

Health endpoint reflects dependency state; a correlation id survives across layers; an induced failure raises the expected alert.

## What Can Be Automated

Presence of a health endpoint and of correlation-id propagation.

## What Requires Manual Review

Alert thresholds and whether anyone actually receives them.

## Common Failure Modes

Logs without correlation ids, so concurrent requests cannot be separated — made worse when shared mutable state swaps metadata between them.

## Example

Reference run: no health endpoint, no metrics, no correlation id, and `CODE-CONC-001` actively corrupted attribution between concurrent failures. Detecting exploitation of the critical findings would not currently be possible.

## Remediation

Add a correlation id first — it is the prerequisite for every other observability improvement — then health, metrics and alerts on auth-failure and 5xx rates.

---

Part of [dotnet-moraa-codereviewer](../README.md). See also [methodology](01-methodology.md), [CVSS](30-cvss.md), [false positives](31-false-positives.md), [AI review](32-ai-review.md).
