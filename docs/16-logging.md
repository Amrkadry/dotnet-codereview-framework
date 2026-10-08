# Logging

## What

What is logged, where it lands, who can read it, how long it is kept, and whether security events are distinguishable.

## Why

Logging is simultaneously a control and an exposure. Over-logging creates a regulated-data archive; under-logging makes attacks undetectable. Both usually coexist.

## How

Find every logging layer (message handlers, action filters, exception handlers) and check for duplication. Verify no request/response bodies are written unmasked. Check the sink path against the webroot. Check for a correlation id and for a distinct security-audit channel.

## What To Test

Post a synthetic national ID and salary; assert neither appears in any emitted log line. Fetch the log directory over HTTP; assert 403/404. Assert authentication failures are logged as security events.

## What Can Be Automated

Body-logging detection; log directory resolving under `AppDomain.BaseDirectory`; missing correlation id.

## What Requires Manual Review

Which fields are sensitive in this domain, and what retention policy applies.

## Common Failure Modes

Three overlapping layers each logging the full body. Logs inside the webroot. Sync-over-async body reads on the error path. Security events buried at `Information` among payload dumps.

## Example

Reference run: three layers logged full request and response bodies unmasked, into `AppDomain.BaseDirectory\Logs` — inside the webroot, so potentially fetchable at `/Logs/log_<date>.txt` (`SEC-LOG-001`). No correlation id, no security-audit channel, and `ForContext` results discarded as no-ops.

## Remediation

Log metadata plus a correlation id; mask by allow-list; move sinks outside the webroot and deny by config; add a separate audit channel with its own retention.

---

Part of [dotnet-moraa-codereviewer](../README.md). See also [methodology](01-methodology.md), [CVSS](30-cvss.md), [false positives](31-false-positives.md), [AI review](32-ai-review.md).
