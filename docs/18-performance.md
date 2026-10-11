# Performance and Availability

## What

Resource limits, buffering, timeouts, algorithmic complexity, N+1 queries and unbounded allocation.

## Why

In an unauthenticated API, a cheap request that costs the server a lot is a denial-of-service primitive.

## How

Compare request limits at every layer (ASP.NET `maxRequestLength` vs IIS `maxAllowedContentLength`). Find code buffering whole bodies. Check every regex for a timeout. Check `executionTimeout`.

## What To Test

Body one byte over the limit → 413; pathological regex input → bounded time; sustained concurrent large bodies → stable working set.

## What Can Be Automated

Limit mismatch between layers; regex without timeout; whole-body buffering.

## What Requires Manual Review

What the legitimate maximum payload actually is.

## Common Failure Modes

Assuming the higher configured limit is the effective one. Overstating impact by ignoring a lower default at another layer — the reference review made exactly this error and corrected it by ~35x.

## Example

Reference run: `maxRequestLength` 1 GB, but no `requestFiltering`, so IIS's ~28.6 MB default bounded it. Within that, the logging handler still amplified ~3x (UTF-16 string plus parsed `JObject`) → ~85-120 MB per unauthenticated request (`PERF-DOS-001`). Separately, 14 regex sites had no timeout (`PERF-DOS-002`).

## Remediation

Set both limits deliberately and consistently; stop buffering; set a process-wide regex timeout in one line at startup; lower `executionTimeout`.

---

Part of [dotnet-moraa-codereviewer](../README.md). See also [methodology](01-methodology.md), [CVSS](30-cvss.md), [false positives](31-false-positives.md), [AI review](32-ai-review.md).
