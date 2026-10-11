# API Design and Contracts

## What

Response contracts, status-code correctness, error shape, content negotiation, versioning and schema exposure.

## Why

Incorrect status codes hide failures from monitoring, and an exposed schema hands an attacker the route map.

## How

Check that validation failures return 400, authorization 401/403, size 413, content type 415, and downstream failure 502/504 rather than a blanket 500. Check whether Swagger/OpenAPI is gated.

## What To Test

Each status path explicitly; malformed JSON; wrong content type; oversized body; downstream timeout.

## What Can Be Automated

Unconditional Swagger registration; catch-all handlers that collapse every exception into 500.

## What Requires Manual Review

Whether an error message leaks too much, and whether a contract change is breaking.

## Common Failure Modes

A global handler returning 500 for client errors. Swagger enabled in production by an assembly-level attribute, which is unconditional by construction.

## Example

Reference run: Swagger registered via `[assembly: PreApplicationStartMethod]` with no environment check and no auth (`SEC-INFO-001`); non-JSON bodies produced 500 instead of 415 (`PERF-DOS-001`).

## Remediation

Gate Swagger behind a default-false setting; map exception types to correct status codes; validate content type before parsing.

---

Part of [dotnet-moraa-codereviewer](../README.md). See also [methodology](01-methodology.md), [CVSS](30-cvss.md), [false positives](31-false-positives.md), [AI review](32-ai-review.md).
