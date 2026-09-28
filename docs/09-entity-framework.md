# Entity Framework

## What

EF-specific review: context lifetime, tracking, lazy loading, N+1, migrations, and connection-string handling.

## Why

EF removes most injection risk but introduces performance and configuration risk, and the connection string is usually where the credentials are.

## How

Check `DbContext` lifetime per request; look for lazy loading inside loops; confirm migrations are versioned; inspect the connection string for inline credentials and for `Encrypt`/`TrustServerCertificate`.

## What To Test

Query counts for list endpoints (assert no N+1); context disposal; concurrency conflicts on update; behaviour when the database is unreachable.

## What Can Be Automated

Connection-string secret detection (deterministic, see `rules/gitleaks/dotnet-config.toml`); `TrustServerCertificate=true` detection; missing `Encrypt=True`.

## What Requires Manual Review

Whether eager-loading choices match real access patterns.

## Common Failure Modes

A password in the connection string. `TrustServerCertificate=True` masking a certificate problem. Long-lived contexts accumulating tracked entities.

## Example

Reference run: the EF connection string carried `user id=svc_app;password=...` in cleartext and shipped in the build output (`SEC-CFG-001`, CVSS 8.8).

## Remediation

Use Integrated Security so no password exists; otherwise encrypt the config section or use a secret store; set `Encrypt=True` with proper certificate validation.

---

Part of [dotnet-moraa-codereviewer](../README.md). See also [methodology](01-methodology.md), [CVSS](30-cvss.md), [false positives](31-false-positives.md), [AI review](32-ai-review.md).
