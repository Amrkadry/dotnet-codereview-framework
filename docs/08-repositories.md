# Repositories and Data Access

## What

How data access is constructed: parameterisation, projection, paging, connection lifetime and error surfacing.

## Why

This is where injection lives, and where an unbounded query becomes an availability problem.

## How

Grep for `SqlCommand`, `CommandText`, `ExecuteStoreQuery`, `Database.SqlQuery`, `ExecuteSqlCommand`, string concatenation into SQL, and for legacy helpers such as `Microsoft.ApplicationBlocks.Data`. For Dataverse/CRM, check whether the requested column set actually contains the attributes later read.

## What To Test

Injection payloads per parameter; empty result sets; single-row expectations against zero and many rows; paging boundaries; connection failure.

## What Can Be Automated

Concatenated SQL detection is deterministic (`CA2100`, Sonar S3649, Semgrep). Column-set/attribute mismatch is AI-assisted — it needs cross-method dataflow plus API semantics.

## What Requires Manual Review

Whether a query is correctly scoped to the caller's tenant. No rule knows which column carries tenancy.

## Common Failure Modes

Indexing `Entities[0]` without a count check. Reading an attribute that was never requested, which silently yields a default rather than an error.

## Example

Reference run: SQL injection came back **clean** — data access is EF6 with LINQ and no raw SQL anywhere, and the legacy `ApplicationBlocks.Data` package is referenced but unused. Conversely, a CRM column-set mismatch made a role claim permanently false (`SEC-AUTHZ-002`), and `Entities[0]` was indexed unchecked (`SEC-AUTH-001`).

## Remediation

Parameterise everything; check counts before indexing; assert requested columns cover every attribute later read; fail closed when a security-relevant attribute is absent.

---

Part of [dotnet-moraa-codereviewer](../README.md). See also [methodology](01-methodology.md), [CVSS](30-cvss.md), [false positives](31-false-positives.md), [AI review](32-ai-review.md).
