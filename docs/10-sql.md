# SQL and Stored Procedures

## What

Review of raw SQL, stored procedures, dynamic SQL and database permissions.

## Why

Injection remains the highest-severity input flaw, and over-privileged database accounts turn any injection into total compromise.

## How

Enumerate every SQL construction site; confirm parameters are `SqlParameter`, not interpolation; inside procedures look for `EXEC(@sql)`; review the application account's grants.

## What To Test

Classic and second-order injection payloads per parameter; unicode and comment variants; assert the application account cannot DDL or read other databases.

## What Can Be Automated

Concatenation into `CommandText` is deterministic. Dynamic SQL inside stored procedures needs database-side inspection, not source scanning.

## What Requires Manual Review

Database permissions and procedure bodies, which usually are not in the application repository at all.

## Common Failure Modes

Assuming an ORM means no SQL anywhere. Parameterising the value but concatenating the column or table name.

## Example

Reference run: no raw SQL sink existed, so SQL injection is recorded in the positive-controls list with the basis stated — EF6 + LINQ, zero `SqlCommand`/`CommandText` occurrences. A negative result is only useful with its basis attached.

## Remediation

Keep all access parameterised; grant the application account least privilege; review procedure bodies separately from application source.

---

Part of [dotnet-moraa-codereviewer](../README.md). See also [methodology](01-methodology.md), [CVSS](30-cvss.md), [false positives](31-false-positives.md), [AI review](32-ai-review.md).
