# Controllers and API Endpoints

## What

Per-endpoint review of authentication, authorization, ownership, model binding, validation, status codes, error handling and logging.

## Why

Controllers are the trust boundary. Missing authorization here is the single highest-impact defect class in a business API, and no mainstream free analyzer detects it.

## How

Enumerate every attribute-routed action via `ApiExplorer` or by parsing `[Route]`/`[HttpX]`. For each, record: `[Authorize]` present? role checked? ownership of the identifier verified against a claim? DTO validated? Then diff the list against the routes an attacker can reach.

## What To Test

Per endpoint: 401 with no token; 403 with a valid token but wrong role; 403/404 for another tenant's object id; 400 for invalid model; 415 for wrong content type; 413 over the size limit; correct status (not 500) on downstream failure.

## What Can Be Automated

Presence of `[Authorize]`/`[AllowAnonymous]` per controller and the existence of a global authorization filter — fully deterministic (proposed `MORAA0002`).

## What Requires Manual Review

Whether an ownership check is *correct*. A code path can compare an id to a claim and still compare the wrong two things.

## Common Failure Modes

Relying on the host being internal. Validating the DTO but trusting an object id inside it. Assuming authentication middleware implies authorization — it does not; it only populates the principal.

## Example

Reference run: `[Authorize]` appeared once across 20 controllers. Booking, credit-card, customer-data and decision-engine endpoints were all reachable with no token (`SEC-AUTHZ-001`, CVSS 9.8). IIS anonymous auth was enabled, so no platform control compensated.

## Remediation

Register a global `AuthorizeAttribute` so the default is deny; add `[AllowAnonymous]` only to the token endpoint; add per-resource ownership checks; assert 401-without-token for every route in an integration test.

---

Part of [dotnet-moraa-codereviewer](../README.md). See also [methodology](01-methodology.md), [CVSS](30-cvss.md), [false positives](31-false-positives.md), [AI review](32-ai-review.md).
