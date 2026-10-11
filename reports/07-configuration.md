# Configuration Findings

| ID | Title | Severity | CVSS | File | Status |
|---|---|---|---|---|---|
| CFG-WEB-001 | X-Powered-By header exposes the framework | LOW | 0 (NONE) | `ExampleApp/Web.config` | ACCEPTED_RISK |

## CFG-WEB-001 — X-Powered-By header exposes the framework

**Problem.** The X-Powered-By response header is not removed, disclosing the framework in use.

**Impact.** Minimal on its own. Included here as the worked example of an ACCEPTED_RISK with a mandatory expiring suppression — the projection refuses to emit a suppression without an expiresOn date, so permanent silent suppression is structurally impossible.

**Recommendation.** Remove the header via customHeaders. Accepted for now because an upstream reverse proxy strips it in this environment.
