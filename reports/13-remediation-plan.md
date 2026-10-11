# Remediation Roadmap

*Ordered by priority, then CVSS, then confidence.*

## P0 — Immediate security risk

| ID | Title | Severity | CVSS | Effort | Reason |
|---|---|---|---|---|---|
| SEC-AUTHZ-001 | No authorization enforced on API controllers | CRITICAL | 9.8 (CRITICAL) | MEDIUM | Any unauthenticated caller can read any order by iterating the id, and the same pattern on write actions would allow modification. |
| SEC-CFG-001 | Hard-coded database credentials in Web.config | CRITICAL | 8.8 (HIGH) | MEDIUM | Anyone with the repository, a build artifact or a server backup obtains direct database access without touching the application. |

## P1 — High-risk security/reliability

| ID | Title | Severity | CVSS | Effort | Reason |
|---|---|---|---|---|---|
| SEC-AUTH-001 | Directory bind accepts an empty password | HIGH | 5.3 (MEDIUM) | SMALL | ValidateCredentials is documented to return true for an empty password against directories that permit unauthenticated binds. |

## P2 — Important technical debt

| ID | Title | Severity | CVSS | Effort | Reason |
|---|---|---|---|---|---|
| PERF-DOS-001 | Regex without a match timeout on a user-reachable path | MEDIUM | 5.3 (MEDIUM) | TRIVIAL | A crafted input forces catastrophic backtracking, pinning a CPU core for the request's lifetime. |

## P3 — Improvement

| ID | Title | Severity | CVSS | Effort | Reason |
|---|---|---|---|---|---|
| ARCH-001 | Duplicated calculation logic with divergent behaviour | LOW | N/A | SMALL | Not a vulnerability, which is why cvss is null — this is the worked example of a category that must never carry a CVSS score. |
| CFG-WEB-001 | X-Powered-By header exposes the framework | LOW | 0 (NONE) | TRIVIAL | Minimal on its own. |

