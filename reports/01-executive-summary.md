# Executive Summary

**Overall risk: CRITICAL**

| Metric | Value |
|---|---|
| Total findings | 6 |
| Critical | 2 |
| High | 1 |
| Medium | 1 |
| Low | 2 |
| CVSS-scored | 5 |
| CVSS N/A (by design) | 1 |
| Highest CVSS | 9.8 |
| Dependency SECURITY queue | 0 |
| Dependency MAINTENANCE queue | 0 |
| Environment-dependent (unresolved) | 2 |

## Top remediation priorities

| # | ID | Title | Severity | CVSS |
|---|---|---|---|---|
| 1 | SEC-AUTHZ-001 | No authorization enforced on API controllers | CRITICAL | 9.8 (CRITICAL) |
| 2 | SEC-CFG-001 | Hard-coded database credentials in Web.config | CRITICAL | 8.8 (HIGH) |
| 3 | SEC-AUTH-001 | Directory bind accepts an empty password | HIGH | 5.3 (MEDIUM) |
| 4 | PERF-DOS-001 | Regex without a match timeout on a user-reachable path | MEDIUM | 5.3 (MEDIUM) |
| 5 | ARCH-001 | Duplicated calculation logic with divergent behaviour | LOW | N/A |
| 6 | CFG-WEB-001 | X-Powered-By header exposes the framework | LOW | 0 (NONE) |

## Findings corrected during validation

*Reasoning that was wrong in an earlier iteration and was fixed. Recorded because a review that never corrects itself is not being checked.*

| ID | Outcome |
|---|---|


## Still environment-dependent

| ID | Open question |
|---|---|
| SEC-AUTH-001 | Does the directory permit unauthenticated binds? Only a live test settles whether this is MEDIUM or CRITICAL. |
| CFG-WEB-001 | If the proxy is bypassed or replaced, this becomes live again. |
