# Test Coverage Gaps

## Required tests by finding

| Finding | Severity | Required tests | Regression test |
|---|---|---|---|
| SEC-AUTHZ-001 | CRITICAL | B-001, B-002, B-003 | Parameterised integration test enumerates every route via ApiExplorer and asserts 401 without a token; a second test asserts 403 when account A requests account B's order. |
| SEC-CFG-001 | CRITICAL | E-001, E-003, E-012 | CI runs gitleaks with the .NET ruleset over the tree AND the built package, failing on any finding; a canary secret proves the gate is active. |
| SEC-AUTH-001 | HIGH | A-001, A-002, A-003 | Test submits an empty password and a base64 blob decoding to empty, asserting rejection before any directory call. |
| PERF-DOS-001 | MEDIUM | P-004, P-005 | Test feeds a pathological input and asserts RegexMatchTimeoutException within the bound rather than an unbounded hang. |
| ARCH-001 | LOW | L-003, L-008, R-004 | Architecture test asserts exactly one implementation of the pricing rule; a unit test pins the rounding policy at the boundary. |
| CFG-WEB-001 | LOW | H-005, N-004 | Integration test asserts the header is absent from responses at the edge. |
