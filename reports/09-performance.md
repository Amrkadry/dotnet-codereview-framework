# Performance Findings

*Generated from the canonical JSON. Do not edit by hand.*

| ID | Title | Severity | CVSS | Confidence | Location | Status |
|---|---|---|---|---|---|---|
| PERF-DOS-001 | Regex without a match timeout on a user-reachable path | MEDIUM | 5.3 (MEDIUM) | CONFIRMED | `ExampleApp/Validation/EmailRule.cs:11` | OPEN |

## PERF-DOS-001 — Regex without a match timeout on a user-reachable path

**Problem.** The pattern uses nested quantifiers and is applied to request input with no match timeout. .NET regexes have no default timeout.

**Impact.** A crafted input forces catastrophic backtracking, pinning a CPU core for the request's lifetime. Unauthenticated and repeatable, this degrades availability.

**Root cause.** A copied regex was never reviewed for linear-time matching, and no process-wide timeout was configured.

**Evidence**

```csharp
// Nested quantifiers on user input, and no timeout argument.
private static readonly Regex Email = new Regex(@"^([a-zA-Z0-9_\-\.]+)+@([a-zA-Z0-9_\-\.]+)+\.([a-zA-Z]{2,5})$");
```

**Tool output**

```text
SonarQube S6444: 1 occurrence (EmailRule.cs:11)
```

**Recommendation.** Set a process-wide default at startup, pass an explicit TimeSpan, simplify the pattern to remove nested quantifiers, and cap input length before matching.

**Corrected code**

```csharp
// One line at startup protects every regex in the process
AppDomain.CurrentDomain.SetData("REGEX_DEFAULT_MATCH_TIMEOUT", TimeSpan.FromSeconds(2));

// And be explicit at the call site, with a non-pathological pattern
private static readonly Regex Email = new Regex(
    @"^[^@\s]{1,64}@[^@\s]{1,255}$",
    RegexOptions.Compiled, TimeSpan.FromMilliseconds(200));
```

**Required tests:** P-004, P-005

**Sources:** manual-review → REPORTED; sonarqube → REPORTED

**Verification.** Checked for an AppDomain-level default timeout that would protect all sites. Not present. → **CONFIRMED**

---

