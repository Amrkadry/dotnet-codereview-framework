# Architecture Findings

*Generated from the canonical JSON. Do not edit by hand.*

| ID | Title | Severity | CVSS | Confidence | Location | Status |
|---|---|---|---|---|---|---|
| ARCH-001 | Duplicated calculation logic with divergent behaviour | LOW | N/A | CONFIRMED | `ExampleApp/Services/PricingService.cs:40` | OPEN |

## ARCH-001 — Duplicated calculation logic with divergent behaviour

**Problem.** One pricing rule is implemented twice with different rounding behaviour, so the two paths disagree on some inputs.

**Impact.** Not a vulnerability, which is why cvss is null — this is the worked example of a category that must never carry a CVSS score. The risk is that a fix applied to one implementation silently misses the other, and that two code paths produce different monetary results for identical inputs.

**Root cause.** A rewrite left the original in place.

**Evidence**

```csharp
// PricingService.cs:40  — rounds half-up
return Math.Round(subtotal * rate, 2, MidpointRounding.AwayFromZero);

// LegacyPricing.cs:88  — rounds half-even. Same rule, different answer.
return Math.Round(subtotal * rate, 2);
```

**Recommendation.** Collapse to one implementation with an explicit, tested rounding policy; delete the other.

**Required tests:** L-003, L-008, R-004

**Sources:** manual-review → REPORTED; sonarqube → REPORTED

**Verification.** Checked whether the legacy path is dead code; it is still called from the batch job. → **CONFIRMED**

---

