# Security Findings

*Generated from the canonical JSON. Do not edit by hand.*

## CRITICAL

### SEC-AUTHZ-001 — No authorization enforced on API controllers

| Field | Value |
|---|---|
| Severity | CRITICAL |
| CVSS | 9.8 (CRITICAL) |
| CVSS Vector | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` |
| Confidence | CONFIRMED |
| CWE | CWE-862 |
| OWASP | A01:2021 |
| Location | `ExampleApp/Controllers/OrdersController.cs:18` |
| Priority | P0 |
| Effort | MEDIUM |
| Status | OPEN |

**Problem.** The controller declares no [Authorize] attribute and no global authorization filter is registered, so every action is reachable without a token. The action also returns an object located purely by a client-supplied id.

**Impact.** Any unauthenticated caller can read any order by iterating the id, and the same pattern on write actions would allow modification. This is both missing authentication and a horizontal IDOR.

**Attack / failure scenario.** GET /api/orders/1..N with no Authorization header returns every order in the system.

**Root cause.** Authorization was assumed to be handled by network placement rather than by the application.

**Evidence**

```csharp
public class OrdersController : ApiController   // no [Authorize]
{
    [HttpGet]
    [Route("api/orders/{id}")]
    public IHttpActionResult GetOrder(int id)
    {
        return Ok(_repo.Find(id));   // no ownership check either
    }
}
```

**Recommendation.** Register a global AuthorizeAttribute so the default is deny, apply [AllowAnonymous] only where intended, and compare the resolved object's owner against a claim on the caller.

**Corrected code**

```csharp
// App_Start/WebApiConfig.cs
config.Filters.Add(new AuthorizeAttribute());   // deny by default

// Controllers/OrdersController.cs
[Authorize]
public class OrdersController : ApiController
{
    [HttpGet, Route("api/orders/{id}")]
    public IHttpActionResult GetOrder(int id)
    {
        var order = _repo.Find(id);
        if (order == null) return NotFound();

        var callerId = User.Identity.GetUserId();
        if (order.CustomerId != callerId) return StatusCode(HttpStatusCode.Forbidden);

        return Ok(order);
    }
}
```

**Required tests:** B-001, B-002, B-003

**Regression test.** Parameterised integration test enumerates every route via ApiExplorer and asserts 401 without a token; a second test asserts 403 when account A requests account B's order.

**Detection (DETERMINISTIC):** semgrep/moraa-dotnet-controller-missing-authorize [PROPOSED]

**Sources:** manual-review → REPORTED; sonarqube → MISSED

**Verification.** Checked for a custom AuthorizeAttribute subclass, an IAuthorizationFilter, an <authorization> config section and host-level authentication. None present. → **CONFIRMED**

---

### SEC-CFG-001 — Hard-coded database credentials in Web.config

| Field | Value |
|---|---|
| Severity | CRITICAL |
| CVSS | 8.8 (HIGH) |
| CVSS Vector | `CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H` |
| Confidence | CONFIRMED |
| CWE | CWE-798, CWE-540 |
| OWASP | A07:2021, A05:2021 |
| Location | `ExampleApp/Web.config:12` |
| Priority | P0 |
| Effort | MEDIUM |
| Status | OPEN |

> [!note] Severity vs CVSS
> CVSS base is 8.8 HIGH because exploitation presupposes read access to the configuration or build artifact. Business severity is CRITICAL because the credential grants direct database access, bypassing every application control. This field exists to document exactly this kind of deliberate divergence.

**Problem.** A database password is stored in cleartext in Web.config, and the Release transform does not remove it, so it ships in the deployment artifact.

**Impact.** Anyone with the repository, a build artifact or a server backup obtains direct database access without touching the application.

**Attack / failure scenario.** A contractor with repository access reads Web.config and connects to db01 directly from the corporate network.

**Root cause.** Configuration is treated as source; no secret store or protected configuration section is in use.

**Evidence**

```xml
<connectionStrings>
  <add name="AppDb"
       connectionString="data source=db01;initial catalog=AppDb;user id=svc_app;password=***REDACTED***"
       providerName="System.Data.SqlClient" />
</connectionStrings>
```

**Tool output**

```text
gitleaks 8.28.0, DEFAULT rules:                 no leaks found
gitleaks 8.28.0 + rules/gitleaks/dotnet-config.toml:  1 leak (dotnet-connectionstring-password)

The default ruleset misses low-entropy passwords in XML attributes. This is the
false-negative case the .NET ruleset exists to close.
```

**Recommendation.** Rotate the credential, move to Integrated Security so no password exists, or encrypt the configuration section. Add the .NET gitleaks ruleset to CI as a blocking gate with a canary.

**Corrected code**

```csharp
<!-- Integrated Security: there is no password to leak -->
<add name="AppDb"
     connectionString="data source=db01;initial catalog=AppDb;Integrated Security=True;Encrypt=True"
     providerName="System.Data.SqlClient" />
```

**Required tests:** E-001, E-003, E-012

**Regression test.** CI runs gitleaks with the .NET ruleset over the tree AND the built package, failing on any finding; a canary secret proves the gate is active.

**Detection (DETERMINISTIC):** gitleaks/dotnet-connectionstring-password [EXISTS], sonarqube/S2068 [EXISTS]

**Sources:** manual-review → REPORTED; gitleaks-moraa-rules → REPORTED; gitleaks → FALSE_NEGATIVE

**Verification.** Checked whether the Release transform scrubs the value. It does not, and the secret is present in the packaged output. → **CONFIRMED**

---

## HIGH

### SEC-AUTH-001 — Directory bind accepts an empty password

| Field | Value |
|---|---|
| Severity | HIGH |
| CVSS | 5.3 (MEDIUM) |
| CVSS Vector | `CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N` |
| Confidence | LIKELY |
| CWE | CWE-287, CWE-521 |
| OWASP | A07:2021 |
| Location | `ExampleApp/Auth/DomainAuth.cs:22` |
| Priority | P1 |
| Effort | SMALL |
| Status | OPEN |

**Problem.** ValidateCredentials is called with no guard against an empty password, over a bind that does not request SecureSocketLayer.

**Impact.** ValidateCredentials is documented to return true for an empty password against directories that permit unauthenticated binds. If that is the case here, supplying an empty password authenticates as any known username. The bind is also not carried over LDAPS.

**Attack / failure scenario.** Submit a login for a known username with an empty password. Whether this succeeds depends on directory configuration, which is why confidence is LIKELY and the 9.8 score is held in conditionalScore rather than reported as the headline.

**Root cause.** A framework helper was used without reading its documented edge cases.

**Evidence**

```csharp
public bool IsValid(string user, string password)
{
    using (var pc = new PrincipalContext(ContextType.Domain, _host, null, ContextOptions.Negotiate))
    {
        return pc.ValidateCredentials(user, password);   // no empty-password guard, no SSL
    }
}
```

**Recommendation.** Reject empty and whitespace credentials before the call, add ContextOptions.SecureSocketLayer, and resolve the host by DNS name so certificate validation can succeed.

**Corrected code**

```csharp
public bool IsValid(string user, string password)
{
    if (string.IsNullOrWhiteSpace(user) || string.IsNullOrWhiteSpace(password))
        return false;                                   // explicit guard

    using (var pc = new PrincipalContext(ContextType.Domain, _host, null,
               ContextOptions.Negotiate | ContextOptions.SecureSocketLayer))
    {
        return pc.ValidateCredentials(user, password);
    }
}
```

**Required tests:** A-001, A-002, A-003

**Regression test.** Test submits an empty password and a base64 blob decoding to empty, asserting rejection before any directory call.

**Detection (DETERMINISTIC):** semgrep/moraa-dotnet-validatecredentials-no-empty-guard [PROPOSED]

**Sources:** manual-review → REPORTED

**Verification.** Checked whether tokens are JWTs, which would add further attack classes. They are opaque machine-key tickets, so no JWT claim is made here. → **CONFIRMED**

---

