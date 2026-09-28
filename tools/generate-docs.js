#!/usr/bin/env node
/**
 * Generates docs/01..33 with the mandated section structure.
 * Content is specific to legacy ASP.NET Framework + ASP.NET Core and cross-references
 * the reference review's real findings. Run: node tools/generate-docs.js
 */
'use strict';
const fs = require('fs');
const path = require('path');
const out = path.join(__dirname, '..', 'docs');
fs.mkdirSync(out, { recursive: true });

const SECTIONS = ['What', 'Why', 'How', 'What To Test', 'What Can Be Automated',
  'What Requires Manual Review', 'Common Failure Modes', 'Example', 'Remediation'];

// d = [file, H1, {section: content}]
const D = [];
const doc = (file, h1, s) => D.push([file, h1, s]);

doc('01-methodology.md', 'Review Methodology', {
  What: 'The eight-phase, evidence-first process: discovery, build/test verification, tool execution with capability detection, ingestion of prior outputs, normalization, correlation and dedup, adversarial validation, projection.',
  Why: 'Reviews fail in two directions: they miss real issues, and they assert issues that are not real. Separating *finding* from *validating* addresses the second, which is the one that destroys a report\'s credibility. In the reference run, adversarial validation corrected 3 of 26 findings and strengthened 2.',
  How: 'Each phase writes into the canonical JSON (`schema/finding.schema.json`). No phase edits a rendered report. `tools/project-findings.js` regenerates every view and fails on integrity violations.',
  'What To Test': 'That the projection is reproducible; that every finding has at least one `sources[]` entry; that no non-scoreable category carries a CVSS; that every FALSE_POSITIVE has an expiring suppression.',
  'What Can Be Automated': 'Discovery, build, tool execution, schema validation, correlation by location+rule, dedup, projection to Markdown/JSON/SARIF, and the integrity gate.',
  'What Requires Manual Review': 'Severity adjustment against business context, exploitability judgement, and the disproof attempt in Phase 7. A model can propose a disproof; a human decides whether the attempt was serious.',
  'Common Failure Modes': 'Trusting a tool\'s silence (stock gitleaks reported zero on a repo with four live credential sets). Trusting an AI\'s confident mechanism (the CORS finding\'s original credential-theft explanation was void). Inflating a latent sink into a live vulnerability.',
  Example: 'Phase 7 applied to a path-traversal candidate: the sink was real, but the only caller passed a server-generated filename. Outcome: recorded as LOW/latent with `cvss: null`, not HIGH. See `SEC-FILE-002`.',
  Remediation: 'Adopt phases 1-8 in order. Do not let Phase 8 run before Phase 7. Treat any finding lacking `verification.disproofAttempt` as unvalidated.'
});

doc('02-architecture.md', 'Framework Architecture', {
  What: 'A canonical-JSON core with pluggable collectors (build, analyzers, scanners, AI) and pure projections (Markdown, JSON, SARIF).',
  Why: 'If reports are authored directly, they drift apart and the numbers stop matching. Making the JSON authoritative means the security report, the exec summary and the SARIF cannot disagree.',
  How: 'Collectors write `findings-*.json` parts. `project-findings.js` merges, validates, sorts (severity → CVSS → confidence → id) and emits views. Nothing downstream may add a fact.',
  'What To Test': 'Round-trip: projecting twice yields identical bytes. Schema negative tests: duplicate id, missing sources, malformed vector, CVSS on an architecture finding — each must fail the build.',
  'What Can Be Automated': 'The whole pipeline. It runs today: `node tools/project-findings.js reviews/example` produced 31 findings, `report.json`, a valid SARIF 2.1.0 file and six Markdown views with zero integrity errors.',
  'What Requires Manual Review': 'Authoring the canonical finding bodies — impact, root cause, corrected code. These are judgement, and the schema deliberately does not try to generate them.',
  'Common Failure Modes': 'Editing a generated report by hand (it will be overwritten). Adding a projection that invents a severity label not present in the canonical object.',
  Example: 'Two independent dependency queues are a projection concern, not a data concern: `category=dependency` plus `cvss===null` selects the maintenance queue. No separate field is needed.',
  Remediation: 'Add a CI step that runs the projection and fails if `git diff --exit-code reports/` is dirty, proving reports are generated rather than edited.'
});

doc('03-project-discovery.md', 'Project Discovery', {
  What: 'Inventory of solution, projects, target frameworks, project style (SDK vs non-SDK), entry points, configuration, CI/CD, containers and version control.',
  Why: 'Project shape determines which tools can run at all. Discovering `packages.config` + non-SDK early prevents reporting a clean dependency audit that never happened.',
  How: 'Parse `.sln` for `^Project(`; read each `.csproj` for `TargetFramework(Version)`, `Import` of `Microsoft.WebApplication.targets`, and analyzer properties; check for `packages.config` vs `PackageReference`, `packages.lock.json`, `.editorconfig`, `Directory.Build.props`, `.github/`, `azure-pipelines.yml`, `Dockerfile`, `.git`.',
  'What To Test': 'That discovery correctly classifies a legacy web project, an SDK library and a test project; that a missing `.git` is reported rather than ignored.',
  'What Can Be Automated': 'All of it. Emit a machine-readable capability profile that gates later phases.',
  'What Requires Manual Review': 'Whether an absent pipeline genuinely does not exist or simply was not delivered with the source — the reference review could not settle this and said so.',
  'Common Failure Modes': 'Assuming one project; assuming `dotnet build` works; missing that `bin/`, `obj/` and `.vs/` were shipped with the source, which changes where secrets live.',
  Example: 'Reference run: `grep -c \'^Project(\' YourApp.sln` → 1. No test project, no CI, no Dockerfile, no `.git`, no lockfile, no analyzers. Four findings came from this phase alone: `TEST-COV-001`, `DEP-AUDIT-001`, `CFG-BUILD-001`, `PROC-CICD-001`.',
  Remediation: 'Record the capability profile in the report so readers know which conclusions rest on tools that could not run.'
});

doc('04-build-and-test.md', 'Build and Test Verification', {
  What: 'Proving the code compiles and the tests run, with exit codes captured, before believing any analysis of it.',
  Why: 'Analyzers that need compilation produce nothing useful on a broken build. A green build with no analyzers is also a false comfort worth naming.',
  How: 'Legacy: `nuget restore` + `MSBuild.exe Sln -t:Build`. SDK: `dotnet restore`/`build`/`test`. Always record COMMAND, PURPOSE, RESULT, EXIT CODE, OUTPUT, INTERPRETATION, and use the vocabulary EXECUTED / FAILED / NOT AVAILABLE / NOT APPLICABLE / UNVERIFIED.',
  'What To Test': 'Build from a clean tree; build in Release (not just Debug), because Release is what transforms configuration; assert the test run executed a non-zero number of tests.',
  'What Can Be Automated': 'Everything, including the distinction between "tests passed" and "no tests exist" — these must never render identically.',
  'What Requires Manual Review': 'Deciding whether a build warning is benign. The reference run\'s leftover Sonar-targets warning was; a missing analyzer package would not be.',
  'Common Failure Modes': 'Reporting `dotnet test` as passing when zero tests ran. Building only Debug and missing that the Release transform is the only thing neutralising `debug="true"`.',
  Example: 'Reference run: MSBuild exit 0, `YourApp -> YourApp\\bin\\YourApp.dll`. `dotnet test` → NOT APPLICABLE, because the solution has one project and no test framework (`TEST-COV-001`).',
  Remediation: 'Make build and test blocking CI gates; fail the pipeline when the executed-test count is zero.'
});

doc('05-controllers.md', 'Controllers and API Endpoints', {
  What: 'Per-endpoint review of authentication, authorization, ownership, model binding, validation, status codes, error handling and logging.',
  Why: 'Controllers are the trust boundary. Missing authorization here is the single highest-impact defect class in a business API, and no mainstream free analyzer detects it.',
  How: 'Enumerate every attribute-routed action via `ApiExplorer` or by parsing `[Route]`/`[HttpX]`. For each, record: `[Authorize]` present? role checked? ownership of the identifier verified against a claim? DTO validated? Then diff the list against the routes an attacker can reach.',
  'What To Test': 'Per endpoint: 401 with no token; 403 with a valid token but wrong role; 403/404 for another tenant\'s object id; 400 for invalid model; 415 for wrong content type; 413 over the size limit; correct status (not 500) on downstream failure.',
  'What Can Be Automated': 'Presence of `[Authorize]`/`[AllowAnonymous]` per controller and the existence of a global authorization filter — fully deterministic (proposed `MORAA0002`).',
  'What Requires Manual Review': 'Whether an ownership check is *correct*. A code path can compare an id to a claim and still compare the wrong two things.',
  'Common Failure Modes': 'Relying on the host being internal. Validating the DTO but trusting an object id inside it. Assuming authentication middleware implies authorization — it does not; it only populates the principal.',
  Example: 'Reference run: `[Authorize]` appeared once across 20 controllers. Loan booking, credit cards, customer data and the decision engine were all reachable with no token (`SEC-AUTHZ-001`, CVSS 9.8). IIS anonymous auth was enabled, so no platform control compensated.',
  Remediation: 'Register a global `AuthorizeAttribute` so the default is deny; add `[AllowAnonymous]` only to the token endpoint; add per-resource ownership checks; assert 401-without-token for every route in an integration test.'
});

doc('06-models-dtos.md', 'Models, DTOs and ViewModels', {
  What: 'Validation coverage, type strength, over-posting exposure and the mapping boundary between transport types and domain entities.',
  Why: 'A DTO is where untrusted input becomes typed data. Weak or uneven validation here pushes the burden onto every downstream consumer.',
  How: 'Enumerate public properties per DTO; measure how many carry a validation attribute; prefer `decimal`/`Guid`/`DateTime`/enums over `string`; verify binding cannot set server-controlled fields.',
  'What To Test': 'Null, empty, whitespace, boundary, over-long, wrong-type, extra unexpected properties, and culture-variant numeric/date input for every DTO reaching a decision path.',
  'What Can Be Automated': 'Validation coverage as a percentage, with a build-failing floor (proposed `moraa-arch-dto-validation-coverage`). Reflection over the DTO namespace is enough.',
  'What Requires Manual Review': 'Whether the permitted character set is right for the field — `^[\\p{L}\\p{M}\'\\-. ]+$` for a name is a judgement about real customer data, not a rule.',
  'Common Failure Modes': 'A single catch-all sanitiser applied by hand, so coverage silently drifts. Using `string` for money and dates. Denylists instead of allow-lists.',
  Example: 'Reference run: roughly half of all `public string` DTO properties carried a validation attribute. The uncovered files were the largest and most sensitive — the three largest write-path DTOs. Coverage was *inverted* (`SEC-VAL-001`).',
  Remediation: 'Replace the catch-all with per-field allow-list attributes, strengthen types, and gate coverage in CI.'
});

doc('07-services.md', 'Services and Application Logic', {
  What: 'Review of service-layer behaviour: error handling, transaction boundaries, idempotency, determinism, and shared mutable state.',
  Why: 'Business rules live here. A service that silently returns a default on failure converts a loud error into a wrong answer, which is worse.',
  How: 'Look for `catch` blocks whose only action is to return `0`, `null` or `default`; for instance fields on types registered as singletons; for culture-sensitive formatting; for duplicated implementations of the same calculation.',
  'What To Test': 'Each failure mode explicitly: dependency throws, dependency times out, dependency returns malformed data. Assert the caller observes a failure rather than a plausible-looking default.',
  'What Can Be Automated': 'Fail-silent detection (`catch` → `return 0`) and singleton-mutable-state detection are both deterministic and high value.',
  'What Requires Manual Review': 'Whether returning a default is *correct* for the domain. In a financial calculation, a zero result is never a safe default — it is a decision.',
  'Common Failure Modes': 'Swallowing exceptions to keep a flow alive; duplicating a calculation so a fix lands in one copy only; storing per-request data on a shared instance.',
  Example: 'Reference run: `EvaluateExpression` caught every exception and returned `0`, on a monetary calculation path; three divergent implementations of `ComputeLimit` existed (`LOGIC-DEC-001`, `ARCH-001`).',
  Remediation: 'Return `T?` or throw; log the identifier of the failing rule; route to manual review. Collapse duplicated calculations into one audited path.'
});

doc('08-repositories.md', 'Repositories and Data Access', {
  What: 'How data access is constructed: parameterisation, projection, paging, connection lifetime and error surfacing.',
  Why: 'This is where injection lives, and where an unbounded query becomes an availability problem.',
  How: 'Grep for `SqlCommand`, `CommandText`, `ExecuteStoreQuery`, `Database.SqlQuery`, `ExecuteSqlCommand`, string concatenation into SQL, and for legacy helpers such as `Microsoft.ApplicationBlocks.Data`. For Dataverse/CRM, check whether the requested column set actually contains the attributes later read.',
  'What To Test': 'Injection payloads per parameter; empty result sets; single-row expectations against zero and many rows; paging boundaries; connection failure.',
  'What Can Be Automated': 'Concatenated SQL detection is deterministic (`CA2100`, Sonar S3649, Semgrep). Column-set/attribute mismatch is AI-assisted — it needs cross-method dataflow plus API semantics.',
  'What Requires Manual Review': 'Whether a query is correctly scoped to the caller\'s tenant. No rule knows which column carries tenancy.',
  'Common Failure Modes': 'Indexing `Entities[0]` without a count check. Reading an attribute that was never requested, which silently yields a default rather than an error.',
  Example: 'Reference run: SQL injection came back **clean** — data access is EF6 with LINQ and no raw SQL anywhere, and the legacy `ApplicationBlocks.Data` package is referenced but unused. Conversely, a CRM column-set mismatch made a role claim permanently false (`SEC-AUTHZ-002`), and `Entities[0]` was indexed unchecked (`SEC-AUTH-001`).',
  Remediation: 'Parameterise everything; check counts before indexing; assert requested columns cover every attribute later read; fail closed when a security-relevant attribute is absent.'
});

doc('09-entity-framework.md', 'Entity Framework', {
  What: 'EF-specific review: context lifetime, tracking, lazy loading, N+1, migrations, and connection-string handling.',
  Why: 'EF removes most injection risk but introduces performance and configuration risk, and the connection string is usually where the credentials are.',
  How: 'Check `DbContext` lifetime per request; look for lazy loading inside loops; confirm migrations are versioned; inspect the connection string for inline credentials and for `Encrypt`/`TrustServerCertificate`.',
  'What To Test': 'Query counts for list endpoints (assert no N+1); context disposal; concurrency conflicts on update; behaviour when the database is unreachable.',
  'What Can Be Automated': 'Connection-string secret detection (deterministic, see `rules/gitleaks/dotnet-config.toml`); `TrustServerCertificate=true` detection; missing `Encrypt=True`.',
  'What Requires Manual Review': 'Whether eager-loading choices match real access patterns.',
  'Common Failure Modes': 'A password in the connection string. `TrustServerCertificate=True` masking a certificate problem. Long-lived contexts accumulating tracked entities.',
  Example: 'Reference run: the EF connection string carried `user id=svc_app;password=...` in cleartext and shipped in the build output (`SEC-CFG-001`, CVSS 8.8).',
  Remediation: 'Use Integrated Security so no password exists; otherwise encrypt the config section or use a secret store; set `Encrypt=True` with proper certificate validation.'
});

doc('10-sql.md', 'SQL and Stored Procedures', {
  What: 'Review of raw SQL, stored procedures, dynamic SQL and database permissions.',
  Why: 'Injection remains the highest-severity input flaw, and over-privileged database accounts turn any injection into total compromise.',
  How: 'Enumerate every SQL construction site; confirm parameters are `SqlParameter`, not interpolation; inside procedures look for `EXEC(@sql)`; review the application account\'s grants.',
  'What To Test': 'Classic and second-order injection payloads per parameter; unicode and comment variants; assert the application account cannot DDL or read other databases.',
  'What Can Be Automated': 'Concatenation into `CommandText` is deterministic. Dynamic SQL inside stored procedures needs database-side inspection, not source scanning.',
  'What Requires Manual Review': 'Database permissions and procedure bodies, which usually are not in the application repository at all.',
  'Common Failure Modes': 'Assuming an ORM means no SQL anywhere. Parameterising the value but concatenating the column or table name.',
  Example: 'Reference run: no raw SQL sink existed, so SQL injection is recorded in the positive-controls list with the basis stated — EF6 + LINQ, zero `SqlCommand`/`CommandText` occurrences. A negative result is only useful with its basis attached.',
  Remediation: 'Keep all access parameterised; grant the application account least privilege; review procedure bodies separately from application source.'
});

doc('11-web-config.md', 'Web.config Review', {
  What: 'Systematic review of every security-relevant element across `Web.config`, `Web.Debug.config`, `Web.Release.config`, the transformed output and the packaged output.',
  Why: 'Configuration is where secrets, transport policy and hardening live, and it is the blind spot of compiled-code analyzers. SonarQube analysed the C# and reported nothing about any of it.',
  How: 'Inspect: `authentication`, `authorization`, `customErrors`, `compilation debug`, `httpRuntime` (`maxRequestLength`, `executionTimeout`, `enableVersionHeader`), `httpCookies` (`requireSSL`, `httpOnlyCookies`), `machineKey`, `sessionState`, `trace`, `handlers`, `modules`, `requestFiltering`/`requestLimits`, `httpProtocol/customHeaders`, `rewrite`, `connectionStrings`, `appSettings`, `globalization`. Then diff base against each transform, and check the **built** output.',
  'What To Test': 'That the transformed artifact has no `debug` attribute, no secrets and the expected headers; that every `appSettings` key read in code is actually declared; that request limits at the ASP.NET and IIS layers agree.',
  'What Can Be Automated': 'Nearly all of it, as XML rules: secrets, `debug="true"`, absent security headers, absent `machineKey`, `requireSSL`, limit mismatch, IP literals, commented settings, and undeclared-key cross-reference.',
  'What Requires Manual Review': 'Whether a value is *right* for the environment, and whether an upstream proxy already supplies missing headers.',
  'Common Failure Modes': 'Reviewing only the base file. Treating a commented block as absent — it is still in the artifact. Assuming an ASP.NET limit is effective when an IIS default is lower.',
  Example: 'Reference run: `DisableSSLValidation=true`, an AES key, four credential sets, production credentials in comments, no security headers, no `machineKey`, `maxRequestLength` 1 GB with no matching `requestFiltering`, and an `appSettings` key (`DomainIP`) read in code but declared nowhere. The Release transform did exactly one thing: remove `debug`.',
  Remediation: 'Move secrets out; set safe defaults in the base file so transforms are belt-and-braces; add the header block; declare limits deliberately at both layers; validate required keys at startup.'
});

doc('12-authentication.md', 'Authentication', {
  What: 'Establishing the actual mechanism — scheme, token format, transport, lifetime, client authentication and identity store — before reviewing anything that depends on it.',
  Why: 'Impact claims about CORS, session theft and token attacks are all wrong if the mechanism is misidentified. In the reference run, confirming "Bearer header, no cookies" invalidated an entire attack narrative.',
  How: 'Find the middleware registration (`UseOAuthAuthorizationServer`, `UseOAuthBearerAuthentication`, `UseCookieAuthentication`, JWT bearer). Determine token format by searching for `JwtSecurityToken`/`SecurityTokenHandler` — absent means opaque machine-key tickets, which excludes every JWT attack class. Check for cookies at all. Check IIS-level auth in `applicationHost.config`.',
  'What To Test': 'Empty username and password; whitespace; a password that decodes to empty; unknown user versus wrong password (same response, same path, similar timing); token expiry; token replay after account disable; client authentication.',
  'What Can Be Automated': 'Missing empty-credential guards before `ValidateCredentials`; `PrincipalContext` without `SecureSocketLayer`; unconditional `context.Validated()`; excessive token lifetime.',
  'What Requires Manual Review': 'Whether the directory permits unauthenticated binds — only a live test against the real DC settles it.',
  'Common Failure Modes': 'Claiming JWT attacks against opaque tokens. Assuming authentication middleware implies authorization. Relying on `ValidateCredentials` without reading its documented empty-password behaviour.',
  Example: 'Reference run: OAuth2 ROPC at `/login`, opaque machine-key OWIN tickets (not JWT), no cookies anywhere, 6-hour lifetime, no refresh, no client authentication, LDAP bind without SSL, and no empty-password guard (`SEC-AUTH-001`, `SEC-AUTH-002`).',
  Remediation: 'Guard empty credentials; use LDAPS; authenticate the client; shorten access tokens and add revocable refresh tokens.'
});

doc('13-authorization.md', 'Authorization', {
  What: 'Whether the populated principal is ever actually consulted: global default, per-endpoint roles, and per-object ownership.',
  Why: 'Authentication without authorization is the most common critical finding in business APIs, and it is invisible to analyzers that reason file-by-file.',
  How: 'Count `[Authorize]` against the number of controllers. Check for a global authorization filter. Trace each role claim back to its source and confirm the source is actually populated. For every endpoint taking an object id, find the ownership comparison.',
  'What To Test': 'Two-account matrix: A\'s token against B\'s object id must fail. No token must fail. Wrong role must fail. A valid id belonging to another branch must fail.',
  'What Can Be Automated': 'Controllers lacking `[Authorize]`/`[AllowAnonymous]`; absence of a global filter. Ownership-check *presence* can be approximated; correctness cannot.',
  'What Requires Manual Review': 'Whether the ownership comparison uses the right claim and the right field.',
  'Common Failure Modes': 'A role claim derived from a field that is never fetched, so it is permanently false. Trusting an id in the request body. Assuming network isolation is authorization.',
  Example: 'Reference run: two distinct failures. `SEC-AUTHZ-001` — one `[Authorize]` across 20 controllers, no global filter, no ownership checks anywhere. `SEC-AUTHZ-002` — a privileged role was read from an entity attribute that was never included in the requested column set, so it always evaluated to false and was then compared against a differently-cased string. The root cause was a code comment falsely claiming the data-access helper retrieved all attributes.',
  Remediation: 'Deny by default globally; fail closed when a role attribute is missing; verify ownership against a claim, never against a request field.'
});

doc('14-security.md', 'Security Review', {
  What: 'The cross-cutting pass over OWASP Top 10 plus .NET-specific classes: secrets, transport, crypto, logging, file handling, deserialization, SSRF, XXE and misconfiguration.',
  Why: 'Class-by-class sweeps catch what endpoint-by-endpoint review misses, and they let negative results be recorded with their basis.',
  How: 'Work the class list, and for each record either a finding or an explicit clean result with the evidence. Grep-driven starting points: `BinaryFormatter`, `TypeNameHandling`, `XmlDocument`/`XmlResolver`, `Process.Start`, `ServerCertificateValidationCallback`, `Aes`/`Rfc2898DeriveBytes`, `Path.Combine`, `HttpClient` with user-controlled URIs.',
  'What To Test': 'One negative test per class, so a regression re-opens visibly rather than silently.',
  'What Can Be Automated': 'Most sink detection. Not reachability, and not business impact.',
  'What Requires Manual Review': 'Chaining. Individually-medium findings can combine into a critical path, which no single rule sees.',
  'Common Failure Modes': 'Reporting sinks without reachability. Omitting clean classes, so a later reviewer cannot tell what was checked.',
  Example: 'Reference run clean results, each with basis: no XXE (no `XmlDocument`/`XmlReader`; XML formatter explicitly cleared), no unsafe deserialization (no `BinaryFormatter`, Newtonsoft without `TypeNameHandling`), no command injection (no `Process.Start`), no SQL injection (EF6 + LINQ only). Chaining example: `SEC-CORS-001` + `SEC-AUTHZ-001` together turn an internal API into an internet-reachable one.',
  Remediation: 'Fix by chain, not by individual severity: closing the perimeter findings first collapses several others.'
});

doc('15-api.md', 'API Design and Contracts', {
  What: 'Response contracts, status-code correctness, error shape, content negotiation, versioning and schema exposure.',
  Why: 'Incorrect status codes hide failures from monitoring, and an exposed schema hands an attacker the route map.',
  How: 'Check that validation failures return 400, authorization 401/403, size 413, content type 415, and downstream failure 502/504 rather than a blanket 500. Check whether Swagger/OpenAPI is gated.',
  'What To Test': 'Each status path explicitly; malformed JSON; wrong content type; oversized body; downstream timeout.',
  'What Can Be Automated': 'Unconditional Swagger registration; catch-all handlers that collapse every exception into 500.',
  'What Requires Manual Review': 'Whether an error message leaks too much, and whether a contract change is breaking.',
  'Common Failure Modes': 'A global handler returning 500 for client errors. Swagger enabled in production by an assembly-level attribute, which is unconditional by construction.',
  Example: 'Reference run: Swagger registered via `[assembly: PreApplicationStartMethod]` with no environment check and no auth (`SEC-INFO-001`); non-JSON bodies produced 500 instead of 415 (`PERF-DOS-001`).',
  Remediation: 'Gate Swagger behind a default-false setting; map exception types to correct status codes; validate content type before parsing.'
});

doc('16-logging.md', 'Logging', {
  What: 'What is logged, where it lands, who can read it, how long it is kept, and whether security events are distinguishable.',
  Why: 'Logging is simultaneously a control and an exposure. Over-logging creates a regulated-data archive; under-logging makes attacks undetectable. Both usually coexist.',
  How: 'Find every logging layer (message handlers, action filters, exception handlers) and check for duplication. Verify no request/response bodies are written unmasked. Check the sink path against the webroot. Check for a correlation id and for a distinct security-audit channel.',
  'What To Test': 'Post a synthetic national ID and salary; assert neither appears in any emitted log line. Fetch the log directory over HTTP; assert 403/404. Assert authentication failures are logged as security events.',
  'What Can Be Automated': 'Body-logging detection; log directory resolving under `AppDomain.BaseDirectory`; missing correlation id.',
  'What Requires Manual Review': 'Which fields are sensitive in this domain, and what retention policy applies.',
  'Common Failure Modes': 'Three overlapping layers each logging the full body. Logs inside the webroot. Sync-over-async body reads on the error path. Security events buried at `Information` among payload dumps.',
  Example: 'Reference run: three layers logged full request and response bodies unmasked, into `AppDomain.BaseDirectory\\Logs` — inside the webroot, so potentially fetchable at `/Logs/log_<date>.txt` (`SEC-LOG-001`). No correlation id, no security-audit channel, and `ForContext` results discarded as no-ops.',
  Remediation: 'Log metadata plus a correlation id; mask by allow-list; move sinks outside the webroot and deny by config; add a separate audit channel with its own retention.'
});

doc('17-observability.md', 'Observability', {
  What: 'Health checks, metrics, tracing, alerting and the ability to reconstruct a request end to end.',
  Why: 'Findings are only actionable if the system can show whether they are being exploited. A review that cannot answer "would we see this?" is incomplete.',
  How: 'Check for a health endpoint, request metrics, a propagated correlation/trace id, and alerts on authentication failure rate, 5xx rate and memory pressure.',
  'What To Test': 'Health endpoint reflects dependency state; a correlation id survives across layers; an induced failure raises the expected alert.',
  'What Can Be Automated': 'Presence of a health endpoint and of correlation-id propagation.',
  'What Requires Manual Review': 'Alert thresholds and whether anyone actually receives them.',
  'Common Failure Modes': 'Logs without correlation ids, so concurrent requests cannot be separated — made worse when shared mutable state swaps metadata between them.',
  Example: 'Reference run: no health endpoint, no metrics, no correlation id, and `CODE-CONC-001` actively corrupted attribution between concurrent failures. Detecting exploitation of the critical findings would not currently be possible.',
  Remediation: 'Add a correlation id first — it is the prerequisite for every other observability improvement — then health, metrics and alerts on auth-failure and 5xx rates.'
});

doc('18-performance.md', 'Performance and Availability', {
  What: 'Resource limits, buffering, timeouts, algorithmic complexity, N+1 queries and unbounded allocation.',
  Why: 'In an unauthenticated API, a cheap request that costs the server a lot is a denial-of-service primitive.',
  How: 'Compare request limits at every layer (ASP.NET `maxRequestLength` vs IIS `maxAllowedContentLength`). Find code buffering whole bodies. Check every regex for a timeout. Check `executionTimeout`.',
  'What To Test': 'Body one byte over the limit → 413; pathological regex input → bounded time; sustained concurrent large bodies → stable working set.',
  'What Can Be Automated': 'Limit mismatch between layers; regex without timeout; whole-body buffering.',
  'What Requires Manual Review': 'What the legitimate maximum payload actually is.',
  'Common Failure Modes': 'Assuming the higher configured limit is the effective one. Overstating impact by ignoring a lower default at another layer — the reference review made exactly this error and corrected it by ~35x.',
  Example: 'Reference run: `maxRequestLength` 1 GB, but no `requestFiltering`, so IIS\'s ~28.6 MB default bounded it. Within that, the logging handler still amplified ~3x (UTF-16 string plus parsed `JObject`) → ~85-120 MB per unauthenticated request (`PERF-DOS-001`). Separately, 14 regex sites had no timeout (`PERF-DOS-002`).',
  Remediation: 'Set both limits deliberately and consistently; stop buffering; set a process-wide regex timeout in one line at startup; lower `executionTimeout`.'
});

doc('19-dependencies.md', 'Dependency Security', {
  What: 'The SECURITY queue: confirmed advisories against the exact versions in use, with exploitability assessed for this application.',
  Why: 'This queue drives urgent patching. Mixing it with "outdated" destroys its signal.',
  How: 'Run a scanner that can read the project shape. `dotnet list package --vulnerable` needs PackageReference; `packages.config` needs OWASP Dependency-Check or Trivy. Record CVE, CVSS, affected and fixed versions, and whether the vulnerable code path is reachable here.',
  'What To Test': 'A regression test per upgrade; a CI gate failing above a severity threshold; a meta-check that the scanner actually produced a report.',
  'What Can Be Automated': 'Entirely — provided capability detection picks a scanner that can read the manifest.',
  'What Requires Manual Review': 'Exploitability in context. A vulnerable parser that never receives untrusted input is a different risk from one that does.',
  'Common Failure Modes': 'Reporting an empty SECURITY queue when no scanner ran. Citing a CVE that does not apply to the pinned version. Fabricating CVE identifiers.',
  Example: 'Reference run: the SECURITY queue is **empty, and the report says why** — `dotnet list package --vulnerable` failed and no alternative scanner was installed (`DEP-AUDIT-001`). Of five CVE identifiers cited in the delegated inventory, all five were verified real and correctly characterised as patched-or-hedged; none was fabricated.',
  Remediation: 'Install a manifest-appropriate scanner and gate CI on it; never present an unrun scan as a clean result.'
});

doc('20-outdated-dependencies.md', 'Outdated Dependencies', {
  What: 'The MAINTENANCE queue: outdated, EOL, deprecated, duplicated and licence-restricted packages. Strictly separate from the SECURITY queue.',
  Why: 'An old package is not automatically a vulnerability, and a current package can still carry one. Conflating them produces both false urgency and false comfort.',
  How: 'Inventory every package with current version, latest, target framework, age, EOL status, licence, and whether another package already provides the capability. Assign `cvss: null` — the scoring model is not meaningful here.',
  'What To Test': 'A regression test per upgrade, especially across breaking changes; a policy test asserting one library per capability.',
  'What Can Be Automated': 'Version currency, EOL and licence checks, and duplicate-capability detection.',
  'What Requires Manual Review': 'Breaking-change risk and upgrade sequencing.',
  'Common Failure Modes': 'Labelling a package vulnerable because it is old. Missing that two libraries provide the same capability, so a fix in one leaves the other exposed.',
  Example: 'Reference run: 120 packages. Retired ADAL alongside its MSAL replacement; a ~2003 SQL helper (referenced but unused); **four** spreadsheet parsers; **two** SFTP stacks — and the host-key finding belonged to WinSCP, not the SSH.NET fork an earlier draft blamed; EPPlus 7.6.0 under a non-commercial licence, a legal exposure for a regulated product (`DEP-MAINT-001`, `cvss: null`).',
  Remediation: 'One library per capability; remove retired packages; resolve the licence question; migrate to PackageReference so audits and lockfiles become possible.'
});

doc('21-iis.md', 'IIS and Hosting', {
  What: 'Host-level configuration: authentication modes, handlers, request filtering, static file exposure, TLS bindings and app-pool identity.',
  Why: 'Host configuration can either compensate for or amplify an application finding, and several findings are only decidable at this layer.',
  How: 'Inspect `applicationHost.config` and the site configuration for `anonymousAuthentication`, `windowsAuthentication`, hidden segments, MIME mappings, request limits and the app-pool identity. Then test whether sensitive directories are actually served.',
  'What To Test': 'Fetch every directory the application writes to — log directories, upload staging — and assert they are not served. Verify TLS version and cipher configuration.',
  'What Can Be Automated': 'Config inspection where the file is available; live probing of known-sensitive paths.',
  'What Requires Manual Review': 'Production host configuration is usually outside the repository; conclusions drawn from a dev `applicationHost.config` must be marked environment-dependent.',
  'Common Failure Modes': 'Assuming production matches the checked-in IIS Express configuration. Assuming a directory under the webroot is protected because nothing links to it.',
  Example: 'Reference run: `.vs/<project>/config/applicationhost.config` showed `anonymousAuthentication enabled="true"` with Windows and Basic disabled — no platform-level gate behind `SEC-AUTHZ-001`. This was explicitly flagged as dev-config evidence, with production unverified.',
  Remediation: 'Deny access to log and staging directories at the host level; add hidden segments; confirm production auth modes; run the application pool as a least-privileged identity.'
});

doc('22-deployment.md', 'Deployment', {
  What: 'How the artifact is produced and released: transforms, packaging, artifact contents and repeatability.',
  Why: 'Several findings are only safe because a transform is applied. If releases are manual, that safety is an assumption rather than a control.',
  How: 'Inspect each transform and the *built* output, not just source. Check whether build artifacts, IDE state and analyser output ship alongside source. Confirm the package is produced by a pipeline.',
  'What To Test': 'Assert the packaged config contains no `debug` attribute and no secrets; assert the artifact excludes `bin/`, `obj/`, `.vs/`.',
  'What Can Be Automated': 'Package content assertions, and diffing base configuration against the transformed result.',
  'What Requires Manual Review': 'Whether the documented release process is the one actually used.',
  'Common Failure Modes': 'Reviewing source configuration and never opening the built package. Hand-built releases that skip the transform.',
  Example: 'Reference run: inspecting the build output proved the secrets and `DisableSSLValidation=true` reach deployment (`obj/Release/Package/PackageTmp/Web.config`, `bin/YourApp.dll.config`). It also showed `bin/`, `obj/`, `.vs/` and `.sonarqube/` shipped with the source, and no pipeline existed (`PROC-CICD-001`).',
  Remediation: 'Build releases only from a pipeline; add `.gitignore` for build and IDE output; assert package contents as a gate.'
});

doc('23-ci-cd.md', 'CI/CD', {
  What: 'The pipeline that makes every other recommendation enforceable: restore, build, test, analyzers, secret scan, dependency scan, SARIF upload.',
  Why: 'Almost every remediation in a review ends "wire this into CI". Without a pipeline, none of them is actionable.',
  How: 'Define blocking gates in order of cost: build, analyzers, tests, secret scan, dependency scan. Upload SARIF so findings appear in code review rather than a report nobody opens.',
  'What To Test': 'Pipeline self-test: introduce a secret, a vulnerable package and a failing test, and confirm each independently fails the build.',
  'What Can Be Automated': 'By definition, all of it.',
  'What Requires Manual Review': 'Which gates block versus warn during adoption, so a legacy codebase is not made undeliverable on day one.',
  'Common Failure Modes': 'Running scanners without `--exit-code`/`--failOnCVSS`, so they report and nothing happens. Using stock secret-scanner rules on .NET and getting a green light that means nothing.',
  Example: 'Reference run: no `.github/`, no `azure-pipelines.yml`, no `.gitlab-ci.yml`, no `Jenkinsfile`, no `Dockerfile`, no `.git`. The recommended pipeline is in `ci/` and deliberately uses the custom gitleaks ruleset, because the stock one returns zero on this repository.',
  Remediation: 'Adopt `ci/github-actions.yml`; start gates as warnings on legacy code and blocking on new code; upload SARIF.'
});

doc('24-sonarqube.md', 'SonarQube', {
  What: 'Running and interpreting SonarQube for .NET, including its real strengths and its documented blind spots.',
  Why: 'Sonar is valuable and widely trusted, which makes understanding what it does *not* find essential.',
  How: '.NET Framework requires the **MSBuild** scanner, not the CLI scanner: `SonarScanner.MSBuild.exe begin /k:<key>` → `msbuild /t:Rebuild` → `end`. Raw analyzer output also lands in `.sonarqube/out/0/Issues.json` and can be parsed directly without a server.',
  'What To Test': 'That the quality gate fails the build; that the scan covers every project; that new-code conditions are enforced.',
  'What Can Be Automated': 'Scan execution and gate enforcement. Parsing `Issues.json` offline is a useful fallback when no server is reachable.',
  'What Requires Manual Review': 'Triaging ~800 maintainability issues into what actually matters, and recognising which security classes Sonar cannot see.',
  'Common Failure Modes': 'Using the CLI scanner on .NET Framework and getting no C# analysis. Treating a passing Sonar gate as a security sign-off. Ignoring that Sonar analyses compiled code and therefore never reads `Web.config`.',
  Example: 'Reference run: 840 issues across 51 rules — and **none of the four Critical security findings**. Genuine contributions: `S2068` (hard-coded credential), `S3329` (static IV), `S6444` ×13 (regex timeout), `S1450` (shared field). Blind: missing authorization, reflected CORS, disabled TLS validation, PII in logs, and everything in configuration.',
  Remediation: 'Run Sonar for maintainability and as one corroborating security source; pair it with a secret scanner, a dependency scanner, configuration rules and manual authorization review.'
});

doc('25-trivy.md', 'Trivy', {
  What: 'Filesystem, dependency, secret, licence and container scanning — useful for .NET precisely because it does not need project evaluation.',
  Why: 'Trivy reads manifests directly, so it works on `packages.config` projects where `dotnet list package --vulnerable` fails outright.',
  How: '`trivy fs --scanners vuln,secret,license --format sarif -o trivy.sarif .` and, if containerised, `trivy image <tag>`. Gate with `--exit-code 1 --severity HIGH,CRITICAL`.',
  'What To Test': 'That the scanner produced a non-empty report; that a known-vulnerable test package is detected; that the gate fails as configured.',
  'What Can Be Automated': 'All of it, including SARIF upload.',
  'What Requires Manual Review': 'Exploitability of each advisory in this application, and licence-policy decisions.',
  'Common Failure Modes': 'Running without `--exit-code`, so the pipeline stays green. Assuming a clean result when the manifest was not recognised.',
  Example: 'Reference run: Trivy was **NOT AVAILABLE** (not installed), and this is stated rather than glossed. It is the recommended remedy for `DEP-AUDIT-001` because it reads `packages.config` without needing the VS web targets.',
  Remediation: 'Install Trivy and add it as the dependency and secret gate; combine with the .NET gitleaks ruleset, since Trivy\'s secret rules share the high-entropy bias.'
});

doc('26-gitleaks.md', 'GitLeaks', {
  What: 'Secret scanning, and the custom .NET ruleset that makes it actually work on ASP.NET Framework applications.',
  Why: 'This is the framework\'s clearest evidence that a tool must be validated, not trusted. Stock gitleaks reported **zero** leaks on a repository containing four sets of live cleartext passwords.',
  How: 'Always pass the .NET config: `gitleaks dir . --config rules/gitleaks/dotnet-config.toml --redact --report-format sarif --report-path gitleaks.sarif`. Use `--redact` always. Scan history with `gitleaks detect` when a `.git` directory exists.',
  'What To Test': 'A canary: commit a fake `<add key="TestPassword" value="Str0ng!" />` and assert the scan fails. Without a canary you cannot distinguish "clean" from "not looking".',
  'What Can Be Automated': 'Scanning and gating. Rule authoring is manual and must be maintained as a first-class asset.',
  'What Requires Manual Review': 'Rule tuning, and confirming each hit is a real secret rather than a placeholder.',
  'Common Failure Modes': 'Trusting the default ruleset on .NET. Scanning only the working tree when history exists. Forgetting `--redact` and writing secrets into CI logs. Using lookahead in a rule — Go\'s RE2 does not support it.',
  Example: 'Reference run, measured: stock rules → 49.18 MB scanned, **0 findings** (false negative). `rules/gitleaks/dotnet-config.toml` → 5.08 MB scanned (allow-list excludes `packages/`, `bin/`, `obj/`), **17 findings**: 9 appSetting secrets, 5 commented credentials, 2 weak static keys, 1 connection-string password. Faster *and* more precise.',
  Remediation: 'Adopt the .NET ruleset, add a canary, gate CI with `--exit-code 1`, and treat the ruleset as code that is reviewed and version-controlled.'
});

doc('27-test-strategy.md', 'Test Strategy', {
  What: 'The test pyramid for a legacy .NET application, and the order in which to build it when starting from zero.',
  Why: 'Remediating security findings without tests risks trading a security defect for a behavioural one. Tests are a prerequisite for safe remediation, not a follow-up.',
  How: 'Start with characterisation tests around the highest-risk logic (the core calculation logic), then security integration tests (401/403 per route), then unit tests for new code. Add a test project targeting the same framework; xUnit works on net48.',
  'What To Test': 'Order by risk: authorization matrix, authentication edge cases, core calculation correctness under hostile and culture-variant input, then everything else.',
  'What Can Be Automated': 'Execution, coverage measurement, and a coverage floor applied to new code only.',
  'What Requires Manual Review': 'What "correct" means for a lending decision — this is the specification the tests encode, and it must come from the business.',
  'Common Failure Modes': 'Chasing a global coverage number on a legacy base instead of covering risk. Writing only happy-path tests.',
  Example: 'Reference run: the solution had **one project and no test framework** (`TEST-COV-001`, HIGH). All 31 findings are currently un-regression-testable, and the fail-to-zero calculation defect, the always-false role claim and the culture-dependent numeric formatting are each exactly what one unit test would have caught.',
  Remediation: 'Add the test project; seed it with the `regressionTest` from each P0/P1 finding; set a floor on new code; make the test run a blocking gate.'
});

doc('28-test-gap-analysis.md', 'Test Gap Analysis', {
  What: 'Identifying untested code, branches, security controls, endpoints, exception paths and configuration — not just reporting a coverage percentage.',
  Why: 'Coverage measures lines executed, not risks covered. A 70%-covered codebase can have zero authorization tests.',
  How: 'Cross-reference each endpoint, each security control and each `catch` block against existing tests. Emit a gap table with risk and priority. Every canonical finding carries `tests[]` and `regressionTest`, so the gap list derives from the findings automatically.',
  'What To Test': 'That the gap report itself is regenerated each run and that closing a finding removes its gap entry.',
  'What Can Be Automated': 'Endpoint enumeration, branch coverage, and the finding→required-test mapping (`reports/06-test-gaps.md` is generated).',
  'What Requires Manual Review': 'Risk ranking of each gap.',
  'Common Failure Modes': 'Reporting "0% coverage" as a metric without converting it into a prioritised, actionable gap list.',
  Example: 'Reference run: coverage is 0% because no tests exist, so the gap list is the full set of `regressionTest` entries across all 31 findings — generated into `reports/06-test-gaps.md` rather than hand-written.',
  Remediation: 'Work the generated gap table in priority order, starting with the authorization matrix.'
});

doc('29-reporting.md', 'Reporting', {
  What: 'The three synchronized representations — Markdown for humans, JSON for machines, SARIF for CI — all projected from the canonical findings.',
  Why: 'Hand-authored parallel reports drift. When the exec summary and the security report disagree on a count, the whole document loses authority.',
  How: '`node tools/project-findings.js reviews/<id>`. It merges canonical parts, validates integrity, sorts, and writes `report.json`, `report.sarif` and the Markdown views. Generated files carry a do-not-edit notice.',
  'What To Test': 'Projection is deterministic; SARIF validates against the 2.1.0 schema; counts in the exec summary equal counts in the canonical JSON.',
  'What Can Be Automated': 'All projection, plus the integrity gate that refuses to emit an inconsistent report.',
  'What Requires Manual Review': 'The narrative framing in the executive summary — which findings to lead with, and why.',
  'Common Failure Modes': 'Editing a generated report. Inflating counts by reporting the same vulnerability once per detecting tool.',
  Example: 'Reference run: 31 findings from 6 canonical parts → `report.json`, a valid SARIF 2.1.0 (31 rules, 31 results, `security-severity` populated) and 6 Markdown views, with zero integrity errors. Multi-tool detections stay single findings via `correlation.mergedFrom`.',
  Remediation: 'Never author a report directly; add a CI check that generated reports are unmodified.'
});

doc('30-cvss.md', 'CVSS Scoring', {
  What: 'When CVSS applies, when it must be `N/A`, and how business severity may legitimately differ from the base score.',
  Why: 'Scoring everything makes the scores meaningless. Scoring nothing makes prioritisation impossible. The boundary has to be explicit and enforced.',
  How: 'Score only where the model is meaningful: a vulnerability with an attacker, a vector and an impact. Set `cvss: null` for maintainability, architecture, testing, process and formatting findings — the projection enforces this for `architecture`, `testing` and `process`. Record `conditionalScore` separately when a score depends on an unverified precondition; never report it as the headline.',
  'What To Test': 'Schema negative tests: a CVSS attached to an architecture finding must fail the build; a malformed vector must fail.',
  'What Can Be Automated': 'Vector validation, score/severity consistency, and the category rule.',
  'What Requires Manual Review': 'Every metric choice, especially `AC` and `S`, and any divergence between CVSS severity and business severity.',
  'Common Failure Modes': 'Scoring a code smell because it sounds security-adjacent. Using the conditional worst-case score as the headline. Letting CVSS override business context in a regulated environment.',
  Example: 'Reference run: 20 findings scored, **11 deliberately N/A**. Two documented divergences — `SEC-CRYPTO-001` is CVSS 7.4 HIGH (MITM needs `AC:H`) but business CRITICAL, because one flag disables certificate validation process-wide for core banking, CRM and the credit bureau; `SEC-CFG-001` is CVSS 8.8 but business CRITICAL. Each carries a written `severityRationale`. `SEC-AUTH-001` is scored 5.3 for its confirmed subset with a `conditionalScore` of 9.8 if the domain permits empty-password binds.',
  Remediation: 'Require `severityRationale` whenever severity and CVSS severity differ; keep conditional scores in their own field; never merge the two dependency queues under one score.'
});

doc('31-false-positives.md', 'False Positives and Suppressions', {
  What: 'Lifecycle for findings that are wrong, accepted, or mitigated: status, suppression id, reason, owner, approver, expiry and review date.',
  Why: 'Suppression is necessary and dangerous. Without an expiry it becomes permanent invisible risk.',
  How: 'Set `status` to `FALSE_POSITIVE`, `ACCEPTED_RISK` or `MITIGATED` and attach a `suppression` block. `expiresOn` is **mandatory** — the projection fails the build on a suppression without one, so permanent silent suppression is structurally impossible.',
  'What To Test': 'A suppression without an expiry fails the build; an expired suppression re-surfaces the finding.',
  'What Can Be Automated': 'Expiry enforcement, re-surfacing, and reporting suppression counts per owner.',
  'What Requires Manual Review': 'Whether the stated reason is genuine, and whether the approver had the authority.',
  'Common Failure Modes': 'Blanket inline suppressions with no reason. Suppressing a finding because it is inconvenient rather than incorrect. Never revisiting.',
  Example: 'A real tuned false positive from the reference run: `dotnet-commented-credential` used a bounded lazy match `.{0,600}?` after `<!--`, because Go\'s RE2 engine has no lookahead and the idiomatic `(?:(?!-->).)*?` was unavailable. The bounded match spanned out of a prose comment at `Web.config:8` into an unrelated live `<add>` element. Fix: require the comment body to consist of `<add>` elements. Findings went **18 → 17**, and the rule was corrected rather than the finding suppressed — which is always the better outcome.',
  Remediation: 'Prefer fixing the rule over suppressing the finding; when suppressing, require reason, owner, approver and expiry; review expiries on a schedule.'
});

doc('32-ai-review.md', 'AI-Assisted Review', {
  What: 'Where AI review genuinely adds value, where it must not be trusted, and how its output is labelled and validated.',
  Why: 'AI review is complementary to deterministic tooling, not a replacement for it — and the reverse is equally true. The reference run produced hard evidence in both directions.',
  How: 'Label every source in `sources[]` with the producing tool and a status. Require `verification.disproofAttempt` before a finding is considered validated. Never let an AI conclusion inherit a tool\'s authority, or vice versa.',
  'What To Test': 'That every finding names its sources; that AI-only findings are marked; that the validation pass records a disproof attempt for each.',
  'What Can Be Automated': 'Source labelling, schema enforcement, and flagging findings that lack a disproof attempt.',
  'What Requires Manual Review': 'Whether an AI-proposed mechanism is actually true. This is where the reference run found its own worst errors.',
  'Common Failure Modes': 'Accepting a confident AI mechanism without checking its premises. Assuming a tool\'s silence is a clean result. Assuming an AI review can substitute for a dependency scanner or a secret scanner.',
  Example: 'Reference run, both directions. **AI/review found what tools missed:** SonarQube reported 840 issues and none of the four Critical security findings; all four came from manual review. **A tool\'s confident zero was simply wrong:** stock gitleaks reported "no leaks found" across 49.18 MB on a repository with four live credential sets. **And the AI was wrong too:** the CORS finding\'s original credential-theft mechanism was void (no cookies exist anywhere), the crypto finding\'s zero-IV defect was in a method with no callers, and the DoS impact was overstated ~35x. All three were corrected only because a disproof pass ran.',
  Remediation: 'Run both. Label both. Validate both. Treat any finding without a recorded disproof attempt as unvalidated, regardless of which produced it.'
});

doc('33-review-checklist.md', 'Review Checklist', {
  What: 'The final quality gate, run before a report is considered complete.',
  Why: 'Reviews fail on omission as much as on error. A checklist converts thoroughness from intention into evidence.',
  How: 'Work the list; for any "no", either fix the report or record the gap explicitly as environment-dependent or not-executed.',
  'What To Test': 'That the checklist is answered per review and archived with it.',
  'What Can Be Automated': 'Roughly half — schema completeness, CVSS discipline, snippet presence, source labelling, test mapping, report regeneration.',
  'What Requires Manual Review': 'Whether evidence is genuinely sufficient, and whether severity judgements hold.',
  'Common Failure Modes': 'Answering the checklist aspirationally. Marking a tool "run" when it was installed but unlicensed.',
  Example: 'Reference run: every project and configuration file inspected; vulnerable and merely-outdated dependencies separated into two queues; prior AI output ingested and three of its findings corrected; 31 findings deduplicated with `mergedFrom`; CVSS on 20 and N/A on 11; snippets and remediation on all; 12 findings marked environment-dependent rather than asserted; Fortify recorded as FAILED (invalid licence) not as a clean scan.',
  Remediation: 'Archive the completed checklist alongside `report.json` so a later reader can audit the review itself.'
});

// ------------------------------------------------------------------ emit
let n = 0;
for (const [file, h1, secs] of D) {
  let body = `# ${h1}\n\n`;
  for (const s of SECTIONS) {
    body += `## ${s}\n\n${secs[s] || '_Not applicable for this topic._'}\n\n`;
  }
  body += `---\n\nPart of [dotnet-moraa-codereviewer](../README.md). ` +
          `See also [methodology](01-methodology.md), [CVSS](30-cvss.md), ` +
          `[false positives](31-false-positives.md), [AI review](32-ai-review.md).\n`;
  fs.writeFileSync(path.join(out, file), body);
  n++;
}
console.log(`wrote ${n} docs to docs/`);
if (n !== 33) console.error(`WARNING: expected 33 docs, wrote ${n}`);
