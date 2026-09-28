# dotnet-codereview-framework

An evidence-first code-review and security-analysis framework for .NET — built for legacy
ASP.NET Framework (`packages.config`, non-SDK csproj, `Global.asax`, OWIN, EF6, `Web.config`, IIS)
as much as for modern ASP.NET Core.

Three things make it different from a checklist:

1. **A runnable orchestrator.** `moraa review <path>` runs every available scanner, reconciles their
   output into one finding set, and writes the review **into the source tree**.
2. **A catalog of 279 concrete .NET test cases**, organised A–Z, each with the signal to look for,
   the pass condition, which stack it applies to, and whether a tool can decide it.
3. **A canonical JSON model** where Markdown, JSON and SARIF are *generated* projections — so the
   executive summary, the security report and the CI feed cannot disagree with each other.

Its governing rule: **no tool is authoritative, including the AI.** Every finding records the tools
that found it *and* the tools that missed it.

---

## Quick start

```bash
# 1. Validate the framework and see which integrations this machine supports.
#    Needs no scanner installed; prints install commands for anything missing.
./scripts/validate.sh --fix          # Windows: .\scripts\validate.ps1 -Fix

# 2. What does the project shape permit, before scanning anything?
node bin/moraa.js discover /src/MyApp

# 3. Review. Writes /src/MyApp/.moraa-review/
node bin/moraa.js review /src/MyApp
```

Output lands **beside the code**, at `<sourcePath>/.moraa-review/`:

```
.moraa-review/
  README.md                       map of content
  00-Executive-Summary.md         overall risk + top priorities
  01-Findings.md                  master table by severity
  02-Tool-Results.md              what ran, what failed, what never looked
  03-Dependencies-Security.md     confirmed advisories
  04-Dependencies-Maintenance.md  outdated / EOL / duplicated
  05-Test-Coverage.md             required tests per finding
  06-Configuration.md
  07-Correlation-and-Dedup.md     which tools agreed, which missed
  08-Remediation-Roadmap.md       P0..P3
  Findings/<ID> <title>.md        one page per finding
  data/report.json                canonical source of truth
  data/report.sarif               SARIF 2.1.0 for code scanning
  data/raw/                       untouched tool output
```

### Integrations

| Adapter | Kind | Notes |
|---|---|---|
| `trivy` | dependency | reads manifests, so it works on `packages.config` where `dotnet list package` cannot run |
| `snyk` | dependency | needs auth; preserves the transitive `from` chain, which changes the fix |
| `osv-scanner` | dependency | free, no auth |
| `dependency-check` | dependency | SARIF, reads `packages.config` |
| `gitleaks` | secret | **always** uses the .NET ruleset; refuses to fall back to stock rules |
| `semgrep` | sast | runs the bundled `dotnet-moraa.yaml` |
| `sonarqube` | quality | Web API, plus an **offline mode** that parses `.sonarqube/out/0/Issues.json` |
| `ai-review` | ai | **optional, off by default** |

Every adapter satisfies one contract and is verified by `node tools/test-adapters.js` **without the
real tool installed**, by parsing a fixture. A status other than `EXECUTED` is structurally
forbidden from carrying findings, which is what makes a false clean impossible to express.

### AI review is optional

It is **off by default** because enabling it transmits source code to a third-party API. Keys are
read from the environment only — `ANTHROPIC_API_KEY`, `OPENAI_API_KEY`, `ZAI_API_KEY` — never from
config files and never from CLI arguments, since `argv` is visible in process listings. AI findings
are capped at confidence `POSSIBLE`, receive no CVSS, and are marked `UNVERIFIED`. Everything else
works fully without it.

With **zero scanners installed** the pipeline still produces a report: discovery alone derived six
findings on a synthetic legacy project, and every absent tool was reported as a capability gap.

See [docs/34-orchestration.md](docs/34-orchestration.md).

---

## The test-case catalog

279 reusable cases across two files. Pull the relevant ids into a review and map them to findings.

- [`catalog/dotnet-test-cases.json`](catalog/dotnet-test-cases.json) — **A–R, 178 cases.** The
  OWASP-aligned core.
- [`catalog/dotnet-test-cases-advanced.json`](catalog/dotnet-test-cases-advanced.json) — **S–Z,
  101 cases.** What is specific to .NET *as a platform*: its serializers, its reflection surface,
  its legacy web stack, its RPC frameworks, the federation protocols it ships clients for,
  HTTP protocol-level issues, and runtime semantics that silently change security decisions.

| | Category | Cases |
|---|---|--:|
| A | Authentication and session/token handling | 18 |
| B | Authorization, access control, IDOR, multi-tenancy | 12 |
| C | Input validation and injection | 15 |
| D | Output encoding, XSS, content-type handling | 8 |
| E | Cryptography and secrets management | 12 |
| F | Transport security (TLS) | 7 |
| G | Logging, monitoring and sensitive data in logs | 9 |
| H | Error handling and information disclosure | 7 |
| I | File upload, download and path traversal | 9 |
| J | Deserialization and XML (XXE) | 7 |
| K | SSRF and outbound request handling | 6 |
| L | Business logic | 12 |
| M | Third-party integration security | 6 |
| N | Configuration and hardening | 15 |
| O | Dependency and supply-chain management | 8 |
| P | Concurrency, resources and availability | 11 |
| Q | Data protection, privacy and regulatory | 7 |
| R | Code-quality signals that carry security weight | 9 |
| **S** | **Unsafe reflection, type resolution and dynamic code execution** | **14** |
| **T** | **ASP.NET platform internals** (ViewState, crypto endpoints, path APIs, impersonation) | **14** |
| **U** | **Template injection and runtime compilation (SSTI)** | **8** |
| **V** | **WCF, SOAP and legacy service stacks** | **9** |
| **W** | **Modern .NET surfaces** (SignalR, gRPC, Blazor, Minimal API, hosted services) | **16** |
| **X** | **Federation protocols** (OAuth 2.0, OpenID Connect, SAML) | **14** |
| **Y** | **HTTP protocol-level attacks** (smuggling, host header, cache poisoning, splitting) | **11** |
| **Z** | **Runtime and platform semantics that change security outcomes** | **15** |

Each case is tagged with what can honestly be automated:

| Automatability | Cases | Meaning |
|---|--:|---|
| `DETERMINISTIC` | 212 | a rule can decide it reliably |
| `MANUAL` | 32 | needs business context |
| `DYNAMIC` | 19 | only a running system settles it |
| `AI_ASSISTED` | 16 | needs cross-file or domain reasoning; propose, human confirms |

By stack: 222 apply to both, 41 are ASP.NET Framework specific, 16 are ASP.NET Core specific.
By priority: 96 critical, 114 high, 64 medium, 5 low.

### Is it exhaustive? No — and that is measurable

`tools/audit-coverage.js` probes the catalog against a maintained list of known-dangerous .NET
APIs, frameworks and attack classes, and **prints what is not covered**:

```bash
node tools/audit-coverage.js            # report gaps (exits 0 — gaps are backlog)
node tools/audit-coverage.js --strict   # fail CI on any gap
```

```
test cases    : 279
categories    : 26
probes        : 147
covered       : 147
gaps          : 0
coverage      : 100.0%
```

**100% means "no *known* gaps", never "exhaustive."** The tool cannot know about a surface nobody
has added a probe for, and it audits *breadth* of classes rather than *depth* within a class. Add a
probe whenever you learn of a surface the catalog should cover — a failing probe is a backlog item,
not an error.

Categories S–Z exist because this audit was run against the A–R catalog and **37 of 47 probed
surfaces came back missing** — including ViewState deserialization RCE, padding-oracle exposure,
`Type.GetType` injection, `XamlReader.Parse`, SAML signature wrapping, host-header reset poisoning,
request smuggling, and culture-sensitive comparison bypass. Asking the question with a tool found
gaps that reading the catalog did not.

Known remaining thinness, stated rather than hidden: ADCS and Kerberos delegation, Azure-specific
identity misuse, side-channel and crypto oracles beyond padding, SQL Server-side permissions and
stored-procedure bodies, and desktop/mobile .NET (WPF, MAUI).

A sample case:

```json
{
  "id": "G-002", "category": "G",
  "title": "Log directory inside the webroot",
  "lookFor": "Path.Combine(AppDomain.CurrentDomain.BaseDirectory, \"Logs\") or ContentRootPath sinks",
  "expected": "log path outside the served root; deny rule as defence in depth",
  "stack": "both", "type": "unit", "priority": "critical",
  "automatable": "DETERMINISTIC", "cwe": "CWE-552"
}
```

---

## Canonical model

The canonical JSON is the **single source of truth**. Every other artifact is a projection and may
never contain a fact absent from it.

```
reviews/<id>/findings-*.json          <-- authored / AI-assisted, schema-validated
            |
            v   tools/project-findings.js
            |
  +---------+----------+-----------------+
  |                    |                 |
report.json        report.sarif      reports/*.md
(machine)          (CI code-scanning) (exec, security, deps, tests, config, roadmap)
```

Schema: [`schema/finding.schema.json`](schema/finding.schema.json).

```bash
node tools/project-findings.js reviews/example    # -> report.json, report.sarif, reports/*.md
node tools/validate-crossrefs.js reviews/example  # catalog + finding-reference integrity
node tools/generate-docs.js                       # -> docs/01..33
```

The projection **fails the build** on integrity violations: duplicate finding ids, a finding with no
`sources`, a malformed CVSS vector, a CVSS score attached to a non-scoreable category, or a
suppression with no expiry date.

### Why the schema looks the way it does

- **`sources[]` records misses, not just hits.** `status` may be `REPORTED`, `MISSED`,
  `FALSE_NEGATIVE`, `NOT_RUN` or `CONTRADICTED`. This is what makes tool disagreement visible instead
  of averaged away.
- **`cvss` is nullable and that is load-bearing.** Architecture, testing and process findings carry
  `cvss: null`, and the projection enforces it. See [docs/30-cvss.md](docs/30-cvss.md).
- **`severity` may differ from CVSS base severity**, but only with a written `severityRationale`.
- **`confidence` is separate from severity.** A defect can be CONFIRMED while its exploit path is
  only POSSIBLE.
- **`conditionalScore`** holds the "if this precondition proves true" score without ever reporting it
  as the headline.
- **`verification.disproofAttempt`** records what was done to *break* the finding. A finding nobody
  tried to disprove is not validated.
- **`correlation.mergedFrom`** is how three tools reporting one vulnerability stay **one** finding
  instead of inflating the count.

---

## Two independent dependency queues

An old package is not automatically a vulnerability, and a current package can still carry one.
These never merge into a single number.

```
SECURITY                          MAINTENANCE
├── confirmed advisory            ├── outdated / behind latest
├── CVE + CVSS + fixed version    ├── EOL / deprecated / unmaintained
├── exploitability in THIS app    ├── duplicated capability
└── upgrade + regression tests    └── licence risk, version drift
```

When the SECURITY queue is empty because no scanner could run, the generated report says exactly
that rather than implying a clean bill of health.

---

## Custom rules, because defaults are not enough on .NET

### Secret scanning

[`rules/gitleaks/dotnet-config.toml`](rules/gitleaks/dotnet-config.toml) — because **stock gitleaks
rules miss how .NET actually stores secrets.**

Measured on a real legacy ASP.NET Framework application: stock rules scanned 49.18 MB and reported
**"no leaks found"** on a tree containing four sets of live cleartext passwords. The default rules
target high-entropy cloud tokens (`AKIA…`, `ghp_…`, PEM blocks, JWTs), not low-entropy passwords in
XML attributes such as `<add key="AdminPassword" value="..." />`. The .NET ruleset found **17**.

Covers: connection-string passwords, secret-bearing `appSettings`, **credentials left in XML
comments**, inline credential assignment in C#, and weak static key literals.

```bash
gitleaks dir . --config rules/gitleaks/dotnet-config.toml --redact \
         --report-format sarif --report-path gitleaks.sarif --exit-code 1
```

Always pair it with a **canary** (see [`ci/github-actions.yml`](ci/github-actions.yml)) so "clean"
cannot silently mean "not looking".

### Static analysis

[`rules/semgrep/dotnet-moraa.yaml`](rules/semgrep/dotnet-moraa.yaml) — 22 rules for the
deterministic findings: reflected-Origin CORS, disabled certificate validation, zero IV, weak KDF
iterations, SSH host-key bypass, body logging, webroot log paths, path traversal, missing
empty-password guards, unconditional Swagger, expression injection, fail-silent `catch` blocks,
culture-sensitive money formatting, untimed regexes, sync-over-async.

Rules for `AI_ASSISTED` findings are deliberately **absent** — a rule that half-detects them produces
noise instead of signal.

---

## Capability detection matters

The framework must never report a clean result it never obtained. Two verified examples:

| Situation | Naive behaviour | Correct behaviour |
|---|---|---|
| `dotnet list package --vulnerable` on a non-SDK web project | reports nothing → looks clean | **FAILED**: the SDK lacks `Microsoft.WebApplication.targets`, and the command does not support `packages.config`. Use OWASP Dependency-Check or Trivy, which read the manifest directly. |
| A SAST tool installed but unlicensed | "executed, 0 findings" | **FAILED**: `Invalid license file`. Zero findings from a tool that never ran is not a result. |

Status vocabulary for every command and tool: **EXECUTED**, **FAILED**, **NOT AVAILABLE**,
**NOT APPLICABLE**, **UNVERIFIED**.

---

## Phases

| # | Phase | Output |
|--:|---|---|
| 1 | Project discovery — solution, projects, framework, entry points, config, CI, containers, VCS | architecture map |
| 2 | Build & test verification | status per command with exit codes |
| 3 | Tool execution — with **capability detection** per project shape | `reports/11-tool-results.md` |
| 4 | Ingest prior outputs — other AI runs, analyzers, scanners | normalized inventory |
| 5 | Normalization — canonical ids, schema validation | `findings-*.json` |
| 6 | Correlation & dedup | `correlation.mergedFrom` |
| 7 | **Adversarial validation** — try to disprove every finding | `verification.*` |
| 8 | Projection — Markdown + JSON + SARIF | `reports/`, `report.json`, `report.sarif` |

Phase 7 is the one most pipelines omit. On the reference run it corrected 3 findings, strengthened 2
and clarified 2 — all three corrections came from the same mistake: **assuming a dangerous-looking
construct was on a live path.** Two were not (dead code, an unreachable limit) and one had the wrong
mechanism entirely. A grep hit is evidence of a *pattern*, not of *reachability*.

---

## Tools and AI are complementary, in both directions

From the reference run, stated plainly because both halves matter:

- **Review found what tools missed.** SonarQube reported 840 issues across 51 rules — and none of the
  four Critical security findings. Its real contributions were narrow but genuine: a hard-coded
  credential, a static IV, 13 untimed regexes, a shared-field concurrency defect. Missing
  authorization, reflected CORS and disabled TLS validation were all invisible to it, and it never
  reads `Web.config` at all because it analyses compiled code.
- **A tool's confident zero was simply wrong.** Stock gitleaks: 0 findings on a repository with four
  live credential sets.
- **And the AI was wrong too.** Three findings had materially incorrect reasoning until an
  adversarial pass caught them.

Run both. Label both. Validate both.

---

## Repository layout

```
dotnet-codereview-framework/
├── README.md
├── bin/moraa.js                        the orchestrator CLI
├── scripts/validate.{ps1,sh}           validate install + report tool support
├── catalog/
│   ├── dotnet-test-cases.json          178 cases, A-R (OWASP-aligned core)
│   └── dotnet-test-cases-advanced.json 101 cases, S-Z (.NET platform specifics)
├── schema/finding.schema.json         canonical contract
├── tools/
│   ├── project-findings.js            canonical -> md + json + sarif, with integrity gate
│   ├── selfcheck.js                   12-gate whole-framework check
│   ├── test-adapters.js               adapter contract harness (no tools needed)
│   ├── test-correlation.js            proves multi-tool dedup
│   ├── validate-crossrefs.js          catalog + finding-reference integrity
│   ├── audit-coverage.js              probes the catalog and PRINTS THE GAPS
│   ├── generate-docs.js               docs/01..33
│   └── summarize-gitleaks.js          gitleaks report roll-up
├── rules/
│   ├── gitleaks/dotnet-config.toml    .NET config-secret rules
│   └── semgrep/dotnet-moraa.yaml      22 deterministic .NET rules
├── reviews/example/                   synthetic worked example (no real application)
├── reports/                           generated views
├── ci/github-actions.yml              blocking gates + secret-scan canary
└── docs/01..33                        methodology, one topic per file
```

Every doc follows the same nine sections: What · Why · How · What To Test · What Can Be Automated ·
What Requires Manual Review · Common Failure Modes · Example · Remediation.

---

## Worked example

[`reviews/example/`](reviews/example/) is **synthetic** and describes no real application. It exists
so the pipeline runs end to end and so every schema feature has a worked example: a CVSS-scored
finding, a deliberately `null` one, a severity/CVSS divergence with a written rationale, a
`conditionalScore`, a tool false negative, and an `ACCEPTED_RISK` with an expiring suppression.

---

## Licence

MIT.
