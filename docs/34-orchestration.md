# Multi-Tool Orchestration

## What

The `moraa` CLI runs a five-stage pipeline over a .NET solution and writes one reconciled review:

```
discover -> run adapters -> normalise -> correlate/dedup -> project
```

Four commands:

| Command | Purpose |
|---|---|
| `moraa review <path>` | the full pipeline |
| `moraa discover <path>` | project shape and capability detection only, no scanning |
| `moraa tools [path]` | list adapters and whether each can run here |
| `moraa init <path>` | write a starter `moraa.config.json` |

Six integrations ship today: **trivy** and **snyk** (dependency), **sonarqube** (quality),
**gitleaks** (secret), **semgrep** (sast), **ai-review** (optional AI).

Output is written **into the source tree** at `<path>/.moraa-review/`, so the review travels with
the code it describes: nine Markdown pages, one page per finding under `Findings/`, plus
`data/report.json`, `data/report.sarif` and `data/raw/` holding untouched tool output.

## Why

Running several scanners is easy. Producing one trustworthy answer from them is not, and the two
failure modes are opposite:

- **Inflation.** Three tools detect one issue and the report claims three findings. Counts stop
  meaning anything.
- **False clean.** A tool fails, is unauthenticated, or was never installed, and its empty output
  is rendered indistinguishably from "we looked and it was fine".

The orchestrator exists to prevent both. Correlation collapses duplicates; the adapter contract
makes a non-executing tool structurally incapable of producing a result that looks clean.

## How

**The adapter contract.** Every integration exports `id, name, kind, stacks, detect(), run(), parse()`.
`run()` returns a status of `EXECUTED`, `FAILED`, `NOT_AVAILABLE`, `NOT_APPLICABLE` or `UNVERIFIED`,
and **any status other than `EXECUTED` is forbidden from carrying findings**. That single rule is
what makes a false clean impossible to express.

`parse()` is pure — no filesystem, no network, no clocks, no randomness — and must return `[]` for
`''`, `'{}'`, `'[]'`, `null`, `undefined` and `'{not json'` without throwing. Purity is what makes
it testable against a fixture with no tool installed.

**Exit codes that are easy to get wrong.** `snyk test`, `semgrep` and `gitleaks` all exit `1` when
they *find* something. Treating that as failure converts a successful scan into an empty,
apparently-clean result — the exact bug this framework is built to avoid. Each adapter maps `0` and
`1` to `EXECUTED` and only other codes to `FAILED`.

**Correlation.** Findings are keyed, strongest first:

1. **advisory identity** — same CVE/GHSA plus same package
2. **concept + file** — a rule-equivalence table maps tool-native rule ids onto shared concepts, so
   SonarQube `S4830` and semgrep `moraa-dotnet-disable-cert-validation` merge even though neither
   knows the other exists
3. **exact rule + location**

Merging keeps the strongest severity and confidence, the richest text, and accumulates every tool's
own words. Nothing is discarded: `sources[]` keeps the full audit trail, and a tool that ran but did
*not* report a given finding is recorded with status `MISSED`. That asymmetry is deliberate —
agreement raises confidence, and a miss is information about the tool.

## What To Test

- Every adapter against its fixture: `node tools/test-adapters.js`
- Correlation behaviour: `node tools/test-correlation.js`
- The whole framework: `node tools/selfcheck.js` (12 gates)
- Your machine's tool support: `scripts/validate.ps1` or `scripts/validate.sh`
- That an empty dependency queue explains itself rather than implying safety
- That a deliberately failing tool never yields findings

## What Can Be Automated

All of it, and it is. Verified state at the time of writing:

| Gate | Result |
|---|---|
| adapter contract tests | 6 pass, 0 fail |
| correlation | 4 raw → 2 canonical, merged 2, cross-tool equivalence works |
| catalog coverage audit | 304 test cases, 0 known gaps |
| canonical projection | SARIF 2.1.0 |
| CLI end-to-end on a synthetic project | 6 findings, vault + JSON + SARIF written |
| secret scan of this repo | clean |
| self check | **12 pass, 0 warn, 0 fail** |

## What Requires Manual Review

- **Exploitability.** A scanner reports a pattern; whether it is reachable in *this* application is
  judgement. See [CVSS](30-cvss.md).
- **Whether an ownership check compares the right two things.** No rule knows which field carries
  tenancy.
- **Every AI finding.** See [AI review](32-ai-review.md).
- **How a Sonar scan was run.** On .NET Framework, analysis requires the MSBuild scanner
  (`begin → msbuild → end`); the plain CLI scanner analyses no C# at all, so a low issue count may
  mean nothing was analysed. Sonar also reads compiled code and therefore never reads `Web.config`
  or `appsettings.json` — configuration is a structural blind spot.

## Common Failure Modes

- **Trusting a tool's silence.** `gitleaks` with stock rules scanned 49 MB of a real legacy
  application and reported *no leaks found* while four sets of live cleartext credentials sat in
  `Web.config`. The adapter therefore always passes `--config rules/gitleaks/dotnet-config.toml`
  and **refuses to fall back to stock rules**, because a false clean is worse than no scan. See
  [gitleaks](26-gitleaks.md).
- **Reporting an unrun scan as clean.** `dotnet list package --vulnerable` cannot evaluate a
  non-SDK web project at all. When no dependency scanner completes,
  `03-Dependencies-Security.md` states *"Empty — and that is a capability gap, not a clean result"*.
  This is enforced by `selfcheck.js`. See [dependencies](19-dependencies.md).
- **Counting detectors instead of defects.** Prevented by `correlation.mergedFrom`.
- **Leaking credentials through the review itself.** Secret findings carry a redacted snippet; the
  AI adapter scrubs key-shaped strings from anything it writes to disk.
- **Shadowing a shell builtin in a helper script.** A `head()` function in `validate.sh` shadowed
  `/usr/bin/head` and corrupted every version probe. Found by running the script, not by reading it.

## Example

```bash
# 1. is the framework healthy, and which tools does this machine support?
./scripts/validate.sh --fix            # or: .\scripts\validate.ps1 -Fix

# 2. what does the project shape permit, before scanning anything?
node bin/moraa.js discover /src/MyApp

# 3. which adapters can actually run here?
node bin/moraa.js tools /src/MyApp

# 4. review. Writes /src/MyApp/.moraa-review/
node bin/moraa.js review /src/MyApp

# narrow the run, or gate a pipeline on severity
node bin/moraa.js review /src/MyApp --only trivy,gitleaks
node bin/moraa.js review /src/MyApp --skip ai-review --fail-on HIGH
```

AI review is **opt-in and off by default**, because enabling it transmits source code to a
third-party API. Keys are read from the environment only — `ANTHROPIC_API_KEY`, `OPENAI_API_KEY` or
`ZAI_API_KEY` — never from config files and never from CLI arguments, since `argv` is visible in
process listings. AI findings are capped at confidence `POSSIBLE`, receive no CVSS, and are marked
`UNVERIFIED`: a model's assertion is a lead, not a conclusion.

```bash
export ANTHROPIC_API_KEY=...           # then set tools.ai-review.enabled = true
node bin/moraa.js review /src/MyApp
```

With **zero scanners installed** the pipeline still works: discovery alone derived six findings on
a synthetic legacy project — no test project, no dependency-audit capability, no analyzers, no CI,
no lockfile, no version control — and every absent tool was reported as a capability gap.

## Remediation

1. Run `scripts/validate.*` first. Install the tools it reports missing, starting with `gitleaks`.
2. Run `moraa discover` and read the capability list before believing any result.
3. Add `moraa review --fail-on HIGH` to CI and upload `data/report.sarif` to code scanning.
4. Add `.moraa-review/` to `.gitignore` unless the repository is private — the vault quotes
   credentials, internal hostnames and unremediated findings.
5. Keep AI review off unless you have accepted that source code leaves the machine.

---

Part of [dotnet-codereview-framework](../README.md). See also
[methodology](01-methodology.md), [architecture](02-architecture.md),
[reporting](29-reporting.md), [false positives](31-false-positives.md).
