# 35 — Usage and switches

Everything the CLI accepts, what each switch actually does, and the workflows they compose into.
Documented against `bin/moraa.js` as it stands. Where a capability has real limits, the limit is
stated here rather than papered over.

---

## The commands

```bash
moraa discover <sourcePath>           # project shape + capability detection. No scanning.
moraa tools [sourcePath]              # which adapters AND built-ins can run here, and why not
moraa review <sourcePath> [options]   # the full pipeline: tools + built-ins, merged
moraa native <sourcePath>             # ONLY the built-in engine — no scanner, no AI, no network
moraa supplychain <sourcePath>        # ONLY the NuGet supply-chain analyzer
moraa binary <sourcePath>             # ONLY the assembly (bin/*.dll) review path
moraa config                          # which integrations are configured (values redacted)
moraa baseline create|show <sourcePath>
moraa init <sourcePath>               # write a starter moraa.config.json
```

Invoke either as the installed binary (`moraa …`) or directly (`node bin/moraa.js …`). The examples
below use `node bin/moraa.js` so they work from a clone without installing.

---

## `discover` — look before you scan

```bash
node bin/moraa.js discover /src/MyApp
```

Reports the project shape and, critically, **what the shape permits**. Output includes:

- stack, solution file, project count (and how many are test projects)
- flags: `packages.config` present, non-SDK csproj present, tests present, lock file present,
  analyzers present, CI present, git repo
- a **capabilities** block — for each capability, `YES`/`NO`, the reason, and an alternative where
  one exists
- any findings establishable from discovery alone

**Run this first on an unfamiliar codebase.** A non-SDK `packages.config` project cannot be
`dotnet build`-ed, which means anything requiring a compile is off the table before you start. Better
to learn that here than from a confusing failure three minutes into a review.

---

## `tools` — what can actually run on this machine

```bash
node bin/moraa.js tools              # in the abstract
node bin/moraa.js tools /src/MyApp   # judged against a real project
```

Prints `READY` or `UNAVAILABLE` per **adapter** (external tools), with the version when available,
the reason when not, and the **exact command to enable it**. Below the adapters it lists the
**built-in sources** (`native`, `supplychain`, `binary`) — these are always READY because they need
no external tool. Nothing is installed by this command.

Pass a source path when you want the answer for a specific project rather than in general — a couple
of adapters are only meaningful against a particular project shape.

---

## `review` — the pipeline

```bash
node bin/moraa.js review /src/MyApp
```

Pipeline order: **discover → run external adapters → run built-in sources → normalise →
correlate/dedup EVERYTHING into one canonical set → project into the vault, JSON, SARIF, Markdown
and Excel.**

The built-in sources are not a separate report — their findings enter the **same** correlation as
adapter findings, so a defect found natively and by a scanner becomes ONE finding with both tools
recorded, and "native found it, scanner X missed it" is visible per finding.

Output lands beside the code at `<sourcePath>/.moraa-review/` (see [40 — Excel output](40-excel-output.md)
for the spreadsheet, [29 — Reporting](29-reporting.md) for the vault).

### Review options

| Switch | Default | Effect |
|---|---|---|
| `--out <dir>` | `.moraa-review` | Output folder, resolved **relative to `<sourcePath>`**, not to the cwd. |
| `--only a,b` | all | Run only the named sources — adapter ids **and** `native`, `supplychain`, `binary`. |
| `--skip a,b` | none | Run everything except the named sources. |
| `--fail-on <sev>` | never fails | Exit `1` when a finding at or above this severity exists. One of `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`. |
| `--format <list>` | `all` | Projections to write: `vault,json,sarif,md,excel` or `all`. `--format excel` writes ONLY `data/report.excel.xml`. |
| `--no-color` | off | Disable ANSI colour. Colour is also off automatically under `NO_COLOR`, `TERM=dumb`, or whenever output is not a terminal — piped output contains **zero** escape bytes. |
| `--config <path>` | search order | Explicit `moraa.config.json`, overriding the default search. |

`--only` and `--skip` take the source **id** (`trivy`, `snyk`, `sonarqube`, `gitleaks`, `semgrep`,
`ai-review`, `roslyn`, `native`, `supplychain`, `binary`). Run `moraa tools` to see the exact ids —
guessing at a name silently runs nothing.

### `--fail-on` is the CI switch

Without it, `review` always exits `0` and a pipeline will never go red. With it, the exit code
becomes the gate:

```bash
node bin/moraa.js review /src/MyApp --fail-on HIGH   # exit 1 if any HIGH or CRITICAL exists
```

Start a legacy codebase at `--fail-on CRITICAL` and tighten over time. Setting `--fail-on LOW` on an
untouched legacy application will fail on the first run and stay failing, which teaches the team to
ignore the gate.

---

## Built-in sources — the zero-install lane

### `native` — the built-in engine

`moraa native <sourcePath>` runs the framework's own analyzer: XML-configuration checks, C#
heuristics and manifest checks, driven by the 304-case .NET catalog. No scanner, no AI, no network.
See [36 — The native engine](36-native-engine.md).

Its honesty contract: every catalog case applicable to the project is either **decided by an
implemented check** or surfaced as an explicit **manual-review item** carrying the case's checklist
question (INFO severity — undecided questions, not defects). Skipped directories (`Tests/`, `obj/`,
`bin/`, `packages/`, `node_modules/`, `Migrations/`) are **named in the output**, so you can see
what was not examined. Suppression in `moraa.config.json`: `native.noManualReview: true`
(discouraged — that is the honest half of the coverage model).

### `supplychain` — NuGet supply-chain analysis

`moraa supplychain <sourcePath>` answers the NuGet-specific questions CVE scanners do not ask:
dependency confusion (private id resolvable from a public feed), feed/credential misconfiguration,
pinning and lockfile integrity, restore-time execution surface. See [37 — Supply-chain](37-supply-chain.md).

### `binary` — deployed-assembly review

`moraa binary <sourcePath>` reviews `bin/*.dll` when source is absent: PE/ECMA-335 metadata,
debug-build-in-production detection, strong-name state, binding redirects, embedded secrets
(**redacted** in every finding), and an optional decompiler pass when `ilspycmd` is installed.
See [38 — Binary review](38-binary-review.md).

All three write their raw result under `<out>/raw/` with `--write` and exit per the standard codes.

---

## PR/diff mode — `--diff`

```bash
node bin/moraa.js review /src/MyApp --diff origin/main
```

The scanners see the WHOLE tree — scanning only changed files would break cross-file analysis — but
after correlation the **reported** set is filtered to files the branch changed. Merge-base semantics
(`base...HEAD`) are the default: only what this branch introduced. `--diff-two-dot` switches to
exact-tree `base..HEAD`; `--diff-context` additionally reports findings whose `additionalLocations`
touch a changed file (catches sink-here/source-there flows the tool did emit as such).

| Switch | Effect |
|---|---|
| `--diff <base>` | Restrict the reported findings to the changed set. |
| `--diff-two-dot` | With `--diff`: `base..HEAD` instead of the default `base...HEAD`. |
| `--diff-context` | With `--diff`: include contextual (additional-location) matches. |
| `--fail-on-new <sev>` | With `--diff` **or baseline mode**: exit `1` when a NEW finding at or above this severity is introduced. |

Honest limit, stated in the output too: a taint finding is reported at its **sink**. A source added
in the diff with its sink in an unchanged file is only seen when the tool emitted the source as an
`additionalLocation` and you passed `--diff-context`. `--diff` is a fast PR gate; the scheduled full
scan remains the safety net.

---

## Baseline mode — review what is NEW

```bash
node bin/moraa.js review /src/MyApp                       # 1. review
node bin/moraa.js baseline create /src/MyApp              # 2. freeze the findings
node bin/moraa.js review /src/MyApp                       # 3. later: NEW / EXISTING / FIXED
```

`baseline create` writes `<out>/data/baseline.json`. Every later review classifies its findings:
**NEW** (not in the baseline — leads the summary and can gate CI via `--fail-on-new`), **EXISTING**
(known debt, fingerprint present), **FIXED** (in the baseline, absent now).

Fingerprints are **rule + file + whitespace-normalised snippet** — deliberately NOT the line number,
so reformatting does not manufacture NEW findings or forget old ones.

Suppressions are accountable:

```bash
node bin/moraa.js baseline create /src/MyApp \
  --suppress "SEC-INJ-001=accepted until vendor patch;expires=2027-03-31"
```

A justification is **required**; the id must be the exact `findingId` from `data/report.json`;
an **expired** suppression is reported back as a finding instead of quietly staying waived.
`moraa baseline show <sourcePath>` lists the baseline with suppressions and expiries.

---

## The two AI modes — both OFF by default

Nothing AI-related runs unless you explicitly enable a mode, and with both off **no API key is
required anywhere**. Governing rule in both modes: **no tool is authoritative, including the AI.**
See [32 — AI review](32-ai-review.md) and [39 — Config and AI modes](39-config-and-ai-modes.md).

### Mode `report` — enrich the produced report, in place

```bash
node bin/moraa.js review /src/MyApp --ai-report
```

Reads the ALREADY-written `data/report.json` plus each finding's title and the code snippet read
from the source file at that line, and writes a per-finding narrative **into the finding's own
Markdown page** — not a separate document. The AI block sits inside stable markers
(`<!-- moraa:ai-report:v1 START id=… -->`) and is **replaced whole** on re-run: idempotent,
never appended, never nested. The canonical JSON is never edited by this mode. Where the model
disagrees with the recorded finding, the disagreement is rendered as UNRESOLVED — never applied.

### Mode `review` — direct AI code review

```bash
node bin/moraa.js review /src/MyApp --ai-review
```

The AI reads selected source files and produces findings attributed to tool `ai-review`, which
correlate like any other tool's findings — capped at confidence POSSIBLE, no CVSS from the model.
Where the AI disagrees with a tool, the disagreement is recorded on the finding and left unresolved.

### Shared AI switches

| Switch | Effect |
|---|---|
| `--ai-report` | Enable mode `report` for this run. |
| `--ai-review` | Enable mode `review` for this run. |
| `--ai-provider <name>` | `anthropic` \| `openai` \| `zai` \| `local` \| `none` \| `auto` (default). |
| `--ai-model <id>` | Model override for both modes. |
| `--ai-base-url <url>` | Required for `--ai-provider local` (any OpenAI-compatible endpoint). |
| `--ai-key <secret>` | **Last resort** — argv is visible in process listings. Prefer the environment. |

Missing key, network failure, HTTP error and rate limiting degrade cleanly: the mode reports why and
the rest of the pipeline is unaffected. An AI status other than EXECUTED never carries findings.

---

## `config` — what is configured, values redacted

```bash
node bin/moraa.js config
```

One `moraa.config.json` holds every integration setting: which tools are enabled, severity
thresholds, SonarQube endpoint, and the two AI mode toggles. `moraa init` writes a starter.
`moraa config` prints what is configured vs missing **without revealing any value** — keys display
as their last 4 characters only.

**Precedence everywhere:** CLI flag → environment variable → `moraa.config.json` → built-in default.

### Secrets

Keys are read from the environment **or** from `moraa.config.json` (`keys.*`) — never from a report,
never echoed in logs, and argv (`--ai-key`) only as a documented last resort. If you put real keys
in the config file, add `moraa.config.json` to `.gitignore` FIRST — the config layer checks and
warns when the repo-root file is not ignored, but the warning is not a substitute for the ignore
rule. `moraa config` never prints values; the self-check fails the repo if a literal key pattern
lands in source.

| Variable | Used by |
|---|---|
| `MORAA_AI_API_KEY` | AI modes (generic; wins over provider-specific) |
| `ANTHROPIC_API_KEY` / `OPENAI_API_KEY` / `ZAI_API_KEY` | AI modes (per provider) |
| `SNYK_TOKEN` | `snyk` adapter |
| `SONAR_TOKEN`, `SONAR_HOST_URL` | `sonarqube` adapter |

---

## Workflows

### First look at an unfamiliar codebase

```bash
node bin/moraa.js discover /src/MyApp     # what is this, and what can be run against it?
node bin/moraa.js tools /src/MyApp        # what do I have installed?
node bin/moraa.js review /src/MyApp       # everything available, merged
```

### Nothing installed but Node

```bash
node bin/moraa.js native /src/MyApp       # real findings from the built-in engine alone
```

The full `review` also works with zero scanners: unavailable adapters report why and name their
enable command, the built-ins run regardless, and the report distinguishes "ran and found nothing"
from "never looked".

### Legacy deployed app — no source, just bin/ and Web.config

```bash
node bin/moraa.js binary /src/DeployedSite
node bin/moraa.js review /src/DeployedSite --only binary,native
```

### CI gate on a PR

```bash
node bin/moraa.js review "$WORKSPACE" --diff origin/main --fail-on-new HIGH
```

Publish `.moraa-review/data/report.sarif` to your code-scanning service; exit `1` fails the build.

### CI gate on a legacy codebase (baseline mode)

```bash
node bin/moraa.js review "$WORKSPACE" --fail-on-new HIGH   # blocks only NEW debt
```

### Excel for the risk register

```bash
node bin/moraa.js review /src/MyApp --format excel
# <source>/.moraa-review/data/report.excel.xml — opens in Excel/LibreOffice, no dependencies
```

---

## Exit codes

| Code | Meaning |
|---|---|
| `0` | Completed. No finding at or above the applicable gate, or no gate was set. |
| `1` | Completed, and a gate fired: `--fail-on`, `--fail-on-new` (diff or baseline NEW set, or an expired suppression). |
| `2` | Usage error, or a config file that is not valid JSON. |

Note the distinction: exit `1` means **the review worked and found something**. It does not mean the
tool failed. CI should treat `2` as "fix the invocation" and `1` as "fix the code".

---

## Reading the output

`<sourcePath>/.moraa-review/` contains a `README.md` mapping the contents, an executive summary, the
per-area reports, and the machine-readable projections:

| File | Use |
|---|---|
| `data/report.json` | canonical source of truth; everything else is generated from it |
| `data/report.sarif` | SARIF 2.1.0 for CI code scanning |
| `data/report.md` | single-file Markdown with stable `<a id="FINDING-ID">` anchors per finding |
| `data/report.excel.xml` | SpreadsheetML 2003 workbook: Summary, Findings, Coverage sheets |
| `data/baseline.json` | the frozen baseline, once `baseline create` has run |
| `data/raw/` | untouched tool output, for reproducing any claim |

All projections are **generated from one canonical finding set** — they cannot disagree with each
other. If you consume findings programmatically, read the JSON or the SARIF; treat Markdown as the
human view.

Every finding records the sources that found it **and the sources that missed it**. That second list
is the point: it is how you tell "clean" from "nothing looked".
