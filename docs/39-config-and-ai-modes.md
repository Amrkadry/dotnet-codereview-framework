# 39 — Configuration and the two AI modes

## One config file, every integration

`moraa.config.json` holds every integration setting: which tools are enabled, severity thresholds,
SonarQube's endpoint, key material, and the two AI mode toggles. `moraa init <sourcePath>` writes a
commented starter; `moraa config` prints what is configured vs missing **with every value
redacted to its last 4 characters**.

Search order: `--config <path>` → `<sourcePath>/moraa.config.json` → cwd → repo root.
Precedence for every setting: **CLI flag → environment variable → config file → built-in default.**
A layer only wins when it actually provides a value.

## Keys

Keys may live in the environment (preferred) or in the config file under `keys.*`. Either way they
are never printed, never written into a report, and never embedded in an error. `--ai-key <secret>`
exists as a documented last resort — argv is visible in `ps -ef` and shell history, so think twice.

| Where | Names |
|---|---|
| Environment (preferred) | `MORAA_AI_API_KEY` (generic), `ANTHROPIC_API_KEY`, `OPENAI_API_KEY`, `ZAI_API_KEY`, `SNYK_TOKEN`, `SONAR_TOKEN`, `SONAR_HOST_URL` |
| Config (`keys.*`) | `anthropic`, `openai`, `zai`, `local`, `snyk`, `sonar` |

If you put real keys in the file: add `moraa.config.json` to `.gitignore` FIRST. The config layer
warns when the repo-root file is not ignored; `git ignore` the rule, do not rely on the warning.
The self-check additionally fails the repo when a literal key pattern (`sk-ant-…`, `sk-…`) appears
in any tracked source file.

## The two AI modes — both OFF by default

With both modes off, **nothing AI-related runs and no key is required anywhere**: the adapter
reports unavailable, `review` proceeds, and no network call is made. You opt in per mode, per run:

```bash
node bin/moraa.js review /src/MyApp --ai-report    # mode 1 only
node bin/moraa.js review /src/MyApp --ai-review    # mode 2 only
node bin/moraa.js review /src/MyApp --ai-report --ai-review   # both
```

or durably in the config: `ai.report.enabled: true` / `ai.review.enabled: true`, or env
`MORAA_AI_REPORT=1` / `MORAA_AI_REVIEW=1`.

### Mode `report` — post-process the produced report

Input: the ALREADY-written `data/report.json`, each finding's title, and the code snippet read from
the source file at that finding's line. Output: a per-finding narrative written **into the finding's
own Markdown page** in the vault — not a separate document.

Idempotency is structural: AI content lives inside `<!-- moraa:ai-report:v1 START id=… -->` …
`END` markers and is **replaced whole** on every re-run (markers the model echoes are neutralised;
a torn block from a crashed run is truncated and rewritten). Re-run twice with the same reply and
the second run changes zero bytes — this is pinned by a test with a stubbed model.

The canonical `data/report.json` is read-only to this mode. Only the Markdown projection is edited.

### Mode `review` — direct AI code review

The AI reads the project's highest-value source files (auth, authorization, config wiring, data
access first, within `maxFiles`/`maxBytesPerFile` budgets) and returns findings attributed to tool
`ai-review`. They enter the **same correlation** as every tool's findings, with two deliberate
caps: confidence POSSIBLE (a model's assertion is a lead) and no CVSS (the model does not score).

### The governing rule, in both modes

**No tool is authoritative, including the AI.** An AI finding never overrides, suppresses or
outranks a tool finding. Where the AI disagrees with a tool — including disagreeing with a recorded
severity — the disagreement is RECORDED on the finding (`CONTRADICTED` source entry, unresolved
question) and left for a human. Nothing is auto-resolved. Where the AI agrees independently,
agreement is noted — that is evidence, and it is kept visible.

## Providers

`ai.provider`: `anthropic` | `openai` | `zai` | `local` | `none` | `auto` (default).

`auto` resolves a provider only from exactly one key being present; with two or more provider keys
it refuses to guess and asks you to name one. `local` means any OpenAI-compatible endpoint — give
`ai.baseUrl` (`--ai-base-url`), e.g. an on-prem vLLM/Ollama gateway; key-optional. `none`
hard-disables AI regardless of keys.

## Degradation, never a spurious pass

Missing key, unreachable endpoint, HTTP error, rate limit: each is classified, reported in plain
language, and the mode returns a status other than EXECUTED — which structurally cannot carry
findings. The rest of the pipeline is unaffected. A half-finished ai-report pass keeps the blocks
it already wrote (they are idempotent) and says exactly which findings were enriched.
