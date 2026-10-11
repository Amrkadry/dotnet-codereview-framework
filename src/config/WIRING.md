# WIRING — how to connect the config layer and the two AI modes to the CLI

**Status: NOT wired.** Everything below exists as importable entry points. No file outside
`src/config/` and `src/adapters/ai-review.js` was changed, so another agent must add the CLI
surface described here to `bin/moraa.js` (or a new `bin/` entry).

The governing rule must survive the wiring unchanged: **no tool is authoritative, INCLUDING the
AI.** Both AI modes are opt-in, both default OFF, and an AI finding never overrides, suppresses or
outranks a tool finding — disagreements are recorded, never resolved.

---

## 1. Entry points that already exist

| Export | File | Purpose |
|---|---|---|
| `loadConfig({configPath, sourcePath, env, flags})` | `src/config/index.js` | load + merge `moraa.config.json` over defaults |
| `resolve({flag, env, config, def})` | `src/config/index.js` | one setting through the precedence chain |
| `resolveAi({config, env, flags})` | `src/config/index.js` | full resolved settings for both AI modes (keys included, in-memory only) |
| `checkConfig({configPath, sourcePath, env, flags})` | `src/config/index.js` | structured configured-vs-missing report (values redacted) |
| `printCheck(report)` | `src/config/index.js` | terminal-safe rendering (guarded) |
| `main(argv)` | `src/config/index.js` | `node src/config/index.js [--config <path>]` — already runnable standalone |
| `redact / scrub / guard / guardedWriteFile / redactConfig` | `src/config/redact.js` | secrets discipline; re-exported from `index.js` |
| `detect / run / parse` | `src/adapters/ai-review.js` | adapter contract — `run()` is MODE 2 |
| `runReport(ctx)` | `src/adapters/ai-review.js` | MODE 1 — post-processing over an existing report |
| `runReview(ctx)` / `modes.review` / `modes.report` | `src/adapters/ai-review.js` | aliases |
| `crossCheck(aiFindings, priorFindings, toolsThatRan)` | `src/adapters/ai-review.js` | pure; records AI-vs-tool agreement/disagreement |
| `upsertBlock(md, id, block)` / `narrativeParse(raw)` | `src/adapters/ai-review.js` | pure; the idempotency machinery |

## 2. CLI flags to add

```
--ai-report [on|off]      enable MODE 1 (post-process the produced Markdown in place)   default: off
--ai-review [on|off]      enable MODE 2 (direct code review as one more tool)           default: off
--config <path>           explicit moraa.config.json (overrides the search order)
--ai-provider <name>      anthropic | openai | zai | local | none | auto                default: auto
--ai-model <id>           model override for both modes
--ai-base-url <url>       base URL override (required for --ai-provider local)
--ai-key <secret>         ⚠ last-resort: argv is visible in process listings (`ps -ef`).
                          Prefer the environment: MORAA_AI_API_KEY / ANTHROPIC_API_KEY /
                          OPENAI_API_KEY / ZAI_API_KEY. Document this in `moraa --help`.
--report-dir <path>       where MODE 1 finds the produced review (default: <source>/.moraa-review,
                          i.e. the same folder `moraa review` already writes)
```

Flag parsing must pass the values through, e.g.:

```js
const flags = {
  aiReport:  flag('ai-report', undefined),   // undefined = not given; falls through precedence
  aiReview:  flag('ai-review', undefined),
  config:    flag('config', undefined),
  aiProvider: flag('ai-provider', undefined),
  aiModel:    flag('ai-model', undefined),
  aiBaseUrl:  flag('ai-base-url', undefined),
  aiKey:      flag('ai-key', undefined)
};
ctx.flags = flags;   // adapters + config layer read ctx.flags
```

Do NOT build a bare `--ai-report` boolean that can never be `false`: pass `undefined` when the
flag is absent so the precedence chain (flag > env > config > default) still works. The config
layer's `parseBool` accepts `on/off/true/false/1/0/yes/no`.

## 3. New command: `moraa config-check`

```js
const cfgLayer = require('../src/config');
case 'config-check': console.log(cfgLayer.printCheck(cfgLayer.checkConfig({
  configPath: flag('config', undefined), sourcePath: argv[1] ? path.resolve(argv[1]) : undefined,
  env: process.env, flags
}))); break;
```

It reports which integrations are configured vs missing WITHOUT revealing values (keys show as
`****` + last 4). It also warns when `moraa.config.json` is not covered by `.gitignore`.

## 4. Hook MODE 2 into the review pipeline (already 95% there)

`bin/moraa.js` already loads `src/adapters/ai-review.js` as an adapter and calls
`detect(ctx)` / `run(ctx)`. With both modes off (the default) the adapter returns
`NOT_APPLICABLE` and costs nothing — no change needed for the off path. To wire it properly:

1. Put `flags` on the ctx: `const ctx = { sourcePath, outPath, project, config, env, log, flags };`
2. Optional but recommended, for disagreement recording: before running adapters, if
   `<outPath>/data/report.json` exists from a previous run, set
   `ctx.priorFindings = JSON.parse(...).findings` and `ctx.toolsThatRan` to the previous run's
   executed tool ids. `run()` then records severity agreement/disagreement on the AI findings via
   `crossCheck()` — recorded, never resolved.

## 5. Hook MODE 1 after the vault is written

MODE 1 post-processes the ALREADY-PRODUCED report, so it must run after step 5 (`writeVault` +
`data/report.json` written) in `cmdReview`:

```js
const ai = require('../src/adapters/ai-review');
if (flags.aiReport !== undefined ? flags.aiReport : (envEnabled || configEnabled)) {
  const r = await ai.runReport({
    reportDir: root,          // the vault root that was just written
    sourcePath, config, env: process.env, flags, log
  });
  if (!r.ok && !r.skipped) console.error(`  ai-report: ${r.error}`);
  if (r.skipped) log(`  ai-report: skipped — ${r.reason}`);
}
```

In practice the gate can simply be "always call `runReport`": when the mode is off it returns
`{ok:false, skipped:true, reason}` without touching anything, and the reason is worth printing.
Mode 1 reads `data/report.json` (read-only), reads the code snippet at each finding's line from
`sourcePath`, and edits only `Findings/*.md` in place inside stable
`<!-- moraa:ai-report:v1 START id=... -->` / `END` markers. Re-runs replace the block; a
byte-identical re-run does not rewrite the file. It never emits a parallel document and never
writes `data/report.json`.

If a future Excel export is added as another projection, the same `runReport` call covers it: mode
1's contract is "consume the produced projections + canonical JSON; edit only the Markdown in
place". There is currently no Excel emitter in this framework.

## 6. Secrets discipline the wiring must preserve

- Never print, log or echo a key — route any value display through `redact()` (last 4 chars only).
- Route every terminal/debug output through `guard()` and every report/Markdown/raw write through
  `guardedWriteFile()`. Config loading never echoes keys, including in verbose mode; config dumps
  must go through `redactConfig()`.
- `moraa.config.json` (real, may contain keys) must be **gitignored before a real key is put in
  it**. `src/config/moraa.config.example.json` is the committed placeholder template. NOTE:
  at the time of writing `.gitignore` does NOT list `moraa.config.json` — `checkConfig()` warns
  about exactly this; the first wiring change should add the ignore line.
- Rate limits (HTTP 429), auth failures and network errors degrade to `FAILED` / clean skips with
  a scrubbed message. Never let them crash the orchestrator or look like a pass.

## 7. Verification already proven (stubbed AI, no network)

- Both modes OFF + no key anywhere: full review runs; adapter `NOT_APPLICABLE`; transport modules
  instrumented to throw if touched — nothing AI-related executes and no key is resolved.
- Precedence: flag beats env beats config beats default (model setting demonstrated).
- Redaction: config containing `sk-test-...` never shows more than `****` + last 4 in config-check,
  verbose dumps, guard output and written files.
- MODE 1 idempotency: two consecutive `runReport` runs with a stubbed AI produce byte-identical
  Markdown (second run reports `unchanged`); a changed stub response replaces the block in place
  without duplicating sections.
- Live provider paths (Anthropic/OpenAI/Z.AI/local) are implemented but UNEXERCISED — every
  verification above stubs `ctx.aiCall` or the transport.
