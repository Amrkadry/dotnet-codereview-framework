# WIRING — registering the native engine

This module is self-contained and is **wired into `bin/moraa.js` as a built-in source** (it runs
by default in `moraa review`, merged into the same correlation as adapter findings). This file
records the shape so the wiring can be verified or redone.

## What exists

- `src/native/index.js` — exports the adapter-contract shape
  (`id: 'native'`, `kind: 'sast'`, `stacks: ['framework','core','both']`, `detect/run/parse`) plus
  the single entry function **`analyze(sourcePath, options)`** returning a contract-valid
  `RunResult`. It needs **no external tool, no network and no AI** — `detect()` is always
  `{ available: true }`. A directory with no .NET surface yields `status: 'NOT_APPLICABLE'` with
  zero findings (never an exception).
- `run(ctx)` accepts the orchestrator's normal `ctx` and uses `ctx.project.stack` when present,
  `ctx.config.native.noManualReview` (optional) to suppress the manual-review items.
- The RunResult carries `catalogCoverage`: one record per catalog case
  (`{ caseId, stack, outcome: 'checked'|'manual-review'|'not-applicable', tool: 'native' }`).
  The Excel Coverage sheet and `moraa review`'s coverage reporting consume this — keep it in
  the result if you touch the module.

## Wiring (as implemented)

`bin/moraa.js` runs `analyze()` as one of the **built-in sources** of `moraa review`, after the
external-tool adapters, and pushes `result.findings` into the same `correlate()` call. So native
findings merge, dedup and record found-by/missed-by against every other tool. Respects
`--only`/`--skip` (id `native`) and `tools.native.enabled=false` in `moraa.config.json`.

Standalone subcommand: `moraa native <sourcePath>` (equivalent to `node src/native/index.js` via
the CLI) runs only this engine and writes the same vault formats.

## Test entry

```
npm run native -- <sourcePath>     # package.json script: node bin/moraa.js native
node bin/moraa.js native /src/MyApp
```

## Nothing else to configure

- No package.json dependency change (zero runtime dependencies, Node >= 18 stdlib only).
- No config required. `native.noManualReview: true` in `moraa.config.json` suppresses the
  manual-review INFO items (NOT recommended — they are the honest half of the coverage model).
