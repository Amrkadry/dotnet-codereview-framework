# WIRING.md — registering the NuGet supply-chain analyzer

This module is complete and self-contained but is **deliberately not wired into the CLI** —
`bin/moraa.js` is off-limits while other work is in flight on it. Another agent must make the
change below.

## What exists

- `src/supplychain/index.js` — exports the adapter-contract shape
  (`id/name/kind/stacks/detect/run/parse`) plus the single entry function **`analyze(sourcePath, options)`**
  returning a contract-valid `RunResult`. It needs **no external tool and no network**, so
  `detect()` is always `{ available: true }`; a directory with no NuGet artifacts yields
  `status: 'NOT_APPLICABLE'` with zero findings (never an exception).

## Registration (one file, one line)

`bin/moraa.js` loads adapters by scanning `src/adapters/*.js` (its `loadAdapters()`).

**Option A (zero CLI change):** create `src/adapters/supplychain.js` containing:

```js
'use strict';
// Adapter surface for src/supplychain — see src/supplychain/WIRING.md.
module.exports = require('../supplychain');
```

The orchestrator then picks it up automatically: `moraa review <path>` runs it with every other
adapter, `moraa tools` lists it, and `tools/test-adapters.js` verifies it against the contract
(it passes the shape, detect, parse-robustness and honesty gates; add
`fixtures/supplychain.json` — a parsed inventory, the shape `run()` writes to
`data/raw/supplychain.inventory.json` — to move it from PARTIAL to full fixture verification).

**Option B (explicit subcommand/flag):** if product direction wants supply-chain analysis as an
opt-in lane rather than an always-on adapter, add a flag to `moraa review`:

```
--supply-chain        run the built-in NuGet supply-chain analyzer (no external tool)
```

and invoke:

```js
const { analyze } = require('../supplychain');
const result = await analyze(sourcePath, { outPath });   // RunResult; correlate result.findings
```

`result.findings` are canonical pre-correlation findings (tool `supplychain`); push them into the
same correlation step used for adapter findings. Respect `--only/--skip` by filtering on id
`'supplychain'`.

## Nothing else to configure

- No package.json change (zero runtime dependencies, Node >= 18 standard library only).
- No config file required; it reads `nuget.config`, `packages.config`, `*.csproj/vbproj/fsproj`,
  `Directory.Packages.props`, `packages.lock.json`, `*.nuspec`, and `packages/**`
  (install scripts, build props/targets).
