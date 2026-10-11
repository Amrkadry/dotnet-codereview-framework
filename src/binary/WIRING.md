# WIRING — registering the binary/assembly review path

This module is complete and self-contained and is **wired into `bin/moraa.js` as a built-in
source** (runs by default in `moraa review` when assemblies are present, merged into the same
correlation as adapter findings). This file records the shape so the wiring can be verified or
redone.

## What exists

- `src/binary/index.js` — exports the adapter-contract shape
  (`id: 'binary'`, `kind: 'sast'`, `stacks: ['framework','core','both']`, `detect/run/parse`)
  plus the single entry function **`analyze(sourcePath, options)`** returning a contract-valid
  `RunResult` (SYNCHRONOUS — do not `await` it; it never throws, failures come back as
  `FAILED`/`NOT_APPLICABLE` results).
- Layer 1 (always works, pure Node): PE/COFF + ECMA-335 metadata parsing from raw bytes —
  managed/native inventory, assembly name/version/target framework, debug-build detection,
  strong-name state, AssemblyRef surface, binding redirects in Web/app.config,
  known-vulnerable version checks, embedded-string secrets with REDACTION.
- Layer 2 (optional): decompiler (ilspycmd > dotPeek > monodis > ikdasm). When none is
  installed the result says so and names `dotnet tool install -g ilspycmd` — never a crash,
  never a spurious pass.

## Wiring (as implemented)

`bin/moraa.js` runs `analyze()` as one of the **built-in sources** of `moraa review`, but only
when `*.dll`/`*.exe` files exist under the source tree (the module reports `NOT_APPLICABLE`
itself when there is nothing to inventory, so a plain source review is unaffected). Respects
`--only`/`--skip` (id `binary`) and `tools.binary.enabled=false` in `moraa.config.json`.

Standalone subcommand: `moraa binary <sourcePath>` runs only this path and writes the same
vault formats.

## Verification already performed

- Real managed assembly: `System.Web.dll` from `C:\Windows\Microsoft.NET\Framework64\v4.0.30319`
  parses to a full inventory (managed, target framework, strong-name state, AssemblyRef list).
- Native/unmanaged DLLs are inventoried as `native`, not misparsed as managed.
- Empty directory → `EXECUTED` with zero findings and an explicit "inventoried 0 image(s)"
  note (no exception; a nonexistent path → `FAILED` with the reason).

## Nothing else to configure

- No package.json dependency change (zero runtime dependencies, Node >= 18 stdlib only).
- No config required. `tools.binary.enabled: false` opts the lane out of `moraa review`.
