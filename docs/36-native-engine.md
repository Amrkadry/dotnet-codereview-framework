# 36 — The native engine

The framework's own analyzer: real findings with **no scanner installed, no AI, no network** —
pure Node standard library. This is what makes the framework standalone rather than an
orchestrator that is useless without other people's binaries.

```bash
node bin/moraa.js native /src/MyApp        # just the engine
node bin/moraa.js review /src/MyApp        # the engine merged with every tool that can run
```

## What it checks

Three surfaces, all in `src/native/checks/`:

| Surface | Examples (catalog ids) |
|---|---|
| XML configuration (`Web.config`, `app.config`, `appsettings*.json`) | `debug=true` (N-006), `customErrors Off` (H-002), weak `machineKey` (A-015, T-002), cleartext connection-string credentials (E-001), `customErrors`/tracing/directory browsing (N-007, N-009), forms-auth cookie misconfiguration (T-009, T-010), ViewState MAC disabled (J-006), request validation downgraded (D-004), WCF bindings/metadata/faults (V-001..V-004), missing security headers (N-004), credential-shaped appsettings values (E-001) |
| C# source | SQL built by concatenation (C-001..C-003), `BinaryFormatter`-class deserializers (J-001, S-006, S-008), `TypeNameHandling != None` (J-002, S-011), certificate-validation bypass (F-001, F-002), `Response.Write` of input (D-001), `Process.Start` with concatenated args (C-007), hardcoded secrets (E-001, M-001), weak crypto (MD5/SHA1/DES/ECB — E-004..E-008), `System.Random` for security values (E-009), disabled token validation (A-011, X-006, X-007), missing anti-forgery on POST controllers (D-008), `[AllowAnonymous]` on sensitive endpoints (B-010), XXE (J-003), open redirects (D-007), reflected-origin/wildcard CORS (N-001, N-002), regex without timeout (P-004), reflection on request data (S-001..S-003), runtime scripting (U-002, U-003), obsolete TLS (F-004), unencrypted SQL connections (F-006) |
| Manifests + startup | End-of-life target frameworks (O-005), floating package versions (O-003), `AllowUnsafeBlocks`, missing lockfile (O-003), missing authZ middleware with mapped endpoints (B-002, W-012), no security headers/HSTS in the pipeline (N-004, F-005), CORS `AllowAnyOrigin` at startup (N-001..N-003), unguarded developer exception page (H-002) |

## The coverage contract — the part that keeps it honest

The engine is driven by `catalog/dotnet-test-cases*.json` (279 cases). **Every catalog case
applicable to the project's stack is accounted for in every run:**

- decided by an implemented check → covered, with a finding when the check matched;
- not mechanically decidable (or not implemented yet) → one **manual-review** item carrying the
  case's own `lookFor`/`expected` checklist question.

Manual-review items are INFO severity **by design**: they are undecided questions, not defects, so
they never gate CI. What they prevent is the report implying a clean bill where nobody looked.
The Excel Coverage sheet (see [40 — Excel output](40-excel-output.md)) renders the full
case-by-case state.

## False-positive discipline

- **Comments are stripped** before code checks match — dead code is not a finding.
- **Tests/, obj/, bin/, packages/, node_modules/, Migrations/** (and editor/build directories) are
  skipped, and **the skip list is printed in the result notes** — what was not examined is visible,
  not hidden.
- **Confidence states how the finding was established**, per check:
  - `CONFIRMED` — a configuration fact read from the file (`debug="true"` is literally there);
  - `LIKELY` — a structural code fact (the dangerous API is called here);
  - `POSSIBLE` — a content-dependent heuristic (the concatenation *might* be safe internal input).
    A bare regex match is POSSIBLE, never more, and the finding says so in plain language.

Severity models impact-if-real; confidence models certainty. Both are always visible.

## Secrets never reach the report

Configuration snippets routinely contain live credentials. Every snippet passes through redaction
before it becomes evidence (`password=***REDACTED***`), and finding text never repeats the value.
The report says a credential exists at file:line — it does not duplicate the credential into the
artifact most likely to be shared.

## Limits, stated

Heuristic static analysis: no cross-file dataflow, no compiled behaviour, no runtime configuration.
POSSIBLE-confidence findings are leads to read, not verdicts. A manual-review item means **nobody
looked** — it is not a pass.
