# 41 — Terminal output and colour

The terminal view (`src/ui/`) has one rule above all others:

> **Colour is presentation, never data.** Piped, redirected or CI-captured output contains ZERO
> ANSI escape bytes — CI logs, `grep` and the framework's own selfcheck parse that output and must
> never meet `\x1b`.

## When colour is on

Checked in this exact order, every run:

1. `NO_COLOR` set (any non-empty value, per no-color.org) → colour **off**, overriding everything.
2. `FORCE_COLOR` set → `0` off, any other value **on** — including through a pipe (this is how you
   colourise a `tee`'d log).
3. Output stream is not a TTY → colour off. This is the default that makes pipes byte-clean.
4. `TERM=dumb` → colour off.
5. Otherwise (interactive terminal) → colour on.

`--no-color` forces colour off regardless of all of the above.

## What is coloured

- **Severity** — CRITICAL (bold on red), HIGH (bold red), MEDIUM (yellow), LOW (blue), INFO (dim).
  The same mapping colours the per-finding lines in `moraa native` and the final severity table.
- **Source status** — EXECUTED green, FAILED red, NOT_AVAILABLE/NOT_APPLICABLE yellow, in the
  per-source progress lines and the final summary.
- Headers bold; limitations and skip-lists dim — the parts people skip are styled to be findable.

## What is printed

A `review` narrates its pipeline (`[1/6] discovering … `[6/6] writing report`), one line per
source with real status and finding counts, the correlation outcome, and the final severity table.
With a baseline present the summary **leads with NEW**:

```
  NEW 3  | existing 210  | fixed 4
```

Single-lane commands (`moraa native|supplychain|binary`) print the engine's own honesty block:
what was analysed, what was skipped (named directories), catalog coverage (checked vs
manual-review), limitations, and the non-manual-review findings with severity, confidence and
location.

## Proven, not promised

The byte-cleanliness contract is pinned by tests: a full CLI run through a pipe is asserted to
contain zero `\x1b` bytes, and the same run with `FORCE_COLOR=1` is asserted to contain them.
The precedence chain (NO_COLOR beats FORCE_COLOR beats TTY beats TERM) is unit-tested case by case.
