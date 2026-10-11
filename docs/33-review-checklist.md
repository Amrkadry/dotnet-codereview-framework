# Review Checklist

## What

The final quality gate, run before a report is considered complete.

## Why

Reviews fail on omission as much as on error. A checklist converts thoroughness from intention into evidence.

## How

Work the list; for any "no", either fix the report or record the gap explicitly as environment-dependent or not-executed.

## What To Test

That the checklist is answered per review and archived with it.

## What Can Be Automated

Roughly half — schema completeness, CVSS discipline, snippet presence, source labelling, test mapping, report regeneration.

## What Requires Manual Review

Whether evidence is genuinely sufficient, and whether severity judgements hold.

## Common Failure Modes

Answering the checklist aspirationally. Marking a tool "run" when it was installed but unlicensed.

## Example

Reference run: every project and configuration file inspected; vulnerable and merely-outdated dependencies separated into two queues; prior AI output ingested and three of its findings corrected; 31 findings deduplicated with `mergedFrom`; CVSS on 20 and N/A on 11; snippets and remediation on all; 12 findings marked environment-dependent rather than asserted; Fortify recorded as FAILED (invalid licence) not as a clean scan.

## Remediation

Archive the completed checklist alongside `report.json` so a later reader can audit the review itself.

---

Part of [dotnet-moraa-codereviewer](../README.md). See also [methodology](01-methodology.md), [CVSS](30-cvss.md), [false positives](31-false-positives.md), [AI review](32-ai-review.md).
