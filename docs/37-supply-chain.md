# 37 — NuGet supply-chain analysis

The layer CVE scanners do not cover. Trivy and Snyk answer *"is this version vulnerable?"* — they
do not ask the NuGet-specific attack questions about **resolution itself**: which feed an id
resolves from, whether it is pinned and hash-verified, what runs at restore time, whether the id
looks shaped for squatting.

```bash
node bin/moraa.js supplychain /src/MyApp
node bin/moraa.js review /src/MyApp        # runs automatically; findings merge with everything else
```

Needs **no external tool and no network** — it reads `nuget.config`, `packages.config`,
`*.csproj`, `Directory.Packages.props`, `packages.lock.json`, `*.nuspec` and `packages/**`
(install scripts, build props/targets) and reasons from repository evidence alone.

## The checks

| Check | What it answers |
|---|---|
| Dependency confusion | Can a private-named id silently resolve from a public feed (or vice versa)? Is there a `packageSourceMapping` constraining which feed serves which id? |
| Feed & credential misconfiguration | HTTP (non-HTTPS) feeds, credentials in plaintext, `clearTextCredentialProviders`, feed-ordering that lets an upstream shadow an internal feed |
| Lockfile & pinning integrity | Floating versions (`*`, ranges), missing `packages.lock.json`, lockfile/manifest drift, central package management inconsistencies |
| Name-risk heuristics | Ids shaped like typosquats, internal names published publicly, near-duplicates of well-known packages |
| Restore-time execution surface | `packages/**/build*.props|targets` imported into builds, install/init scripts, anything that runs code at restore or build time |

## What it does NOT claim

Static, offline, repository-only. Package resolution is **not executed** and no feed is contacted,
so these remain explicitly UNVERIFIED by this analyzer: whether a public id is actually registered
today, which exact binary a restore would fetch, and whether a script's logic is malicious. The
result's `limitations` field says this on every run — absence of a finding here is not a bill of
health for your feed.

Hierarchical NuGet merge semantics (nearest-wins per section, machine/user inheritance across
nested `nuget.config` files) are approximated, and any conclusion that depends on the merge is
flagged at lower confidence.

## Reading the results

Findings use the canonical model (tool `supplychain`) and correlate like any other tool's: a
floating-version finding on the same package as a CVE finding stays ONE finding with both sources
recorded. The parsed inventory is written to `data/raw/supplychain.inventory.json` (credentials
redacted at parse time) so any claim can be reproduced.
