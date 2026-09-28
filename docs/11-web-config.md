# Web.config Review

## What

Systematic review of every security-relevant element across `Web.config`, `Web.Debug.config`, `Web.Release.config`, the transformed output and the packaged output.

## Why

Configuration is where secrets, transport policy and hardening live, and it is the blind spot of compiled-code analyzers. SonarQube analysed the C# and reported nothing about any of it.

## How

Inspect: `authentication`, `authorization`, `customErrors`, `compilation debug`, `httpRuntime` (`maxRequestLength`, `executionTimeout`, `enableVersionHeader`), `httpCookies` (`requireSSL`, `httpOnlyCookies`), `machineKey`, `sessionState`, `trace`, `handlers`, `modules`, `requestFiltering`/`requestLimits`, `httpProtocol/customHeaders`, `rewrite`, `connectionStrings`, `appSettings`, `globalization`. Then diff base against each transform, and check the **built** output.

## What To Test

That the transformed artifact has no `debug` attribute, no secrets and the expected headers; that every `appSettings` key read in code is actually declared; that request limits at the ASP.NET and IIS layers agree.

## What Can Be Automated

Nearly all of it, as XML rules: secrets, `debug="true"`, absent security headers, absent `machineKey`, `requireSSL`, limit mismatch, IP literals, commented settings, and undeclared-key cross-reference.

## What Requires Manual Review

Whether a value is *right* for the environment, and whether an upstream proxy already supplies missing headers.

## Common Failure Modes

Reviewing only the base file. Treating a commented block as absent — it is still in the artifact. Assuming an ASP.NET limit is effective when an IIS default is lower.

## Example

Reference run: `DisableSSLValidation=true`, an AES key, four credential sets, production credentials in comments, no security headers, no `machineKey`, `maxRequestLength` 1 GB with no matching `requestFiltering`, and an `appSettings` key (`DomainIP`) read in code but declared nowhere. The Release transform did exactly one thing: remove `debug`.

## Remediation

Move secrets out; set safe defaults in the base file so transforms are belt-and-braces; add the header block; declare limits deliberately at both layers; validate required keys at startup.

---

Part of [dotnet-moraa-codereviewer](../README.md). See also [methodology](01-methodology.md), [CVSS](30-cvss.md), [false positives](31-false-positives.md), [AI review](32-ai-review.md).
