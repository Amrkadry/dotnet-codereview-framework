# Authentication

## What

Establishing the actual mechanism — scheme, token format, transport, lifetime, client authentication and identity store — before reviewing anything that depends on it.

## Why

Impact claims about CORS, session theft and token attacks are all wrong if the mechanism is misidentified. In the reference run, confirming "Bearer header, no cookies" invalidated an entire attack narrative.

## How

Find the middleware registration (`UseOAuthAuthorizationServer`, `UseOAuthBearerAuthentication`, `UseCookieAuthentication`, JWT bearer). Determine token format by searching for `JwtSecurityToken`/`SecurityTokenHandler` — absent means opaque machine-key tickets, which excludes every JWT attack class. Check for cookies at all. Check IIS-level auth in `applicationHost.config`.

## What To Test

Empty username and password; whitespace; a password that decodes to empty; unknown user versus wrong password (same response, same path, similar timing); token expiry; token replay after account disable; client authentication.

## What Can Be Automated

Missing empty-credential guards before `ValidateCredentials`; `PrincipalContext` without `SecureSocketLayer`; unconditional `context.Validated()`; excessive token lifetime.

## What Requires Manual Review

Whether the directory permits unauthenticated binds — only a live test against the real DC settles it.

## Common Failure Modes

Claiming JWT attacks against opaque tokens. Assuming authentication middleware implies authorization. Relying on `ValidateCredentials` without reading its documented empty-password behaviour.

## Example

Reference run: OAuth2 ROPC at `/login`, opaque machine-key OWIN tickets (not JWT), no cookies anywhere, 6-hour lifetime, no refresh, no client authentication, LDAP bind without SSL, and no empty-password guard (`SEC-AUTH-001`, `SEC-AUTH-002`).

## Remediation

Guard empty credentials; use LDAPS; authenticate the client; shorten access tokens and add revocable refresh tokens.

---

Part of [dotnet-moraa-codereviewer](../README.md). See also [methodology](01-methodology.md), [CVSS](30-cvss.md), [false positives](31-false-positives.md), [AI review](32-ai-review.md).
