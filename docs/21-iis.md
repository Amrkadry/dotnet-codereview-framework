# IIS and Hosting

## What

Host-level configuration: authentication modes, handlers, request filtering, static file exposure, TLS bindings and app-pool identity.

## Why

Host configuration can either compensate for or amplify an application finding, and several findings are only decidable at this layer.

## How

Inspect `applicationHost.config` and the site configuration for `anonymousAuthentication`, `windowsAuthentication`, hidden segments, MIME mappings, request limits and the app-pool identity. Then test whether sensitive directories are actually served.

## What To Test

Fetch every directory the application writes to — log directories, upload staging — and assert they are not served. Verify TLS version and cipher configuration.

## What Can Be Automated

Config inspection where the file is available; live probing of known-sensitive paths.

## What Requires Manual Review

Production host configuration is usually outside the repository; conclusions drawn from a dev `applicationHost.config` must be marked environment-dependent.

## Common Failure Modes

Assuming production matches the checked-in IIS Express configuration. Assuming a directory under the webroot is protected because nothing links to it.

## Example

Reference run: `.vs/<project>/config/applicationhost.config` showed `anonymousAuthentication enabled="true"` with Windows and Basic disabled — no platform-level gate behind `SEC-AUTHZ-001`. This was explicitly flagged as dev-config evidence, with production unverified.

## Remediation

Deny access to log and staging directories at the host level; add hidden segments; confirm production auth modes; run the application pool as a least-privileged identity.

---

Part of [dotnet-moraa-codereviewer](../README.md). See also [methodology](01-methodology.md), [CVSS](30-cvss.md), [false positives](31-false-positives.md), [AI review](32-ai-review.md).
