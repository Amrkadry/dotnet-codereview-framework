# 38 — Binary / deployed-assembly review

Legacy .NET reviews often hand you `bin/*.dll` and a `Web.config` — no source, sometimes no
solution. This path reviews what is actually deployed.

```bash
node bin/moraa.js binary /src/DeployedSite
node bin/moraa.js review /src/DeployedSite --only binary,native
```

## Layer 1 — always works (pure Node, no tool)

PE/COFF and ECMA-335 metadata are parsed directly from the bytes:

- **Inventory** — managed vs native images, assembly names and versions, target framework.
- **Debug-build detection** — a `[DebuggableAttribute]`-marked debug build deployed to production
  is a real finding: optimisations off, symbols present, timing side channels intact.
- **Strong-name state** — signed or not, per assembly.
- **Dependency surface** — every `AssemblyRef`, so you can see what the deployment actually needs
  (and which references are *not* co-located — deployment gaps).
- **Binding redirects** — `Web.config`/`app.config` redirects that silently up- or downgrade a
  dependency away from the version everything else was tested against.
- **Known-vulnerable version checks** — assembly versions compared against a table.
- **Embedded strings** — the `#US` heap and readable ASCII/UTF-16 scanned for connection strings,
  credentials, API keys and internal hostnames. Every hit is **REDACTED in the finding**: the
  report says a secret exists at which assembly and string index — it never copies the secret.

## Layer 2 — optional decompiler

If `ilspycmd` (or dotPeek, monodis, ikdasm) is installed, assemblies are decompiled to a temp
directory and the recovered source is handed to the framework's source analyzers. When **none** is
installed the result says so and names the enable command:

```
dotnet tool install -g ilspycmd
```

That is a capability gap reported as data — never a crash, never a spurious pass. Source-level
checks that would have run on recovered code are absent from the result, and the result says which.

## Verified against real assemblies

The module was exercised on real system assemblies (e.g. `System.Web.dll` from
`C:\Windows\Microsoft.NET\Framework64\v4.0.30319`) — full managed inventory with the AssemblyRef
surface — and on native (unmanaged) DLLs, which are inventoried as `native` rather than misparsed.
An empty directory yields `EXECUTED` with an explicit "inventoried 0 image(s)" note.

## When to use it

- Source lost or third-party: review what ships, not what the repo claims.
- Legacy engagements where the handover is a zip of the IIS site.
- Cross-checking: the deployed `Newtonsoft.Json.dll` version versus what every manifest claims.
