// dotnet-codereview-framework — src/adapters/roslyn.js
// Author: Amr Kadry (github.com/Amrkadry) · MIT License
'use strict';
/**
 * Roslyn analyzer adapter — the .NET-native SAST entry.
 *
 * Drives Roslyn analyzers through `dotnet build`, which compiles the code and reports analyzer
 * diagnostics as compile output. SARIF is requested with the mandatory `,version=2.1` ErrorLog
 * suffix: Roslyn's ErrorLog default is SARIF v1, which src/normalize/sarif.js cannot read.
 *
 * WHY PER PROJECT AND NOT PER SOLUTION: with a solution, every project writes the same ErrorLog
 * path and only the LAST project's diagnostics survive (dotnet/roslyn#24319). Building each
 * project separately gives every project its own SARIF file.
 *
 * THE HONEST PATH FOR LEGACY .NET FRAMEWORK: `dotnet build` cannot evaluate non-SDK csproj files,
 * packages.config restores, or legacy web projects importing Microsoft.WebApplication.targets.
 * For those shapes this adapter refuses loudly (NOT_APPLICABLE with real alternatives) rather
 * than reporting a spurious clean result — legacy .NET Framework is this framework's stated
 * specialty, so a silent pass here would be the worst possible outcome.
 */

const { execFileSync } = require('child_process');
const fs = require('fs');
const path = require('path');
const C = require('../core/adapter-contract');
const { fromSarif } = require('../normalize/sarif');

const ID = 'roslyn';

/**
 * VERIFIED rule-id table: Roslyn-emitted diagnostic id -> canonical metadata.
 * Anything unmapped keeps what the SARIF gave. Entries are added here only when their CWE and
 * severity have been checked against the analyzer's own documentation — never guessed.
 *
 * SecurityCodeScan: https://security-code-scan.github.io/
 * Microsoft .NET analyzers: learn.microsoft.com/dotnet/fundamentals/code-analysis/quality-rules/
 */
const RULES = {
  // ---- SecurityCodeScan
  SCS0001: { cwe: ['CWE-78'], severity: 'HIGH' },
  SCS0002: { cwe: ['CWE-89'], severity: 'HIGH' },
  SCS0003: { cwe: ['CWE-643'], severity: 'MEDIUM' },
  SCS0004: { cwe: ['CWE-295'], severity: 'HIGH' },
  SCS0005: { cwe: ['CWE-338'], severity: 'MEDIUM' },
  SCS0006: { cwe: ['CWE-328'], severity: 'MEDIUM' },
  SCS0007: { cwe: ['CWE-611'], severity: 'HIGH' },
  SCS0008: { cwe: ['CWE-614'], severity: 'MEDIUM' },
  SCS0009: { cwe: ['CWE-1004'], severity: 'MEDIUM' },
  SCS0010: { cwe: ['CWE-327'], severity: 'MEDIUM' },
  SCS0011: { cwe: ['CWE-611'], severity: 'MEDIUM' },
  SCS0012: { cwe: ['CWE-862'], severity: 'HIGH' },
  SCS0013: { cwe: ['CWE-326'], severity: 'MEDIUM' },
  SCS0015: { cwe: ['CWE-798'], severity: 'HIGH' },
  SCS0016: { cwe: ['CWE-352'], severity: 'MEDIUM' },
  SCS0017: { cwe: ['CWE-20'], severity: 'MEDIUM' },
  SCS0018: { cwe: ['CWE-22'], severity: 'HIGH' },
  SCS0019: { cwe: ['CWE-524'], severity: 'MEDIUM' },
  SCS0021: { cwe: ['CWE-20'], severity: 'MEDIUM' },
  SCS0022: { cwe: ['CWE-807'], severity: 'MEDIUM' },
  SCS0023: { cwe: ['CWE-311'], severity: 'MEDIUM' },
  SCS0024: { cwe: ['CWE-807'], severity: 'HIGH' },
  SCS0026: { cwe: ['CWE-90'], severity: 'HIGH' },
  SCS0027: { cwe: ['CWE-601'], severity: 'MEDIUM' },
  SCS0028: { cwe: ['CWE-502'], severity: 'HIGH' },
  SCS0029: { cwe: ['CWE-79'], severity: 'HIGH' },
  SCS0030: { cwe: ['CWE-20'], severity: 'MEDIUM' },
  SCS0031: { cwe: ['CWE-90'], severity: 'HIGH' },
  SCS0032: { cwe: ['CWE-521'], severity: 'LOW' },
  SCS0033: { cwe: ['CWE-521'], severity: 'LOW' },
  SCS0034: { cwe: ['CWE-521'], severity: 'LOW' },
  // ---- Microsoft .NET analyzers (CA)
  CA2100: { cwe: ['CWE-89'], severity: 'HIGH' },
  CA3001: { cwe: ['CWE-89'], severity: 'HIGH' },
  CA3002: { cwe: ['CWE-79'], severity: 'HIGH' },
  CA3003: { cwe: ['CWE-22'], severity: 'HIGH' },
  CA3004: { cwe: ['CWE-209'], severity: 'MEDIUM' },
  CA3005: { cwe: ['CWE-90'], severity: 'HIGH' },
  CA3006: { cwe: ['CWE-78'], severity: 'HIGH' },
  CA3007: { cwe: ['CWE-601'], severity: 'MEDIUM' },
  CA3008: { cwe: ['CWE-643'], severity: 'MEDIUM' },
  CA3009: { cwe: ['CWE-91'], severity: 'MEDIUM' },
  CA3010: { cwe: ['CWE-91'], severity: 'MEDIUM' },
  CA3011: { cwe: ['CWE-114'], severity: 'HIGH' },
  CA3012: { cwe: ['CWE-1333'], severity: 'MEDIUM' },
  CA3061: { cwe: ['CWE-611'], severity: 'MEDIUM' },
  CA3075: { cwe: ['CWE-611'], severity: 'HIGH' },
  CA3076: { cwe: ['CWE-94'], severity: 'HIGH' },
  CA3077: { cwe: ['CWE-611'], severity: 'MEDIUM' },
  CA3147: { cwe: ['CWE-352'], severity: 'MEDIUM' },
  CA5350: { cwe: ['CWE-327'], severity: 'MEDIUM' },
  CA5351: { cwe: ['CWE-327'], severity: 'HIGH' },
  CA5358: { cwe: ['CWE-326'], severity: 'MEDIUM' },
  CA5359: { cwe: ['CWE-295'], severity: 'HIGH' },
  CA5360: { cwe: ['CWE-502'], severity: 'HIGH' },
  CA5361: { cwe: ['CWE-757'], severity: 'MEDIUM' },
  CA5362: { cwe: ['CWE-502'], severity: 'MEDIUM' },
  CA5363: { cwe: ['CWE-20'], severity: 'MEDIUM' },
  CA5364: { cwe: ['CWE-327'], severity: 'MEDIUM' },
  CA5365: { cwe: ['CWE-113'], severity: 'MEDIUM' },
  CA5366: { cwe: ['CWE-611'], severity: 'MEDIUM' },
  CA5369: { cwe: ['CWE-611'], severity: 'MEDIUM' },
  CA5370: { cwe: ['CWE-611'], severity: 'MEDIUM' },
  CA5371: { cwe: ['CWE-611'], severity: 'MEDIUM' },
  CA5372: { cwe: ['CWE-611'], severity: 'MEDIUM' },
  CA5373: { cwe: ['CWE-327'], severity: 'MEDIUM' },
  CA5374: { cwe: ['CWE-94'], severity: 'MEDIUM' },
  CA5375: { cwe: ['CWE-522'], severity: 'MEDIUM' },
  CA5376: { cwe: ['CWE-319'], severity: 'MEDIUM' },
  CA5377: { cwe: ['CWE-284'], severity: 'MEDIUM' },
  CA5378: { cwe: ['CWE-757'], severity: 'MEDIUM' },
  CA5379: { cwe: ['CWE-327'], severity: 'MEDIUM' },
  CA5380: { cwe: ['CWE-295'], severity: 'HIGH' },
  CA5381: { cwe: ['CWE-295'], severity: 'HIGH' },
  CA5382: { cwe: ['CWE-614'], severity: 'MEDIUM' },
  CA5383: { cwe: ['CWE-614'], severity: 'MEDIUM' },
  CA5384: { cwe: ['CWE-327'], severity: 'MEDIUM' },
  CA5385: { cwe: ['CWE-326'], severity: 'MEDIUM' },
  CA5386: { cwe: ['CWE-757'], severity: 'LOW' },
  CA5387: { cwe: ['CWE-916'], severity: 'MEDIUM' },
  CA5388: { cwe: ['CWE-916'], severity: 'MEDIUM' },
  CA5389: { cwe: ['CWE-22'], severity: 'HIGH' },
  CA5390: { cwe: ['CWE-798'], severity: 'HIGH' },
  CA5391: { cwe: ['CWE-352'], severity: 'MEDIUM' },
  CA5392: { cwe: ['CWE-114'], severity: 'MEDIUM' },
  CA5393: { cwe: ['CWE-114'], severity: 'MEDIUM' },
  CA5394: { cwe: ['CWE-338'], severity: 'MEDIUM' },
  CA5395: { cwe: ['CWE-352'], severity: 'MEDIUM' },
  CA5396: { cwe: ['CWE-1004'], severity: 'MEDIUM' },
  CA5397: { cwe: ['CWE-327'], severity: 'MEDIUM' },
  CA5398: { cwe: ['CWE-327'], severity: 'LOW' },
  CA5399: { cwe: ['CWE-299'], severity: 'MEDIUM' },
  CA5400: { cwe: ['CWE-299'], severity: 'MEDIUM' },
  CA5401: { cwe: ['CWE-329'], severity: 'HIGH' },
  CA5402: { cwe: ['CWE-329'], severity: 'MEDIUM' },
  CA5403: { cwe: ['CWE-798'], severity: 'HIGH' }
};
// CA2300..CA2330 deserialization family: every one of these is CWE-502, HIGH.
['CA2300', 'CA2301', 'CA2302', 'CA2305', 'CA2310', 'CA2311', 'CA2312',
  'CA2321', 'CA2322', 'CA2326', 'CA2327', 'CA2328', 'CA2329', 'CA2330']
  .forEach(id => { RULES[id] = { cwe: ['CWE-502'], severity: 'HIGH' }; });

function detect(ctx) {
  try {
    const out = execFileSync('dotnet', ['--version'], { encoding: 'utf8', timeout: 60000 });
    return { available: true, version: String(out).trim().split('\n')[0], command: 'dotnet --version' };
  } catch {
    return {
      available: false,
      reason: 'The .NET SDK is not installed, so no Roslyn analyzer ran. Roslyn analysis requires a compile.',
      command: 'install the .NET SDK from https://dotnet.microsoft.com/download'
    };
  }
}

/** Why a discovered project cannot be evaluated by `dotnet build`. */
function whyUnbuildable(p) {
  const why = [];
  if (p.sdkStyle !== true) why.push('non-SDK csproj — `dotnet build` cannot evaluate it');
  if (p.usesPackagesConfig === true) why.push('packages.config restore, which the dotnet SDK does not support');
  if (p.sdkStyle !== true && p.isWebProject === true)
    why.push('a legacy web project importing Microsoft.WebApplication.targets, which the dotnet SDK does not ship');
  return why.join('; ') || 'not an SDK-style project without packages.config';
}

function run(ctx) {
  const started = Date.now();
  const d = detect(ctx);
  if (!d.available) return C.notAvailable(ID, d.reason, d.command);

  // ------------------------------------------------ project-shape gate
  // THE MOST IMPORTANT PART OF THIS ADAPTER: a project `dotnet build` cannot evaluate must be
  // reported as such, never laundered into a clean result.
  const projects = (ctx.project && ctx.project.projects) || [];
  const buildable = projects.filter(p => p.sdkStyle === true && p.usesPackagesConfig !== true);
  const legacy = projects.filter(p => !buildable.includes(p));

  if (projects.length === 0) {
    return {
      status: 'NOT_APPLICABLE', tool: ID, version: d.version, command: '(not run)', findings: [],
      notes: 'No C#/VB project files were discovered, so there is nothing for Roslyn to compile.',
      limitations: 'Roslyn analysis requires a compile; with no project files there was nothing to ' +
        'compile. This is NOT a clean result — no analyzer ran.'
    };
  }

  if (buildable.length === 0) {
    const named = projects.slice(0, 5)
      .map(p => `${p.name || p.file} — ${whyUnbuildable(p)}`)
      .join('; ') + (projects.length > 5 ? `; and ${projects.length - 5} more` : '');
    return {
      status: 'NOT_APPLICABLE', tool: ID, version: d.version, command: '(not run)', findings: [],
      notes: `No buildable project: ${named}.`,
      limitations: 'This is NOT a clean result. Roslyn analysis requires a successful compile and ' +
        '`dotnet build` cannot evaluate these projects at all. No analyzer diagnostics were obtained.',
      remediation:
        'msbuild.exe <solution> /p:ErrorLog=roslyn.sarif,version=2.1  (Visual Studio Developer Command ' +
        'Prompt — MSBuild ships the web targets the dotnet SDK does not)\n' +
        'dotnet tool install --global security-scan  &&  security-scan <solution>.sln --export=scs.sarif  ' +
        '(SecurityCodeScan standalone runner, works on non-SDK solutions)\n' +
        'SonarScanner.MSBuild.exe begin / msbuild / end'
    };
  }

  // ------------------------------------------------ config
  const cfg = (ctx.config.tools && ctx.config.tools[ID]) || {};
  const analysisMode = cfg.analysisMode || 'All';
  const configuration = cfg.configuration || 'Release';
  const timeoutMs = cfg.timeoutMs || 20 * 60 * 1000;
  // Puma Scan's analyzer package (Puma.Security.Rules.*) is commercially licensed and served from
  // a private feed, so it is NOT hardcoded here — users who license it add its package id to
  // cfg.analyzerPackages and it flows through the injection mechanism below unchanged.
  const analyzerPackages = cfg.analyzerPackages || [
    { id: 'SecurityCodeScan.VS2019', version: '5.6.7' },
    { id: 'SonarAnalyzer.CSharp', version: '9.32.0.97167' },
    { id: 'Microsoft.CodeAnalysis.NetAnalyzers', version: '8.0.0' }
  ];

  // ------------------------------------------------ analyzer props shim
  // SARIF version: Roslyn's ErrorLog default is SARIF v1, which src/normalize/sarif.js cannot
  // read, so `,version=2.1` is MANDATORY. The suffix CANNOT be carried on the command line:
  // the dotnet/MSBuild driver splits `-p:ErrorLog=path,version=2.1` at the comma (verified on
  // SDK 9.0.304 — csc then receives only the path and emits SARIF 1.0.0). The suffix is
  // therefore set inside this props file, where property values are not split, and csc
  // receives /errorlog:<path>,version=2.1 intact. The file is passed via
  // CustomBeforeMicrosoftCommonProps so no file in the source tree is edited.
  //
  // Injection is OFF by default: the honest default analyses with what the project ALREADY
  // references plus the .NET SDK's built-in Microsoft.CodeAnalysis.NetAnalyzers — no restore,
  // no network, no mutation of the source tree. The PackageReference section below is written
  // only when cfg.injectAnalyzers is true, because injected packages require a NuGet restore
  // and therefore network access.
  fs.mkdirSync(path.join(ctx.outPath, 'raw'), { recursive: true });
  const propsPath = path.join(ctx.outPath, 'raw', 'moraa-roslyn.props');
  const pkgRefs = cfg.injectAnalyzers === true
    ? '\n  <ItemGroup>\n' + analyzerPackages.map(p =>
        `    <PackageReference Include="${p.id}" Version="${p.version}" PrivateAssets="all" />`).join('\n') +
      '\n  </ItemGroup>\n'
    : '';
  fs.writeFileSync(propsPath,
    '<Project>\n' +
    '  <!-- Written by the moraa roslyn adapter. Loaded via -p:CustomBeforeMicrosoftCommonProps. -->\n' +
    '  <PropertyGroup>\n' +
    '    <!-- The version suffix must live here: the dotnet CLI splits a command-line\n' +
    '         -p:ErrorLog=path,version=2.1 at the comma, and Roslyn then emits SARIF v1,\n' +
    '         which the moraa SARIF normaliser cannot read. -->\n' +
    '    <ErrorLog>$(MoraaRoslynErrorLog),version=2.1</ErrorLog>\n' +
    '  </PropertyGroup>' + pkgRefs + '</Project>\n');

  // ------------------------------------------------ build each project
  const sarifDir = path.join(ctx.outPath, 'raw', 'roslyn');
  fs.mkdirSync(sarifDir, { recursive: true });

  const results = [];
  let firstCommand = null;
  let firstStderr = '';
  let exitCodeOut = 0;

  for (const p of buildable) {
    const safeName = String(p.name || path.basename(p.file, path.extname(p.file)))
      .replace(/[^A-Za-z0-9._-]/g, '_');
    const sarifPath = path.join(sarifDir, `${safeName}.sarif`);
    // WHY per project and not per solution: with a solution, every project writes the same
    // ErrorLog path and only the LAST project's diagnostics survive (dotnet/roslyn#24319).
    // The `,version=2.1` suffix travels inside the adapter props file (see above) because the
    // dotnet CLI splits command-line properties at the comma.
    const args = ['build', path.resolve(ctx.sourcePath, p.file), '-c', configuration,
      '--nologo', '-v:quiet',
      '-p:CustomBeforeMicrosoftCommonProps=' + propsPath,
      '-p:MoraaRoslynErrorLog=' + sarifPath,
      '-p:EnableNETAnalyzers=true', `-p:AnalysisMode=${analysisMode}`,
      '-p:RunAnalyzersDuringBuild=true', '-p:TreatWarningsAsErrors=false', '-warnaserror:false'];
    const command = 'dotnet ' + args.join(' ');
    if (!firstCommand) firstCommand = command;

    let exitCode = 0;
    let error = null;
    try {
      execFileSync('dotnet', args, { encoding: 'utf8', timeout: timeoutMs, stdio: 'pipe' });
    } catch (e) {
      exitCode = typeof e.status === 'number' ? e.status : 1;
      error = String(e.stderr || e.message || '');
    }
    // A non-zero exit is NOT fatal if the SARIF file was still written: analyzer diagnostics are
    // emitted even when the compile reports errors.
    const ok = fs.existsSync(sarifPath);
    if (!ok) {
      if (!firstStderr && error) firstStderr = error;
      if (exitCode !== 0 && exitCodeOut === 0) exitCodeOut = exitCode;
    }
    results.push({ project: p.name || p.file, exitCode, sarifPath, ok, error });
  }

  // ------------------------------------------------ combine and normalise
  const docs = [];
  for (const r of results) {
    if (!r.ok) continue;
    try {
      const t = fs.readFileSync(r.sarifPath, 'utf8');
      if (t.trim()) docs.push(JSON.parse(t));
    } catch { /* an unreadable log is as good as a missing one */ }
  }

  if (!docs.length) {
    return C.failed(ID,
      `No project produced a readable SARIF ErrorLog, so no analyzer diagnostic was obtained. ` +
      `First build stderr: ${firstStderr.slice(0, 300)}`,
      { command: firstCommand, exitCode: exitCodeOut || 1, durationMs: Date.now() - started });
  }

  const rawPath = path.join(ctx.outPath, 'raw', 'roslyn.json');
  const rawString = JSON.stringify({ tool: 'roslyn', logs: docs }, null, 2);
  fs.writeFileSync(rawPath, rawString);
  const findings = parse(rawString, ctx);

  // ------------------------------------------------ honesty: limitations
  const failedBuilds = results.filter(r => !r.ok);
  const limitations = [];
  if (failedBuilds.length) {
    limitations.push('Roslyn analysis requires a successful compile; the following projects failed ' +
      'to build and contributed nothing — their silence is NOT a clean result: ' +
      failedBuilds.map(r => r.project).join(', ') + '.');
  }
  if (legacy.length) {
    limitations.push('Skipped as legacy/non-SDK — `dotnet build` cannot evaluate them ' +
      '(' + legacy.map(p => whyUnbuildable(p)).join('; ') + '): ' + legacy.map(p => p.name || p.file).join(', ') + '.');
  }
  limitations.push('The rule set is limited to the analyzers the project already references plus ' +
    'the .NET SDK built-in NetAnalyzers' +
    (cfg.injectAnalyzers === true ? '' : ', because analyzer injection is disabled') +
    ' — an empty result may mean no security analyzer was present, not that the code is clean.');
  limitations.push('Analyzers see compiled code and never read Web.config or appsettings.json, so ' +
    'configuration defects are invisible to this tool.');

  return {
    status: 'EXECUTED', tool: ID, version: d.version,
    command: firstCommand,
    exitCode: exitCodeOut,
    durationMs: Date.now() - started,
    rawPath,
    findings,
    notes: `${docs.length} of ${buildable.length} project(s) compiled with analyzer diagnostics ` +
      `captured; ${findings.length} diagnostic(s) reported.`,
    limitations: limitations.join(' ')
  };
}

/**
 * Post-process one canonical finding produced by fromSarif: apply the VERIFIED rule table,
 * attach the detection block, and set confidence honestly. An analyzer match is a real signal
 * but NOT a proven exploit, so confidence never rises above LIKELY and no impact or CVSS is
 * invented.
 */
function post(f) {
  const rid = f.subcategory || '';
  const entry = RULES[rid];

  if (entry) {
    f.cwe = [...new Set([...(f.cwe || []), ...entry.cwe])];
    f.severity = entry.severity;
    f.category = entry.category || 'security';
  } else if (/^(CA2[13]\d\d|CA3\d\d\d|CA5\d\d\d|SCS\d+)$/.test(rid)) {
    // Unmapped but from a known security-analyzer family: treat as security, keep SARIF severity.
    f.category = 'security';
  } else if (/^(CS|CA|S|IDE)\d+$/.test(rid)) {
    // Compiler or code-analysis diagnostics are code quality, not security.
    f.category = 'code-quality';
  }
  // Everything else: leave untouched.

  f.detection = {
    class: 'DETERMINISTIC',
    rules: [{ engine: 'roslyn', ruleId: rid || '(unknown)', status: 'EXISTS' }]
  };
  // Do NOT claim CONFIRMED — an analyzer match is not a proven exploit.
  if (entry && f.location && f.location.startLine) f.confidence = 'LIKELY';

  // f.impact stays empty if empty (the normaliser's honesty rule — no fabricated impact),
  // and f.cvss stays null (Roslyn emits no CVSS; inventing one would be dishonest).
  return f;
}

/**
 * Parse Roslyn SARIF output into canonical findings. PURE: no fs, no network, no Date, no
 * randomness. Accepts a SARIF string/object, the `{tool:'roslyn', logs:[...]}` wrapper the run
 * step writes, or an array of SARIF docs. Returns [] for empty or malformed input. Never throws.
 */
function parse(raw, ctx) {
  let docs = [];
  try {
    const v = typeof raw === 'string' ? JSON.parse(raw) : raw;
    if (Array.isArray(v)) docs = v;
    else if (v && Array.isArray(v.logs)) docs = v.logs;
    else if (v && typeof v === 'object') docs = [v];
  } catch { return []; }
  if (!docs.length) return [];

  const findings = [];
  for (const doc of docs) {
    let f;
    try { f = fromSarif(doc, { toolId: ID, toolKind: 'sast' }); } catch { f = []; }
    if (Array.isArray(f)) findings.push(...f);
  }
  return findings.map(post);
}

module.exports = {
  id: ID, name: 'Roslyn Analyzers', kind: 'sast',
  stacks: ['core', 'both'],
  detect, run, parse
};
