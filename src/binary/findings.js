// dotnet-codereview-framework — src/binary/findings.js
// Author: Amr Kadry (github.com/Amrkadry) · MIT License
'use strict';
/**
 * Canonical finding builders for the binary path — PURE functions from parsed inventory to
 * schema-shaped findings (schema/finding.schema.json). No I/O, no parsing of buffers here.
 *
 * House rules applied:
 *   - Every finding carries location.file, evidence (with toolOutput naming exactly how the
 *     fact was established), a confidence, and a concrete remediation.
 *   - Tool attribution is "binary" in sources[]; detection rules use the schema's "custom"
 *     engine because the binary path is its own engine, not a wrapper.
 *   - cvss is null throughout: these findings are deterministic facts whose risk depends on
 *     reachability the binary alone cannot prove. Where severity would otherwise look like a
 *     CVSS claim, a severityRationale says what was actually established.
 *   - Secrets are redacted at the source; builders never receive raw values.
 */

const KV = require('./known-vulnerable');

const SOURCE = { tool: 'binary', status: 'REPORTED' };

function mk(ruleId, o) {
  return Object.assign({
    category: 'security',
    severity: 'MEDIUM',
    confidence: 'CONFIRMED',
    cvss: null,
    evidence: { snippet: '', language: 'text' },
    problem: '',
    impact: '',
    recommendation: '',
    tests: [],
    detection: { class: 'DETERMINISTIC', rules: [{ engine: 'custom', ruleId, status: 'EXISTS' }] },
    sources: [Object.assign({ sourceFindingId: ruleId }, SOURCE)],
    status: 'OPEN'
  }, o);
}

// ---------------------------------------------------------------- assembly inventory findings

function debugBuild(inv, file) {
  const modes = inv.debug.debuggingModes;
  const modeText = modes === null || modes === undefined
    ? `isJITOptimizerDisabled=true (two-bool ctor)`
    : `DebuggingModes=0x${Number(modes).toString(16)} (DisableOptimizations set)`;
  return mk('binary-debug-build', {
    title: `Debug build deployed: ${inv.assembly ? inv.assembly.name : file} shipped with JIT optimization disabled`,
    category: 'deployment',
    severity: 'HIGH',
    confidence: 'CONFIRMED',
    cwe: ['CWE-489'],
    location: { file },
    evidence: {
      snippet: `[assembly: DebuggableAttribute] — ${modeText}`,
      language: 'text',
      toolOutput: `metadata: CustomAttribute table resolves DebuggableAttribute with optimizations disabled`
    },
    problem: `The shipped assembly was compiled in DEBUG configuration: its DebuggableAttribute ` +
      `disables JIT optimizations and enables debugger instrumentation.`,
    impact: 'Debug builds in production expose internal state to any attached debugger, run ' +
      'slower, and can behave differently from the tested release build. Combined with a ' +
      'debug-enabled web configuration this becomes an active-debugging exposure.',
    recommendation: 'Rebuild in Release configuration and redeploy. Verify with this same check ' +
      '— the attribute is visible in the binary regardless of source availability.',
    tests: ['N-006'],
    priority: 'P2',
    effort: 'SMALL',
    severityRationale: 'Deterministic build-configuration fact; severity reflects operational and ' +
      'information-disclosure risk rather than a scored vulnerability.'
  });
}

function eolRuntime(inv, file) {
  return mk('binary-eol-runtime', {
    title: `Assembly targets end-of-life runtime: ${inv.targetFramework}`,
    category: 'dependency',
    severity: 'MEDIUM',
    confidence: 'CONFIRMED',
    cwe: ['CWE-1104'],
    location: { file },
    evidence: {
      snippet: `TargetFrameworkAttribute: "${inv.targetFramework}"`,
      language: 'text',
      toolOutput: `metadata: TargetFrameworkAttribute on assembly; CLR header reports runtime ${inv.cli.runtimeVersion} (${inv.cli.runtimeLabel})`
    },
    problem: `The assembly declares ${inv.targetFramework}, a .NET version that is past end of ` +
      'support. It receives no security updates, and patches must come from workarounds or upgrades.',
    impact: 'Any vulnerability in the runtime itself stays exploitable on this deployment forever; ' +
      'support tooling and NuGet feeds increasingly drop these targets.',
    recommendation: 'Plan an upgrade to a supported target (.NET Framework 4.8 or .NET 8+). ' +
      'Until then, compensate at the platform layer (TLS configuration, WAF rules, patching) and ' +
      'track runtime advisories manually.',
    priority: 'P2',
    effort: 'LARGE'
  });
}

function strongName(inv, file) {
  return mk('binary-strong-name', {
    title: `Assembly is not strong-name signed: ${inv.assembly ? inv.assembly.name : file}`,
    category: 'security',
    severity: 'LOW',
    confidence: 'CONFIRMED',
    cwe: ['CWE-494'],
    location: { file },
    evidence: {
      snippet: inv.cli.strongNameFlagOnly
        ? 'COR20 flags set STRONGNAMESIGNED but the strong-name signature blob is empty (delay-signed)'
        : 'COR20 flags: STRONGNAMESIGNED not set; strong-name signature blob absent',
      language: 'text',
      toolOutput: `IMAGE_COR20_HEADER flags=0x${inv.cli.cliHeader.flags.toString(16)}`
    },
    problem: 'The assembly carries no strong-name signature, so its identity cannot be verified ' +
      'and its content has no tamper evidence.',
    impact: 'A replaced or patched DLL in the deployment folder loads silently; nothing in the ' +
      'application would detect the substitution.',
    recommendation: 'If the assembly is first-party, strong-name sign it and verify signatures at ' +
      'deployment. For third-party assemblies without signatures, record expected file hashes and ' +
      'check them on deploy.',
    priority: 'P3',
    effort: 'SMALL'
  });
}

function pdbPath(inv, file, entry) {
  return mk('binary-pdb-path', {
    title: 'Build-machine PDB path embedded in shipped binary',
    category: 'security',
    severity: 'LOW',
    confidence: 'CONFIRMED',
    cwe: ['CWE-540'],
    location: { file },
    evidence: {
      snippet: `debug directory (type ${entry.typeName}): ${entry.pdbPath}`,
      language: 'text',
      toolOutput: `IMAGE_DEBUG_DIRECTORY entry: type=${entry.type} format=${entry.pdbGuid ? 'RSDS' : 'NB10'} age=${entry.pdbAge}`
    },
    problem: 'The binary embeds the full path of its PDB symbol file, disclosing build-machine ' +
      'directory structure and often usernames.',
    impact: 'An attacker learns internal paths, developer identities and build layout — useful ' +
      'reconnaissance for lateral movement or social engineering, and noise in any log review.',
    recommendation: 'Strip PDB references on release builds (or build with /pathmap), and ship ' +
      'symbols only to the symbol server, not the deployment folder.',
    priority: 'P3',
    effort: 'SMALL'
  });
}

// ---------------------------------------------------------------------- dependency findings

function knownVulnerableDep(ref, entry, file, refSource) {
  return mk('binary-known-vulnerable-dependency', {
    title: `${ref.name} ${ref.version}: known vulnerable version (${entry.cve})`,
    category: 'dependency',
    severity: entry.severity,
    confidence: 'CONFIRMED',
    cwe: ['CWE-1104'],
    owasp: ['A06:2021'],
    location: { file },
    evidence: {
      snippet: `AssemblyRef: ${ref.name}, version ${ref.version} < fixed ${entry.fixedLabel}`,
      language: 'text',
      toolOutput: `source of version: ${refSource}; metadata AssemblyRef table`
    },
    problem: `The assembly references ${ref.name} ${ref.version}. ${entry.summary}`,
    impact: `If ${ref.name} code paths are reachable, the advisory applies to this deployment. ` +
      'Version pinning is established fact; reachability is not asserted by this scan.',
    recommendation: `Upgrade ${ref.name} to ${entry.fixedLabel} or later, verify binding redirects ` +
      'do not pin the old version, and regression-test every feature that touches the library.',
    tests: ['O-001', 'O-002'],
    priority: 'P1',
    effort: 'MEDIUM',
    severityRationale: 'Severity follows the advisory class offline; no CVSS score is asserted ' +
      'because the binary alone cannot prove the vulnerable path is reachable.',
    references: [entry.url]
  });
}

function bindingRedirect(rd, file, escalations) {
  const majorJump = KV.parseVersion(rd.oldMin) && KV.parseVersion(rd.newVersion) &&
    rd.oldMin.split('.')[0] !== rd.newVersion.split('.')[0];
  const vulnerable = escalations && escalations.targetVulnerable;
  return mk('binary-binding-redirect', {
    title: `Binding redirect silently rewrites ${rd.assemblyName || 'assembly'} ${rd.oldVersion} -> ${rd.newVersion}`,
    category: 'configuration',
    severity: vulnerable ? 'HIGH' : (majorJump ? 'MEDIUM' : 'LOW'),
    confidence: 'CONFIRMED',
    location: { file },
    evidence: {
      snippet: `<dependentAssembly><assemblyIdentity name="${rd.assemblyName}"${rd.publicKeyToken ? ` publicKeyToken="${rd.publicKeyToken}"` : ''}/>` +
        `<bindingRedirect oldVersion="${rd.oldVersion}" newVersion="${rd.newVersion}"/></dependentAssembly>`,
      language: 'xml',
      toolOutput: 'Web.config/App.config <runtime><assemblyBinding> block, verbatim'
    },
    problem: `At load time the runtime resolves ${rd.assemblyName || 'this assembly'} to version ` +
      `${rd.newVersion}, regardless of the ${rd.oldVersion} that assemblies were compiled against.`,
    impact: vulnerable
      ? `The redirect pins the deployment to ${rd.newVersion}, which is itself in a known-vulnerable ` +
        'range: even a fixed copy in bin/ would be bypassed by this redirect.'
      : majorJump
        ? 'A major-version redirect can change behaviour silently and masks the version actually running.'
        : 'The version that runs differs from the version compiled against; upgrades and audits that ' +
          'read manifests will disagree with what executes.',
    recommendation: vulnerable
      ? `Point the redirect at a fixed version and deploy that version; ${rd.newVersion} is known-vulnerable.`
      : 'Confirm the redirect is intentional, update compiled references to the redirected version, ' +
        'and remove redirects that exist only to silence version warnings.',
    priority: vulnerable ? 'P1' : 'P3',
    effort: 'SMALL',
    tests: ['O-007']
  });
}

function versionConflict(group, file) {
  return mk('binary-version-conflict', {
    title: `Multiple versions of ${group.name} co-located in deployment`,
    category: 'dependency',
    severity: 'MEDIUM',
    confidence: 'CONFIRMED',
    cwe: ['CWE-1104'],
    owasp: ['A06:2021'],
    location: { file: file || group.files[0] },
    evidence: {
      snippet: group.files.map(f => `${f.file} -> ${f.version}`).join('\n'),
      language: 'text',
      toolOutput: 'assembly inventory: same assembly name with different versions on disk'
    },
    problem: `${group.files.length} different versions of ${group.name} exist in the deployment ` +
      'tree; which one loads depends on probing order, not intent.',
    impact: 'Behaviour can differ between environments and after file shuffles; security fixes in ' +
      'one copy do not apply to the other, and both may load side by side.',
    recommendation: 'Keep exactly one version per assembly in bin/. Delete stale copies, and let ' +
      'binding redirects (if any) state the intended version explicitly.',
    tests: ['O-007'],
    priority: 'P2',
    effort: 'SMALL'
  });
}

function missingDependency(ref, file) {
  return mk('binary-missing-dependency', {
    title: `Referenced assembly not co-located: ${ref.name} ${ref.version}`,
    category: 'reliability',
    severity: 'MEDIUM',
    confidence: 'LIKELY',
    location: { file },
    evidence: {
      snippet: `AssemblyRef: ${ref.name}, version ${ref.version} — no matching file in the deployment tree`,
      language: 'text',
      toolOutput: 'metadata AssemblyRef table vs. co-located assembly inventory'
    },
    problem: 'The application binds to this assembly but no copy of it ships beside the binaries. ' +
      'It may resolve from the GAC — or fail at first use.',
    impact: 'If the GAC does not provide the version, the first request or call that touches the ' +
      'reference throws FileLoadException/FileNotFoundException in production.',
    recommendation: 'Deploy the referenced assembly with the application (or install and verify the ' +
      'exact GAC version), and document the resolution source.',
    priority: 'P2',
    effort: 'SMALL',
    severityRationale: 'LIKELY, not CONFIRMED: offline analysis cannot see the GAC or probing paths.'
  });
}

// ------------------------------------------------------------------------- string findings

function secretString(hit, file) {
  return mk(hit.ruleId, {
    title: `${hit.rule.title}: ${hit.assembly || file}`,
    category: 'security',
    severity: hit.rule.severity,
    confidence: hit.rule.confidence,
    cwe: hit.rule.cwe,
    owasp: hit.ruleId === 'binary-internal-endpoint' ? undefined : ['A07:2021'],
    location: { file },
    evidence: {
      snippet: hit.display,
      language: 'text',
      redacted: true,
      toolOutput: `binary string scan: rule=${hit.ruleId} origin=${hit.origin} heapOffset=0x` +
        (hit.heapOffset || 0).toString(16) + (hit.detail && hit.detail.embeddedCredentials ? ' credentialsEmbedded=true' : '')
    },
    problem: `${hit.rule.title}. The value is baked into the shipped binary and readable by any ` +
      'decompiler (ilspycmd, dnSpy, strings).',
    impact: 'Anyone with the deployment files can recover the credential without touching source ' +
      'control; rotation requires a rebuild and redeploy.',
    recommendation: 'Confirm whether the value is live. If so, rotate it, move it to configuration ' +
      'outside the binary (or a secret store), and rebuild.',
    tests: hit.ruleId === 'binary-internal-endpoint' ? [] : ['E-003'],
    priority: hit.rule.severity === 'HIGH' ? 'P1' : 'P2',
    effort: 'SMALL'
  });
}

// ------------------------------------------------------------------------------ capability

function noDecompiler(status) {
  return mk('binary-decompiler-unavailable', {
    title: 'No decompiler installed: source-level checks did not run on these binaries',
    category: 'process',
    severity: 'LOW',
    confidence: 'CONFIRMED',
    location: { file: '.' },
    evidence: {
      snippet: status.reason,
      language: 'text',
      toolOutput: `probe order: ${(status.tried || []).map(t => `${t.id}=${t.available ? 'found' : 'absent'}`).join(', ')}`
    },
    problem: 'The binary/assembly path ran at metadata level only. Without a decompiler, the ' +
      'framework\'s source analyzers cannot inspect recovered C#, so source-derived findings are ' +
      'absent from this report.',
    impact: 'This is a coverage gap, not a clean result: logic, injection and configuration ' +
      'defects visible in source remain unexamined.',
    recommendation: `Install the decompiler with: ${status.command}. Then re-run the binary path.`,
    tests: ['O-002'],
    priority: 'P3',
    effort: 'TRIVIAL'
  });
}

module.exports = {
  debugBuild, eolRuntime, strongName, pdbPath,
  knownVulnerableDep, bindingRedirect, versionConflict, missingDependency,
  secretString, noDecompiler
};
