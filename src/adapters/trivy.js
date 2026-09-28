'use strict';
/**
 * REFERENCE ADAPTER — Trivy.
 *
 * Trivy is the primary dependency scanner for legacy .NET because it reads manifests directly
 * and therefore works on `packages.config` projects, where `dotnet list package --vulnerable`
 * cannot run at all (it needs project evaluation and only supports PackageReference).
 *
 * This adapter uses Trivy's NATIVE JSON rather than its SARIF, because the native form carries
 * package name, installed version and fixed version — the fields a maintenance/upgrade decision
 * needs, which SARIF flattens into prose.
 *
 * Verified output shape (trivy >= 0.20 JSON schema v2):
 *   { SchemaVersion, ArtifactName, ArtifactType,
 *     Results: [ { Target, Class, Type,
 *                  Vulnerabilities: [ { VulnerabilityID, PkgName, InstalledVersion,
 *                                       FixedVersion, Severity, Title, Description,
 *                                       PrimaryURL, CweIDs, CVSS: { nvd: { V3Score, V3Vector } },
 *                                       References } ],
 *                  Secrets:           [ { RuleID, Category, Severity, Title, StartLine, Match } ],
 *                  Misconfigurations: [ { ID, Title, Description, Severity, Resolution,
 *                                         CauseMetadata: { StartLine } } ] } ] }
 */

const { execFileSync } = require('child_process');
const fs = require('fs');
const path = require('path');
const C = require('../core/adapter-contract');

const ID = 'trivy';

function detect(ctx) {
  try {
    const out = execFileSync('trivy', ['--version'], { encoding: 'utf8', timeout: 20000 });
    const m = out.match(/Version:\s*([0-9.]+)/i) || out.match(/([0-9]+\.[0-9]+\.[0-9]+)/);
    return { available: true, version: m ? m[1] : 'unknown', command: 'trivy --version' };
  } catch (e) {
    return {
      available: false,
      reason: 'trivy not found on PATH',
      command: 'winget install AquaSecurity.Trivy   # or: brew install trivy'
    };
  }
}

function run(ctx) {
  const d = detect(ctx);
  if (!d.available) {
    return C.notAvailable(ID,
      'Trivy is not installed, so no dependency, secret or misconfiguration scan was performed. ' +
      'This matters on packages.config projects, where `dotnet list package --vulnerable` also cannot run.',
      d.command);
  }

  const rawPath = path.join(ctx.outPath, 'raw', 'trivy.json');
  fs.mkdirSync(path.dirname(rawPath), { recursive: true });

  const args = ['fs', '--scanners', 'vuln,secret,misconfig',
    '--format', 'json', '--output', rawPath,
    '--skip-dirs', 'packages,bin,obj,node_modules,.git',
    '--exit-code', '0',                 // findings are data, not a process failure
    ctx.sourcePath];
  const command = 'trivy ' + args.join(' ');
  const started = Date.now();

  let exitCode = 0;
  try {
    execFileSync('trivy', args, { encoding: 'utf8', timeout: 15 * 60 * 1000, stdio: 'pipe' });
  } catch (e) {
    exitCode = typeof e.status === 'number' ? e.status : 1;
    if (!fs.existsSync(rawPath)) {
      return C.failed(ID, `Trivy exited ${exitCode} and wrote no report: ${String(e.message).slice(0, 300)}`,
        { command, exitCode, durationMs: Date.now() - started });
    }
  }

  let raw = '';
  try { raw = fs.readFileSync(rawPath, 'utf8'); } catch { /* handled below */ }
  if (!raw.trim()) {
    return C.failed(ID, 'Trivy produced an empty report.', { command, exitCode, rawPath });
  }

  let findings;
  try {
    findings = parse(raw, ctx);
  } catch (e) {
    return C.failed(ID, 'Trivy report could not be parsed: ' + e.message, { command, exitCode, rawPath });
  }

  return {
    status: 'EXECUTED', tool: ID, version: d.version, command, exitCode,
    durationMs: Date.now() - started, rawPath, findings,
    notes: `Trivy reported ${findings.length} finding(s) across vuln, secret and misconfig scanners.`,
    limitations: 'Reads manifests, not compiled code: no dataflow, so it cannot find logic or ' +
      'authorization defects. Advisory coverage depends on the vulnerability DB being current.'
  };
}

/** Pure. Never throws on junk; returns [] instead. */
function parse(raw, ctx) {
  let doc;
  try {
    doc = typeof raw === 'string' ? JSON.parse(raw) : raw;
  } catch { return []; }
  if (!doc || !Array.isArray(doc.Results)) return [];

  const rel = p => {
    const s = String(p || '').replace(/\\/g, '/');
    const root = String((ctx && ctx.sourcePath) || '').replace(/\\/g, '/');
    return root && s.startsWith(root) ? s.slice(root.length).replace(/^\//, '') : s;
  };

  const out = [];

  for (const result of doc.Results) {
    const target = rel(result.Target);

    // ---------- dependency vulnerabilities ----------
    for (const v of result.Vulnerabilities || []) {
      const nvd = (v.CVSS && (v.CVSS.nvd || v.CVSS.ghsa || Object.values(v.CVSS)[0])) || {};
      const score = Number(nvd.V3Score);
      const vector = typeof nvd.V3Vector === 'string' && /^CVSS:3/.test(nvd.V3Vector)
        ? nvd.V3Vector : null;

      out.push({
        title: `${v.PkgName || 'package'} ${v.InstalledVersion || ''}: ${v.Title || v.VulnerabilityID || 'known vulnerability'}`.trim(),
        category: 'dependency',
        subcategory: v.VulnerabilityID,
        severity: isFinite(score) && score > 0
          ? C.severityFromCvss(score)
          : C.normaliseSeverity(v.Severity, 'MEDIUM'),
        confidence: 'CONFIRMED',   // an advisory against a pinned version is a fact
        cvss: isFinite(score) && score > 0 ? {
          version: '3.1', score: Math.round(score * 10) / 10,
          vector, severity: C.severityFromCvss(score),
          note: vector ? undefined : 'Score from the advisory DB; no v3 vector supplied.'
        } : null,
        cwe: Array.isArray(v.CweIDs) && v.CweIDs.length ? v.CweIDs : undefined,
        advisories: [v.VulnerabilityID].filter(Boolean),
        owasp: ['A06:2021'],
        package: { name: v.PkgName, installed: v.InstalledVersion, fixed: v.FixedVersion || null },
        location: { file: target || '(manifest)' },
        evidence: {
          snippet: `${v.PkgName} ${v.InstalledVersion}` +
            (v.FixedVersion ? `  ->  fixed in ${v.FixedVersion}` : '  ->  NO FIXED VERSION AVAILABLE'),
          language: 'text',
          toolOutput: `trivy ${v.VulnerabilityID} severity=${v.Severity} target=${target}`
        },
        problem: (v.Description || v.Title || '').slice(0, 1200),
        impact: v.FixedVersion
          ? `Reachable via ${v.PkgName} ${v.InstalledVersion}. A fixed version exists (${v.FixedVersion}), so this is a patchable advisory.`
          : `Reachable via ${v.PkgName} ${v.InstalledVersion}. No fixed version is published, so mitigation or replacement is required rather than an upgrade.`,
        recommendation: v.FixedVersion
          ? `Upgrade ${v.PkgName} to ${v.FixedVersion} or later, then run the regression tests for every feature that uses it.`
          : `No upgrade available. Assess whether the vulnerable code path is reachable here; if it is, replace the package or apply the advisory's mitigation.`,
        tests: ['O-001', 'DEP-001'],
        detection: { class: 'DETERMINISTIC', rules: [{ engine: 'trivy', ruleId: v.VulnerabilityID, status: 'EXISTS' }] },
        sources: [{ tool: ID, sourceFindingId: v.VulnerabilityID, status: 'REPORTED' }],
        status: 'OPEN',
        references: [v.PrimaryURL].concat(v.References || []).filter(Boolean).slice(0, 5)
      });
    }

    // ---------- secrets ----------
    for (const s of result.Secrets || []) {
      out.push({
        title: `Secret in source: ${s.Title || s.RuleID}`,
        category: 'security',
        subcategory: s.RuleID,
        severity: C.normaliseSeverity(s.Severity, 'HIGH'),
        confidence: 'LIKELY',      // secret matches need human confirmation
        cvss: null,
        cwe: ['CWE-798'],
        owasp: ['A07:2021'],
        location: { file: target, startLine: s.StartLine },
        evidence: {
          snippet: '[redacted by adapter]',   // never propagate the matched secret
          language: 'text',
          toolOutput: `trivy secret rule=${s.RuleID} category=${s.Category}`,
          redacted: true
        },
        problem: `Trivy's secret scanner matched rule ${s.RuleID} (${s.Category}) in ${target}.`,
        impact: 'If this is a live credential, anyone with repository or artifact access can use it directly.',
        recommendation: 'Confirm whether the value is live. If so, rotate it and move it to a secret store. ' +
          'Note that Trivy\'s secret rules share gitleaks\' bias toward high-entropy tokens, so pair this ' +
          'with rules/gitleaks/dotnet-config.toml for .NET XML appSettings.',
        tests: ['E-001', 'E-012'],
        detection: { class: 'DETERMINISTIC', rules: [{ engine: 'trivy', ruleId: s.RuleID, status: 'EXISTS' }] },
        sources: [{ tool: ID, sourceFindingId: s.RuleID, status: 'REPORTED' }],
        status: 'OPEN'
      });
    }

    // ---------- misconfiguration ----------
    for (const m of result.Misconfigurations || []) {
      out.push({
        title: m.Title || m.ID,
        category: 'configuration',
        subcategory: m.ID,
        severity: C.normaliseSeverity(m.Severity, 'MEDIUM'),
        confidence: 'LIKELY',
        cvss: null,
        location: { file: target, startLine: (m.CauseMetadata && m.CauseMetadata.StartLine) || undefined },
        evidence: {
          snippet: (m.CauseMetadata && m.CauseMetadata.Code &&
            (m.CauseMetadata.Code.Lines || []).map(l => l.Content).join('\n')) || '',
          language: 'text',
          toolOutput: `trivy misconfig ${m.ID} severity=${m.Severity}`
        },
        problem: m.Description || m.Title || '',
        impact: m.Message || 'Configuration deviates from a hardening baseline.',
        recommendation: m.Resolution || 'Apply the referenced hardening guidance.',
        tests: ['N-004'],
        detection: { class: 'DETERMINISTIC', rules: [{ engine: 'trivy', ruleId: m.ID, status: 'EXISTS' }] },
        sources: [{ tool: ID, sourceFindingId: m.ID, status: 'REPORTED' }],
        status: 'OPEN',
        references: [m.PrimaryURL].filter(Boolean)
      });
    }
  }

  return out;
}

module.exports = {
  id: ID,
  name: 'Trivy',
  kind: 'dependency',
  stacks: ['framework', 'core', 'both'],
  detect, run, parse
};
