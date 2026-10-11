// dotnet-codereview-framework — src/adapters/gitleaks.js
// Author: Amr Kadry (github.com/Amrkadry) · MIT License
'use strict';
/**
 * GitLeaks adapter — secret scanning with the framework's .NET ruleset.
 *
 * THE RULESET IS NOT OPTIONAL. Stock gitleaks rules target high-entropy, well-formed tokens
 * (AKIA…, ghp_…, PEM blocks, JWTs). They do not match how .NET Framework applications actually
 * store secrets: low-entropy, human-chosen passwords inside XML attributes such as
 * `<add key="AdminPassword" value="..." />`. Measured on a real legacy application, the stock
 * ruleset scanned 49 MB and reported "no leaks found" while four sets of live cleartext
 * credentials sat in Web.config; the .NET ruleset found 17.
 *
 * So this adapter always passes --config, and it records in `limitations` that a clean result is
 * only meaningful when a canary proves the gate is actually looking.
 */

const { execFileSync } = require('child_process');
const fs = require('fs');
const path = require('path');
const C = require('../core/adapter-contract');
const { fromSarif } = require('../normalize/sarif');

const ID = 'gitleaks';
const FRAMEWORK_ROOT = path.resolve(__dirname, '..', '..');

function detect(ctx) {
  try {
    const out = execFileSync('gitleaks', ['version'], { encoding: 'utf8', timeout: 30000 });
    return { available: true, version: out.trim().split('\n').pop().trim(), command: 'gitleaks version' };
  } catch {
    return {
      available: false,
      reason: 'gitleaks is not installed, so no secret scan ran. On .NET this is a significant gap: ' +
        'credentials in Web.config are the most common critical finding and nothing else in the ' +
        'pipeline looks for them.',
      command: 'go install github.com/gitleaks/gitleaks/v8@latest   # or download a release binary'
    };
  }
}

function run(ctx) {
  const d = detect(ctx);
  if (!d.available) return C.notAvailable(ID, d.reason, d.command);

  const cfg = (ctx.config.tools && ctx.config.tools[ID]) || {};
  const ruleset = path.resolve(FRAMEWORK_ROOT, cfg.config || 'rules/gitleaks/dotnet-config.toml');
  if (!fs.existsSync(ruleset)) {
    return C.failed(ID,
      `The .NET ruleset was not found at ${ruleset}. Refusing to fall back to the stock rules, ` +
      'because they return a false clean on .NET config files and a false clean is worse than no scan.');
  }

  const rawPath = path.join(ctx.outPath, 'raw', 'gitleaks.sarif');
  fs.mkdirSync(path.dirname(rawPath), { recursive: true });

  // `dir` scans the working tree. When the source is a git repo we ALSO want history, but that is
  // a separate concern: report it as a limitation rather than silently scanning only one of them.
  const args = ['dir', ctx.sourcePath, '--config', ruleset, '--redact', '--no-banner',
    '--report-format', 'sarif', '--report-path', rawPath, '--exit-code', '0'];
  const command = 'gitleaks ' + args.join(' ');
  const started = Date.now();

  let exitCode = 0;
  try {
    execFileSync('gitleaks', args, { encoding: 'utf8', timeout: 15 * 60 * 1000, stdio: 'pipe' });
  } catch (e) {
    exitCode = typeof e.status === 'number' ? e.status : 1;
    // With --exit-code 0 a non-zero status is a real failure, not "leaks found".
    if (!fs.existsSync(rawPath)) {
      return C.failed(ID, `gitleaks exited ${exitCode} and wrote no report: ` +
        String(e.stderr || e.message).slice(0, 300), { command, exitCode, durationMs: Date.now() - started });
    }
  }

  let raw = '';
  try { raw = fs.readFileSync(rawPath, 'utf8'); } catch { /* handled */ }
  if (!raw.trim()) return C.failed(ID, 'gitleaks produced an empty report.', { command, exitCode, rawPath });

  const findings = parse(raw, ctx);
  const historyNote = ctx.project && ctx.project.flags && ctx.project.flags.isGitRepo
    ? 'The working tree was scanned. Run `gitleaks detect` separately to cover git history — a ' +
      'rotated secret still present in history is still exposed.'
    : 'No .git directory is present, so history cannot be scanned at all: only the current tree was examined.';

  return {
    status: 'EXECUTED', tool: ID, version: d.version, command, exitCode,
    durationMs: Date.now() - started, rawPath, findings,
    notes: `gitleaks reported ${findings.length} finding(s) using ${path.basename(ruleset)}. ` +
      'The .NET ruleset is used deliberately: stock rules miss low-entropy passwords in XML appSettings.',
    limitations: 'Pattern matching cannot distinguish a live credential from a placeholder, so every ' +
      'hit needs confirmation. ' + historyNote + ' A clean result is only meaningful if a canary ' +
      'secret proves the gate is active.'
  };
}

function parse(raw, ctx) {
  let found;
  try { found = fromSarif(raw, { toolId: ID, toolKind: 'secret' }); } catch { return []; }
  if (!Array.isArray(found)) return [];

  // gitleaks is handed an ABSOLUTE scan root, so every path it reports back is absolute.
  // Left alone that leaks the reviewing machine's directory layout into the report, the
  // SARIF and the Excel, and it breaks every consumer that resolves a location against the
  // repository root -- a GitHub code-scanning annotation cannot attach to "D:/...". Every
  // other source in this pipeline emits repo-relative, forward-slash paths; so does this one now.
  const root = (ctx && ctx.sourcePath) ? String(ctx.sourcePath) : null;
  const relPath = file => {
    let t = String(file || '').split(String.fromCharCode(92)).join('/');
    if (!root) return t;
    const r = root.split(String.fromCharCode(92)).join('/').replace(/\/+$/, '');
    if (t.toLowerCase().startsWith(r.toLowerCase() + '/')) t = t.slice(r.length + 1);
    return t.replace(/^\.\//, '');
  };

  return found.map(f => {
    const rule = f.subcategory || '';
    // Commented-out credentials are a distinct and often worse case: they are frequently the
    // PRODUCTION values, left behind when an environment was switched.
    const isCommented = /commented/i.test(rule);
    const isWeakKey = /weak-static-key/i.test(rule);

    // The SARIF message gitleaks emits reads "<rule> has detected secret for file <abs path>",
    // which puts a machine string and a local path where a human-readable title belongs. The
    // location already carries the file, so the title states the FINDING instead.
    const where = relPath(f.location && f.location.file);
    const kind = isCommented
      ? 'Credential left in a comment'
      : isWeakKey
        ? 'Hard-coded cryptographic key literal'
        : 'Secret-shaped literal in source or configuration';

    return Object.assign(f, {
      title: `${kind} (${rule || 'gitleaks'})`,
      location: Object.assign({}, f.location, { file: where }),
      category: 'security',
      severity: 'HIGH',
      confidence: 'LIKELY',
      cvss: null,               // exploitability depends on whether the value is live
      cwe: isCommented ? ['CWE-540', 'CWE-798'] : ['CWE-798'],
      owasp: ['A07:2021', 'A05:2021'],
      evidence: {
        snippet: '[redacted by adapter — see the source file at the cited line]',
        language: 'text',
        redacted: true,
        toolOutput: `gitleaks rule=${rule || '(unknown)'}`
      },
      problem: isCommented
        ? `A credential is present inside a comment (rule ${rule}). Commenting a value out does not ` +
          'remove it from the file, the repository, or the build artifact.'
        : isWeakKey
          ? `A hard-coded key literal was found (rule ${rule}). A key committed to source provides ` +
            'no confidentiality: anyone with the repository can decrypt or forge anything it protects.'
          : `A secret-shaped value was found in a configuration or source file (rule ${rule}).`,
      impact: 'If this value is live, anyone with access to the repository, a build artifact or a ' +
        'server backup can use it directly, bypassing every control in the application. ' +
        (isCommented ? 'Commented blocks frequently hold the PRODUCTION credentials.' : ''),
      recommendation: 'Confirm whether the value is live; if so treat it as compromised and rotate it. ' +
        'Move secrets to a managed store or an encrypted configuration section, prefer Integrated ' +
        'Security so no password exists at all, delete commented credential blocks, and add this scan ' +
        'to CI as a blocking gate with a canary.',
      tests: isCommented ? ['E-002', 'E-003', 'E-012'] : ['E-001', 'E-003', 'E-012'],
      detection: {
        class: 'DETERMINISTIC',
        rules: [{ engine: 'gitleaks', ruleId: rule || '(unknown)', status: 'EXISTS' }]
      },
      priority: 'P0',
      effort: 'MEDIUM'
    });
  });
}

module.exports = {
  id: ID, name: 'GitLeaks', kind: 'secret',
  stacks: ['framework', 'core', 'both'],
  detect, run, parse
};
