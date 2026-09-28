'use strict';
/**
 * Semgrep adapter.
 *
 * Runs the framework's own .NET ruleset (rules/semgrep/dotnet-moraa.yaml) plus, optionally,
 * Semgrep's registry packs. The bundled ruleset deliberately covers only DETERMINISTIC findings —
 * classes that need cross-file or domain reasoning are left to review, because a rule that
 * half-detects them produces noise instead of signal.
 */

const { execFileSync } = require('child_process');
const fs = require('fs');
const path = require('path');
const C = require('../core/adapter-contract');
const { fromSarif } = require('../normalize/sarif');

const ID = 'semgrep';
const FRAMEWORK_ROOT = path.resolve(__dirname, '..', '..');

function detect(ctx) {
  try {
    const out = execFileSync('semgrep', ['--version'], { encoding: 'utf8', timeout: 60000 });
    return { available: true, version: out.trim().split('\n')[0], command: 'semgrep --version' };
  } catch {
    return {
      available: false,
      reason: 'semgrep is not installed, so no pattern-based static analysis ran.',
      command: 'pip install semgrep   # or: brew install semgrep'
    };
  }
}

function run(ctx) {
  const d = detect(ctx);
  if (!d.available) return C.notAvailable(ID, d.reason, d.command);

  const cfg = (ctx.config.tools && ctx.config.tools[ID]) || {};
  const ruleset = path.resolve(FRAMEWORK_ROOT, cfg.config || 'rules/semgrep/dotnet-moraa.yaml');
  if (!fs.existsSync(ruleset)) {
    return C.failed(ID, `Semgrep ruleset not found at ${ruleset}.`);
  }

  const rawPath = path.join(ctx.outPath, 'raw', 'semgrep.sarif');
  fs.mkdirSync(path.dirname(rawPath), { recursive: true });

  const configs = ['--config', ruleset];
  (cfg.extraConfigs || []).forEach(c => configs.push('--config', c));

  const args = [...configs, '--sarif', '--output', rawPath,
    '--exclude', 'bin', '--exclude', 'obj', '--exclude', 'packages',
    '--exclude', 'node_modules', '--exclude', '.moraa-review',
    '--metrics', 'off',            // do not phone home from a security review
    '--quiet', ctx.sourcePath];
  const command = 'semgrep ' + args.join(' ');
  const started = Date.now();

  let exitCode = 0;
  try {
    execFileSync('semgrep', args, { encoding: 'utf8', timeout: 20 * 60 * 1000, stdio: 'pipe' });
  } catch (e) {
    exitCode = typeof e.status === 'number' ? e.status : 1;
    // semgrep: 0 = clean, 1 = findings. Anything else is a real failure.
    if (exitCode !== 1 && !fs.existsSync(rawPath)) {
      return C.failed(ID, `Semgrep exited ${exitCode}: ${String(e.stderr || e.message).slice(0, 300)}`,
        { command, exitCode, durationMs: Date.now() - started });
    }
  }

  let raw = '';
  try { raw = fs.readFileSync(rawPath, 'utf8'); } catch { /* handled */ }
  if (!raw.trim()) return C.failed(ID, 'Semgrep produced an empty SARIF report.', { command, exitCode, rawPath });

  const findings = parse(raw, ctx);
  return {
    status: 'EXECUTED', tool: ID, version: d.version, command, exitCode,
    durationMs: Date.now() - started, rawPath, findings,
    notes: `Semgrep reported ${findings.length} finding(s) using ${path.basename(ruleset)}` +
      ((cfg.extraConfigs || []).length ? ` plus ${cfg.extraConfigs.length} extra config(s).` : '.'),
    limitations: 'Pattern matching with limited dataflow. It cannot establish reachability, tenancy ' +
      'or whether an ownership check compares the right two things, so authorization-model defects ' +
      'remain a manual concern.'
  };
}

function parse(raw, ctx) {
  let found;
  try { found = fromSarif(raw, { toolId: ID, toolKind: 'sast' }); } catch { return []; }
  if (!Array.isArray(found)) return [];

  // Map the framework's own rule ids onto the concepts the correlation engine understands, and
  // attach the catalog test cases each rule exists to enforce.
  const TESTS = {
    'moraa-dotnet-disable-cert-validation': ['F-001', 'F-002'],
    'moraa-dotnet-cors-reflected-origin': ['N-001', 'N-003'],
    'moraa-dotnet-cors-wildcard-with-credentials': ['N-002'],
    'moraa-dotnet-static-zero-iv': ['E-004', 'E-005'],
    'moraa-dotnet-weak-pbkdf2-iterations': ['E-007'],
    'moraa-dotnet-sftp-accept-any-hostkey': ['F-003'],
    'moraa-dotnet-log-request-body': ['G-001', 'G-004'],
    'moraa-dotnet-log-dir-under-basedirectory': ['G-002', 'G-003'],
    'moraa-dotnet-absolute-path-in-response': ['H-004'],
    'moraa-dotnet-timestamp-filename': ['I-005', 'I-006'],
    'moraa-dotnet-pathcombine-unvalidated-param': ['I-001'],
    'moraa-dotnet-validatecredentials-no-empty-guard': ['A-001', 'A-002'],
    'moraa-dotnet-principalcontext-no-ssl': ['A-003'],
    'moraa-dotnet-oauth-validate-client-unconditional': ['A-006'],
    'moraa-dotnet-token-lifetime-excessive': ['A-007', 'A-008'],
    'moraa-dotnet-swagger-unconditional': ['H-006'],
    'moraa-dotnet-expression-built-by-concat': ['C-008', 'U-008'],
    'moraa-dotnet-catch-returns-default': ['L-001'],
    'moraa-dotnet-tostring-no-invariant-numeric': ['C-015', 'L-008'],
    'moraa-dotnet-regex-no-timeout': ['P-004', 'P-005'],
    'moraa-dotnet-sync-over-async-content-read': ['P-002'],
    'moraa-dotnet-parse-body-without-contenttype-check': ['H-003']
  };

  return found.map(f => {
    const rid = f.subcategory || '';
    const tests = TESTS[rid];
    if (tests) f.tests = tests;
    f.detection = {
      class: 'DETERMINISTIC',
      rules: [{ engine: 'semgrep', ruleId: rid || '(unknown)', status: 'EXISTS' }]
    };
    // Semgrep's `help` carries the rule's message; keep it as the recommendation but do not
    // pretend it is a tailored fix.
    if (!f.impact && f.problem) {
      f.impact = 'Impact is not asserted by the scanner. Assess reachability in this application ' +
        'before treating this as exploitable.';
    }
    return f;
  });
}

module.exports = {
  id: ID, name: 'Semgrep', kind: 'sast',
  stacks: ['framework', 'core', 'both'],
  detect, run, parse
};
