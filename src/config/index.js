// dotnet-codereview-framework — src/config/index.js
// Author: Amr Kadry (github.com/Amrkadry) · MIT License
'use strict';
/**
 * THE CONFIG LAYER — one file for every integration.
 *
 * FILE
 *   `moraa.config.json` holds API keys, endpoints, which integrations are enabled, severity
 *   thresholds and the two AI mode toggles. `moraa.config.example.json` is the committed
 *   placeholder template; the REAL file must be gitignored and never committed.
 *
 * PRECEDENCE (implemented by resolve(); documented here and in WIRING.md):
 *       CLI flag  >  environment variable  >  config file  >  built-in default
 *   A layer only wins when it actually provides a value; `undefined`/absent falls through.
 *
 * SECRETS DISCIPLINE (non-negotiable, see ./redact.js):
 *   - A key is NEVER printed. Display form is last-4 only (`****MNOP`).
 *   - guard()/guardedWriteFile() wrap every output path (terminal, logs, Markdown, raw dumps).
 *   - Loading a config with a real key does not echo it — even in verbose/debug mode. Debug
 *     dumps go through redactConfig().
 *   - This module returns resolved keys ONLY inside the object it returns to the adapter; it
 *     never logs them, never embeds them in errors, and never writes them anywhere.
 *
 * AI MODES (both DEFAULT TO OFF; the user explicitly enables either, both, or neither):
 *   ai.report.enabled — MODE 1: post-process an ALREADY-PRODUCED report (Markdown projection of
 *                       the canonical JSON) and enrich each finding's own section in place.
 *   ai.review.enabled — MODE 2: direct code review; findings enter the canonical model as
 *                       tool "ai-review" and correlate like any other tool's findings.
 *   With both off, nothing AI-related runs and no API key is required anywhere.
 *
 * ENTRY POINTS
 *   loadConfig({configPath, sourcePath, env, flags})  -> {found, path, config}
 *   resolveAi({config, env, flags})                   -> per-mode resolved settings
 *   checkConfig({configPath, sourcePath, env, flags}) -> which integrations are configured vs
 *                                                        missing, WITHOUT revealing values
 *   printCheck(report)                                -> terminal-safe text (guarded)
 *   Run directly:  node src/config/index.js [--config <path>]
 */

const fs = require('fs');
const path = require('path');
const R = require('./redact');

const CONFIG_FILENAME = 'moraa.config.json';

/** Built-in defaults. Every layer may override; everything here is the safest possible state. */
const DEFAULTS = {
  schema: 2,
  outDir: '.moraa-review',
  failOn: null,
  ai: {
    // 'auto' resolves a provider ONLY from an explicitly enabled mode, by whichever single key
    // is present. 'none' hard-disables AI regardless of keys. Providers: anthropic | openai |
    // zai | local (OpenAI-compatible baseUrl required) | none | auto.
    provider: 'auto',
    model: null,
    baseUrl: null,
    timeoutMs: 180000,
    maxTokens: 8000,
    key: null, // discouraged (see .gitignore warning below); env var preferred
    report: { enabled: false, severityThreshold: 'LOW', contextLines: 4, maxFindings: 50 },
    review: { enabled: false, severityThreshold: 'LOW', maxFiles: 12, maxBytesPerFile: 60000 }
  },
  keys: { anthropic: null, openai: null, zai: null, local: null, snyk: null, sonar: null },
  endpoints: { sonarqube: { hostUrl: null, projectKey: null } },
  tools: {}
};

const PROVIDERS = {
  anthropic: { label: 'Anthropic', env: 'ANTHROPIC_API_KEY', base: 'https://api.anthropic.com', model: 'claude-sonnet-5', api: 'messages', keyOptional: false },
  openai: { label: 'OpenAI', env: 'OPENAI_API_KEY', base: 'https://api.openai.com', model: 'gpt-4o', api: 'chat', keyOptional: false },
  zai: { label: 'Z.AI (OpenAI-compatible)', env: 'ZAI_API_KEY', base: 'https://api.z.ai/api/paas/v4', model: 'glm-5.3', api: 'chat', keyOptional: false },
  local: { label: 'Local OpenAI-compatible endpoint', env: null, base: null, model: null, api: 'chat', keyOptional: true, requiresBaseUrl: true },
  none: { label: 'disabled', env: null, base: null, model: null, api: null, keyOptional: true },
  auto: { label: 'auto-detect from keys', env: null, base: null, model: null, api: null, keyOptional: true }
};

const ENV_TRUTHY = new Set(['1', 'true', 'yes', 'on']);
const ENV_FALSY = new Set(['0', 'false', 'no', 'off']);
const SEVERITIES = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'];

// ------------------------------------------------------------------ loading

function deepMerge(base, over) {
  if (over === undefined) return base;
  if (base === null || typeof base !== 'object' || Array.isArray(base) ||
      over === null || typeof over !== 'object' || Array.isArray(over)) {
    return over === undefined ? base : over;
  }
  const out = Object.assign({}, base);
  for (const k of Object.keys(over)) out[k] = deepMerge(base[k], over[k]);
  return out;
}

function parseBool(v) {
  if (v === undefined || v === null) return undefined;
  if (typeof v === 'boolean') return v;
  const s = String(v).trim().toLowerCase();
  if (ENV_TRUTHY.has(s)) return true;
  if (ENV_FALSY.has(s)) return false;
  return undefined;
}

/** Where is the config? Explicit flag wins, then cwd, then this repo's root. */
function configCandidates({ configPath, sourcePath } = {}) {
  const list = [];
  if (configPath) list.push(path.resolve(configPath));
  if (sourcePath) list.push(path.join(path.resolve(sourcePath), CONFIG_FILENAME));
  list.push(path.join(process.cwd(), CONFIG_FILENAME));
  list.push(path.join(__dirname, '..', '..', CONFIG_FILENAME));
  return [...new Set(list)];
}

/**
 * Load moraa.config.json and merge it over the defaults.
 * NEVER echoes key values; the returned object holds them in memory only.
 */
function loadConfig(opts = {}) {
  const env = opts.env || process.env;
  const flags = opts.flags || {};
  const result = { found: false, path: null, config: deepMerge(undefined, DEFAULTS), warnings: [] };
  const candidates = configCandidates(opts);
  let chosen = null;
  for (const c of candidates) {
    if (fs.existsSync(c)) { chosen = c; break; }
  }
  if (chosen) {
    try {
      result.file = JSON.parse(fs.readFileSync(chosen, 'utf8'));
      result.found = true;
      result.path = chosen;
    } catch (e) {
      result.warnings.push(`config file ${chosen} is not valid JSON (${e.message}); defaults in force`);
    }
  }
  // Guard against a repo-root config that does not cover .gitignore — a real key in it could be
  // committed. We report; we do not silently accept.
  if (result.found && path.basename(result.path) === CONFIG_FILENAME) {
    try {
      const gi = fs.readFileSync(path.join(__dirname, '..', '..', '.gitignore'), 'utf8');
      if (!gi.split(/\r?\n/).some(l => l.trim() === CONFIG_FILENAME || l.trim() === `**/${CONFIG_FILENAME}`)) {
        result.warnings.push(
          `${CONFIG_FILENAME} is NOT listed in .gitignore — a real key in it could be committed. ` +
          'Add it to .gitignore (or keep keys in the environment) before putting a real key in the file.');
      }
    } catch { /* .gitignore unreadable: say nothing here, config-check reports it */ }
  }
  result.config = deepMerge(DEFAULTS, result.file || {});
  return result;
}

// ------------------------------------------------------------------ precedence

/**
 * THE precedence rule, for one setting.
 * resolve({flag, env, config, def}) -> {value, source} with source in flag|env|config|default.
 */
function resolve({ flag, env, config, def }) {
  if (flag !== undefined && flag !== null) return { value: flag, source: 'flag' };
  if (env !== undefined && env !== null && env !== '') return { value: env, source: 'env' };
  if (config !== undefined && config !== null && config !== '') return { value: config, source: 'config' };
  return { value: def === undefined ? null : def, source: 'default' };
}

const envOf = (env, name) => (env[name] === '' ? undefined : env[name]);

// ------------------------------------------------------------------ AI resolution

function normSeverity(s, fallback) {
  const v = String(s || '').toUpperCase();
  return SEVERITIES.includes(v) ? v : fallback;
}

function pickProviderName(cfg, env, flags) {
  const r = resolve({
    flag: flags.aiProvider,
    env: envOf(env, 'MORAA_AI_PROVIDER'),
    config: (cfg.ai && cfg.ai.provider) || undefined,
    def: DEFAULTS.ai.provider
  });
  const raw = String(r.value || 'auto').toLowerCase();
  return PROVIDERS[raw] ? raw : 'auto';
}

/**
 * Resolve the API key for a provider across all layers.
 * Order: flag > env (generic MORAA_AI_API_KEY, then provider-specific) > config keys.* > none.
 * Returns { key, source } — key is null when absent. NEVER log the key.
 */
function resolveKey(provider, cfg, env, flags) {
  const pc = PROVIDERS[provider] || {};
  const cfgKey = (cfg.keys && cfg.keys[provider]) || (cfg.ai && cfg.ai.key) || null;
  const layers = [
    { v: flags.aiKey, s: 'flag' },
    { v: envOf(env, 'MORAA_AI_API_KEY'), s: 'env' },
    { v: pc.env ? envOf(env, pc.env) : undefined, s: 'env' },
    { v: cfgKey || undefined, s: 'config' }
  ];
  for (const l of layers) {
    if (l.v !== undefined && l.v !== null && l.v !== '') return { key: String(l.v), source: l.s };
  }
  return { key: null, source: 'none' };
}

/**
 * Resolve ONE AI mode's full settings.
 * @returns enabled, configured, provider, providerLabel, model, baseUrl, key (raw), keyShown
 *          (redacted), keySource, timeoutMs, maxTokens, mode-specific knobs, problems[].
 */
function resolveMode(mode, cfg, env, flags, fromFile) {
  const legacy = (cfg.tools && cfg.tools['ai-review']) || {}; // pre-2.0 shape: tools.ai-review.*
  const shared = cfg.ai || {};
  const m = shared[mode] || {};

  // enabled: flag > env > per-mode config > legacy tools.ai-review.enabled (mode "review" only) > false
  const flagName = mode === 'report' ? 'aiReport' : 'aiReview';
  const envName = mode === 'report' ? 'MORAA_AI_REPORT' : 'MORAA_AI_REVIEW';
  const enabledLayers = [
    { v: parseBool(flags[flagName]), s: 'flag' },
    { v: parseBool(envOf(env, envName)), s: 'env' },
    { v: parseBool(m.enabled), s: 'config' },
    ...(mode === 'review' ? [{ v: parseBool(legacy.enabled), s: 'config(legacy)' }] : []),
    { v: false, s: 'default' }
  ];
  const enabledRes = enabledLayers.find(l => l.v !== undefined);
  const enabledValue = enabledRes.v === true;
  // Without a config file on disk, anything from the merged config IS the default.
  const enabledSource = !fromFile && enabledRes.s === 'config' ? 'default' : enabledRes.s;

  const providerName = pickProviderName(cfg, env, flags);
  const pc = PROVIDERS[providerName];

  const modelRes = resolve({
    flag: flags.aiModel, env: envOf(env, 'MORAA_AI_MODEL'),
    config: m.model || shared.model || legacy.model || undefined,
    def: null
  });
  const baseRes = resolve({
    flag: flags.aiBaseUrl, env: envOf(env, 'MORAA_AI_BASE_URL'),
    config: m.baseUrl || shared.baseUrl || legacy.baseUrl || undefined,
    def: null
  });
  const keyRes = resolveKey(providerName, cfg, env, flags);

  const problems = [];
  let provider = providerName;
  let configured = true;

  if (!enabledValue) {
    configured = false; // OFF — nothing to configure, nothing to check
  } else if (provider === 'none' || provider === 'auto') {
    // Auto: exactly one provider with a key present may be implied. Never guess between two.
    const withKeys = ['anthropic', 'openai', 'zai'].filter(p =>
      (cfg.keys && cfg.keys[p]) || envOf(env, PROVIDERS[p].env) ||
      (p === providerName && keyRes.key));
    const explicitLocal = provider === 'local' || (cfg.keys && cfg.keys.local) || baseRes.value;
    if (provider === 'none') {
      problems.push('provider is "none": AI is hard-disabled for this mode regardless of keys.');
      configured = false;
    } else if (withKeys.length === 1) {
      provider = withKeys[0];
    } else if (withKeys.length > 1) {
      problems.push(`provider is "auto" but several provider keys are present (${withKeys.join(', ')}). ` +
        'Set ai.provider to exactly one of: anthropic | openai | zai | local.');
      configured = false;
    } else if (providerName === 'local' || explicitLocal) {
      provider = 'local';
    } else {
      problems.push('no API key found. Keys are read from MORAA_AI_API_KEY, or a provider-specific ' +
        'env var (ANTHROPIC_API_KEY / OPENAI_API_KEY / ZAI_API_KEY), or config keys.* — in that ' +
        'order after any CLI flag.');
      configured = false;
    }
  }

  const effProvider = PROVIDERS[provider] ? provider : 'auto';
  const effPc = PROVIDERS[effProvider] || {};
  let effKey = keyRes.key;
  let effKeySource = keyRes.source;
  if (provider !== providerName) { // auto resolved to a concrete provider; re-resolve its key
    const r2 = resolveKey(provider, cfg, env, flags);
    effKey = r2.key; effKeySource = r2.source;
  }

  if (enabledValue && configured && effProvider !== 'none') {
    if (!effKey && !effPc.keyOptional) {
      problems.push(`provider "${effProvider}" needs a key (env ${effPc.env || 'MORAA_AI_API_KEY'} or config keys.${effProvider}); none found.`);
      configured = false;
    }
    const baseUrl = baseRes.value || effPc.base || null;
    if (!baseUrl) {
      problems.push(`provider "${effProvider}" has no baseUrl (set ai.baseUrl for a local OpenAI-compatible endpoint).`);
      configured = false;
    }
    if (effKey && /[\s'"]/.test(effKey)) {
      problems.push('the configured key contains whitespace or quotes; it was probably pasted with extras.');
      configured = false;
    }
  }

  return {
    mode,
    enabled: enabledValue,
    enabledSource,
    enabledSourceValue: enabledRes.v,
    configured,
    provider: configured ? effProvider : providerName,
    providerLabel: (PROVIDERS[configured ? effProvider : providerName] || {}).label || providerName,
    model: modelRes.value || (PROVIDERS[effProvider] || {}).model || null,
    baseUrl: baseRes.value || (PROVIDERS[effProvider] || {}).base || null,
    key: effKey,
    keyShown: effKey ? R.redact(effKey) : null,
    keySource: effKeySource,
    timeoutMs: Number(m.timeoutMs || shared.timeoutMs || DEFAULTS.ai.timeoutMs),
    maxTokens: Number(m.maxTokens || shared.maxTokens || DEFAULTS.ai.maxTokens),
    severityThreshold: normSeverity(m.severityThreshold, 'LOW'),
    // mode 1 knobs
    contextLines: Number(m.contextLines || DEFAULTS.ai.report.contextLines),
    maxFindings: Number(m.maxFindings || DEFAULTS.ai.report.maxFindings),
    // mode 2 knobs
    maxFiles: Number(m.maxFiles || legacy.maxFiles || DEFAULTS.ai.review.maxFiles),
    maxBytesPerFile: Number(m.maxBytesPerFile || legacy.maxBytesPerFile || DEFAULTS.ai.review.maxBytesPerFile),
    problems
  };
}

/** Resolve BOTH AI modes. `config` may be the already-loaded object or undefined. */
function resolveAi({ config, env, flags, configPath, sourcePath, found: foundIn } = {}) {
  const loaded = config
    ? { config: deepMerge(DEFAULTS, config), path: config._path || null,
        found: foundIn !== undefined ? !!foundIn : true, warnings: [] }
    : loadConfig({ configPath, sourcePath, env, flags });
  const e = env || process.env;
  const f = flags || {};
  const report = resolveMode('report', loaded.config, e, f, loaded.found);
  const review = resolveMode('review', loaded.config, e, f, loaded.found);
  return {
    configFile: loaded.path,
    warnings: loaded.warnings || [],
    report, review,
    bothOff: !report.enabled && !review.enabled,
    anyEnabled: report.enabled || review.enabled,
    anyConfigured: (report.enabled && report.configured) || (review.enabled && review.configured)
  };
}

// ------------------------------------------------------------------ config-check

function integrationStatus(id, label, kind, { needed, present, note, enabled }) {
  return {
    id, label, kind,
    needed,                      // 'key' | 'none' | 'config'
    configured: !!present,
    enabled: enabled !== false,
    detail: note,
    redactedHint: null
  };
}

/**
 * Which integrations are configured vs missing — WITHOUT revealing any value.
 * Returns a structured report; printCheck() renders it terminal-safely.
 */
function checkConfig(opts = {}) {
  const env = opts.env || process.env;
  const flags = opts.flags || {};
  const loaded = opts.config
    ? { config: deepMerge(DEFAULTS, opts.config), path: opts.config._path || null, found: true, warnings: [] }
    : loadConfig({ configPath: opts.configPath, sourcePath: opts.sourcePath, env, flags });
  const cfg = loaded.config;
  const ai = resolveAi({ config: cfg, env, flags, found: loaded.found });
  const keys = cfg.keys || {};
  const repoRoot = path.join(__dirname, '..', '..');

  const integrations = [];

  // --- the two AI modes (opt-in) ---
  for (const m of [ai.report, ai.review]) {
    integrations.push({
      id: `ai.${m.mode}`, label: `AI mode "${m.mode}" (${m.mode === 'report' ? 'enrich existing report' : 'direct code review'})`,
      kind: 'ai',
      enabled: m.enabled, enabledSource: m.enabledSource,
      configured: m.enabled ? m.configured : false,
      detail: !m.enabled
        ? `OFF by design (opt-in). Currently off via: ${m.enabledSource}. To enable: --ai-${m.mode}, MORAA_AI_${m.mode.toUpperCase()}=1, or ai.${m.mode}.enabled=true`
        : (m.configured
          ? `provider=${m.provider}, model=${m.model || '(provider default)'}, key=${m.keyShown || '(none needed)'} [${m.keySource}]`
          : m.problems.join(' ')),
      problems: m.problems
    });
  }

  // --- deterministic scanners: key/config presence only (binary presence is detect()'s job) ---
  const snykKey = envOf(env, 'SNYK_TOKEN') || keys.snyk || null;
  integrations.push(integrationStatus('snyk', 'Snyk (dependency)', 'dependency', {
    needed: 'key', present: !!snykKey,
    note: snykKey ? `SNYK_TOKEN/keys.snyk set (${R.redact(snykKey)})` : 'missing: SNYK_TOKEN (env) or keys.snyk (config)'
  }));
  const sonarKey = envOf(env, 'SONAR_TOKEN') || keys.sonar || null;
  const sonarHost = envOf(env, 'SONAR_HOST_URL') || (cfg.endpoints && cfg.endpoints.sonarqube && cfg.endpoints.sonarqube.hostUrl) || null;
  integrations.push(integrationStatus('sonarqube', 'SonarQube (quality)', 'quality', {
    needed: 'config', present: !!sonarHost,
    note: `host ${sonarHost ? 'set' : 'missing (SONAR_HOST_URL or endpoints.sonarqube.hostUrl)'}, token ${sonarKey ? 'set (' + R.redact(sonarKey) + ')' : 'optional for offline mode'}`
  }));
  const gitleaksCfg = (cfg.tools && cfg.tools.gitleaks && cfg.tools.gitleaks.config) || 'rules/gitleaks/dotnet-config.toml';
  const gitleaksOk = fs.existsSync(path.join(repoRoot, gitleaksCfg));
  integrations.push(integrationStatus('gitleaks', 'gitleaks (secret)', 'secret', {
    needed: 'config', present: gitleaksOk, enabled: (cfg.tools && cfg.tools.gitleaks && cfg.tools.gitleaks.enabled) !== false,
    note: gitleaksOk ? `ruleset ${gitleaksCfg} present (no key required)` : `ruleset ${gitleaksCfg} NOT FOUND`
  }));
  const semgrepCfg = (cfg.tools && cfg.tools.semgrep && cfg.tools.semgrep.config) || 'rules/semgrep/dotnet-moraa.yaml';
  const semgrepOk = fs.existsSync(path.join(repoRoot, semgrepCfg));
  integrations.push(integrationStatus('semgrep', 'semgrep (sast)', 'sast', {
    needed: 'config', present: semgrepOk, enabled: (cfg.tools && cfg.tools.semgrep && cfg.tools.semgrep.enabled) !== false,
    note: semgrepOk ? `ruleset ${semgrepCfg} present (no key required)` : `ruleset ${semgrepCfg} NOT FOUND`
  }));
  for (const [id, label] of [['trivy', 'Trivy (dependency)'], ['osv-scanner', 'osv-scanner (dependency)'], ['dependency-check', 'OWASP Dependency-Check (dependency)']]) {
    integrations.push(integrationStatus(id, label, 'dependency', {
      needed: 'none', present: true, enabled: (cfg.tools && cfg.tools[id] && cfg.tools[id].enabled) !== false,
      note: 'no key required; availability of the binary is decided by adapter detect()'
    }));
  }

  return {
    configFile: { found: loaded.found, path: loaded.path, redacted: R.redactConfig(loaded.file || {}) },
    warnings: (loaded.warnings || []).concat(ai.warnings || []),
    ai: { report: ai.report, review: ai.review, bothOff: ai.bothOff },
    integrations,
    // Deliberately NOT included: any raw key value. Everything above is redacted or boolean.
  };
}

/** Render a checkConfig() report as terminal-safe text (runs through guard()). */
function printCheck(report) {
  const lines = [];
  lines.push('moraa config check');
  lines.push(`  config file : ${report.configFile.found ? report.configFile.path : 'none found (defaults in force)'}`);
  for (const w of report.warnings) lines.push(`  WARNING     : ${R.scrub(w)}`);
  lines.push('');
  lines.push('  AI modes (both default OFF; enabling either transmits source/code context to an API)');
  for (const i of report.integrations.filter(x => x.kind === 'ai')) {
    lines.push(`    [${i.enabled ? (i.configured ? 'READY    ' : 'MISSING  ') : 'OFF      '}] ${i.label}`);
    lines.push(`               ${R.scrub(i.detail || '')}`);
    for (const p of i.problems || []) lines.push(`               ! ${R.scrub(p)}`);
  }
  lines.push('');
  lines.push('  Other integrations');
  for (const i of report.integrations.filter(x => x.kind !== 'ai')) {
    const st = !i.enabled ? 'DISABLED ' : (i.configured ? 'READY    ' : 'MISSING  ');
    lines.push(`    [${st}] ${i.label} — ${R.scrub(i.detail || '')}`);
  }
  lines.push('');
  lines.push('  Precedence: CLI flag > environment variable > moraa.config.json > built-in default.');
  lines.push('  No secret values are shown by design — keys display as their last 4 characters only.');
  return R.guard(lines.join('\n'), 'config-check output');
}

/** CLI entry: `node src/config/index.js [--config <path>]`. Prints the check; exit 0 always. */
function main(argv = process.argv.slice(2)) {
  const i = argv.indexOf('--config');
  const configPath = i >= 0 ? argv[i + 1] : undefined;
  const report = checkConfig({ configPath, env: process.env, flags: {} });
  console.log(printCheck(report));
  return report;
}

if (require.main === module) main();

module.exports = {
  CONFIG_FILENAME, DEFAULTS, PROVIDERS,
  loadConfig, resolve, resolveAi, resolveKey, resolveMode,
  checkConfig, printCheck, main,
  // secrets discipline re-exports: one import site for every consumer
  redact: R.redact, scrub: R.scrub, guard: R.guard,
  guardedWriteFile: R.guardedWriteFile, redactConfig: R.redactConfig, isKeyShaped: R.isKeyShaped
};
