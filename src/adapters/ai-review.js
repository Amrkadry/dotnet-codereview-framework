'use strict';
/**
 * AI-assisted review adapter — TWO INDEPENDENT OPT-IN MODES.
 *
 * GOVERNING RULE (holds in BOTH modes): no tool is authoritative, INCLUDING the AI. An AI finding
 * NEVER silently overrides, suppresses or outranks a tool finding. Where the AI disagrees with a
 * tool, the disagreement is RECORDED on the finding (sources[].status CONTRADICTED, notes,
 * verification.openQuestion) and left UNRESOLVED for a human. AI findings are capped at
 * confidence POSSIBLE, receive no CVSS from the model, and are marked UNVERIFIED.
 *
 * MODE 1 — "report" (post-processing; entry point runReport)
 *   Input : an ALREADY-PRODUCED review — the Markdown projection (Findings/*.md pages or any
 *           Markdown whose sections carry finding ids) plus data/report.json, and, for each
 *           finding, the CODE SNIPPET read from the source file at that finding's line with
 *           context (ai.report.contextLines).
 *   Output: a per-finding narrative (what the issue is, the risk in context, the fix), written
 *           INTO the finding's own Markdown section. No separate parallel document is emitted.
 *   IDEMPOTENCY: AI-authored content is wrapped in stable markers
 *           `<!-- moraa:ai-report:v1 START id=<findingId> -->` … `END` and is REPLACED WHOLE on
 *           re-run — never appended, never nested. If the regenerated block is byte-identical,
 *           the file is not touched at all.
 *   The canonical JSON stays the source of truth; this mode edits only the Markdown projection.
 *
 * MODE 2 — "review" (direct code review; the adapter contract entry points detect/run)
 *   The AI reads selected source files directly and produces findings attributed to tool
 *   'ai-review'. They enter the SAME canonical model and correlate like any other tool's
 *   findings. If prior canonical findings are supplied (ctx.priorFindings), crossCheck() records
 *   agreements and disagreements explicitly — never a silent override.
 *
 * BOTH MODES DEFAULT TO OFF. With both off, nothing AI-related runs and NO API key is required
 * anywhere: detect() reports unavailable, run() returns NOT_APPLICABLE with zero findings, and
 * runReport() returns {skipped:true} without touching the network or the filesystem.
 *
 * CONFIG — see src/config/. One moraa.config.json holds keys, endpoints, enabled flags and
 * thresholds. Precedence everywhere: CLI flag > environment variable > config file > default.
 * Providers: anthropic | openai | zai | local (any OpenAI-compatible baseUrl) | none, defaulting
 * to none/auto. SECRETS: keys are never logged, never written raw, never echoed in verbose mode;
 * every output path runs through the guard in src/config/redact.js.
 *
 * DEGRADATION: missing key -> NOT_AVAILABLE with enable instructions; network failure, HTTP
 * error or rate limit -> FAILED with a clear scrubbed message. This adapter never throws and
 * never emits a spurious pass: a status other than EXECUTED never carries findings.
 */

const fs = require('fs');
const path = require('path');
const https = require('https');
const http = require('http');
const C = require('../core/adapter-contract');
const cfg = require('../config');
const R = require('../config/redact');

const ID = 'ai-review';

// ------------------------------------------------------------------ transport (stdlib only)

/** POST JSON over node:https/node:http. No dependencies, no fetch polyfills. */
function postJson(urlStr, headers, payload, timeoutMs) {
  return new Promise((resolve, reject) => {
    let u;
    try { u = new URL(urlStr); } catch (e) { return reject(new Error(`bad URL: ${R.scrub(e.message)}`)); }
    const mod = u.protocol === 'http:' ? http : https;
    const body = JSON.stringify(payload);
    const req = mod.request({
      hostname: u.hostname, port: u.port || (u.protocol === 'http:' ? 80 : 443),
      path: u.pathname + u.search, method: 'POST',
      headers: Object.assign({
        'content-type': 'application/json', 'content-length': Buffer.byteLength(body)
      }, headers)
    }, res => {
      let data = '';
      res.on('data', d => { data += d; });
      res.on('end', () => resolve({ statusCode: res.statusCode, headers: res.headers, body: data }));
    });
    req.on('error', reject);
    req.setTimeout(timeoutMs || 180000, () => req.destroy(new Error('AI request timed out')));
    req.write(body); req.end();
  });
}

/** Classified provider failure — never a crash, never a spurious pass. */
class AiError extends Error {
  constructor(kind, message, extra = {}) { super(message); this.kind = kind; Object.assign(this, extra); }
}

/** Join a base URL and an API path without doubling segments. */
function joinUrl(base, apiPath) {
  let b = String(base || '').replace(/\/+$/, '');
  if (/\/(chat\/completions|messages)$/.test(b)) return b;          // caller configured the full URL
  if (/\/paas\/v4$/.test(b) && apiPath.startsWith('/v1/')) apiPath = apiPath.slice(3); // z.ai style
  return b + apiPath;
}

/**
 * One provider call. Settings come pre-resolved from the config layer (provider/model/baseUrl/
 * key/timeout/maxTokens). Throws ONLY classified AiError; every message is scrubbed.
 */
async function callProvider(s, system, user) {
  if (!s || !s.provider || s.provider === 'none' || s.provider === 'auto') {
    throw new AiError('config', 'no AI provider is configured (set ai.provider or a provider key).');
  }
  const api = cfg.PROVIDERS[s.provider] && cfg.PROVIDERS[s.provider].api;
  const url = joinUrl(s.baseUrl, api === 'messages' ? '/v1/messages' : '/v1/chat/completions');
  const headers = {};
  if (s.key) {
    if (api === 'messages') { headers['x-api-key'] = s.key; headers['anthropic-version'] = '2023-06-01'; }
    else headers.authorization = `Bearer ${s.key}`;
  }
  const payload = api === 'messages'
    ? { model: s.model, max_tokens: s.maxTokens, system, messages: [{ role: 'user', content: user }] }
    : { model: s.model, max_tokens: s.maxTokens,
        messages: [{ role: 'system', content: system }, { role: 'user', content: user }] };

  let resp;
  try {
    resp = await postJson(url, headers, payload, s.timeoutMs);
  } catch (e) {
    throw new AiError('network', `AI request failed: ${R.scrub(e.message)}`);
  }
  if (resp.statusCode === 429) {
    const ra = resp.headers && (resp.headers['retry-after'] || resp.headers['Retry-After']);
    throw new AiError('rate-limited',
      `AI provider rate-limited the request (HTTP 429)${ra ? `; retry after ${R.scrub(String(ra))}s` : ''}. ` +
      'No AI analysis was produced; the rest of the pipeline is unaffected.',
      { statusCode: 429 });
  }
  if (resp.statusCode === 401 || resp.statusCode === 403) {
    throw new AiError('auth', `AI provider rejected the credential (HTTP ${resp.statusCode}). ` +
      'Check the key — display form ' + (s.keyShown || '(none)') + '.');
  }
  if (resp.statusCode < 200 || resp.statusCode >= 300) {
    throw new AiError('http', `AI provider returned HTTP ${resp.statusCode}: ${R.scrub(resp.body).slice(0, 300)}`,
      { statusCode: resp.statusCode });
  }
  return resp.body;
}

// ------------------------------------------------------------------ prompts

const REVIEW_SYSTEM = `You are a .NET application security reviewer. You are given source files from one
application. Report ONLY defects you can point at in the supplied code.

Hard rules:
- Never invent a file path, line number or code snippet. Quote the code verbatim.
- If you are unsure a defect is real, omit it. A short accurate list beats a long speculative one.
- Do NOT report generic advice, style opinions, or anything you cannot tie to a specific line.
- Focus on what static analysers miss: missing authorization, broken access control, ownership
  checks, trust-boundary errors, unsafe configuration wiring, logic that fails open.
- You are ONE tool among several. Your findings will be correlated with deterministic tools and
  you have no authority over them. Report your own reading; do not assume another tool is wrong.

Reply with ONLY a JSON array, no prose, no markdown fence. Each element:
{
  "title": "short specific title",
  "file": "path exactly as given to you",
  "startLine": 123,
  "category": "security|configuration|reliability|code-quality|architecture",
  "severity": "CRITICAL|HIGH|MEDIUM|LOW",
  "cwe": ["CWE-862"],
  "snippet": "verbatim code, max 12 lines",
  "problem": "what is wrong",
  "impact": "what an attacker or a failure achieves, in this application",
  "recommendation": "concrete fix"
}
Return [] if you find nothing you can evidence.`;

const NARRATIVE_SYSTEM = `You are a .NET code reviewer writing ONE narrative for ONE already-recorded
finding. You are given the finding's metadata and the actual code around its location.

Write for a developer who owns this file. Explain the issue in the concrete code shown, the risk
IN THIS CONTEXT (not in the abstract), and a concrete fix. You may quote short fragments of the
supplied snippet, but never invent code you were not shown.

You are ONE voice among several tools. You have NO authority: you cannot remove, downgrade or
reclassify the finding. If you believe the recorded severity or the finding itself is wrong, say
so ONLY in the "disagreement" field — it will be recorded as an unresolved disagreement, never
applied. Do not repeat the disagreement in the other fields.

Reply with ONLY a JSON object, no prose, no markdown fence:
{
  "explanation": "what the issue is, grounded in the shown code, 1-3 sentences",
  "risk": "the risk in this application's context, 1-3 sentences",
  "fix": "the concrete fix, 1-3 sentences",
  "disagreement": null
}
"disagreement" is null, or ONE short paragraph: what you disagree with (severity label, exploit
assumption, or the finding itself) and why. Return valid JSON only.`;

// ------------------------------------------------------------------ adapter contract

/** Config resolution for this adapter. Never logs; keys travel inside the returned object only. */
function aiSettings(ctx) {
  return cfg.resolveAi({
    config: ctx.config, env: ctx.env || process.env, flags: ctx.flags || {},
    configPath: ctx.configPath, sourcePath: ctx.sourcePath
  });
}

/**
 * detect(): can EITHER mode run here? Both modes off -> unavailable (this is the honest default).
 * Never throws; never reveals key values.
 */
function detect(ctx) {
  let s;
  try { s = aiSettings(ctx); } catch (e) {
    return { available: false, reason: `AI review disabled: config error: ${R.scrub(e.message)}` };
  }
  if (s.bothOff) {
    return {
      available: false,
      reason: 'AI review is OPT-IN and both modes are OFF. Mode "report" enriches an existing ' +
        'report in place; mode "review" produces findings as one more tool. Enable with ' +
        'ai.report.enabled / ai.review.enabled in moraa.config.json, --ai-report / --ai-review, ' +
        'or MORAA_AI_REPORT / MORAA_AI_REVIEW. Nothing AI-related runs while both are off.'
    };
  }
  const parts = [];
  for (const m of [s.report, s.review]) {
    if (!m.enabled) { parts.push(`${m.mode}: OFF`); continue; }
    parts.push(m.configured
      ? `${m.mode}: ${m.provider}${m.model ? ':' + m.model : ''} (key ${m.keyShown || 'not needed'})`
      : `${m.mode}: ENABLED BUT NOT CONFIGURED — ${m.problems.join(' ')}`);
  }
  const anyOk = (s.report.enabled && s.report.configured) || (s.review.enabled && s.review.configured);
  return {
    available: anyOk,
    version: parts.join(' | '),
    reason: anyOk ? undefined : 'Every enabled AI mode is missing configuration; see the breakdown.',
    command: 'node src/config/index.js  (config-check: shows what is configured vs missing, values redacted)'
  };
}

/**
 * MODE 2 — direct code review. Returns a contract-valid RunResult. Never throws.
 * ctx: { sourcePath, outPath, config, env, flags, log, priorFindings?, toolsThatRan? }
 */
async function run(ctx) {
  let s;
  try { s = aiSettings(ctx); } catch (e) {
    return C.failed(ID, `config error: ${R.scrub(e.message)}`);
  }

  if (!s.review.enabled) {
    return {
      status: 'NOT_APPLICABLE', tool: ID, findings: [],
      notes: 'AI review mode "review" (direct code review) is OFF — it is opt-in because it ' +
        (s.report.enabled
          ? 'transmits source code to an API. Mode "report" is enabled and runs as report ' +
            'post-processing AFTER this vault is written (ai-review adapter .runReport()).'
          : 'transmits source code to a third-party API. Enable with ai.review.enabled.'),
      limitations: 'No AI-assisted review was performed. Deterministic tools do not cover ' +
        'design-level access control, so that class may be under-represented in this report.',
      remediation: 'set ai.review.enabled=true (or --ai-review / MORAA_AI_REVIEW=1) and provide a key'
    };
  }
  if (!s.review.configured) {
    return {
      status: 'NOT_AVAILABLE', tool: ID, findings: [], notes: s.review.problems.join(' '),
      limitations: `No results were obtained from ${ID}. This is NOT a clean result.`,
      remediation: 'node src/config/index.js  (see what is missing; values are redacted)'
    };
  }

  const sM = s.review;
  const files = selectFiles(ctx, sM);
  if (!files.length) return C.failed(ID, 'No reviewable source files were found under the source path.');

  const bundle = files.map(f => {
    const rel = path.relative(ctx.sourcePath, f).replace(/\\/g, '/');
    let text = '';
    try { text = fs.readFileSync(f, 'utf8'); } catch { return null; }
    const numbered = text.split('\n').map((l, i) => `${i + 1}: ${l}`).join('\n');
    return `===== FILE: ${rel} =====\n${numbered}`;
  }).filter(Boolean).join('\n\n');

  // Transparency: say what is being transmitted, without transmitting anything unexpected.
  const log = ctx.log || (() => {});
  log(`  ${ID}: mode "review" — sending ${files.length} file(s), ` +
    `${(bundle.length / 1024).toFixed(0)} KB to ${sM.providerLabel} (${sM.model}). Source code leaves this machine.`);

  const started = Date.now();
  let body;
  try {
    body = await callProvider(sM, REVIEW_SYSTEM, bundle);
  } catch (e) {
    const kindNote = e.kind === 'rate-limited' ? ' (transient — the pipeline continues without AI findings)'
      : e.kind === 'network' ? ' (the pipeline continues without AI findings)' : '';
    return C.failed(ID, `${R.scrub(e.message)}${kindNote}`, { durationMs: Date.now() - started });
  }

  // Persist a SCRUBBED copy for auditability — the guard runs on this write path too.
  let rawPath;
  try {
    rawPath = path.join(ctx.outPath, 'raw', 'ai-review.json');
    R.guardedWriteFile(rawPath, R.scrub(typeof body === 'string' ? body : JSON.stringify(body)));
  } catch (e) {
    return C.failed(ID, `could not persist raw AI output: ${R.scrub(e.message)}`, { durationMs: Date.now() - started });
  }

  let findings;
  try {
    findings = parse(body, ctx);
  } catch (e) {
    return C.failed(ID, 'AI response could not be parsed: ' + R.scrub(e.message), { rawPath });
  }

  // GOVERNING RULE: record agreement/disagreement against prior canonical findings — never resolve.
  let disagreements = 0;
  if (Array.isArray(ctx.priorFindings) && ctx.priorFindings.length) {
    const cc = crossCheck(findings, ctx.priorFindings, ctx.toolsThatRan || []);
    findings = cc.findings;
    disagreements = cc.disagreements;
  }

  return {
    status: 'EXECUTED', tool: ID, version: `${sM.provider}:${sM.model}`,
    command: `POST ${joinUrl(sM.baseUrl, '')} (provider=${sM.provider}, model=${sM.model}, ${files.length} files)`,
    exitCode: 0, durationMs: Date.now() - started, rawPath, findings,
    notes: `AI review of ${files.length} file(s) produced ${findings.length} candidate finding(s)` +
      (disagreements ? `, including ${disagreements} recorded disagreement(s) with other tools' findings` : '') +
      '. All are capped at confidence POSSIBLE and carry no CVSS: they require confirmation before ' +
      'being treated as established. They correlate like any other tool\u2019s findings and never override them.',
    limitations: 'A model can be confidently wrong. Findings here are leads, not conclusions, and ' +
      'only the files listed in the command were reviewed — this is not whole-repository coverage.'
  };
}

/** Choose the highest-value files to review, within a budget. */
function selectFiles(ctx, sM) {
  const maxFiles = sM.maxFiles || 12;
  const maxBytes = sM.maxBytesPerFile || 60000;
  // Priority: auth, authorization, config wiring, data access, then controllers.
  const PRIORITY = [
    /auth/i, /identity|login|token|jwt|principal/i, /startup|global\.asax|program\.cs/i,
    /config/i, /middleware|filter|handler/i, /repositor|dataaccess|dbcontext/i,
    /controller/i, /service/i
  ];
  const out = [];
  const walk = dir => {
    let entries = [];
    try { entries = fs.readdirSync(dir, { withFileTypes: true }); } catch { return; }
    for (const e of entries) {
      const full = path.join(dir, e.name);
      if (e.isDirectory()) {
        if (/^(bin|obj|packages|node_modules|\.git|\.vs|\.moraa-review|\.sonarqube)$/i.test(e.name)) continue;
        walk(full);
      } else if (/\.(cs|config|json)$/i.test(e.name)) {
        let size = 0;
        try { size = fs.statSync(full).size; } catch { continue; }
        if (size > maxBytes || size === 0) continue;
        out.push(full);
      }
    }
  };
  walk(ctx.sourcePath);

  const score = f => {
    const rel = f.replace(/\\/g, '/');
    for (let i = 0; i < PRIORITY.length; i++) if (PRIORITY[i].test(rel)) return i;
    return PRIORITY.length;
  };
  return out.sort((a, b) => score(a) - score(b)).slice(0, maxFiles);
}

/** Pure. Extracts the JSON array from a provider response of either shape. */
function parse(raw, ctx) {
  if (!raw) return [];
  let doc;
  try { doc = typeof raw === 'string' ? JSON.parse(raw) : raw; } catch { return []; }
  if (!doc || typeof doc !== 'object') return [];

  // Pull the assistant text out of either provider envelope.
  let text = '';
  if (Array.isArray(doc.content)) {
    text = doc.content.map(c => (c && c.text) || '').join('\n');           // anthropic
  } else if (Array.isArray(doc.choices)) {
    text = doc.choices.map(c => (c.message && c.message.content) || '').join('\n'); // openai-compatible
  } else if (Array.isArray(doc)) {
    text = JSON.stringify(doc);                                            // already the array
  } else return [];

  if (!text.trim()) return [];
  // Tolerate a fenced block or leading prose.
  const m = text.match(/\[[\s\S]*\]/);
  if (!m) return [];
  let items;
  try { items = JSON.parse(m[0]); } catch { return []; }
  if (!Array.isArray(items)) return [];

  const allowedCat = ['security', 'configuration', 'reliability', 'code-quality', 'architecture'];
  const out = [];
  for (const it of items) {
    if (!it || typeof it !== 'object' || !it.title || !it.file) continue;
    const category = allowedCat.includes(it.category) ? it.category : 'security';
    out.push({
      title: String(it.title).slice(0, 200),
      category,
      subcategory: 'ai-review',
      severity: C.normaliseSeverity(it.severity, 'MEDIUM'),
      // Capped deliberately: a model's assertion is a lead.
      confidence: 'POSSIBLE',
      cvss: null,
      cwe: Array.isArray(it.cwe) ? it.cwe.filter(c => /^CWE-\d+$/.test(c)) : undefined,
      location: {
        file: String(it.file).replace(/\\/g, '/'),
        startLine: Number.isInteger(it.startLine) ? it.startLine : undefined
      },
      evidence: {
        snippet: R.scrub(String(it.snippet || '')).split('\n').slice(0, 12).join('\n'),
        language: 'csharp',
        toolOutput: 'ai-review: model-proposed finding, unconfirmed'
      },
      problem: R.scrub(String(it.problem || '')),
      impact: R.scrub(String(it.impact || '')),
      recommendation: R.scrub(String(it.recommendation || '')),
      detection: { class: 'AI_ASSISTED', rules: [] },
      sources: [{
        tool: ID, status: 'REPORTED',
        note: 'AI-proposed; requires human or deterministic confirmation. Never overrides a tool finding.'
      }],
      status: 'UNVERIFIED',
      verification: {
        method: 'Proposed by an AI review of the file contents.',
        outcome: 'UNVERIFIED',
        openQuestion: 'Confirm against the code before acting. AI findings are leads, not conclusions.'
      }
    });
  }
  return out;
}

// ------------------------------------------------------------------ governing-rule machinery

const SEV_RANK = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3, INFO: 4 };
const normPath = p => String(p || '').replace(/\\/g, '/').replace(/^\.\//, '').toLowerCase();
const LINE_WINDOW = 4;

/**
 * PURE. Cross-check AI findings against prior canonical findings.
 * Agreement is noted; disagreement is RECORDED (sources[].status 'CONTRADICTED' +
 * verification.openQuestion) and NEVER resolved by editing severities or dropping either side.
 * @returns {findings, agreements, disagreements}
 */
function crossCheck(aiFindings, priorFindings, toolsThatRan = []) {
  const prior = JSON.parse(JSON.stringify(priorFindings || []));
  const findings = JSON.parse(JSON.stringify(aiFindings || []));
  let agreements = 0, disagreements = 0;

  for (const f of findings) {
    const file = normPath(f.location && f.location.file);
    const line = (f.location && f.location.startLine) || 0;
    const cwes = new Set(f.cwe || []);
    const matches = prior.filter(p => {
      if (normPath(p.location && p.location.file) !== file) return false;
      const pl = (p.location && p.location.startLine) || 0;
      if (pl && line && Math.abs(pl - line) <= LINE_WINDOW) return true;
      return (p.cwe || []).some(c => cwes.has(c));
    });
    const aiSrc = (f.sources || []).find(s => s.tool === ID);
    if (!matches.length) {
      const othersHere = toolsThatRan.filter(t => t !== ID);
      if (aiSrc) aiSrc.note += othersHere.length
        ? ' No other tool reported this location; a miss is not evidence of absence — AI-only lead.'
        : ' AI-only lead; no other tool data available for this location.';
      continue;
    }
    // Strongest tool severity among co-located findings is the position we compare against.
    const counterpart = matches.slice().sort((a, b) => SEV_RANK[a.severity] - SEV_RANK[b.severity])[0];
    const otherTools = [...new Set((counterpart.sources || [])
      .map(s => s.tool).filter(t => t && t !== ID))];
    const theirSeverity = counterpart.severity;
    if (theirSeverity === f.severity) {
      agreements++;
      if (aiSrc) aiSrc.note += ` Independent AI read agrees with the recorded severity (${theirSeverity}) of ${otherTools.join(', ') || 'the correlated finding'}.`;
    } else {
      disagreements++;
      const note = `ai-review disagrees with ${otherTools.join(', ') || 'the correlated finding'} on severity: ` +
        `tool(s) say ${theirSeverity} at ${counterpart.location.file}:${counterpart.location.startLine || '?'}, ` +
        `ai-review assesses ${f.severity}. Disagreement RECORDED, NOT resolved — no tool is authoritative, ` +
        'including the AI; a human decides.';
      (f.sources = f.sources || []).push({
        tool: otherTools[0] || 'correlated-finding', status: 'CONTRADICTED', note
      });
      f.verification = f.verification || {};
      f.verification.openQuestion = [f.verification.openQuestion, `Unresolved severity disagreement: ${note}`]
        .filter(Boolean).join(' ');
    }
  }
  return { findings, agreements, disagreements };
}

// ------------------------------------------------------------------ MODE 1 — report

const MARK = 'moraa:ai-report:v1';
const escRe = s => String(s).replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

/** Regex matching THIS finding's complete, exactly-addressed marker block. */
const AI_TEMPLATE_HEADER = '## AI narrative — ai-report mode';

/**
 * Locate THIS finding's marker region with BOUNDARY AWARENESS.
 * The region is ours only if NO other START marker sits between our START and the END — a lazy
 * regex alone would happily consume a neighbouring finding's block once our own END is lost.
 * Returns {start, end, torn:false} | {start, torn:true} | null (no START for this id).
 */
function blockRegion(text, id) {
  const sm = text.match(new RegExp(`<!--\\s*${MARK} START\\s+id=${escRe(id)}\\s*-->`));
  if (!sm) return null;
  const after = text.slice(sm.index);
  const em = after.match(new RegExp(`<!--\\s*${MARK} END\\s*-->`));
  if (!em) return { start: sm.index, torn: true };
  // Search for a SECOND START only AFTER our own marker (inner begins with it).
  const inner = after.slice(sm[0].length, em.index);
  if (new RegExp(`<!--\\s*${MARK} START`).test(inner)) return { start: sm.index, torn: true };
  return { start: sm.index, end: sm.index + em.index + em[0].length, torn: false };
}

/** Neutralise any marker the model echoed, so blocks can never nest. */
const neutraliseMarkers = t => String(t == null ? '' : t)
  .replace(new RegExp(`${MARK}`, 'g'), 'moraa:ai-report(MARKER-NEUTRALISED)');

/** How many complete marker blocks does this document hold? */
const countBlocks = md => (String(md).match(new RegExp(`<!--\\s*${MARK} START`, 'g')) || []).length;

/**
 * Insert-or-replace one finding's AI block inside a Markdown document.
 *
 * Replacement scope is DELIBERATELY conservative — non-AI content must never be destroyed:
 *   1. an exactly-addressed block (`START id=<findingId>` … `END`) is REPLACED in place;
 *   2. one legacy id-less block is upgraded (at most one may exist);
 *   3. a TORN block (an orphan START whose region runs to EOF and carries our template header —
 *      the realistic crash-mid-write shape, where everything after the cut is already gone from
 *      disk) is dropped and freshly inserted;
 *   4. an orphan START with content/marker AFTER it is ambiguous — the bytes between could be
 *      another finding's section — so the finding is REFUSED with a clear reason instead of
 *      guessing. Nothing is deleted; a human or a fresh `moraa review` regeneration resolves it.
 * Otherwise the block is inserted at the END of the finding's own section (the next heading of
 * the same or higher level), or appended at EOF when no section heading carries the id.
 * Returns {text, replaced, refused?}.
 */
function upsertBlock(md, id, block) {
  let text = String(md);

  // 1. intact, exactly-addressed region -> replace it, byte-surgical, nothing else touched.
  const region = blockRegion(text, id);
  if (region && !region.torn) {
    return { text: text.slice(0, region.start) + block + text.slice(region.end), replaced: true };
  }

  // 3./4. torn START (our END is missing, or an END exists but belongs to a later block).
  if (region && region.torn) {
    const afterStart = text.slice(region.start);
    const endRel = afterStart.search(new RegExp(`<!--\\s*${MARK} END\\s*-->`));
    const reStartAny = new RegExp(`<!--\\s*${MARK} START`, 'g');
    reStartAny.lastIndex = 1;
    const nextStartMatch = reStartAny.exec(afterStart);
    const nextStartRel = nextStartMatch ? nextStartMatch.index : -1;
    const regionText = nextStartRel !== -1 ? afterStart.slice(0, nextStartRel) : afterStart;
    const pureTornToEnd = nextStartRel === -1 && endRel === -1 && regionText.includes(AI_TEMPLATE_HEADER);
    if (pureTornToEnd) {
      // Crash mid-write: everything from the cut is already gone. Drop the partial AI bytes,
      // keep the document, insert the fresh block below.
      text = text.slice(0, region.start).replace(/\s*$/, '\n') + '\n';
    } else {
      return { text, replaced: false, refused:
        `unterminated ${MARK} block for ${id} with content after it — the region between the ` +
        'orphan marker and the next marker cannot be safely attributed (it may hold another ' +
        'finding\u2019s section). Nothing was deleted; fix or remove the orphan marker, or ' +
        'regenerate the report, then re-run.' };
    }
  }

  // 2. legacy id-less block (upgradeable, at most one; boundary-checked like the above).
  const idless = text.match(new RegExp(`<!--\\s*${MARK} START(?!\\s+id=)`));
  if (idless) {
    const after = text.slice(idless.index);
    const em = after.match(new RegExp(`<!--\\s*${MARK} END\\s*-->`));
    const inner = em ? after.slice(0, em.index) : '';
    if (em && !new RegExp(`<!--\\s*${MARK} START`).test(inner)) {
      return { text: text.slice(0, idless.index) + block + text.slice(idless.index + em.index + em[0].length), replaced: true };
    }
  }

  // Find the finding's own section: a heading containing the id.
  const lines = text.split('\n');
  let headIdx = -1, headLevel = 0;
  for (let i = 0; i < lines.length; i++) {
    const m = lines[i].match(/^(#{1,6})\s/);
    if (m && lines[i].includes(id)) { headIdx = i; headLevel = m[1].length; break; }
  }
  if (headIdx >= 0) {
    for (let j = headIdx + 1; j < lines.length; j++) {
      const m = lines[j].match(/^(#{1,6})\s/);
      if (m && m[1].length <= headLevel) {
        const at = lines.slice(0, j).join('\n').replace(/\s*$/, '\n\n');
        return { text: at + block + '\n\n' + lines.slice(j).join('\n'), replaced: false };
      }
    }
  }
  // No section boundary: append at end of file.
  return { text: text.replace(/\s*$/, '\n') + '\n' + block + '\n', replaced: false };
}

/** Pure-ish. Turn the model's reply into a validated narrative. Tolerates fences and prose. */
function narrativeParse(raw) {
  if (raw == null) return null;
  let text = typeof raw === 'string' ? raw : (() => {
    try { // provider envelope -> assistant text
      const doc = raw;
      if (Array.isArray(doc.content)) return doc.content.map(c => (c && c.text) || '').join('\n');
      if (Array.isArray(doc.choices)) return doc.choices.map(c => (c.message && c.message.content) || '').join('\n');
    } catch { /* fall through */ }
    return String(raw);
  })();
  text = String(text).trim();
  if (!text) return null;

  let obj = null;
  const candidates = [text, (text.match(/```(?:json)?\s*([\s\S]*?)```/) || [])[1], (text.match(/\{[\s\S]*\}/) || [])[0]];
  for (const c of candidates) {
    if (!c) continue;
    try {
      const v = JSON.parse(c);
      if (v && typeof v === 'object' && !Array.isArray(v)) { obj = v; break; }
    } catch { /* try next shape */ }
  }
  const clip = (v, n) => R.scrub(String(v == null ? '' : v).trim()).slice(0, n);
  if (obj) {
    return {
      explanation: clip(obj.explanation, 2400),
      risk: clip(obj.risk, 2400),
      fix: clip(obj.fix, 2400),
      disagreement: obj.disagreement == null ? null : clip(obj.disagreement, 1600) || null,
      fromPlainText: false
    };
  }
  // Plain prose fallback: it is the model's own words — keep as the explanation, say so.
  return { explanation: clip(text, 2400), risk: '', fix: '', disagreement: null, fromPlainText: true };
}

function renderNarrativeBlock(finding, n, meta) {
  const L = [];
  L.push(`<!-- ${MARK} START id=${finding.findingId} -->`, '');
  L.push('## AI narrative — ai-report mode (unverified)', '');
  L.push('> [!warning] AI-authored, machine-replaceable block');
  L.push(`> Generated by \`${meta.providerLabel}\` (\`${meta.model}\`) on ${new Date().toISOString().slice(0, 10)}.`);
  L.push('> **No tool is authoritative, including the AI.** This narrative is commentary, not a verdict:');
  L.push('> the canonical record is `data/report.json`, and this ENTIRE block is replaced — not appended —');
  L.push('> on every re-run of ai-report mode.', '');
  L.push('### What the issue is', '', neutraliseMarkers(n.explanation) || '_(the model returned no explanation)_', '');
  L.push('### Why it matters in this code', '', neutraliseMarkers(n.risk) || '_(not supplied)_', '');
  L.push('### How to fix it', '', neutraliseMarkers(n.fix) || '_(not supplied)_', '');
  if (n.disagreement) {
    L.push('### Disagreement with the recorded finding (UNRESOLVED)', '');
    L.push(`> [!question] The AI disputed part of this finding. Recorded, **not** applied — nothing was`, '',
      '> removed, reclassified or re-scored. Decide as a human.', '');
    L.push(neutraliseMarkers(n.disagreement), '');
  }
  if (n.fromPlainText) {
    L.push('_The model reply was plain prose rather than the requested JSON shape; it is reproduced verbatim above._', '');
  }
  L.push(`<!-- ${MARK} END -->`);
  return L.join('\n');
}

/** Read the code snippet at a finding's location, with context lines. */
function snippetFor(sourcePath, relFile, startLine, endLine, contextLines) {
  const tried = [];
  const bases = [sourcePath, path.dirname(sourcePath)].filter(Boolean);
  for (const b of bases) {
    const abs = path.resolve(b, String(relFile || ''));
    tried.push(abs);
    try {
      if (!fs.existsSync(abs)) continue;
      const lines = fs.readFileSync(abs, 'utf8').split('\n');
      const start = Math.max(1, (startLine || 1) - contextLines);
      const end = Math.min(lines.length, (endLine || startLine || 1) + contextLines);
      const text = lines.slice(start - 1, end).map((l, i) => `${start + i}: ${l}`).join('\n');
      return { available: true, file: String(relFile).replace(/\\/g, '/'), from: start, to: end, text: R.scrub(text) };
    } catch { /* try next base */ }
  }
  return { available: false, file: String(relFile).replace(/\\/g, '/'), attempted: tried.map(t => R.scrub(t)) };
}

const severityAtLeast = (sev, threshold) =>
  SEV_RANK[sev] <= SEV_RANK[threshold];

/**
 * MODE 1 — "report": enrich an ALREADY-PRODUCED review, in place.
 *
 * ctx: {
 *   reportDir            the review output folder (contains data/report.json and Findings/*.md)
 *   sourcePath           the reviewed source tree (snippets are read from here)
 *   files?               explicit Markdown files to enrich (overrides Findings/*.md discovery)
 *   config?, env?, flags?  config-layer inputs
 *   aiCall?              async (payload) => rawModelText — INJECTABLE FOR TESTS; when absent the
 *                        real provider is called
 *   log?                 logger (guarded: never prints key material)
 * }
 *
 * Returns a plain result object; NEVER throws. {ok:false, skipped:true} when the mode is off.
 * The canonical data/report.json is read-only here — this mode edits only Markdown.
 */
async function runReport(ctx = {}) {
  const env = ctx.env || process.env;
  const flags = ctx.flags || {};
  const rawLog = ctx.log || (() => {});
  const log = (...a) => rawLog(...a.map(x => (typeof x === 'string' ? R.guard(x, 'ai-report log') : x)));

  let s;
  try { s = aiSettings(ctx); } catch (e) {
    return { ok: false, mode: 'report', error: `config error: ${R.scrub(e.message)}` };
  }
  const sM = s.report;

  // ---- opt-in gates: both must pass before ANY AI-related work happens
  if (!sM.enabled) {
    return { ok: false, mode: 'report', skipped: true,
      reason: 'ai.report.enabled is false — mode "report" is opt-in and defaults to OFF. ' +
        'Enable with ai.report.enabled=true, --ai-report, or MORAA_AI_REPORT=1.' };
  }
  if (!sM.configured) {
    return { ok: false, mode: 'report', skipped: true,
      reason: `mode "report" is enabled but not configured: ${sM.problems.join(' ')} ` +
        'Run `node src/config/index.js` for a redacted status.' };
  }

  try {
    const reportDir = ctx.reportDir ||
      (ctx.sourcePath ? path.join(ctx.sourcePath, (ctx.config && ctx.config.outDir) || '.moraa-review') : null);
    if (!reportDir) return { ok: false, mode: 'report', error: 'no reportDir or sourcePath given.' };

    // ---- input: the ALREADY-PRODUCED canonical output. Never fabricated here.
    const canonicalPath = path.join(reportDir, 'data', 'report.json');
    if (!fs.existsSync(canonicalPath)) {
      return { ok: false, mode: 'report', error:
        `no data/report.json under ${reportDir}. Mode "report" post-processes an EXISTING review ` +
        '(it is a projection pass, not a producer); run `moraa review` first.' };
    }
    const canonical = JSON.parse(fs.readFileSync(canonicalPath, 'utf8'));
    const allFindings = canonical.findings || [];
    if (!allFindings.length) {
      return { ok: true, mode: 'report', enriched: [], unchanged: [], failedFindings: [],
        note: 'the canonical report has zero findings; nothing to enrich.' };
    }

    const threshold = sM.severityThreshold;
    const targets = allFindings
      .filter(f => severityAtLeast(f.severity, threshold))
      .sort((a, b) => SEV_RANK[a.severity] - SEV_RANK[b.severity])
      .slice(0, sM.maxFindings);
    const belowThreshold = allFindings.length - allFindings.filter(f => severityAtLeast(f.severity, threshold)).length;

    // ---- locate each finding's own Markdown section/page
    let pagesById = new Map();
    if (Array.isArray(ctx.files) && ctx.files.length) {
      for (const file of ctx.files) {
        const t = fs.readFileSync(file, 'utf8');
        for (const f of targets) if (t.includes(f.findingId)) pagesById.set(f.findingId, file);
      }
    } else {
      const dir = path.join(reportDir, 'Findings');
      if (fs.existsSync(dir)) {
        for (const e of fs.readdirSync(dir)) {
          if (!e.endsWith('.md')) continue;
          const full = path.join(dir, e);
          const hit = targets.find(f => e.startsWith(f.findingId));
          if (hit) pagesById.set(hit.findingId, full);
        }
      }
    }

    const enriched = [], unchanged = [], failedFindings = [], noPage = [];
    const providerLabel = sM.providerLabel, model = sM.model;

    for (const f of targets) {
      const page = pagesById.get(f.findingId);
      if (!page) { noPage.push(f.findingId); continue; }

      const snippet = snippetFor(ctx.sourcePath || path.dirname(reportDir), f.location && f.location.file,
        f.location && f.location.startLine, f.location && f.location.endLine, sM.contextLines);

      const payload = {
        findingId: f.findingId,
        title: f.title,
        severity: f.severity,
        confidence: f.confidence,
        category: f.category,
        location: { file: f.location && f.location.file, startLine: f.location && f.location.startLine },
        problem: f.problem,
        impact: f.impact,
        recommendation: f.recommendation,
        reportedBy: (f.sources || []).filter(x => x.status === 'REPORTED').map(x => x.tool),
        missedBy: (f.sources || []).filter(x => x.status === 'MISSED').map(x => x.tool),
        snippet: snippet.available
          ? { file: snippet.file, lines: `${snippet.from}-${snippet.to}`, code: snippet.text }
          : { available: false, note: 'the source file could not be read; reason from the metadata only and say so if unsure.' },
        instruction: 'Return ONLY the JSON object described in the system prompt.'
      };

      try {
        const raw = ctx.aiCall
          ? await ctx.aiCall(payload)
          : await callProvider(sM, NARRATIVE_SYSTEM, JSON.stringify(payload, null, 2));
        const n = narrativeParse(raw);
        if (!n) { failedFindings.push({ id: f.findingId, reason: 'model returned an empty reply' }); continue; }
        const block = renderNarrativeBlock(f, n, { providerLabel, model });
        const before = fs.readFileSync(page, 'utf8');
        const up = upsertBlock(before, f.findingId, block);
        if (up.refused) {
          // Conservative recovery: never delete content we cannot attribute.
          failedFindings.push({ id: f.findingId, reason: up.refused });
          continue;
        }
        const after = up.text;
        if (after !== before) {
          // THE GUARD runs on every byte we write to a report.
          R.guardedWriteFile(page, after, { quiet: true });
          enriched.push(f.findingId);
        } else {
          unchanged.push(f.findingId);   // idempotent re-run: byte-identical -> file untouched
        }
      } catch (e) {
        const kind = e.kind ? ` [${e.kind}]` : '';
        failedFindings.push({ id: f.findingId, reason: R.scrub(e.message) + kind });
        if (e.kind === 'rate-limited' || e.kind === 'network' || e.kind === 'http' || e.kind === 'auth') {
          // Provider-level failure: stop rather than half-enrich; say exactly what was written.
          return { ok: false, mode: 'report', error: R.scrub(e.message),
            provider: providerLabel, model,
            enrichedSoFar: enriched, unchangedSoFar: unchanged, failedFindings,
            note: 'stopped after the provider error; files already enriched keep their AI blocks, ' +
              'all other findings are untouched. Re-run when the provider recovers — enrichment is idempotent.' };
        }
      }
    }

    log(`  ${ID}: mode "report" — enriched ${enriched.length} finding page(s)` +
      (unchanged.length ? `, ${unchanged.length} already up to date (idempotent re-run)` : '') +
      (failedFindings.length ? `, ${failedFindings.length} failed` : '') +
      (noPage.length ? `, ${noPage.length} had no Markdown page` : '') +
      (belowThreshold ? `; ${belowThreshold} below severityThreshold ${threshold} were not sent` : ''));
    log('  Canonical data/report.json was NOT modified — the AI edits only the Markdown projection.');

    return {
      ok: true, mode: 'report', provider: sM.provider, providerLabel, model,
      enriched, unchanged, failedFindings, noPage, belowThreshold
    };
  } catch (e) {
    return { ok: false, mode: 'report', error: R.scrub(e.message) };
  }
}

// ------------------------------------------------------------------ exports

module.exports = {
  id: ID, name: 'AI-assisted review', kind: 'ai',
  stacks: ['framework', 'core', 'both'],

  // adapter contract
  detect, run, parse,

  // MODE 1 entry point (post-processing over an existing report)
  runReport,

  // explicit aliases / helpers for the CLI wiring described in src/config/WIRING.md
  runReview: run,                      // MODE 2 alias
  modes: { report: runReport, review: run },
  crossCheck,                          // pure; unit-testable
  upsertBlock, narrativeParse,         // pure; unit-testable (idempotency machinery)
  MARK,

  // secrets discipline passthrough (kept for older callers)
  _scrub: R.scrub,

  // internal, exported for verification harnesses only — not part of the public surface
  _callProvider: callProvider, _postJson: postJson
};
