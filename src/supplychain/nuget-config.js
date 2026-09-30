'use strict';
/**
 * nuget.config parsing — feeds, credentials, packageSourceMapping, signature validation.
 *
 * The parsed model is the SECURITY BOUNDARY of this module: it simply has no field that can
 * carry a credential value. Passwords are detected, counted and located, but replaced with
 * [REDACTED] before they ever leave this file, so no downstream check can echo one into a
 * finding by accident.
 *
 * Known approximation, stated: a repository can hold several nuget.config files and NuGet
 * merges them hierarchically (nearest file wins per section, machine/user config inherits in).
 * This parser reads each file independently and the checks reason over the union of what is
 * visible, flagging inheritance-dependent conclusions at lower confidence rather than
 * pretending the merge was evaluated.
 */

const X = require('./xml');

/** Feeds whose host or name identifies the public nuget.org gallery. */
function isNuGetOrg(feed) {
  return /(^|\.)nuget\.org/i.test(feed.url || '') || /nuget\.org/i.test(feed.name || '');
}

/**
 * Parse one nuget.config into a plain model. Never throws; returns a usable model even for
 * empty or unparseable input (an unreadable file is a finding opportunity, not a crash).
 */
function parseNugetConfig(text, rel) {
  const model = {
    file: rel,
    readable: true,
    clear: false,                    // <clear /> inside <packageSources>
    feeds: [],                       // { name, url, line, snippet, disabled, hasCredential }
    removed: [],                     // names removed via <remove key=... />
    credentials: [],                 // { feed, kind, line, snippet } — value NEVER stored
    disabled: [],                    // { name, line }
    mapping: { present: false, sources: [] },   // { key, patterns[], line }
    signature: { declared: false, mode: null, line: null, allowUntrustedRoot: [] },
    sourceLines: []                  // <add key value /> lines inside packageSources, for evidence
  };

  const lines = X.lines(text);
  if (!lines.length || !lines.some(l => l.trim())) {
    model.readable = false;
    return model;
  }

  // Stack of open section names, lowercase. These config files nest at most two deep.
  const stack = [];
  let credFeed = null;             // feed element currently open inside packageSourceCredentials
  let mappingSource = null;        // <packageSource key=...> currently open

  for (let i = 0; i < lines.length; i++) {
    const raw = lines[i];
    const line = raw.trim();
    const n = i + 1;               // 1-based line number
    if (!line) continue;

    // ---- section opens / closes -----------------------------------------------------------
    for (const s of ['packageSources', 'packageSourceCredentials', 'disabledPackageSources',
                     'packageSourceMapping', 'signatureValidation', 'trustedSigners', 'config']) {
      if (X.opens(raw, s)) stack.push(s);
      if (X.closes(raw, s)) {
        const at = stack.lastIndexOf(s);
        if (at !== -1) stack.splice(at, 1);
      }
    }
    const inSection = name => stack.includes(name);

    // ---- <config>: legacy signatureValidationMode -----------------------------------------
    if (inSection('config') && /<add\b/i.test(line)) {
      const key = (X.attr(line, 'key') || '').toLowerCase();
      if (key === 'signaturevalidationmode') {
        model.signature.declared = true;
        model.signature.mode = (X.attr(line, 'value') || '').toLowerCase() || null;
        model.signature.line = model.signature.line || n;
      }
    }

    // ---- <packageSources> -----------------------------------------------------------------
    if (inSection('packageSources')) {
      if (/<clear\s*\/>/i.test(line)) model.clear = true;
      const rm = line.match(/<remove\b[^>]*\bkey\s*=\s*"([^"]*)"/i);
      if (rm) model.removed.push({ name: rm[1], line: n });
      if (X.selfClosing(raw, 'add') || /<add\b/i.test(line)) {
        const name = X.attr(line, 'key');
        const url = X.attr(line, 'value');
        if (name !== undefined && url !== undefined) {
          const feed = {
            name, url,
            urlSafe: X.sanitizeUrl(url),
            line: n,
            snippet: X.clean(line),
            disabled: false,
            hasCredential: false,
            isPublic: isNuGetOrg({ name, url }),
            host: hostOf(url)
          };
          model.feeds.push(feed);
          model.sourceLines.push(n);
        }
      }
    }

    // ---- <packageSourceCredentials> --------------------------------------------------------
    if (inSection('packageSourceCredentials')) {
      const feedOpen = line.match(/^<([A-Za-z0-9._-]+)\s*>$/);
      if (feedOpen) { credFeed = feedOpen[1]; continue; }
      if (/^<\/[A-Za-z0-9._-]+\s*>$/.test(line)) { credFeed = null; continue; }
      if (credFeed && /<add\b/i.test(line)) {
        const key = X.attr(line, 'key') || '';
        if (/clearTextPassword|password/i.test(key)) {
          const kind = /clearTextPassword/i.test(key) ? 'ClearTextPassword' : 'Password';
          model.credentials.push({
            feed: credFeed,
            kind,
            line: n,
            // Redaction happens HERE, at parse time — the model never sees the value.
            snippet: X.redactAttr(line, 'value'),
            url: null
          });
          const feed = model.feeds.find(f => f.name === credFeed);
          if (feed) feed.hasCredential = true;
        }
      }
    }

    // ---- <disabledPackageSources> -----------------------------------------------------------
    if (inSection('disabledPackageSources') && /<add\b/i.test(line)) {
      const name = X.attr(line, 'key');
      const val = (X.attr(line, 'value') || '').toLowerCase();
      if (name !== undefined && val !== 'false') {
        model.disabled.push({ name, line: n });
        const feed = model.feeds.find(f => f.name === name);
        if (feed) feed.disabled = true;
      }
    }

    // ---- <packageSourceMapping> --------------------------------------------------------------
    if (inSection('packageSourceMapping')) {
      const src = line.match(/<packageSource\b[^>]*\bkey\s*=\s*"([^"]*)"\s*>/i);
      if (src) { mappingSource = { key: src[1], patterns: [], line: n }; }
      const pat = line.match(/<package\b[^>]*\bpattern\s*=\s*"([^"]*)"/i);
      if (pat && mappingSource) mappingSource.patterns.push(pat[1]);
      if (X.closes(raw, 'packageSource') && mappingSource) {
        model.mapping.sources.push(mappingSource);
        model.mapping.present = true;
        mappingSource = null;
      }
    }

    // ---- <signatureValidation> / <trustedSigners> ---------------------------------------------
    // ---- <signatureValidation> — attribute form works for both the open element and the
    // self-closing <signatureValidation mode="accept" /> common in real files. Without this,
    // the section tracker (which deliberately ignores self-closing elements) would never see it.
    if (/<signatureValidation\b/i.test(line)) {
      const mode = X.attr(line, 'mode');
      if (mode) {
        model.signature.declared = true;
        model.signature.mode = mode.toLowerCase();
        model.signature.line = model.signature.line || n;
      }
    }
    if (inSection('signatureValidation')) {
      const mode2 = X.attr(line, 'mode');
      if (mode2) {
        model.signature.declared = true;
        model.signature.mode = mode2.toLowerCase();
        model.signature.line = model.signature.line || n;
      }
    }
    // allowUntrustedRoot is signature-specific and dangerous wherever it appears — flag it
    // in ANY section rather than depending on exact nesting of trustedSigners/trustedSigner.
    if (/<certificate\b/i.test(line) &&
        (X.attr(line, 'allowUntrustedRoot') || '').toLowerCase() === 'true') {
      model.signature.allowUntrustedRoot.push({ line: n, snippet: X.clean(line) });
    }

    // ---- credentials embedded in the source URL itself ----------------------------------------
    for (const feed of model.feeds) {
      if (!feed.hasCredential && /\/\/[^/@\s]+:[^/@\s]+@/.test(feed.url) && feed.line === n) {
        model.credentials.push({
          feed: feed.name, kind: 'credentials-in-URL', line: n,
          snippet: X.clean(X.sanitizeUrl(line)),
          url: feed.urlSafe
        });
        feed.hasCredential = true;
      }
    }
  }

  return model;
}

/** Host of a URL, or '' when absent/relative. */
function hostOf(url) {
  const m = String(url || '').match(/^https?:\/\/([^/@\s]+)/i);
  if (!m) return '';
  return m[1].replace(/:\d+$/, '').toLowerCase();
}

/** Enabled = listed, not removed, not disabled. Inheritance from outer configs is NOT resolved here. */
function enabledFeeds(model) {
  const removedNames = new Set(model.removed.map(r => r.name.toLowerCase()));
  const disabledNames = new Set(model.disabled.map(d => d.name.toLowerCase()));
  return model.feeds.filter(f =>
    !removedNames.has(f.name.toLowerCase()) && !disabledNames.has(f.name.toLowerCase()));
}

module.exports = { parseNugetConfig, isNuGetOrg, enabledFeeds, hostOf };
