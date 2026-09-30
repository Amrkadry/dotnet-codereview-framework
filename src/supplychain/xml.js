'use strict';
/**
 * Line-preserving helpers over the small XML dialects the NuGet toolchain uses
 * (packages.config, *.csproj, nuget.config, *.nuspec, Directory.Packages.props).
 *
 * Why regex over lines and not a real XML parser: the framework has a hard
 * zero-dependency rule, and every file this module reads is flat, generated,
 * namespace-free configuration. The trade-off is stated, not hidden: an exotic
 * file that hides its elements behind an XML namespace prefix or CDATA will be
 * MISSED, not misreported — the failure mode of this parser is silence on
 * unusual input, never a fabricated finding.
 *
 * Every helper is pure and never throws on junk input.
 */

/** Split text into lines. Accepts anything; returns [] for falsy input. */
function lines(text) {
  return String(text || '').split(/\r?\n/);
}

/** Attribute value from a single line, double- or single-quoted. undefined when absent. */
function attr(line, name) {
  const m = line.match(new RegExp('\\b' + name + '\\s*=\\s*"([^"]*)"')) ||
            line.match(new RegExp("\\b" + name + "\\s*=\\s*'([^']*)'"));
  return m ? m[1] : undefined;
}

/** True when the line opens <name ...> (self-closing <name ... /> does NOT open a scope). */
function opens(line, name) {
  const m = line.match(new RegExp('<' + name + '(\\s[^>]*)?/?>', 'i'));
  return !!m && !/\/\s*>\s*$/.test(line);
}

/** True when the line closes </name>. */
function closes(line, name) {
  return new RegExp('</\\s*' + name + '\\s*>', 'i').test(line);
}

/** True when the line is a self-closing element of <name ... />. */
function selfClosing(line, name) {
  return new RegExp('<' + name + '(\\s[^>]*)?/\\s*>', 'i').test(line);
}

/** Collapse whitespace and cap length — evidence snippets are quotes, not transcripts. */
function clean(line, max = 300) {
  return String(line || '').trim().replace(/\s+/g, ' ').slice(0, max);
}

/**
 * Return the line with the value of `name="..."` replaced by [REDACTED].
 * Used for EVERY snippet that carries a credential-bearing attribute, so a
 * plaintext password can never reach a finding through this module.
 */
function redactAttr(line, name) {
  const re = new RegExp('(' + name + '\\s*=\\s*")([^"]*)(")');
  const re2 = new RegExp("(" + name + "\\s*=\\s*')([^']*)(')");
  return String(line || '').replace(re, '$1[REDACTED]$3').replace(re2, '$1[REDACTED]$3');
}

/**
 * Strip userinfo credentials from a URL for safe display. "https://user:pass@host/v3"
 * becomes "https://[REDACTED]@host/v3"; anything without credentials is untouched.
 */
function sanitizeUrl(url) {
  return String(url || '')
    .replace(/(\/\/)[^/@\s]+:[^/@\s]+@/, '$1[REDACTED]@')
    .replace(/(\/\/)[^/@\s]+@/, '$1[REDACTED]@');
}

module.exports = { lines, attr, opens, closes, selfClosing, clean, redactAttr, sanitizeUrl };
