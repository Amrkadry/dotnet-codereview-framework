'use strict';
/**
 * Configuration-derived dependency surface: binding redirects from Web.config / App.config and
 * target entries from *.deps.json.
 *
 * Config XML is parsed with narrow regexes rather than a full XML parser (Node ships none) — the
 * constructs matched here are rigid, machine-written blocks inside <runtime>/<assemblyBinding>.
 * Anything that does not match is skipped, never half-interpreted.
 */

/**
 * Extract bindingRedirect declarations.
 * Returns [{ assemblyName, publicKeyToken, culture, oldVersion (raw range), newVersion,
 *            oldMin, oldMax, changesVersion }]
 * Pure. Never throws.
 */
function parseBindingRedirects(xml) {
  const out = [];
  if (!xml || typeof xml !== 'string') return out;

  const blocks = xml.match(/<dependentAssembly\b[^>]*>[\s\S]*?<\/dependentAssembly>/gi) || [];
  for (const block of blocks) {
    const id = attr(block, 'assemblyIdentity');
    const redirects = block.match(/<bindingRedirect\b[^>]*\/?>/gi) || [];
    for (const rd of redirects) {
      const oldVersion = attrOf(rd, 'oldVersion');
      const newVersion = attrOf(rd, 'newVersion');
      if (!oldVersion || !newVersion) continue;
      const [oldMin, oldMax = oldMin] = oldVersion.split('-').map(s => s && s.trim());
      out.push({
        assemblyName: (id && attrOf(id, 'name')) || null,
        publicKeyToken: (id && attrOf(id, 'publicKeyToken')) || null,
        culture: (id && attrOf(id, 'culture')) || null,
        oldVersion,
        newVersion,
        oldMin: oldMin || null,
        oldMax: oldMax || null,
        changesVersion: versionsDiffer(oldMin, newVersion)
      });
    }
  }
  return out;
}

/** Attribute map of the first <assemblyIdentity ...> in a block, as a string of its attrs. */
function attr(block, tag) {
  const m = block.match(new RegExp(`<${tag}\\b[^>]*>`, 'i'));
  return m ? m[0] : null;
}
function attrOf(tagXml, name) {
  if (!tagXml) return null;
  const m = tagXml.match(new RegExp(`${name}\\s*=\\s*"([^"]*)"`, 'i')) ||
            tagXml.match(new RegExp(`${name}\\s*=\\s*'([^']*)'`, 'i'));
  return m ? m[1] : null;
}

function versionsDiffer(a, b) {
  const norm = (v) => String(v || '').split('.').map(p => Number(p) || 0).join('.');
  return !!a && !!b && norm(a) !== norm(b);
}

/** Does a redirect move across a MAJOR version boundary (more likely to change behaviour)? */
function crossesMajor(oldVersion, newVersion) {
  const major = (v) => Number(String(v || '').split('.')[0]);
  return Number.isFinite(major(oldVersion)) && Number.isFinite(major(newVersion)) &&
    major(oldVersion) !== major(newVersion);
}

/**
 * Parse a *.deps.json target block (ASP.NET Core deployments).
 * Returns { targetFramework, runtimeTarget, dependencies: [{ name, version, type }] } or null.
 */
function parseDepsJson(raw) {
  let doc;
  try { doc = JSON.parse(raw); } catch { return null; }
  if (!doc || !doc.targets) return null;

  const runtimeTarget = doc.runtimeTarget && doc.runtimeTarget.name;
  const targetName = (runtimeTarget && doc.targets[runtimeTarget] && runtimeTarget) || Object.keys(doc.targets)[0];
  if (!targetName) return null;
  const target = doc.targets[targetName];

  const dependencies = [];
  for (const [key, meta] of Object.entries(target)) {
    const at = key.lastIndexOf('/');
    if (at < 0) continue;
    dependencies.push({
      name: key.slice(0, at),
      version: key.slice(at + 1),
      type: (meta && meta.type) || 'package'
    });
  }
  return { targetFramework: targetName, runtimeTarget, dependencies };
}

module.exports = { parseBindingRedirects, parseDepsJson, crossesMajor, versionsDiffer };
