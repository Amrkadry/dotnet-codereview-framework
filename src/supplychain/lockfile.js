// dotnet-codereview-framework — src/supplychain/lockfile.js
// Author: Amr Kadry (github.com/Amrkadry) · MIT License
'use strict';
/**
 * packages.lock.json parsing.
 *
 * The lockfile is the integrity anchor of a PackageReference project: `restore --locked-mode`
 * refuses to proceed when content does not match, and the contentHash entries are what make
 * each package verifiable. Findings about it therefore need per-package granularity —
 * which JSON.parse alone cannot give, because it discards line numbers.
 *
 * Strategy: JSON.parse for the structural verdict, plus a small indentation-aware line scan
 * that maps each package entry back to its opening line and records whether a contentHash
 * was present. Both are pure; malformed JSON yields { parseOk: false } instead of an
 * exception, and the line scan still runs so findings can cite real lines.
 *
 * Shape being scanned (NuGet lockfile v1/v2):
 *   { "version": 1,
 *     "dependencies": {
 *       "net6.0": {
 *         "Newtonsoft.Json": { "type": "Direct", "requested": "[13.0.1, )",
 *                              "resolved": "13.0.1", "contentHash": "..." } } } }
 */

const X = require('./xml');

/** Keys whose presence marks an object as a package entry rather than a framework block. */
const ENTRY_KEYS = new Set(['type', 'requested', 'resolved', 'contentHash']);

function parseLockfile(text, rel) {
  const model = { file: rel, parseOk: false, version: null, parseError: null, entries: [] };

  try {
    const doc = JSON.parse(String(text || ''));
    model.parseOk = true;
    model.version = (doc && doc.version) || null;
    model.__doc = doc;   // kept only for the fallback below; not part of the public model
  } catch (e) {
    model.parseError = String(e.message).slice(0, 200);
  }

  const lines = X.lines(text);
  // Open JSON objects: { indent, name, openLine, framework, entry }
  const stack = [];

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    if (!line.trim()) continue;

    const open = line.match(/^(\s*)"((?:[^"\\]|\\.)*)"\s*:\s*\{/);
    if (open) {
      const indent = open[1].length;
      while (stack.length && stack[stack.length - 1].indent >= indent) stack.pop();
      const parent = stack[stack.length - 1] || null;
      stack.push({
        indent,
        name: open[2],
        openLine: i + 1,
        // The object directly under "dependencies" is a target framework, e.g. "net6.0";
        // its children are package entries. Anything under a framework block inherits it.
        framework: parent && parent.name === 'dependencies' ? open[2]
          : (parent && parent.framework) || null,
        entry: null
      });
      continue;
    }

    const prop = line.match(/^\s*"((?:[^"\\]|\\.)+)"\s*:\s*("?[^",{}]*"?)\s*,?\s*$/);
    if (!prop || !stack.length) continue;
    const key = prop[1];
    if (!ENTRY_KEYS.has(key)) continue;

    const frame = stack[stack.length - 1];
    if (!frame.entry) {
      frame.entry = {
        id: frame.name,
        framework: frame.framework,
        type: null, requested: null, resolved: null, hasHash: false,
        line: frame.openLine
      };
      model.entries.push(frame.entry);
    }
    const value = prop[2].replace(/^"|"$/g, '').trim();
    if (key === 'type') frame.entry.type = value;
    if (key === 'requested') frame.entry.requested = value;
    if (key === 'resolved') frame.entry.resolved = value;
    if (key === 'contentHash') frame.entry.hasHash = value.length > 0;
  }

  // FALLBACK: the line scan only sees entries in pretty-printed JSON (one object per line).
  // A minified or single-line lockfile would otherwise yield ZERO entries and every manifest
  // reference would be falsely reported "not in lockfile" — a fabricated staleness finding.
  // When the scan found nothing but JSON.parse succeeded, rebuild entries from the parsed
  // document; the line is then located by text search, or line 1 when the file is one line.
  if (model.entries.length === 0 && model.parseOk && model.__doc &&
      model.__doc.dependencies && typeof model.__doc.dependencies === 'object') {
    for (const [tfm, pkgs] of Object.entries(model.__doc.dependencies)) {
      if (!pkgs || typeof pkgs !== 'object' || Array.isArray(pkgs)) continue;
      for (const [id, meta] of Object.entries(pkgs)) {
        if (!meta || typeof meta !== 'object') continue;
        const idx = lines.findIndex(l => l.includes('"' + id + '"'));
        model.entries.push({
          id,
          framework: tfm,
          type: meta.type || null,
          requested: meta.requested || null,
          resolved: meta.resolved || null,
          hasHash: typeof meta.contentHash === 'string' && meta.contentHash.length > 0,
          line: idx >= 0 ? idx + 1 : 1
        });
      }
    }
  }
  delete model.__doc;

  return model;
}

module.exports = { parseLockfile };
