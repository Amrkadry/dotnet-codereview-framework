'use strict';
/**
 * CHECK 1 — dependency confusion / substitution.
 *
 * The deterministic facts available offline are the feeds a nuget.config enables and whether
 * packageSourceMapping constrains which feed may serve which id. The finding: a declared
 * package id that a PRIVATE feed could serve while the public nuget.org feed is ALSO enabled
 * and no mapping restricts it. In that state, resolution between the feeds is decided by
 * source order and moment-to-moment availability — not by ownership — so an attacker who
 * registers the id publicly can win the restore.
 *
 * What is deliberately NOT claimed: whether the public name is already registered. Proving
 * that needs the network, and this analyzer has none by design; every finding states this as
 * a limitation instead of asserting exploitability.
 */

const { buildFinding } = require('../finding');
const { isNuGetOrg, enabledFeeds } = require('../nuget-config');

/** NuGet packageSourceMapping pattern -> anchored case-insensitive regex. `*` is a wildcard. */
function patternToRegex(pattern) {
  const esc = String(pattern).replace(/[.+?^${}()|[\]\\]/g, '\\$&').replace(/\*/g, '.*');
  return new RegExp('^' + esc + '$', 'i');
}

/** Union of every packageSourceMapping defined by any nuget.config in the tree. */
function collectMapping(nugetConfigs) {
  const sources = [];
  for (const cfg of nugetConfigs) {
    for (const s of cfg.model.mapping.sources) {
      sources.push({ key: s.key, patterns: s.patterns.slice(), file: cfg.file, line: s.line });
    }
  }
  return { present: sources.length > 0, sources };
}

function coveredByMapping(mapping, id) {
  return mapping.sources.some(s =>
    s.patterns.some(p => patternToRegex(p).test(id)));
}

/**
 * All feeds in play across every nuget.config: enabled public feeds and enabled private feeds,
 * deduplicated by name+host. Whether nuget.org was seen EXPLICITLY or is only INHERITED from
 * machine/user config (no <clear/>, never disabled) decides the finding's confidence.
 */
function feedPicture(nugetConfigs) {
  const pub = new Map(), priv = new Map();
  let explicitPublic = false, anyClear = false, publicRemovedOrDisabled = false;

  for (const cfg of nugetConfigs) {
    const m = cfg.model;
    if (m.clear) anyClear = true;
    for (const f of enabledFeeds(m)) {
      const key = (f.name + '|' + f.host).toLowerCase();
      const entry = { name: f.name, urlSafe: f.urlSafe, host: f.host, file: cfg.file, line: f.line };
      if (isNuGetOrg(f)) {
        explicitPublic = true;
        if (!pub.has(key)) pub.set(key, entry);
      } else if (!priv.has(key)) {
        priv.set(key, entry);
      }
    }
    for (const d of m.disabled) if (isNuGetOrg({ name: d.name, url: d.name })) publicRemovedOrDisabled = true;
    for (const r of m.removed) if (isNuGetOrg({ name: r.name, url: r.name })) publicRemovedOrDisabled = true;
  }

  const inheritedPublic = !explicitPublic && !anyClear && !publicRemovedOrDisabled;
  return {
    publicFeeds: [...pub.values()],
    privateFeeds: [...priv.values()],
    explicitPublic,
    inheritedPublic,
    publicEnabled: explicitPublic || inheritedPublic
  };
}

/** Unique declared packages across PackageReference projects and packages.config files. */
function declaredPackages(inv) {
  const byId = new Map();   // lowercase id -> { id, file, line, snippet, via }
  const add = (id, file, line, snippet, via) => {
    const key = String(id).toLowerCase();
    if (!key || byId.has(key)) return;
    byId.set(key, { id, file, line, snippet, via });
  };
  for (const p of inv.projects) {
    for (const r of p.model.packageRefs) {
      if (r.via === 'Include') add(r.id, p.file, r.line, r.snippet, 'PackageReference');
    }
  }
  for (const pc of inv.packagesConfig) {
    for (const p of pc.model.packages) add(p.id, pc.file, p.line, p.snippet, 'packages.config');
  }
  return [...byId.values()];
}

/**
 * @param inv  inventory from scan.buildInventory
 * @returns    canonical findings
 */
function dependencyConfusion(inv) {
  const pic = feedPicture(inv.nugetConfigs);
  if (!pic.publicEnabled || pic.privateFeeds.length === 0) return [];

  const mapping = collectMapping(inv.nugetConfigs);
  const out = [];

  for (const pkg of declaredPackages(inv)) {
    if (mapping.present && coveredByMapping(mapping, pkg.id)) continue;   // protected — silent

    const mappingActive = mapping.present;   // present, but this id matches no block
    const feedsInPlay = pic.privateFeeds.slice(0, 3)
      .map(f => `${f.name} -> ${f.urlSafe} (nuget.config ${f.file}:${f.line})`)
      .join('; ');
    const pubDesc = pic.explicitPublic
      ? 'nuget.org is explicitly enabled in this repository'
      : 'nuget.org is not listed in any repository nuget.config, but no <clear/> removes it either, ' +
        'so feeds inherited from user/machine NuGet configuration — typically including nuget.org — remain enabled';

    out.push(buildFinding('nuget-dependency-confusion', {
      title: `Package ${pkg.id} can resolve from a private feed with the public feed also enabled`,
      severity: mappingActive ? 'MEDIUM' : 'HIGH',
      confidence: pic.explicitPublic ? 'CONFIRMED' : 'LIKELY',
      severityRationale: 'No specific advisory is asserted; the severity models the substitution ' +
        'surface itself. It drops to MEDIUM when packageSourceMapping exists but does not cover ' +
        'this id, because NuGet then fails the restore rather than silently substituting.',
      cwe: ['CWE-829', 'CWE-1357'],
      owasp: ['A08:2021'],
      location: { file: pkg.file, startLine: pkg.line },
      evidence: {
        snippet: pkg.snippet,
        language: 'xml',
        toolOutput: `feeds in play — private: ${feedsInPlay || '(private feed enabled)'}; ` +
          `public: nuget.org; packageSourceMapping: ` +
          (mapping.present ? `present, but no pattern matches "${pkg.id}"` : 'ABSENT')
      },
      problem: `${pkg.id} is declared via ${pkg.via} while a private feed and the public feed are ` +
        `both enabled${mapping.present ? ' and the packageSourceMapping section does not cover this id' :
        ' and no packageSourceMapping section exists'}. ${pubDesc}.`,
      attackScenario: 'An attacker registers the same id on the public gallery (or on any ' +
        'reachable feed that sorts ahead of the private one). A restore that resolves before the ' +
        'private feed can serve the id — a newly added reference, a momentary feed outage, a ' +
        'misspelled id — receives the attacker-built package instead.',
      impact: 'Dependency substitution at restore time executes attacker-controlled code with the ' +
        'build\'s full privileges. NOTE THE LIMIT: this analyzer has no network access, so whether ' +
        `the public name "${pkg.id}" is currently unregistered (and thus registrable) could NOT be ` +
        'verified. The finding asserts the configuration exposure only, not exploitability.',
      rootCause: 'NuGet consults enabled sources in configured order when several can serve an id; ' +
        'without packageSourceMapping, nothing ties a private id to its private feed.',
      recommendation: mapping.present
        ? `Extend packageSourceMapping so a <packageSource> block covers "${pkg.id}" and maps it to ` +
          'the private feed only, then verify a clean restore — with mapping active, an id matching ' +
          'no block fails restore instead of falling back to any feed.'
        : 'Add a packageSourceMapping section to the nearest nuget.config: map the private id ' +
          'prefix(es) (e.g. "Company.*") to the private feed ONLY, map the remaining public ids to ' +
          'nuget.org explicitly, and prefer <clear/> in packageSources so inherited machine-level ' +
          'feeds cannot reintroduce the ambiguity. Then restore with --locked-mode in CI.',
      tests: ['O-004'],
      effort: 'SMALL',
      priority: mappingActive ? 'P3' : 'P2',
      references: [
        'https://learn.microsoft.com/nuget/consume-packages/package-source-mapping',
        'https://learn.microsoft.com/nuget/reference/security-best-practices'
      ],
      sourceNote: 'feed topology and mapping state read from nuget.config; no restore was executed ' +
        'and no registry was contacted',
      engine: 'config-xml'
    }));
  }
  return out;
}

module.exports = { dependencyConfusion, feedPicture, collectMapping, coveredByMapping, patternToRegex };
