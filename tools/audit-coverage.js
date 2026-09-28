#!/usr/bin/env node
/**
 * Coverage audit for the .NET test-case catalog.
 *
 * WHY THIS EXISTS
 * "Does the catalog cover everything?" is not answerable by reading it. This tool probes the
 * catalog against a maintained list of known-dangerous .NET APIs, frameworks and attack
 * classes and prints what is NOT covered. The honest answer to "is it exhaustive?" is always
 * no — this makes the gap measurable and reviewable instead of a claim.
 *
 * Add a probe whenever you learn of a surface the catalog should cover. A failing probe is a
 * backlog item, not an error, so this exits 0 by default. Use --strict in CI to fail on gaps.
 *
 *   node tools/audit-coverage.js
 *   node tools/audit-coverage.js --strict
 */
'use strict';
const fs = require('fs');
const path = require('path');

const strict = process.argv.includes('--strict');
const catalogDir = path.join(__dirname, '..', 'catalog');
const files = fs.readdirSync(catalogDir).filter(f => f.endsWith('.json')).sort();
const catalogs = files.map(f => JSON.parse(fs.readFileSync(path.join(catalogDir, f), 'utf8')));
const tests = catalogs.flatMap(c => c.tests);
const categories = Object.assign({}, ...catalogs.map(c => c.categories));

// Searchable haystack: all text fields of every case.
const hay = tests.map(t =>
  [t.title, t.lookFor, t.expected, t.cwe, t.category].join(' ')).join('\n').toLowerCase();

/**
 * Probes: [group, needle, note]
 * `needle` is matched case-insensitively against the catalog text.
 */
const PROBES = [
  // --- serializers and type resolution ---
  ['Deserialization', 'binaryformatter'], ['Deserialization', 'typenamehandling'],
  ['Deserialization', 'javascriptserializer'], ['Deserialization', 'netdatacontract'],
  ['Deserialization', 'xmlserializer'], ['Deserialization', 'xamlreader'],
  ['Deserialization', 'yamldotnet'], ['Deserialization', 'messagepack'],
  ['Deserialization', 'losformatter'], ['Deserialization', 'objectstateformatter'],
  ['Deserialization', 'serializationbinder'],
  // --- reflection / dynamic code ---
  ['Reflection', 'type.gettype'], ['Reflection', 'activator.createinstance'],
  ['Reflection', 'assembly.load'], ['Reflection', 'methodinfo.invoke'],
  ['Reflection', 'bindingflags'],
  ['DynamicCode', 'csharpscript'], ['DynamicCode', 'csharpcodeprovider'],
  ['DynamicCode', 'razorengine'], ['DynamicCode', 'dynamic linq'],
  // --- template injection ---
  ['SSTI', 'scriban'], ['SSTI', 'handlebars'], ['SSTI', 'dotliquid'], ['SSTI', 'fluid'],
  ['SSTI', 'ncalc'],
  // --- ASP.NET platform ---
  ['Platform', 'viewstate'], ['Platform', 'machinekey'], ['Platform', 'padding-oracle'],
  ['Platform', 'viewstateuserkey'], ['Platform', 'server.mappath'],
  ['Platform', 'impersonat'], ['Platform', 'cookieless'], ['Platform', 'elmah'],
  ['Platform', 'eventvalidation'], ['Platform', 'outputcache'], ['Platform', 'forms authentication'],
  // --- injection ---
  ['Injection', 'sql'], ['Injection', 'ldap'], ['Injection', 'xpath'],
  ['Injection', 'command'], ['Injection', 'nosql'], ['Injection', 'log injection'],
  ['Injection', 'crlf'], ['Injection', 'order by'],
  // --- XML ---
  ['XML', 'xxe'], ['XML', 'dtdprocessing'], ['XML', 'xslt'], ['XML', 'billion laughs'],
  // --- auth / federation ---
  ['Auth', 'empty password'], ['Auth', 'ldaps'], ['Auth', 'jwt'], ['Auth', 'alg'],
  ['Auth', 'session fixation'], ['Auth', 'lockout'], ['Auth', 'mfa'],
  ['Auth', 'password reset'], ['Auth', 'data protection'],
  ['Federation', 'redirect_uri'], ['Federation', 'state parameter'], ['Federation', 'pkce'],
  ['Federation', 'nonce'], ['Federation', 'implicit flow'], ['Federation', 'saml'],
  ['Federation', 'signature wrapping'], ['Federation', 'audience'], ['Federation', 'scope'],
  ['Federation', 'account linking'],
  // --- authorization ---
  ['Authz', 'authorize'], ['Authz', 'idor'], ['Authz', 'tenant'],
  ['Authz', 'mass assignment'], ['Authz', 'privilege escalation'],
  ['Authz', 'spoofable header'], ['Authz', 'verb tampering'],
  // --- HTTP protocol ---
  ['HTTP', 'smuggling'], ['HTTP', 'host header'], ['HTTP', 'cache poisoning'],
  ['HTTP', 'cache deception'], ['HTTP', 'response splitting'],
  ['HTTP', 'x-forwarded-for'], ['HTTP', 'method override'], ['HTTP', 'normalis'],
  // --- crypto / secrets ---
  ['Crypto', 'zero iv'], ['Crypto', 'ecb'], ['Crypto', 'pbkdf2'],
  ['Crypto', 'constant-time'], ['Crypto', 'randomness'], ['Crypto', 'hard-coded credentials'],
  ['Crypto', 'commented'], ['Crypto', 'build artifact'],
  // --- transport ---
  ['Transport', 'certificate validation'], ['Transport', 'host-key'],
  ['Transport', 'tls'], ['Transport', 'hsts'], ['Transport', 'encrypt=true'],
  // --- files ---
  ['Files', 'path traversal'], ['Files', 'zip'], ['Files', 'magic-number'],
  ['Files', 'webroot'], ['Files', 'temporary file'], ['Files', 'recursive delete'],
  // --- SSRF ---
  ['SSRF', 'ssrf'], ['SSRF', 'metadata'], ['SSRF', 'redirect'],
  // --- legacy services ---
  ['WCF', 'wcf'], ['WCF', 'wshttpbinding'], ['WCF', 'asmx'],
  ['WCF', 'servicemetadata'], ['WCF', 'soapaction'],
  // --- modern surfaces ---
  ['Modern', 'signalr'], ['Modern', 'grpc'], ['Modern', 'blazor'],
  ['Modern', 'markupstring'], ['Modern', 'minimal api'], ['Modern', 'backgroundservice'],
  ['Modern', 'scoped service'], ['Modern', 'health'], ['Modern', 'user-secrets'],
  // --- concurrency / availability ---
  ['Runtime', 'singleton'], ['Runtime', 'sync-over-async'], ['Runtime', 'async void'],
  ['Runtime', 'dbcontext'], ['Runtime', 'regex'], ['Runtime', 'integer overflow'],
  ['Runtime', 'culture'], ['Runtime', 'ordinal'], ['Runtime', 'datetime.now'],
  ['Runtime', 'cancellationtoken'], ['Runtime', 'idisposable'],
  // --- supply chain / process ---
  ['SupplyChain', 'lockfile'], ['SupplyChain', 'packagesourcemapping'],
  ['SupplyChain', 'end-of-life'], ['SupplyChain', 'licence'], ['SupplyChain', 'audit'],
  ['Process', 'analyzer'], ['Process', 'pipeline'], ['Process', 'canary'],
  // --- data protection ---
  ['Privacy', 'pii'], ['Privacy', 'card'], ['Privacy', 'biometric'],
  ['Privacy', 'retention'], ['Privacy', 'production data'],
  // --- output encoding ---
  ['Output', 'xss'], ['Output', 'nosniff'], ['Output', 'open redirect'],
  ['Output', 'csrf'], ['Output', 'antiforgery']
];

const covered = [];
const gaps = [];
for (const [group, needle] of PROBES) {
  (hay.includes(needle.toLowerCase()) ? covered : gaps).push([group, needle]);
}

// ------------------------------------------------------------------ report
console.log('.NET test-case catalog coverage audit\n');
console.log(`catalog files : ${files.join(', ')}`);
console.log(`test cases    : ${tests.length}`);
console.log(`categories    : ${Object.keys(categories).length}`);
console.log(`probes        : ${PROBES.length}`);
console.log(`covered       : ${covered.length}`);
console.log(`gaps          : ${gaps.length}`);
console.log(`coverage      : ${((covered.length / PROBES.length) * 100).toFixed(1)}%\n`);

const byCat = tests.reduce((m, t) => (m[t.category] = (m[t.category] || 0) + 1, m), {});
console.log('cases per category:');
Object.keys(categories).sort().forEach(c =>
  console.log(`  ${c}  ${String(byCat[c] || 0).padStart(3)}  ${categories[c]}`));

const byAuto = tests.reduce((m, t) => (m[t.automatable] = (m[t.automatable] || 0) + 1, m), {});
console.log('\nautomatability:');
Object.entries(byAuto).sort((a, b) => b[1] - a[1])
  .forEach(([k, v]) => console.log(`  ${String(v).padStart(3)}  ${k}`));

if (gaps.length) {
  console.log('\nUNCOVERED PROBES — these are the known gaps:');
  const grouped = gaps.reduce((m, [g, n]) => ((m[g] = m[g] || []).push(n), m), {});
  Object.entries(grouped).forEach(([g, ns]) => console.log(`  ${g}: ${ns.join(', ')}`));
  console.log('\nEach line above is a backlog item. Add a case, then re-run.');
} else {
  console.log('\nEvery probe is covered. That is NOT proof of exhaustiveness —');
  console.log('it means the catalog covers everything this tool currently knows to ask about.');
  console.log('Add probes as new attack surfaces become known.');
}

console.log('\nNote: this audits BREADTH of classes, not depth within a class, and it cannot');
console.log('know about surfaces nobody has added a probe for. Treat 100% as "no known gaps".');

if (strict && gaps.length) process.exit(1);
