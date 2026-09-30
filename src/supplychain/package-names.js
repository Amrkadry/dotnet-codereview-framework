'use strict';
/**
 * Package-name risk heuristics — the curated well-known list and the Levenshtein near-miss
 * test behind the typosquat check.
 *
 * Honesty constraints, enforced here rather than in prose:
 *  - The list is CURATED, not measured. Nothing in this module claims the packages are "most
 *    downloaded" or quotes any statistic, because the analyzer has no network access to base
 *    one on.
 *  - A near-miss is evidence of SHAPE, not of intent. Every name-based finding leaves this
 *    module at confidence POSSIBLE with an explicit "a human must confirm" instruction —
 *    a false typosquat accusation is worse than a miss.
 */

/**
 * Modest curated set of widely used .NET package ids. Case-insensitive comparisons happen
 * downstream (NuGet ids are case-insensitive, so case is never a typosquat signal).
 */
const WELL_KNOWN = [
  'Newtonsoft.Json', 'EntityFramework', 'Microsoft.EntityFrameworkCore', 'Dapper',
  'AutoMapper', 'Serilog', 'NLog', 'log4net', 'Moq', 'xunit', 'NUnit',
  'MSTest.TestFramework', 'FluentAssertions', 'RestSharp', 'HtmlAgilityPack',
  'MediatR', 'FluentValidation', 'Polly', 'StackExchange.Redis', 'RabbitMQ.Client',
  'protobuf-net', 'CsvHelper', 'EPPlus', 'MailKit', 'MimeKit', 'Autofac', 'Ninject',
  'Hangfire', 'Quartz', 'Castle.Core', 'NSubstitute', 'Shouldly', 'Bogus',
  'Swashbuckle.AspNetCore', 'Microsoft.Extensions.Logging',
  'Microsoft.Extensions.DependencyInjection', 'Microsoft.Extensions.Configuration',
  'Microsoft.Extensions.Hosting', 'Microsoft.AspNetCore.Mvc', 'Microsoft.Data.SqlClient',
  'System.Data.SqlClient', 'Npgsql', 'MySql.Data', 'Microsoft.Owin', 'Owin',
  'Microsoft.AspNet.WebApi.Client', 'Microsoft.AspNet.Mvc', 'jQuery', 'bootstrap',
  'Microsoft.IdentityModel.Tokens', 'System.IdentityModel.Tokens.Jwt', 'IdentityServer4',
  'Grpc.AspNetCore', 'Microsoft.AspNetCore.SignalR', 'WindowsAzure.Storage',
  'Azure.Storage.Blobs', 'AWSSDK.Core', 'SixLabors.ImageSharp', 'SkiaSharp',
  'iTextSharp', 'PdfSharp', 'NodaTime', 'Humanizer', 'Refit', 'Mapster',
  'Microsoft.EntityFrameworkCore.SqlServer', 'Microsoft.AspNetCore.Authentication.JwtBearer',
  'Microsoft.NET.Test.Sdk', 'Coverlet.Collector', 'StyleCop.Analyzers', 'SonarAnalyzer.CSharp'
];

const KNOWN = new Set(WELL_KNOWN.map(s => s.toLowerCase()));

/** Classic dynamic-programming Levenshtein distance, two-row implementation. */
function levenshtein(a, b) {
  if (a === b) return 0;
  if (!a.length) return b.length;
  if (!b.length) return a.length;
  let prev = new Array(b.length + 1);
  let cur = new Array(b.length + 1);
  for (let j = 0; j <= b.length; j++) prev[j] = j;
  for (let i = 1; i <= a.length; i++) {
    cur[0] = i;
    for (let j = 1; j <= b.length; j++) {
      const cost = a[i - 1] === b[j - 1] ? 0 : 1;
      cur[j] = Math.min(cur[j - 1] + 1,      // insertion
                        prev[j] + 1,         // deletion
                        prev[j - 1] + cost); // substitution
    }
    const t = prev; prev = cur; cur = t;
  }
  return prev[b.length];
}

/**
 * Is this distance meaningful enough to raise, for a name of this length?
 * Deliberately conservative — a shorter name has more legitimate neighbours per edit.
 *   len >= 6  -> distance 1 may flag
 *   len >= 14 -> distance 2 may flag (long compound names tolerate more drift)
 */
function withinThreshold(len, distance) {
  if (distance === 1) return len >= 6;
  if (distance === 2) return len >= 14;
  return false;
}

/**
 * Classify one package id.
 * Returns { known, nearest, distance, flagged, reason } — flagged only for near-misses on
 * KNOWN names or ids using characters outside the NuGet norm (e.g. homoglyphs, spaces).
 */
function classifyName(id) {
  const idLower = String(id || '').trim().toLowerCase();
  const out = { known: KNOWN.has(idLower), nearest: null, distance: null, flagged: false, reason: null };

  if (out.known) return out;

  // Characters outside [A-Za-z0-9 . _ -] are unusual for a NuGet id and cheap to check exactly.
  const oddChars = String(id).match(/[^A-Za-z0-9._\- ]/g);
  if (oddChars && oddChars.length) {
    out.flagged = true;
    out.reason = 'contains characters outside the usual NuGet id alphabet ' +
      `(${oddChars.slice(0, 5).map(c => JSON.stringify(c)).join(', ')})`;
    return out;
  }

  let best = null, bestDist = Infinity;
  for (const known of KNOWN) {
    const d = Math.abs(known.length - idLower.length);
    if (d > 2 || d > bestDist) continue;         // length gap alone rules it out — cheap prune
    const dist = levenshtein(idLower, known);
    if (dist < bestDist) { bestDist = dist; best = known; }
  }
  out.nearest = best;
  out.distance = bestDist === Infinity ? null : bestDist;
  if (best && withinThreshold(idLower.length, bestDist)) {
    out.flagged = true;
    out.reason = `edit distance ${bestDist} from the well-known id "${best}"`;
  }
  return out;
}

module.exports = { WELL_KNOWN, levenshtein, classifyName, withinThreshold };
