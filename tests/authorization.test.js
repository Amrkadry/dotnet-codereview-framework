'use strict';
/**
 * Tests for cs-controller-no-authorization, and for the anti-forgery check's awareness of how
 * the application actually authenticates.
 *
 * Both behaviours come from running this framework against a real loan-origination API. Of its
 * 19 controllers, 18 carried no [Authorize] and no global filter existed anywhere, so every
 * mutating banking endpoint was reachable with no credentials at all -- and the pipeline said
 * nothing about it, while reporting a HIGH anti-forgery finding on each of those same
 * controllers. That is backwards twice over: the severe problem was silent, and the reported
 * one was not even reachable, because the app authenticates with bearer tokens and a browser
 * does not attach those to a cross-site request on its own.
 *
 * The fixtures below are the smallest shapes that reproduce each decision.
 */
const { test, describe } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

const NATIVE = require('../src/native');

/** Run the native engine over a throwaway project and return its findings. */
async function analyse(files) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'moraa-authz-'));
  try {
    for (const [rel, body] of Object.entries(files)) {
      const full = path.join(dir, rel);
      fs.mkdirSync(path.dirname(full), { recursive: true });
      fs.writeFileSync(full, body);
    }
    // A csproj makes the tree a recognisable .NET surface.
    if (!files['App.csproj']) {
      fs.writeFileSync(path.join(dir, 'App.csproj'), '<Project Sdk="Microsoft.NET.Sdk"></Project>');
    }
    const r = await NATIVE.analyze(dir);
    return r.findings || [];
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
}

const authzFindings = f => f.filter(x => /no authorization requirement/.test(x.title || ''));
const csrfFindings = f => f.filter(x => /anti-forgery token/.test(x.title || ''));

const UNPROTECTED = [
  'using System.Web.Http;',
  'namespace App.Controllers {',
  '  public class LoansController : ApiController {',
  '    [Route("api/Loans")]',
  '    [HttpPost]',
  '    public IHttpActionResult Create(object dto) { return Ok(); }',
  '  }',
  '}'
].join('\n');

describe('cs-controller-no-authorization', () => {
  test('a mutating controller with no [Authorize] and no global filter is CRITICAL', async () => {
    const f = authzFindings(await analyse({ 'Controllers/LoansController.cs': UNPROTECTED }));
    assert.equal(f.length, 1, 'expected exactly one authorization finding');
    assert.equal(f[0].severity, 'CRITICAL');
    assert.ok(f[0].cwe.includes('CWE-862'));
    assert.match(f[0].title, /LoansController/);
    assert.match(f[0].location.file, /LoansController\.cs$/);
  });

  test('a class-level [Authorize] clears it', async () => {
    const src = UNPROTECTED.replace('  public class', '  [Authorize]\n  public class');
    assert.equal(authzFindings(await analyse({ 'Controllers/LoansController.cs': src })).length, 0);
  });

  test('a method-level [Authorize] clears it', async () => {
    const src = UNPROTECTED.replace('    [HttpPost]', '    [Authorize]\n    [HttpPost]');
    assert.equal(authzFindings(await analyse({ 'Controllers/LoansController.cs': src })).length, 0);
  });

  test('a global authorization filter registered in another file clears every controller', async () => {
    const files = {
      'Controllers/LoansController.cs': UNPROTECTED,
      'Controllers/CardsController.cs': UNPROTECTED.replace(/Loans/g, 'Cards'),
      'App_Start/WebApiConfig.cs': [
        'using System.Web.Http;',
        'public static class WebApiConfig {',
        '  public static void Register(HttpConfiguration config) {',
        '    config.Filters.Add(new AuthorizeAttribute());',
        '  }',
        '}'
      ].join('\n')
    };
    assert.equal(authzFindings(await analyse(files)).length, 0,
      'deny-by-default is already in force, so there is nothing to report');
  });

  test('a read-only controller is reported, but below a mutating one', async () => {
    const src = UNPROTECTED.replace('[HttpPost]', '[HttpGet]');
    const f = authzFindings(await analyse({ 'Controllers/LoansController.cs': src }));
    assert.equal(f.length, 1);
    assert.equal(f[0].severity, 'HIGH', 'readable without auth is serious but not CRITICAL');
  });

  test('a plain class that is not a controller is ignored', async () => {
    const src = 'namespace App { public class LoanService { public void Create() {} } }';
    assert.equal(authzFindings(await analyse({ 'Services/LoanService.cs': src })).length, 0);
  });

  test('a controller with no action verbs at all is ignored', async () => {
    const src = [
      'namespace App.Controllers {',
      '  public class BaseController : ApiController {',
      '    protected string Helper() { return "x"; }',
      '  }',
      '}'
    ].join('\n');
    assert.equal(authzFindings(await analyse({ 'Controllers/BaseController.cs': src })).length, 0);
  });
});

describe('anti-forgery severity follows the authentication model', () => {
  test('bearer-token auth downgrades CSRF, because there are no ambient credentials', async () => {
    const files = {
      'Controllers/LoansController.cs': UNPROTECTED,
      'TokenBasedAuth/Startup.cs': [
        'using Microsoft.Owin.Security.OAuth;',
        'public class Startup {',
        '  public void Configure() {',
        '    var options = new OAuthAuthorizationServerOptions { AllowInsecureHttp = false };',
        '  }',
        '}'
      ].join('\n')
    };
    const f = csrfFindings(await analyse(files));
    assert.equal(f.length, 1);
    assert.equal(f[0].severity, 'LOW');
    assert.equal(f[0].confidence, 'POSSIBLE');
    assert.match(f[0].impact, /bearer tokens/,
      'the finding must explain why it is low, not just assert it');
  });

  test('cookie auth anywhere keeps CSRF at HIGH', async () => {
    const files = {
      'Controllers/LoansController.cs': UNPROTECTED,
      'Auth/Startup.cs': [
        'public class Startup {',
        '  public void Configure() { app.UseCookieAuthentication(new CookieAuthenticationOptions()); }',
        '}'
      ].join('\n')
    };
    const f = csrfFindings(await analyse(files));
    assert.equal(f.length, 1);
    assert.equal(f[0].severity, 'HIGH');
    assert.equal(f[0].confidence, 'LIKELY');
  });

  test('an explicit ValidateAntiForgeryToken clears the finding entirely', async () => {
    const src = UNPROTECTED.replace('    [HttpPost]', '    [ValidateAntiForgeryToken]\n    [HttpPost]');
    assert.equal(csrfFindings(await analyse({ 'Controllers/LoansController.cs': src })).length, 0);
  });
});
