'use strict';
/**
 * Tests for cross-shell path handling (src/core/platform.js) and the scanner installer
 * (src/install/index.js).
 *
 * The path tests exist because of a real failure: `moraa discover /d/Projects/App` run under
 * Windows node resolved a directory that does not exist, scanned nothing, and then reported a
 * confident "0 projects" with findings derived from that emptiness. A wrong answer that looks
 * like a right one is the worst outcome this framework can produce, so the translation is
 * pinned here against a real temporary directory rather than a mock.
 *
 * The installer tests assert the safety property that matters: a plan never mutates the
 * machine. Nothing here shells out to a package manager.
 */
const { test, describe } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

const PLATFORM = require('../src/core/platform');
const INSTALL = require('../src/install');

describe('platform description', () => {
  test('reports exactly one operating system', () => {
    const d = PLATFORM.describe();
    const flags = [d.isWindows, d.isLinux, d.isMac].filter(Boolean);
    assert.equal(flags.length, 1, 'exactly one of isWindows/isLinux/isMac must be true');
    assert.ok(d.label && typeof d.label === 'string');
    assert.ok(d.arch && typeof d.arch === 'string');
  });

  test('WSL is only ever claimed on linux', () => {
    const d = PLATFORM.describe();
    if (d.isWsl) assert.ok(d.isLinux, 'isWsl implies isLinux');
  });
});

describe('path translation between shells', () => {
  test('WSL and Git Bash drive paths both map to a drive letter', () => {
    assert.deepEqual(PLATFORM.translations('/mnt/d/Projects'), ['d:/Projects']);
    assert.deepEqual(PLATFORM.translations('/d/Projects'), ['d:/Projects']);
    assert.deepEqual(PLATFORM.translations('/cygdrive/d/Projects'), ['d:/Projects']);
  });

  test('a Windows path maps back to both POSIX conventions', () => {
    assert.deepEqual(PLATFORM.translations('D:/Projects'), ['/mnt/d/Projects', '/d/Projects']);
  });

  test('a backslash Windows path is understood too', () => {
    const p = 'D:' + String.fromCharCode(92) + 'Projects';
    assert.deepEqual(PLATFORM.translations(p), ['/mnt/d/Projects', '/d/Projects']);
  });

  test('a bare drive root keeps a trailing slash rather than becoming "d:"', () => {
    assert.deepEqual(PLATFORM.translations('/mnt/d'), ['d:/']);
  });

  test('a multi-segment POSIX path that is not a drive is left alone', () => {
    // /usr/local is two segments where the first is not a single letter: nothing to translate.
    assert.deepEqual(PLATFORM.translations('/usr/local'), []);
  });
});

describe('resolveUserPath', () => {
  test('an existing path is returned untouched and never reported as translated', () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'moraa-plat-'));
    try {
      const r = PLATFORM.resolveUserPath(dir);
      assert.equal(r.translatedFrom, null, 'a path that already exists must not be rewritten');
      assert.equal(path.resolve(r.path), path.resolve(dir));
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });

  test('a path that resolves nowhere is handed back as typed, so the error names it', () => {
    const missing = path.join(os.tmpdir(), 'moraa-does-not-exist-' + Date.now());
    const r = PLATFORM.resolveUserPath(missing);
    assert.equal(r.translatedFrom, null);
    assert.equal(r.path, path.resolve(missing));
  });

  test('the drive form of a real directory is found from the other shell convention', () => {
    const d = PLATFORM.describe();
    // Only meaningful where both conventions can address the same filesystem.
    if (!d.isWindows) return;
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'moraa-plat-'));
    try {
      const resolved = path.resolve(dir);
      const m = /^([a-zA-Z]):[\\/](.*)$/.exec(resolved);
      if (!m) return;
      const posix = '/' + m[1].toLowerCase() + '/' + m[2].split(path.sep).join('/');
      const r = PLATFORM.resolveUserPath(posix);
      assert.equal(r.translatedFrom, posix, 'the Git Bash form should be recognised as a translation');
      assert.equal(path.resolve(r.path).toLowerCase(), resolved.toLowerCase());
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });
});

describe('installer plan', () => {
  test('a plan is inert: it reports state and never installs anything', () => {
    const p = INSTALL.plan([]);
    assert.ok(Array.isArray(p.items) && p.items.length > 0);
    for (const it of p.items) {
      assert.equal(typeof it.name, 'string');
      assert.equal(typeof it.installed, 'boolean');
      assert.ok(it.why && it.why.length > 20, 'every tool states why it is worth installing');
      // Either this machine has a recipe, or the tool is reported as a manual download.
      assert.ok(it.command || it.manual, 'a tool must be installable or documented');
    }
  });

  test('an unknown tool is surfaced rather than silently dropped', () => {
    const p = INSTALL.plan(['definitely-not-a-scanner']);
    assert.deepEqual(p.unknown, ['definitely-not-a-scanner']);
    assert.equal(p.items.length, 0, 'an unknown name must not quietly expand to every tool');
  });

  test('naming one tool plans only that tool', () => {
    const p = INSTALL.plan(['gitleaks']);
    assert.equal(p.items.length, 1);
    assert.equal(p.items[0].name, 'gitleaks');
    assert.deepEqual(p.unknown, []);
  });

  test('every recipe is a bare argv, never a shell string', () => {
    for (const [name, r] of Object.entries(INSTALL.RECIPES)) {
      assert.ok(r.probe, name + ' must declare the binary to probe');
      assert.ok(r.manual && /^https:/.test(r.manual), name + ' must carry an https fallback URL');
      for (const [mgr, recipe] of Object.entries(r.by)) {
        assert.equal(typeof recipe[0], 'string', name + '/' + mgr + ' binary');
        assert.ok(Array.isArray(recipe[1]), name + '/' + mgr + ' args must be an array');
        // Shell metacharacters would mean the recipe relies on a shell we do not spawn.
        for (const a of recipe[1]) {
          assert.ok(!/[;&|><`$]/.test(a),
            name + '/' + mgr + ' arg "' + a + '" must not need a shell');
        }
      }
    }
  });

  test('elevation is only ever claimed for system package managers, never on Windows', () => {
    assert.equal(INSTALL.needsPrivilege('npm'), false);
    assert.equal(INSTALL.needsPrivilege('go'), false);
    if (process.platform === 'win32') {
      assert.equal(INSTALL.needsPrivilege('apt'), false, 'no sudo on Windows');
    } else {
      assert.equal(INSTALL.needsPrivilege('apt'), true);
      assert.equal(INSTALL.needsPrivilege('dnf'), true);
    }
  });
});
