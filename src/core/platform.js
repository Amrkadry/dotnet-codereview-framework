'use strict';
/**
 * Where are we actually running, and what does a path mean here?
 *
 * This framework is used from three shells that disagree about paths: PowerShell/cmd on
 * Windows, Git Bash on Windows (which presents D: as /d), and WSL or native Linux (which
 * presents D: as /mnt/d). A user who copies a path out of one shell and runs moraa in
 * another used to get silence rather than an error: `discover /d/Projects/App` resolved
 * to the non-existent C:\d\Projects\App under Windows node, found no projects, and then
 * reported a confident "0 projects" with findings derived from that emptiness.
 *
 * Translation is deliberately conservative. A path that already exists is NEVER rewritten,
 * so a real directory called /mnt or /d on a Linux box keeps working; translation is only
 * attempted when the literal path does not resolve, and only when the alternative does.
 */

const fs = require('fs');
const os = require('os');
const path = require('path');

/** True when this Linux kernel is actually WSL. */
function detectWsl() {
  if (process.platform !== 'linux') return false;
  if (process.env.WSL_DISTRO_NAME || process.env.WSL_INTEROP) return true;
  try {
    return /microsoft|wsl/i.test(fs.readFileSync('/proc/version', 'utf8'));
  } catch { return false; }
}

/** True when this Windows process is running under a POSIX shell (Git Bash / MSYS / Cygwin). */
function detectPosixShellOnWindows() {
  if (process.platform !== 'win32') return false;
  return !!(process.env.MSYSTEM || process.env.TERM === 'cygwin' ||
    /\b(bash|sh)(\.exe)?$/i.test(process.env.SHELL || ''));
}

function describe() {
  const wsl = detectWsl();
  return {
    platform: process.platform,
    isWindows: process.platform === 'win32',
    isLinux: process.platform === 'linux',
    isMac: process.platform === 'darwin',
    isWsl: wsl,
    // A WSL process can reach the Windows filesystem through /mnt; a plain Linux box cannot.
    canReachWindowsDrives: wsl || (process.platform === 'win32'),
    posixShellOnWindows: detectPosixShellOnWindows(),
    label: process.platform === 'win32' ? 'Windows'
      : wsl ? 'WSL (' + (process.env.WSL_DISTRO_NAME || 'linux') + ')'
        : process.platform === 'linux' ? 'Linux'
          : process.platform === 'darwin' ? 'macOS' : process.platform,
    arch: os.arch()
  };
}

/**
 * Candidate rewrites of a path between the three shells' conventions.
 * Returns the alternatives in preference order; the caller decides which exists.
 */
function translations(input) {
  const p = String(input || '');
  const out = [];
  const WIN_SEP = String.fromCharCode(92);  // literal backslash, kept out of regex sources
  const fwd = p.split(WIN_SEP).join('/');

  // /mnt/d/x  (WSL)      -> d:/x
  // /d/x      (Git Bash) -> d:/x
  // /cygdrive/d/x        -> d:/x
  let m = /^\/mnt\/([a-zA-Z])(\/.*)?$/.exec(fwd) ||
          /^\/cygdrive\/([a-zA-Z])(\/.*)?$/.exec(fwd) ||
          /^\/([a-zA-Z])(\/.*)?$/.exec(fwd);
  if (m) out.push(m[1] + ':' + (m[2] || '/'));

  // d:/x -> /mnt/d/x and /d/x, for the reverse direction
  m = /^([a-zA-Z]):(\/.*)?$/.exec(fwd);
  if (m) {
    const drive = m[1].toLowerCase();
    const rest = m[2] || '/';
    out.push('/mnt/' + drive + rest);
    out.push('/' + drive + rest);
  }
  return out;
}

/**
 * Resolve a user-supplied path, accepting any of the three shells' conventions.
 *
 * Never rewrites a path that already exists. Returns { path, translatedFrom } so a caller
 * can tell the user what happened — a silent rewrite would be its own kind of lie.
 */
function resolveUserPath(input) {
  const raw = String(input == null ? '' : input);
  const direct = path.resolve(raw);
  if (fs.existsSync(direct)) return { path: direct, translatedFrom: null };
  // Also accept the literal string when it exists unresolved (POSIX absolute under Windows node).
  if (fs.existsSync(raw)) return { path: raw, translatedFrom: null };

  for (const alt of translations(raw)) {
    const resolved = path.resolve(alt);
    if (fs.existsSync(resolved)) return { path: resolved, translatedFrom: raw };
    if (fs.existsSync(alt)) return { path: alt, translatedFrom: raw };
  }
  // Nothing matched: hand back the ordinary resolution so the caller reports "not found"
  // against the path the user actually typed.
  return { path: direct, translatedFrom: null };
}

module.exports = { describe, detectWsl, translations, resolveUserPath };
