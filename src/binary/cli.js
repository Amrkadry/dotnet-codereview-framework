'use strict';
/**
 * ECMA-335 / [MS COR] CLI header reader — decides "is this a managed .NET assembly".
 *
 * A managed PE carries the CLR Runtime Header in data directory 14. That RVA points at an
 * IMAGE_COR20_HEADER, whose metadata directory in turn points at the 'BSJB' metadata root.
 * The presence AND parseability of both is what "managed" means here — a stray nonzero
 * directory is not enough to claim it.
 *
 * Flags (ECMA-335 II.25.3.3):
 *   0x00000001 ILONLY            0x00000004 IL_LIBRARY
 *   0x00000002 32BITREQUIRED     0x00020000 32BITPREFERRED (AnyCPU, 32-bit preferred)
 *   0x00000008 STRONGNAMESIGNED  0x00000010 NATIVE_ENTRYPOINT
 */

const COR20_FLAGS = {
  IL_ONLY: 0x1,
  '32BIT_REQUIRED': 0x2,
  IL_LIBRARY: 0x4,
  STRONGNAME_SIGNED: 0x8,
  NATIVE_ENTRYPOINT: 0x10,
  TRACK_DEBUG_DATA: 0x10000,
  '32BIT_PREFERRED': 0x20000
};

const RUNTIME_VERSIONS = {
  '2.5': 'CLR 2 / .NET Framework 2.0-3.5',
  '2.0': 'CLR 1.x',
  '4.0': 'CLR 4 / .NET Framework 4.x or .NET Core/5+'
};

/**
 * Parse the IMAGE_COR20_HEADER at file offset `offset`. Returns null when the structure is
 * absent or out of bounds; never guesses.
 */
function parseCor20Header(buf, offset) {
  if (!offset || offset + 72 > buf.length) return null;   // sizeof(IMAGE_COR20_HEADER) = 72
  return {
    cb: buf.readUInt32LE(offset),
    majorRuntimeVersion: buf.readUInt16LE(offset + 4),
    minorRuntimeVersion: buf.readUInt16LE(offset + 6),
    metadata: {
      rva: buf.readUInt32LE(offset + 8),
      size: buf.readUInt32LE(offset + 12)
    },
    flags: buf.readUInt32LE(offset + 16),
    entryPointToken: buf.readUInt32LE(offset + 20),
    resources: { rva: buf.readUInt32LE(offset + 24), size: buf.readUInt32LE(offset + 28) },
    strongNameSignature: { rva: buf.readUInt32LE(offset + 32), size: buf.readUInt32LE(offset + 36) },
    vtableFixups: { rva: buf.readUInt32LE(offset + 48), size: buf.readUInt32LE(offset + 52) }
  };
}

/**
 * Decide managed-ness and derive the deployment-relevant shape of the assembly.
 * Returns null if `pe` has no CLR directory (the caller reports native), otherwise a record.
 */
function describeManaged(pe, buf) {
  const dir = pe.comDirectory;
  if (!dir.rva || !dir.size) return null;

  const header = parseCor20Header(buf, pe.rvaToOffset(dir.rva));
  if (!header) {
    // Directory nonzero but the header is not parseable — report that honestly rather than
    // claiming either managed or native.
    return { managed: null, reason: 'CLR directory present but IMAGE_COR20_HEADER unreadable' };
  }
  if (header.metadata.rva === 0 || header.metadata.size === 0) {
    return { managed: null, reason: 'CLR header present but no metadata directory' };
  }

  const f = header.flags;
  const ilOnly = (f & COR20_FLAGS.IL_ONLY) !== 0;
  const strongNameFlag = (f & COR20_FLAGS.STRONGNAME_SIGNED) !== 0;
  const hasStrongNameBlob = header.strongNameSignature.size > 0;
  const bit32Required = (f & COR20_FLAGS['32BIT_REQUIRED']) !== 0;
  const bit32Preferred = (f & COR20_FLAGS['32BIT_PREFERRED']) !== 0;

  let bitness;
  if (!ilOnly) bitness = `mixed-mode (${pe.machineName})`;
  else if (bit32Preferred) bitness = 'AnyCPU (32-bit preferred)';
  else if (bit32Required) bitness = 'x86 (32-bit required)';
  else bitness = `AnyCPU (${pe.machineName} image)`;

  const rtv = `${header.majorRuntimeVersion}.${header.minorRuntimeVersion}`;

  return {
    managed: true,
    reason: 'CLR runtime header and metadata directory present',
    cliHeader: header,
    ilOnly,
    mixedMode: !ilOnly,
    nativeEntryPoint: (f & COR20_FLAGS.NATIVE_ENTRYPOINT) !== 0,
    // Delay-signed assemblies set the flag but ship a zero-size signature; require both.
    strongNameSigned: strongNameFlag && hasStrongNameBlob,
    strongNameFlagOnly: strongNameFlag && !hasStrongNameBlob,
    runtimeVersion: rtv,
    runtimeLabel: RUNTIME_VERSIONS[rtv] || `runtime ${rtv}`,
    bitness
  };
}

module.exports = { parseCor20Header, describeManaged, COR20_FLAGS };
