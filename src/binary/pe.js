'use strict';
/**
 * PE/COFF container reader — the layer every other binary module stands on.
 *
 * Parses the raw bytes against the documented [MS PE/COFF] layout:
 *   DOS header (MZ) -> e_lfanew -> 'PE\0\0' -> COFF header -> optional header
 *   -> data directories (16 entries) -> section table.
 *
 * Two rules govern this file:
 *   1. Every read is bounds-checked. A malformed or truncated file returns null — it never
 *      throws and never guesses at an offset past the end of the buffer.
 *   2. If a structure is not present (e.g. no CLR directory, no debug directory) the field is
 *      null or an empty array. Absence is reported as absence.
 */

const MACHINE_NAMES = {
  0x014c: 'x86',
  0x01c0: 'ARM',
  0x01c4: 'ARM Thumb-2',
  0x01c6: 'ARMv8 (32-bit)',
  0x01f0: 'PowerPC',
  0x0200: 'IA-64',
  0x5032: 'RISC-V 32-bit',
  0x5064: 'RISC-V 64-bit',
  0x8664: 'x64',
  0xaa64: 'ARM64'
};

const SUBSYSTEM_NAMES = {
  1: 'native',
  2: 'windows-gui',
  3: 'console',
  7: 'posix-cui',
  9: 'windows-ce',
  10: 'efi-application',
  16: 'windows-boot-application'
};

const DEBUG_TYPES = {
  0: 'unknown',
  1: 'coff',
  2: 'codeview-pdb',
  4: 'fpo',
  6: 'misc',
  9: 'borland',
  10: 'clang',
  12: 'vc-feature',
  13: 'pococodeview-pdb',
  16: 'repro',
  17: 'ex-dll-characteristics',
  20: 'src-links',
  21: 'embeddable-pdb'
};

/** Read a null-terminated ASCII string at `off`, capped at `max` bytes. */
function asciiZ(buf, off, max = 260) {
  const end = Math.min(buf.length, off + max);
  let i = off;
  while (i < end && buf[i] !== 0) i++;
  return buf.toString('latin1', off, i);
}

/**
 * Parse the PE headers. Returns null when the buffer is not a PE at all or is truncated
 * partway through a header. Returns { sections, rvaToOffset, ... } on success.
 */
function parsePe(buf) {
  if (!Buffer.isBuffer(buf) || buf.length < 0x40) return null;
  if (buf.readUInt16LE(0) !== 0x5a4d) return null;             // 'MZ'

  const eLfanew = buf.readUInt32LE(0x3c);
  if (!eLfanew || eLfanew + 24 > buf.length) return null;
  if (buf.readUInt32LE(eLfanew) !== 0x00004550) return null;   // 'PE\0\0'

  const coff = eLfanew + 4;                                     // COFF header
  const machine = buf.readUInt16LE(coff);
  const numberOfSections = buf.readUInt16LE(coff + 2);
  const timeStamp = buf.readUInt32LE(coff + 4);
  const sizeOfOptionalHeader = buf.readUInt16LE(coff + 16);
  const characteristics = buf.readUInt16LE(coff + 18);

  const opt = coff + 20;                                        // optional header
  if (opt + 2 > buf.length) return null;
  const magic = buf.readUInt16LE(opt);
  const pe32Plus = magic === 0x20b;
  if (magic !== 0x10b && !pe32Plus) return null;                // not PE32/PE32+ (ROM, unknown)

  // Data directories sit after the fixed part of the optional header: 96 bytes for PE32,
  // 112 for PE32+, immediately preceded by NumberOfRvaAndSizes.
  const ddOffset = opt + (pe32Plus ? 112 : 96);
  if (ddOffset + 4 > buf.length) return null;
  const numberOfRvaAndSizes = buf.readUInt32LE(ddOffset - 4);
  const dataDirectory = (i) => {
    if (i >= numberOfRvaAndSizes || ddOffset + i * 8 + 8 > buf.length) return { rva: 0, size: 0 };
    return { rva: buf.readUInt32LE(ddOffset + i * 8), size: buf.readUInt32LE(ddOffset + i * 8 + 4) };
  };

  // Section table immediately follows the optional header.
  const sectionsStart = opt + sizeOfOptionalHeader;
  if (sectionsStart + numberOfSections * 40 > buf.length) return null;
  const sections = [];
  for (let s = 0; s < numberOfSections; s++) {
    const base = sectionsStart + s * 40;
    sections.push({
      name: asciiZ(buf, base, 8),
      virtualSize: buf.readUInt32LE(base + 8),
      virtualAddress: buf.readUInt32LE(base + 12),
      sizeOfRawData: buf.readUInt32LE(base + 16),
      pointerToRawData: buf.readUInt32LE(base + 20)
    });
  }

  const rvaToOffset = (rva) => {
    if (!rva) return 0;
    for (const s of sections) {
      const span = Math.max(s.virtualSize, s.sizeOfRawData);
      if (rva >= s.virtualAddress && rva < s.virtualAddress + span) {
        const off = s.pointerToRawData + (rva - s.virtualAddress);
        return off < buf.length ? off : 0;
      }
    }
    return 0;   // RVA not backed by any section — never guess
  };

  return {
    eLfanew,
    machine,
    machineName: MACHINE_NAMES[machine] || `machine-0x${machine.toString(16)}`,
    isDll: (characteristics & 0x2000) !== 0,
    characteristics,
    timeStamp,
    timeStampIso: timeStamp
      ? new Date(timeStamp * 1000).toISOString().replace(/\.\d+Z$/, 'Z')
      : null,
    pe32Plus,
    subsystem: buf.readUInt16LE(opt + 68),
    subsystemName: SUBSYSTEM_NAMES[buf.readUInt16LE(opt + 68)] || `subsystem-${buf.readUInt16LE(opt + 68)}`,
    sections,
    comDirectory: dataDirectory(14),        // CLR Runtime Header
    debugDirectory: dataDirectory(6),
    rvaToOffset
  };
}

/**
 * Parse IMAGE_DEBUG_DIRECTORY entries. Returns an array (possibly empty):
 *   { type, typeName, timeStamp, sizeOfData, pdbPath?, pdbGuid?, pdbAge? }
 * Only codeview ('RSDS'/'NB10') entries are decoded down to the PDB path.
 */
function parseDebugDirectory(buf, pe) {
  const dir = pe.debugDirectory;
  const out = [];
  if (!dir || !dir.rva || !dir.size) return out;
  const base = pe.rvaToOffset(dir.rva);
  if (!base || base + dir.size > buf.length) return out;

  const count = Math.floor(dir.size / 28);        // sizeof(IMAGE_DEBUG_DIRECTORY)
  for (let i = 0; i < count; i++) {
    const e = base + i * 28;
    const type = buf.readUInt32LE(e + 12);
    const sizeOfData = buf.readUInt32LE(e + 16);
    const addressOfRawData = buf.readUInt32LE(e + 20);
    const pointerToRawData = buf.readUInt32LE(e + 24);
    const entry = {
      type,
      typeName: DEBUG_TYPES[type] || `type-${type}`,
      timeStamp: buf.readUInt32LE(e + 4),
      sizeOfData
    };
    const dataOff = pointerToRawData || pe.rvaToOffset(addressOfRawData);
    if (dataOff && dataOff + Math.min(sizeOfData, 1024) <= buf.length) {
      if (type === 2 && sizeOfData >= 24) {       // IMAGE_DEBUG_TYPE_CODEVIEW
        const sig = buf.toString('latin1', dataOff, dataOff + 4);
        if (sig === 'RSDS') {
          entry.pdbPath = asciiZ(buf, dataOff + 24, Math.min(sizeOfData - 24, 1024));
          entry.pdbGuid = buf.toString('hex', dataOff + 4, dataOff + 20);
          entry.pdbAge = buf.readUInt32LE(dataOff + 20);
        } else if (sig === 'NB10') {
          entry.pdbPath = asciiZ(buf, dataOff + 16, Math.min(sizeOfData - 16, 1024));
          entry.pdbAge = buf.readUInt32LE(dataOff + 12);
        } else {
          entry.pdbFormat = sig;
        }
      }
    }
    out.push(entry);
  }
  return out;
}

module.exports = { parsePe, parseDebugDirectory, MACHINE_NAMES, DEBUG_TYPES };
