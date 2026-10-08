// dotnet-codereview-framework — src/binary/metadata.js
// Author: Amr Kadry (github.com/Amrkadry) · MIT License
'use strict';
/**
 * ECMA-335 Partition II metadata reader — heaps and the compressed '#~' table stream.
 *
 * Layout (ECMA-335 II.24):
 *   'BSJB' root -> version string -> stream headers -> streams
 *   '#Strings'  UTF-8 heap, null-terminated entries
 *   '#US'       user strings, UTF-16LE, compressed-length prefixed
 *   '#Blob'     blobs, compressed-length prefixed
 *   '#GUID'     16-byte GUIDs
 *   '#~'        table stream: header, row counts, then rows of every present table back-to-back
 *
 * The hard part is row layout: rows are variable width because heap indexes and coded indexes
 * are 2 or 4 bytes depending on heap sizes and the largest row count among the tables a coded
 * index spans (II.24.2.6). The full II.22 schema for tables 0x00-0x2B is therefore declared
 * below, so a walk never has to guess. A table this file does not model (0x30+, i.e. portable
 * PDB tables) aborts the walk — the caller gets everything parsed so far plus `unresolvedFrom`,
 * per the "return null rather than guessing" rule.
 */

const crypto = require('crypto');

// ---------------------------------------------------------------- schema declarations (II.22)

const T = {
  MODULE: 0x00, TYPEREF: 0x01, TYPEDEF: 0x02, FIELD: 0x04, METHODDEF: 0x06, PARAM: 0x08,
  INTERFACEIMPL: 0x09, MEMBERREF: 0x0A, CONSTANT: 0x0B, CUSTOMATTRIBUTE: 0x0C,
  FIELDMARSHAL: 0x0D, DECLSECURITY: 0x0E, CLASSLAYOUT: 0x0F, FIELDLAYOUT: 0x10,
  STANDALONESIG: 0x11, EVENTMAP: 0x12, EVENT: 0x14, PROPERTYMAP: 0x15, PROPERTY: 0x17,
  METHODSEMANTICS: 0x18, METHODIMPL: 0x19, MODULEREF: 0x1A, TYPESPEC: 0x1B, IMPLMAP: 0x1C,
  FIELDRVA: 0x1D, ENCLOG: 0x1E, ENCMAP: 0x1F, ASSEMBLY: 0x20, ASSEMBLYPROCESSOR: 0x21,
  ASSEMBLYOS: 0x22, ASSEMBLYREF: 0x23, ASSEMBLYREFPROCESSOR: 0x24, ASSEMBLYREFOS: 0x25,
  FILE: 0x26, EXPORTEDTYPE: 0x27, MANIFESTRESOURCE: 0x28, NESTEDCLASS: 0x29,
  GENERICPARAM: 0x2A, METHODSPEC: 0x2B, GENERICPARAMCONSTRAINT: 0x2C
};

const TABLE_NAMES = {
  0x00: 'Module', 0x01: 'TypeRef', 0x02: 'TypeDef', 0x03: 'FieldPtr', 0x04: 'Field',
  0x05: 'MethodPtr', 0x06: 'MethodDef', 0x07: 'ParamPtr', 0x08: 'Param', 0x09: 'InterfaceImpl',
  0x0A: 'MemberRef', 0x0B: 'Constant', 0x0C: 'CustomAttribute', 0x0D: 'FieldMarshal',
  0x0E: 'DeclSecurity', 0x0F: 'ClassLayout', 0x10: 'FieldLayout', 0x11: 'StandAloneSig',
  0x12: 'EventMap', 0x13: 'EventPtr', 0x14: 'Event', 0x15: 'PropertyMap', 0x16: 'PropertyPtr',
  0x17: 'Property', 0x18: 'MethodSemantics', 0x19: 'MethodImpl', 0x1A: 'ModuleRef',
  0x1B: 'TypeSpec', 0x1C: 'ImplMap', 0x1D: 'FieldRVA', 0x1E: 'ENCLog', 0x1F: 'ENCMap',
  0x20: 'Assembly', 0x21: 'AssemblyProcessor', 0x22: 'AssemblyOS', 0x23: 'AssemblyRef',
  0x24: 'AssemblyRefProcessor', 0x25: 'AssemblyRefOS', 0x26: 'File', 0x27: 'ExportedType',
  0x28: 'ManifestResource', 0x29: 'NestedClass', 0x2A: 'GenericParam',
  0x2B: 'MethodSpec', 0x2C: 'GenericParamConstraint'
};

// Column kinds: u1/u2/u4 fixed; str/guid/blob heap indexes; idx a simple table index;
// coded a coded index over the listed tables (tag bits = ceil(log2(n)), II.24.2.6).
const SCHEMAS = {
  0x00: [['Generation', 'u2'], ['Name', 'str'], ['Mvid', 'guid'], ['EncId', 'guid'], ['EncBaseId', 'guid']],
  0x01: [['ResolutionScope', ['coded', [T.MODULE, T.MODULEREF, T.ASSEMBLYREF, T.TYPEREF]]], ['Name', 'str'], ['Namespace', 'str']],
  0x02: [['Flags', 'u4'], ['Name', 'str'], ['Namespace', 'str'],
    ['Extends', ['coded', [T.TYPEDEF, T.TYPEREF, T.TYPESPEC]]],
    ['FieldList', ['idx', T.FIELD]], ['MethodList', ['idx', T.METHODDEF]]],
  0x03: [['Field', ['idx', T.FIELD]]],
  0x04: [['Flags', 'u2'], ['Name', 'str'], ['Signature', 'blob']],
  0x05: [['Method', ['idx', T.METHODDEF]]],
  0x06: [['RVA', 'u4'], ['ImplFlags', 'u2'], ['Flags', 'u2'], ['Name', 'str'], ['Signature', 'blob'], ['ParamList', ['idx', T.PARAM]]],
  0x07: [['Param', ['idx', T.PARAM]]],
  0x08: [['Flags', 'u2'], ['Sequence', 'u2'], ['Name', 'str']],
  0x09: [['Class', ['idx', T.TYPEDEF]], ['Interface', ['coded', [T.TYPEDEF, T.TYPEREF, T.TYPESPEC]]]],
  0x0A: [['Class', ['coded', [T.TYPEDEF, T.TYPEREF, T.TYPESPEC]]], ['Name', 'str'], ['Signature', 'blob']],
  0x0B: [['Type', 'u1'], ['Pad', 'u1'], ['Parent', ['coded', [T.FIELD, T.PARAM, T.PROPERTY]]], ['Value', 'blob']],
  0x0C: [['Parent', ['coded', [T.METHODDEF, T.FIELD, T.TYPEREF, T.TYPEDEF, T.PARAM, T.INTERFACEIMPL,
    T.MEMBERREF, T.MODULE, T.DECLSECURITY, T.PROPERTY, T.EVENT, T.STANDALONESIG, T.MODULEREF,
    T.TYPESPEC, T.ASSEMBLY, T.ASSEMBLYREF, T.FILE, T.EXPORTEDTYPE, T.MANIFESTRESOURCE,
    T.GENERICPARAM, T.GENERICPARAMCONSTRAINT]]],
  // CustomAttributeType: tags 0,1,4-7 unused; 2 = MethodDef, 3 = MemberRef (3 tag bits).
  ['Type', ['coded', [null, null, T.METHODDEF, T.MEMBERREF, null, null, null, null]]],
  ['Value', 'blob']],
  0x0D: [['NativeType', 'blob'], ['Parent', ['coded', [T.FIELD, T.PARAM]]]],
  0x0E: [['Action', 'u2'], ['Parent', ['coded', [T.TYPEDEF, T.METHODDEF, T.ASSEMBLY]]], ['PermissionSet', 'blob']],
  0x0F: [['PackingSize', 'u2'], ['ClassSize', 'u4'], ['Parent', ['idx', T.TYPEDEF]]],
  0x10: [['Offset', 'u4'], ['Field', ['idx', T.FIELD]]],
  0x11: [['Signature', 'blob']],
  0x12: [['Parent', ['idx', T.TYPEDEF]], ['EventList', ['idx', T.EVENT]]],
  0x13: [['Event', ['idx', T.EVENT]]],
  0x14: [['EventFlags', 'u2'], ['Name', 'str'], ['EventType', ['coded', [T.TYPEDEF, T.TYPEREF, T.TYPESPEC]]]],
  0x15: [['Parent', ['idx', T.TYPEDEF]], ['PropertyList', ['idx', T.PROPERTY]]],
  0x16: [['Property', ['idx', T.PROPERTY]]],
  0x17: [['Flags', 'u2'], ['Name', 'str'], ['Type', 'blob']],
  0x18: [['Semantics', 'u2'], ['Method', ['idx', T.METHODDEF]], ['Association', ['coded', [T.EVENT, T.PROPERTY]]]],
  0x19: [['Class', ['idx', T.TYPEDEF]], ['MethodBody', ['coded', [T.METHODDEF, T.MEMBERREF]]],
    ['MethodDeclaration', ['coded', [T.METHODDEF, T.MEMBERREF]]]],
  0x1A: [['Name', 'str']],
  0x1B: [['Signature', 'blob']],
  0x1C: [['MappingFlags', 'u2'], ['MemberForwarded', ['coded', [T.FIELD, T.METHODDEF]]],
    ['ImportName', 'str'], ['ImportScope', ['idx', T.MODULEREF]]],
  0x1D: [['RVA', 'u4'], ['Field', ['idx', T.FIELD]]],
  0x1E: [['Token', 'u4'], ['FuncCode', 'u4']],
  0x1F: [['Token', 'u4']],
  0x20: [['HashAlgId', 'u4'], ['MajorVersion', 'u2'], ['MinorVersion', 'u2'], ['BuildNumber', 'u2'],
    ['RevisionNumber', 'u2'], ['Flags', 'u4'], ['PublicKey', 'blob'], ['Name', 'str'], ['Culture', 'str']],
  0x21: [['Processor', 'u4']],
  0x22: [['OSPlatformID', 'u4'], ['OSMajorVersion', 'u4'], ['OSMinorVersion', 'u4']],
  0x23: [['MajorVersion', 'u2'], ['MinorVersion', 'u2'], ['BuildNumber', 'u2'], ['RevisionNumber', 'u2'],
    ['Flags', 'u4'], ['PublicKeyOrToken', 'blob'], ['Name', 'str'], ['Culture', 'str'], ['HashValue', 'blob']],
  0x24: [['Processor', 'u4'], ['AssemblyRef', ['idx', T.ASSEMBLYREF]]],
  0x25: [['OSPlatformID', 'u4'], ['OSMajorVersion', 'u4'], ['OSMinorVersion', 'u4'], ['AssemblyRef', ['idx', T.ASSEMBLYREF]]],
  0x26: [['Flags', 'u4'], ['Name', 'str'], ['HashValue', 'blob']],
  0x27: [['Flags', 'u4'], ['TypeDefId', 'u4'], ['Name', 'str'], ['Namespace', 'str'],
    ['Implementation', ['coded', [T.FILE, T.EXPORTEDTYPE, T.ASSEMBLYREF]]]],
  0x28: [['Offset', 'u4'], ['Flags', 'u4'], ['Name', 'str'],
    ['Implementation', ['coded', [T.FILE, T.EXPORTEDTYPE, T.ASSEMBLYREF]]]],
  0x29: [['NestedClass', ['idx', T.TYPEDEF]], ['EnclosingClass', ['idx', T.TYPEDEF]]],
  0x2A: [['Number', 'u2'], ['Flags', 'u2'], ['Owner', ['coded', [T.TYPEDEF, T.METHODDEF]]], ['Name', 'str']],
  0x2B: [['Method', ['coded', [T.METHODDEF, T.MEMBERREF]]], ['Instantiation', 'blob']],   // MethodSpec (CorHdr.h mdtMethodSpec = 0x2B)
  0x2C: [['Owner', ['idx', T.GENERICPARAM]], ['Constraint', ['coded', [T.TYPEDEF, T.TYPEREF, T.TYPESPEC]]]]  // GenericParamConstraint
};

// ------------------------------------------------------------------ bounds-checked primitives

const u1 = (buf, off) => (off < buf.length ? buf[off] : null);
const u2 = (buf, off) => (off + 2 <= buf.length ? buf.readUInt16LE(off) : null);
const u4 = (buf, off) => (off + 4 <= buf.length ? buf.readUInt32LE(off) : null);

/** ECMA-335 II.23.2 compressed unsigned integer. Returns { value, size } or null. */
function readCompressedUint(buf, off) {
  const b0 = u1(buf, off);
  if (b0 === null) return null;
  if ((b0 & 0x80) === 0) return { value: b0, size: 1 };
  if ((b0 & 0xc0) === 0x80) {
    const b1 = u1(buf, off + 1);
    return b1 === null ? null : { value: ((b0 & 0x3f) << 8) | b1, size: 2 };
  }
  if ((b0 & 0xe0) === 0xc0) {
    const b1 = u1(buf, off + 1), b2 = u1(buf, off + 2), b3 = u1(buf, off + 3);
    return b1 === null || b2 === null || b3 === null
      ? null
      : { value: ((b0 & 0x1f) << 24) | (b1 << 16) | (b2 << 8) | b3, size: 4 };
  }
  return null;                                   // 0xE0-0xFF reserved
}

// ------------------------------------------------------------------------------ heap readers

/**
 * Parse the 'BSJB' metadata root at absolute file offset `base`.
 * Returns { version, streams: { name -> {offset (absolute), size} } } or null.
 */
function parseMetadataRoot(buf, base) {
  if (!base || base + 16 > buf.length) return null;
  if (buf.toString('latin1', base, base + 4) !== 'BSJB') return null;
  const verLen = u4(buf, base + 12);
  if (verLen === null || verLen > 2048) return null;
  let off = base + 16 + ((verLen + 3) & ~3);      // version string, 4-byte aligned
  const flags = u2(buf, off);
  const nStreams = u2(buf, off + 2);
  if (flags === null || nStreams === null || nStreams > 16) return null;
  off += 4;

  const streams = {};
  for (let i = 0; i < nStreams; i++) {
    const sOff = u4(buf, off);
    const sSize = u4(buf, off + 4);
    if (sOff === null || sSize === null) return null;
    let nameEnd = off + 8;
    const nameStart = nameEnd;
    while (nameEnd < buf.length && buf[nameEnd] !== 0) nameEnd++;
    if (nameEnd === buf.length) return null;
    const name = buf.toString('latin1', nameStart, nameEnd);
    streams[name] = { offset: base + sOff, size: sSize };
    off = nameEnd + 1;
    off = (off + 3) & ~3;                          // names are 4-byte aligned
  }
  return { version: buf.toString('latin1', base + 16, base + 16 + verLen).replace(/\0.*$/, ''), streams };
}

/** #Strings heap: entries are null-terminated UTF-8, index points at the first byte. */
function makeStringsHeap(buf, heap) {
  if (!heap || heap.offset + heap.size > buf.length) return null;
  const base = heap.offset;
  return (idx) => {
    if (idx === 0) return '';                       // offset 0 is the mandatory empty string
    if (idx >= heap.size) return null;
    let end = base + idx;
    const cap = base + heap.size;
    while (end < cap && buf[end] !== 0) end++;
    return buf.toString('utf8', base + idx, end);
  };
}

/** #Blob heap entry (without its length prefix), or null. */
function blobAt(buf, heap, idx) {
  if (!heap || !idx || idx >= heap.size) return null;
  const r = readCompressedUint(buf, heap.offset + idx);
  if (!r || !r.value) return r && r.value === 0 ? Buffer.alloc(0) : null;
  const start = heap.offset + idx + r.size;
  if (start + r.value > buf.length) return null;
  return buf.subarray(start, start + r.value);
}

/**
 * #US heap: a chain of entries, each compressed-length prefixed UTF-16LE with one trailing
 * "contains non-ASCII" flag byte counted inside the length. Returns [{ index, value }].
 */
function readUserStrings(buf, heap, maxEntries = 20000) {
  const out = [];
  if (!heap || heap.offset + heap.size > buf.length) return out;
  let idx = 1;                                     // entry 0 is the mandatory null string
  while (idx < heap.size && out.length < maxEntries) {
    const r = readCompressedUint(buf, heap.offset + idx);
    if (!r) break;
    if (r.value === 0) { idx += r.size; continue; }
    const start = heap.offset + idx + r.size;
    if (start + r.value > heap.offset + heap.size) break;
    try {
      const s = buf.toString('utf16le', start, start + r.value - 1);
      if (s) out.push({ index: idx, value: s });
    } catch { /* decode gap: keep walking */ }
    idx += r.size + r.value;
  }
  return out;
}

// ------------------------------------------------------------------------------ table stream

// ---------------------------------------------------------------- table-row sanity validation
//
// Per ECMA-335 the width of a coded index is 4 bytes iff the largest table it spans exceeds
// 2^(16-tagbits)-1 rows. That rule is violated in the wild by some real-world writers (e.g. some
// .NET Framework images emit MemberRef.Class 4 bytes wide regardless of row counts). A wrong
// width does not fail loudly — it silently shifts every later table. So each table's chosen
// width is validated against a structural predicate on its first rows, and spec-first fallback
// candidates (wider coded/idx columns) are tried when validation fails. The variant actually
// used is recorded per table — nothing is guessed silently.

const codedOk = (col, v, ctx, allowNil, extraBits) => {
  const tables = col[1];
  const bits = Math.ceil(Math.log2(tables.length)) + (extraBits || 0);
  const tag = v & ((1 << bits) - 1);
  const row = v >> bits;
  if (tag >= tables.length) return false;
  const t = tables[tag];
  if (t === null) return row === 0;                 // unused tags encode row 0
  if (row === 0) return !!allowNil;                 // nil only where the schema allows it
  return row <= (ctx.rowCounts[t] || 0);
};
// A coded value is plausible if it splits cleanly at the standard tag width or one bit wider
// (some writers emit an extra tag bit; e.g. csc.exe-era images with 3-bit TypeDefOrRef tags).
const CODED_REF = (col, v, ctx, allowNil) =>
  codedOk(col, v, ctx, allowNil, 0) || codedOk(col, v, ctx, allowNil, 1);
const REF = (tn, v, ctx, slack) => v >= 1 && v <= ((ctx.rowCounts[tn] || 0) + (slack || 0));
const STR = (v, ctx) => {
  if (v >= ctx.stringSize) return false;
  const s = ctx.stringsAt ? ctx.stringsAt(v) : null;
  if (s === null) return v === ctx.stringSize;      // index one past the end is legal for Culture
  return s === '' || /^[\x20-\x7e\u00a0-\uffff]{0,120}/.test(s);
};
const BLOB = (v, ctx) => v < ctx.blobSize;

const VALIDATORS = {
  0x00: (r, c) => STR(r.Name, c) && REF('guid', r.Mvid, c, 2),
  0x01: (r, c) => STR(r.Name, c) && (r.Namespace === 0 || STR(r.Namespace, c)) &&
    CODED_REF(SCHEMAS[0x01][0][1], r.ResolutionScope, c),
  0x02: (r, c) => STR(r.Name, c) && CODED_REF(SCHEMAS[0x02][3][1], r.Extends, c, true) &&
    REF(T.FIELD, r.FieldList, c, 1) && REF(T.METHODDEF, r.MethodList, c, 1),
  0x04: (r, c) => STR(r.Name, c) && BLOB(r.Signature, c),
  0x06: (r, c) => STR(r.Name, c) && BLOB(r.Signature, c) && REF(T.PARAM, r.ParamList, c, 1),
  0x08: (r, c) => STR(r.Name, c),
  0x09: (r, c) => REF(T.TYPEDEF, r.Class, c) && CODED_REF(SCHEMAS[0x09][1][1], r.Interface, c),
  0x0a: (r, c) => CODED_REF(SCHEMAS[0x0a][0][1], r.Class, c) && STR(r.Name, c) && BLOB(r.Signature, c),
  0x0b: (r, c) => (r.Type & 0x1f) <= 0x1b && r.Pad === 0 && BLOB(r.Value, c),
  0x0c: (r, c) => CODED_REF(SCHEMAS[0x0c][0][1], r.Parent, c) &&
    CODED_REF(SCHEMAS[0x0c][1][1], r.Type, c) && BLOB(r.Value, c),
  0x0d: (r, c) => BLOB(r.NativeType, c) && CODED_REF(SCHEMAS[0x0d][1][1], r.Parent, c),
  0x0e: (r, c) => r.Action >= 1 && r.Action <= 24 && CODED_REF(SCHEMAS[0x0e][1][1], r.Parent, c) && BLOB(r.PermissionSet, c),
  0x0f: (r, c) => REF(T.TYPEDEF, r.Parent, c),
  0x10: (r, c) => REF(T.FIELD, r.Field, c),
  0x11: (r, c) => BLOB(r.Signature, c),
  0x12: (r, c) => REF(T.TYPEDEF, r.Parent, c) && REF(T.EVENT, r.EventList, c, 1),
  0x14: (r, c) => STR(r.Name, c) && CODED_REF(SCHEMAS[0x14][2][1], r.EventType, c),
  0x15: (r, c) => REF(T.TYPEDEF, r.Parent, c) && REF(T.PROPERTY, r.PropertyList, c, 1),
  0x17: (r, c) => STR(r.Name, c) && BLOB(r.Type, c),
  0x18: (r, c) => [1, 2, 4, 8, 0x10, 0x20, 0x40, 0x80].includes(r.Semantics) &&
    REF(T.METHODDEF, r.Method, c) && CODED_REF(SCHEMAS[0x18][2][1], r.Association, c),
  0x19: (r, c) => REF(T.TYPEDEF, r.Class, c) && CODED_REF(SCHEMAS[0x19][1][1], r.MethodBody, c) &&
    CODED_REF(SCHEMAS[0x19][2][1], r.MethodDeclaration, c),
  0x1a: (r, c) => STR(r.Name, c),
  0x1b: (r, c) => BLOB(r.Signature, c),
  0x1c: (r, c) => CODED_REF(SCHEMAS[0x1c][1][1], r.MemberForwarded, c) && STR(r.ImportName, c) &&
    REF(T.MODULEREF, r.ImportScope, c, 1),
  0x1d: (r, c) => REF(T.FIELD, r.Field, c),
  0x20: (r, c) => (r.HashAlgId === 0 || (r.HashAlgId >= 0x8001 && r.HashAlgId <= 0x800c)) &&
    STR(r.Name, c) && (r.Culture === 0 || STR(r.Culture, c)) && BLOB(r.PublicKey, c),
  0x23: (r, c) => STR(r.Name, c) && (r.Culture === 0 || STR(r.Culture, c)) &&
    BLOB(r.PublicKeyOrToken, c) && BLOB(r.HashValue, c),
  0x24: (r, c) => REF(T.ASSEMBLYREF, r.AssemblyRef, c),
  0x25: (r, c) => REF(T.ASSEMBLYREF, r.AssemblyRef, c),
  0x26: (r, c) => STR(r.Name, c) && BLOB(r.HashValue, c),
  0x27: (r, c) => STR(r.Name, c) && (r.Namespace === 0 || STR(r.Namespace, c)) &&
    CODED_REF(SCHEMAS[0x27][4][1], r.Implementation, c, true),
  0x28: (r, c) => (r.Flags & ~1) === 0 && STR(r.Name, c) && CODED_REF(SCHEMAS[0x28][3][1], r.Implementation, c, true),
  0x29: (r, c) => REF(T.TYPEDEF, r.NestedClass, c) && REF(T.TYPEDEF, r.EnclosingClass, c),
  0x2a: (r, c) => r.Number >= 0 && CODED_REF(SCHEMAS[0x2a][2][1], r.Owner, c) && STR(r.Name, c),
  0x2b: (r, c) => CODED_REF(SCHEMAS[0x2b][0][1], r.Method, c) && BLOB(r.Instantiation, c),
  0x2c: (r, c) => REF(T.GENERICPARAM, r.Owner, c) && CODED_REF(SCHEMAS[0x2c][1][1], r.Constraint, c)
};

function rowIsPlausible(t, rows, ctx) {
  const check = VALIDATORS[t];
  if (!check) return true;                          // no predicate: accept silently is NOT ok, so
                                                    // callers restrict wanted to validated tables
  return rows.every(r => { try { return check(r, ctx); } catch { return false; } });
}

/**
 * Parse the '#~' (compressed) table stream.
 * `wanted` lists the table ids to decode; `heapCtx` = { stringsAt, stringSize, blobSize }
 * enables width validation. Returns { rowCounts, heapSizes, tables, unresolvedFrom, widthsUsed,
 * unverified, widthResidual }.
 *
 * WIDTH RESOLUTION. Per ECMA-335 a coded index is 4 bytes iff the largest table it spans exceeds
 * 2^(16-tagbits)-1 rows, but some real-world writers violate that (e.g. .NET Framework images
 * that emit MemberRef.Class 4 bytes wide regardless of row counts), and a wrong width shifts
 * every later table SILENTLY. Two defences, neither of which guesses:
 *   1. per-table structural validation of the chosen width against the first rows;
 *   2. the GLOBAL constraint that the chain of table rows must land exactly on the stream end.
 * A depth-first search over spec-first width variants finds the combination satisfying both;
 * the variant used per table is recorded. If nothing satisfies the boundary, spec widths are
 * used and the unvalidatable tables are listed in `unverified`, with the byte residual in
 * `widthResidual` — visible, never silent.
 */
function parseTableStream(buf, stream, wanted, heapCtx) {
  if (!stream || stream.offset + 24 > buf.length) return null;
  const base = stream.offset;
  const heapSizesByte = u1(buf, base + 6);
  const valid = buf.readBigUInt64LE(base + 8);
  if (heapSizesByte === null) return null;

  const heapSizes = {
    strings: (heapSizesByte & 0x01) !== 0,
    guid: (heapSizesByte & 0x02) !== 0,
    blob: (heapSizesByte & 0x04) !== 0
  };

  // Row counts, one u4 per set bit in Valid, ascending.
  const present = [];
  for (let t = 0; t <= 63; t++) if ((valid >> BigInt(t)) & 1n) present.push(t);
  let off = base + 24;
  const rowCounts = {};
  for (const t of present) {
    const n = u4(buf, off);
    if (n === null) return null;
    rowCounts[t] = n;
    off += 4;
  }

  const colSize = (col) => {
    const kind = Array.isArray(col) ? col[0] : col;
    if (kind === 'u1') return 1;
    if (kind === 'u2') return 2;
    if (kind === 'u4') return 4;
    if (kind === 'str') return heapSizes.strings ? 4 : 2;
    if (kind === 'guid') return heapSizes.guid ? 4 : 2;
    if (kind === 'blob') return heapSizes.blob ? 4 : 2;
    if (kind === 'idx') return (rowCounts[col[1]] || 0) > 0xffff ? 4 : 2;
    if (kind === 'coded') {
      const tables = col[1];
      const bits = Math.ceil(Math.log2(tables.length));
      const max = Math.max(...tables.map(tn => rowCounts[tn] || 0));
      return max > ((1 << (16 - bits)) - 1) ? 4 : 2;
    }
    return null;
  };

  const decodeRow = (schema, sizes, at) => {
    const row = {};
    let ro = at;
    schema.forEach(([name, col], ci) => {
      const size = sizes[ci];
      const kind = Array.isArray(col) ? col[0] : col;
      if (kind === 'u1') row[name] = buf[ro];
      else if (kind === 'u2') row[name] = buf.readUInt16LE(ro);
      else if (kind === 'u4') row[name] = buf.readUInt32LE(ro);
      else row[name] = size === 4 ? u4(buf, ro) : u2(buf, ro);   // heap and coded indexes: raw
      ro += size;
    });
    return row;
  };

  const tables = {};
  const widthsUsed = {};
  const unverified = [];
  let unresolvedFrom = null;
  const vctx = Object.assign({}, heapCtx, { rowCounts });   // validators need row counts
  const streamEnd = stream.offset + stream.size;

  // Per-table width candidates: spec first, then individual widened coded/idx columns, then all.
  const candidatesFor = (t) => {
    const schema = SCHEMAS[t];
    const primary = schema.map(c => colSize(c[1]));
    if (primary.some(s => s === null)) return null;
    const bumpable = schema.map((c, i) => {
      const kind = Array.isArray(c[1]) ? c[1][0] : c[1];
      return (kind === 'coded' || kind === 'idx') && primary[i] === 2 ? i : -1;
    }).filter(i => i >= 0);
    // All subsets of bumpable columns, spec first, fewest bumps last — partial widenings occur.
    const variants = [primary];
    const limit = Math.min(bumpable.length, 4);
    for (let mask = 1; mask < (1 << limit); mask++) {
      const v = primary.slice();
      for (let b = 0; b < limit; b++) if (mask & (1 << b)) v[bumpable[b]] = 4;
      variants.push(v);
    }
    return variants;
  };

  // Depth-first search over width variants, spec-first, pruned by the stream-end boundary.
  // Metadata streams are 4-byte aligned, so the table chain may be followed by up to 3 bytes
  // of padding; landing exactly or within that padding both satisfy the constraint.
  const solutions = [];
  const MAX_NODES = 20000;
  const MAX_SOLUTIONS = 8;
  let nodes = 0;
  let hitUnknown = null;
  const landsOK = (at) => at === streamEnd || (streamEnd - at) <= 3;
  const ranksWorse = (unver, widened, best) => best &&
    (unver.length > best.unverified.length ||
      (unver.length === best.unverified.length && widened > best.widened));
  const insert = (sol) => {
    solutions.push(sol);
    solutions.sort((a, b) =>
      ((a.truncated ? 1 : 0) - (b.truncated ? 1 : 0)) ||
      (a.unverified.length - b.unverified.length) ||
      (a.widened - b.widened) ||
      (Math.abs(a.end - streamEnd) - Math.abs(b.end - streamEnd))
    );
    if (solutions.length > MAX_SOLUTIONS) solutions.length = MAX_SOLUTIONS;
  };
  const search = (idx, at, choices, widened, unver) => {
    if (nodes++ > MAX_NODES) return;
    if (solutions.length && ranksWorse(unver, widened, solutions[0])) return;  // cannot improve
    if (idx === present.length) {
      if (!landsOK(at)) return;                       // THE global constraint: land on the end
      insert({ choices: choices.slice(), unverified: unver.slice(), widened, end: at });
      return;
    }
    const t = present[idx];
    const schema = SCHEMAS[t];
    if (!schema) {                                    // table this module does not model
      hitUnknown = t;
      if (at <= streamEnd) {
        insert({ choices: choices.slice(), unverified: unver.slice(), widened, end: at, truncated: true });
      }
      return;
    }
    const n = rowCounts[t];
    if (n === 0) {
      choices.push({ t, sizes: null });
      search(idx + 1, at, choices, widened, unver);
      choices.pop();
      return;
    }
    const variants = candidatesFor(t);
    if (!variants) { hitUnknown = t; return; }
    for (const cand of variants) {
      const isSpec = cand === variants[0];
      const rowSize = cand.reduce((a, b) => a + b, 0);
      if (at + n * rowSize > streamEnd) continue;     // would overrun: prune
      let ok = false;
      if (heapCtx) {
        try {
          const probe = [];
          for (let r = 0; r < Math.min(n, 3); r++) probe.push(decodeRow(schema, cand, at + r * rowSize));
          ok = rowIsPlausible(t, probe, vctx);
        } catch { ok = false; }
      } else ok = isSpec;                             // no validation context: spec order wins
      if (!ok && !isSpec) continue;                   // widened without validation: never
      choices.push({ t, sizes: cand });
      const nxt = unver.slice();
      if (!ok) nxt.push(t);
      search(idx + 1, at + n * rowSize, choices, widened + (isSpec ? 0 : 1), nxt);
      choices.pop();
    }
  };
  search(0, off, [], 0, []);

  const best = solutions[0] || null;   // insert() keeps solutions ranked

  if (best) {
    let at = off;
    for (const choice of best.choices) {
      const t = choice.t;
      const n = rowCounts[t];
      if (n === 0) { widthsUsed[t] = 'empty'; continue; }
      const rowSize = choice.sizes.reduce((a, b) => a + b, 0);
      const isSpecWidth = SCHEMAS[t].every((c, i) => colSize(c[1]) === choice.sizes[i]);
      if (wanted.includes(t)) {
        const rows = [];
        for (let r = 0; r < n; r++) rows.push(decodeRow(SCHEMAS[t], choice.sizes, at + r * rowSize));
        tables[t] = rows;
      }
      widthsUsed[t] = choice.unverified ? 'unverified(spec)' : (isSpecWidth ? 'spec' : 'widened(' + rowSize + 'B)');
      if (choice.unverified) unverified.push(t);
      at += n * rowSize;
    }
  } else {
    // No combination satisfies the boundary: spec widths for everything, honestly recorded.
    let walk = off;
    for (const t of present) {
      const schema = SCHEMAS[t];
      if (!schema) { unresolvedFrom = t; break; }
      const n = rowCounts[t];
      if (n === 0) { widthsUsed[t] = 'empty'; continue; }
      const sizes = schema.map(c => colSize(c[1]));
      if (sizes.some(s => s === null)) { unresolvedFrom = t; break; }
      const rowSize = sizes.reduce((a, b) => a + b, 0);
      if (walk + n * rowSize > buf.length) { unresolvedFrom = t; break; }
      if (wanted.includes(t)) {
        const rows = [];
        for (let r = 0; r < n; r++) rows.push(decodeRow(schema, sizes, walk + r * rowSize));
        tables[t] = rows;
      }
      unverified.push(t);
      widthsUsed[t] = 'unverified(spec)';
      walk += n * rowSize;
    }
  }
  if (!best) unverified.push(...present.filter(t => widthsUsed[t] === undefined));
  const consumed = best ? best.end : (() => { let w = off; for (const t of present) { if (widthsUsed[t] === 'empty') continue; const s = SCHEMAS[t]; if (!s) break; const sizes = s.map(c => colSize(c[1])); if (sizes.some(x => x === null)) break; w += rowCounts[t] * sizes.reduce((a, b) => a + b, 0); } return w; })();

  return { heapSizes, rowCounts, tables, unresolvedFrom, widthsUsed, unverified, widthResidual: streamEnd - consumed };
}

/**
 * Decode a coded index { table, row } (row is 1-based per ECMA-335).
 * `tagBitsOverride` extends the standard tag width when a writer emitted wider tags.
 */
function decodeCoded(value, tables, tagBitsOverride) {
  if (value === undefined || value === null) return null;
  let bits = Math.ceil(Math.log2(tables.length)) + (tagBitsOverride || 0);
  const tag = value & ((1 << bits) - 1);
  const row = value >> bits;
  const table = tables[tag];
  return table ? { table, row } : { table: null, row };   // unused tag: report honestly
}

// ------------------------------------------------------------------------------ entry points

/**
 * Full parse for one file buffer. Combines PE + CLI + metadata. Returns a record or
 * { error } — never throws.
 */
function inspectAssemblyBuffer(buf) {
  try {
    const pe = require('./pe').parsePe(buf);
    if (!pe) return { error: 'not a PE file', managed: false };
    const debugEntries = require('./pe').parseDebugDirectory(buf, pe);
    const cli = require('./cli').describeManaged(pe, buf);
    if (!cli) return { error: null, managed: false, pe, debugEntries, native: true };
    if (cli.managed === null) return { error: cli.reason, managed: null, pe, debugEntries };

    const metaBase = pe.rvaToOffset(cli.cliHeader.metadata.rva);
    const root = parseMetadataRoot(buf, metaBase);
    if (!root) return { error: 'metadata root unreadable', managed: true, pe, debugEntries, cli };

    const tablesStream = root.streams['#~'] || root.streams['#-'] || null;
    const uncompressed = !root.streams['#~'] && !!root.streams['#-'];
    const stringsAt = makeStringsHeap(buf, root.streams['#Strings']);
    const usHeap = root.streams['#US'] || null;
    const blobHeap = root.streams['#Blob'] || null;
    const guidHeap = root.streams['#GUID'] || null;

    let ts = null;
    if (tablesStream && !uncompressed) {
      const stringsSize = root.streams['#Strings'] ? root.streams['#Strings'].size : 0;
      const blobSize = blobHeap ? blobHeap.size : 0;
      ts = parseTableStream(buf, tablesStream, [
        T.MODULE, T.TYPEREF, T.MEMBERREF, T.CUSTOMATTRIBUTE, T.ASSEMBLY, T.ASSEMBLYREF
      ], { stringsAt: makeStringsHeap(buf, root.streams['#Strings']), stringSize: stringsSize, blobSize });
    }

    // ---- Assembly table (0x20): identity of THIS assembly.
    let assembly = null;
    const asmRows = ts && ts.tables[T.ASSEMBLY];
    if (asmRows && asmRows.length && stringsAt) {
      const a = asmRows[0];
      const pk = blobAt(buf, blobHeap, a.PublicKey);
      assembly = {
        name: stringsAt(a.Name) || null,
        version: `${a.MajorVersion}.${a.MinorVersion}.${a.BuildNumber}.${a.RevisionNumber}`,
        culture: stringsAt(a.Culture) || '',
        hashAlgId: a.HashAlgId,
        publicKeyToken: pk && pk.length ? publicKeyToken(pk) : null,
        hasPublicKey: !!(pk && pk.length)
      };
    }

    // ---- Module table (0x00): module name + MVID.
    let module = null;
    const modRows = ts && ts.tables[T.MODULE];
    if (modRows && modRows.length && stringsAt) {
      module = { name: stringsAt(modRows[0].Name) || null, mvidHex: null };
    }

    // ---- AssemblyRef table (0x23): the direct dependency surface.
    const references = [];
    const refRows = (ts && ts.tables[T.ASSEMBLYREF]) || [];
    for (const r of refRows) {
      references.push({
        name: stringsAt ? (stringsAt(r.Name) || '?') : '?',
        version: `${r.MajorVersion}.${r.MinorVersion}.${r.BuildNumber}.${r.RevisionNumber}`,
        culture: stringsAt ? (stringsAt(r.Culture) || '') : '',
        publicKeyOrToken: !!r.PublicKeyOrToken,
        retargetable: (r.Flags & 0x1) !== 0
      });
    }

    // ---- CustomAttribute resolution: TypeRef + MemberRef name lookup.
    const typeRefName = (row) => {
      const rows = ts && ts.tables[T.TYPEREF];
      if (!rows || !rows[row - 1] || !stringsAt) return null;
      const r = rows[row - 1];
      return { namespace: stringsAt(r.Namespace) || '', name: stringsAt(r.Name) || '' };
    };
    const memberRefTarget = (row) => {
      const rows = ts && ts.tables[T.MEMBERREF];
      if (!rows || !rows[row - 1] || !stringsAt) return null;
      const r = rows[row - 1];
      const cls = decodeCoded(r.Class, [T.TYPEDEF, T.TYPEREF, T.TYPESPEC]);
      const className = cls && cls.table === T.TYPEREF ? typeRefName(cls.row) : null;
      return { name: stringsAt(r.Name) || '', class: className };
    };

    const attributes = [];
    const caRows = (ts && ts.tables[T.CUSTOMATTRIBUTE]) || [];
    for (const ca of caRows) {
      const type = decodeCoded(ca.Type, [null, null, T.METHODDEF, T.MEMBERREF, null, null, null, null]);
      if (!type) continue;
      let ctorName = null, cls = null;
      if (type.table === T.MEMBERREF) {
        const mr = memberRefTarget(type.row);
        if (mr) { ctorName = mr.name; cls = mr.class; }
      }
      // Attribute identity is (class name, '.ctor'); keep the blob for the caller to decode.
      if (cls && ctorName === '.ctor') {
        attributes.push({
          parent: decodeCoded(ca.Parent, [T.METHODDEF, T.FIELD, T.TYPEREF, T.TYPEDEF, T.PARAM,
            T.INTERFACEIMPL, T.MEMBERREF, T.MODULE, T.DECLSECURITY, T.PROPERTY, T.EVENT,
            T.STANDALONESIG, T.MODULEREF, T.TYPESPEC, T.ASSEMBLY, T.ASSEMBLYREF, T.FILE,
            T.EXPORTEDTYPE, T.MANIFESTRESOURCE, T.GENERICPARAM, T.GENERICPARAMCONSTRAINT]),
          typeNamespace: cls.namespace, typeName: cls.name,
          blob: blobAt(buf, blobHeap, ca.Value)
        });
      }
    }

    return {
      error: null,
      managed: true,
      pe, debugEntries, cli,
      metadata: {
        version: root.version,
        uncompressedTables: uncompressed,
        unresolvedFrom: ts ? ts.unresolvedFrom : 'stream',
        widthsUsed: ts ? ts.widthsUsed : null,
        unverifiedWidths: ts ? ts.unverified : [],
        widthResidual: ts ? ts.widthResidual : null,
        rowCountSummary: ts ? Object.fromEntries(Object.entries(ts.rowCounts).filter(([, n]) => n > 0).map(([t, n]) => [TABLE_NAMES[t] || `0x${Number(t).toString(16)}`, n])) : null
      },
      assembly, module, references, attributes,
      userStringsHeap: usHeap,
      heaps: { strings: stringsAt ? 'ok' : 'missing', blob: blobHeap ? 'ok' : 'missing', us: usHeap ? 'ok' : 'missing' }
    };
  } catch (e) {
    return { error: `parse failed: ${e.message}`, managed: null };
  }
}

/** SHA-1 of the public key BLOB, last 8 bytes in reverse byte order, hex — the ECMA-335 token. */
function publicKeyToken(publicKeyBlob) {
  try {
    const h = crypto.createHash('sha1').update(publicKeyBlob).digest();
    return Buffer.from(h.subarray(12, 20)).reverse().toString('hex');
  } catch { return null; }
}

/** Custom-attribute blob decoding (II.23.3): prolog 0x0001, then fixed args. */

/** Serialized string argument (SerString): compressed length + UTF-8 bytes. */
function attrStringArg(blob) {
  if (!blob || blob.length < 4 || blob[0] !== 0x01 || blob[1] !== 0x00) return null;
  const r = readCompressedUint(blob, 2);
  if (!r) return null;
  const start = 2 + r.size;
  if (start + r.value > blob.length) return null;
  return blob.toString('utf8', start, start + r.value);
}

/** Named-argument-free blob of N 1-byte booleans. */
function attrBoolArgs(blob, n) {
  if (!blob || blob.length < 2 + n || blob[0] !== 0x01 || blob[1] !== 0x00) return null;
  const out = [];
  for (let i = 0; i < n; i++) out.push(blob[2 + i] !== 0);
  return out;
}

/** First 4-byte little-endian integer argument (enum underlying type). */
function attrUint32Arg(blob) {
  if (!blob || blob.length < 6 || blob[0] !== 0x01 || blob[1] !== 0x00) return null;
  return blob.readUInt32LE(2);
}

module.exports = {
  TABLE_NAMES, SCHEMAS,
  readCompressedUint, parseMetadataRoot, makeStringsHeap, blobAt, readUserStrings,
  parseTableStream, decodeCoded, inspectAssemblyBuffer,
  publicKeyToken, attrStringArg, attrBoolArgs, attrUint32Arg
};
