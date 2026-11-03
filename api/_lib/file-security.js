import { inflateRawSync } from 'node:zlib';
import { createHash, timingSafeEqual } from 'node:crypto';

const DEFAULTS = Object.freeze({ maxEntries: 64, maxUncompressedBytes: 25 * 1024 * 1024, maxEntryBytes: 10 * 1024 * 1024, maxRatio: 25, maxImagePixels: 25_000_000, maxImageDimension: 8192 });

const CRC32_TABLE = (() => {
  const table = new Uint32Array(256);
  for (let index = 0; index < 256; index++) {
    let value = index;
    for (let bit = 0; bit < 8; bit++) value = (value & 1) ? (0xedb88320 ^ (value >>> 1)) : (value >>> 1);
    table[index] = value >>> 0;
  }
  return table;
})();

/** IEEE 802.3 / ZIP CRC-32 (polynomial 0xEDB88320). */
export function calculateZipCrc32(input) {
  const bytes = Buffer.from(input || []);
  let crc = 0xffffffff;
  for (const byte of bytes) crc = CRC32_TABLE[(crc ^ byte) & 0xff] ^ (crc >>> 8);
  return (crc ^ 0xffffffff) >>> 0;
}

function dimensions(width, height, limits) {
  if (!width || !height || width > limits.maxImageDimension || height > limits.maxImageDimension || width * height > limits.maxImagePixels) return { safe: false, width, height, reason: 'IMAGE_PIXEL_LIMIT' };
  return { safe: true, width, height };
}

export function inspectImageHeader(input, options = {}) {
  const buffer = Buffer.from(input || []);
  const limits = { ...DEFAULTS, ...options };
  if (buffer.length < 10) return { safe: false, reason: 'IMAGE_HEADER_TRUNCATED' };
  if (buffer.subarray(0, 8).equals(Buffer.from([137,80,78,71,13,10,26,10]))) {
    if (buffer.length < 24 || buffer.toString('ascii', 12, 16) !== 'IHDR') return { safe: false, reason: 'PNG_IHDR_INVALID' };
    return dimensions(buffer.readUInt32BE(16), buffer.readUInt32BE(20), limits);
  }
  if (buffer.toString('ascii', 0, 3) === 'GIF') return dimensions(buffer.readUInt16LE(6), buffer.readUInt16LE(8), limits);
  if (buffer[0] === 0xff && buffer[1] === 0xd8) {
    let offset = 2;
    while (offset + 4 <= buffer.length) {
      if (buffer[offset] !== 0xff) { offset++; continue; }
      while (buffer[offset] === 0xff) offset++;
      const marker = buffer[offset++];
      if (marker === 0xd9 || marker === 0xda) break;
      if (marker === 0x01 || (marker >= 0xd0 && marker <= 0xd7)) continue;
      if (offset + 2 > buffer.length) break;
      const length = buffer.readUInt16BE(offset);
      if (length < 2 || offset + length > buffer.length) return { safe: false, reason: 'JPEG_SEGMENT_INVALID' };
      if ([0xc0,0xc1,0xc2,0xc3,0xc5,0xc6,0xc7,0xc9,0xca,0xcb,0xcd,0xce,0xcf].includes(marker)) {
        if (length < 7) return { safe: false, reason: 'JPEG_SOF_INVALID' };
        return dimensions(buffer.readUInt16BE(offset + 5), buffer.readUInt16BE(offset + 3), limits);
      }
      offset += length;
    }
    return { safe: false, reason: 'JPEG_DIMENSIONS_NOT_FOUND' };
  }
  return { safe: false, reason: 'UNSUPPORTED_IMAGE_FORMAT' };
}

function safeArchivePath(name) {
  const value = String(name).replaceAll('\\', '/');
  if (!value || value.includes('\0') || value.startsWith('/') || /^[a-z]:/i.test(value)) return false;
  const parts = value.split('/');
  return !parts.some((part) => part === '..' || part === '.');
}


function safeZipExtraFields(buffer, offset, length) {
  const end = offset + length;
  if (end > buffer.length) return false;
  while (offset < end) {
    if (offset + 4 > end) return false;
    const id = buffer.readUInt16LE(offset);
    const size = buffer.readUInt16LE(offset + 2);
    offset += 4;
    if (offset + size > end || id === 0x0001 || id === 0x7075 || id === 0x6375) return false;
    offset += size;
  }
  return offset === end;
}

function decodeZipName(buffer, flags) {
  if ((flags & 0x0800) === 0) {
    if ([...buffer].some((byte) => byte > 0x7f)) throw new Error('ZIP_NON_ASCII_NAME_WITHOUT_UTF8_FLAG');
    return buffer.toString('ascii');
  }
  const value = new TextDecoder('utf-8', { fatal: true }).decode(buffer);
  if (value.includes('\ufffd')) throw new Error('ZIP_UTF8_NAME_INVALID');
  return value;
}

function findEocd(buffer) {
  const min = Math.max(0, buffer.length - 65_557);
  for (let offset = buffer.length - 22; offset >= min; offset--) if (buffer.readUInt32LE(offset) === 0x06054b50) return offset;
  return -1;
}

/** Bounded ZIP central-directory inspection; ZIP64 and encrypted entries are rejected. */
export function inspectZipBuffer(input, options = {}) {
  const buffer = Buffer.from(input || []);
  const limits = { ...DEFAULTS, ...options };
  if (buffer.length < 22) return { safe: false, reason: 'ZIP_TRUNCATED', entries: [] };
  const eocd = findEocd(buffer);
  if (eocd < 0) return { safe: false, reason: 'ZIP_EOCD_MISSING', entries: [] };
  const disk = buffer.readUInt16LE(eocd + 4);
  const centralDisk = buffer.readUInt16LE(eocd + 6);
  const entriesOnDisk = buffer.readUInt16LE(eocd + 8);
  const entryCount = buffer.readUInt16LE(eocd + 10);
  const centralSize = buffer.readUInt32LE(eocd + 12);
  const centralOffset = buffer.readUInt32LE(eocd + 16);
  const commentLength = buffer.readUInt16LE(eocd + 20);
  if (disk || centralDisk || entriesOnDisk !== entryCount || entryCount === 0xffff || centralSize === 0xffffffff || centralOffset === 0xffffffff) return { safe: false, reason: 'ZIP_MULTIDISK_OR_ZIP64_UNSUPPORTED', entries: [] };
  if (entryCount > limits.maxEntries || eocd + 22 + commentLength > buffer.length || centralOffset + centralSize !== eocd) return { safe: false, reason: 'ZIP_DIRECTORY_LIMIT_OR_BOUNDS', entries: [] };
  let offset = centralOffset;
  let totalUncompressed = 0;
  const entries = [];
  const seenNames = new Set();
  const seenLocalOffsets = new Set();
  const localRecordRanges = [];
  for (let index = 0; index < entryCount; index++) {
    if (offset + 46 > buffer.length || buffer.readUInt32LE(offset) !== 0x02014b50) return { safe: false, reason: 'ZIP_CENTRAL_ENTRY_INVALID', entries };
    const flags = buffer.readUInt16LE(offset + 8);
    const method = buffer.readUInt16LE(offset + 10);
    const crc32 = buffer.readUInt32LE(offset + 16);
    const compressedSize = buffer.readUInt32LE(offset + 20);
    const uncompressedSize = buffer.readUInt32LE(offset + 24);
    const nameLength = buffer.readUInt16LE(offset + 28);
    const extraLength = buffer.readUInt16LE(offset + 30);
    const entryCommentLength = buffer.readUInt16LE(offset + 32);
    const diskStart = buffer.readUInt16LE(offset + 34);
    const externalAttributes = buffer.readUInt32LE(offset + 38);
    const localOffset = buffer.readUInt32LE(offset + 42);
    const end = offset + 46 + nameLength + extraLength + entryCommentLength;
    if (end > buffer.length || diskStart !== 0 || compressedSize === 0xffffffff || uncompressedSize === 0xffffffff || localOffset === 0xffffffff) return { safe: false, reason: 'ZIP_ENTRY_BOUNDS_OR_ZIP64', entries };
    const extraStart = offset + 46 + nameLength;
    if (!safeZipExtraFields(buffer, extraStart, extraLength)) return { safe: false, reason: 'ZIP_UNSAFE_EXTRA_FIELDS', entries };
    let name;
    try { name = decodeZipName(buffer.subarray(offset + 46, offset + 46 + nameLength), flags); } catch { return { safe: false, reason: 'ZIP_FILENAME_ENCODING_INVALID', entries }; }
    if (name.normalize('NFKC') !== name || /[\u0000-\u001f\u007f]/.test(name)) return { safe: false, reason: 'ZIP_FILENAME_NONCANONICAL', entry: name, entries };
    // Normalize separators and case for cross-platform extraction semantics;
    // reject aliases instead of letting the extraction library choose a winner.
    const canonicalName = name.replaceAll('\\', '/').normalize('NFKC').toLowerCase();
    if (seenNames.has(canonicalName)) return { safe: false, reason: 'ZIP_DUPLICATE_NAME', entry: name, entries };
    seenNames.add(canonicalName);
    if (seenLocalOffsets.has(localOffset)) return { safe: false, reason: 'ZIP_LOCAL_RECORD_ALIAS', entry: name, entries };
    seenLocalOffsets.add(localOffset);
    const unixMode = (externalAttributes >>> 16) & 0o170000;
    if (!safeArchivePath(name)) return { safe: false, reason: 'ZIP_PATH_TRAVERSAL', entry: name, entries };
    if (unixMode === 0o120000) return { safe: false, reason: 'ZIP_SYMLINK', entry: name, entries };
    if ((flags & 1) !== 0 || ![0, 8].includes(method)) return { safe: false, reason: 'ZIP_ENCRYPTED_OR_UNSUPPORTED_COMPRESSION', entry: name, entries };
    if (uncompressedSize > limits.maxEntryBytes || compressedSize > buffer.length || (compressedSize === 0 ? uncompressedSize > 0 : uncompressedSize / compressedSize > limits.maxRatio)) return { safe: false, reason: 'ZIP_ENTRY_EXPANSION_LIMIT', entry: name, entries };
    totalUncompressed += uncompressedSize;
    if (totalUncompressed > limits.maxUncompressedBytes) return { safe: false, reason: 'ZIP_TOTAL_EXPANSION_LIMIT', entry: name, entries };
    if (localOffset + 30 > buffer.length || buffer.readUInt32LE(localOffset) !== 0x04034b50) return { safe: false, reason: 'ZIP_LOCAL_HEADER_INVALID', entry: name, entries };
    const localFlags = buffer.readUInt16LE(localOffset + 6);
    const localMethod = buffer.readUInt16LE(localOffset + 8);
    const localCrc = buffer.readUInt32LE(localOffset + 14);
    const localCompressedSize = buffer.readUInt32LE(localOffset + 18);
    const localUncompressedSize = buffer.readUInt32LE(localOffset + 22);
    const localNameLength = buffer.readUInt16LE(localOffset + 26);
    const localExtraLength = buffer.readUInt16LE(localOffset + 28);
    const localVariableEnd = localOffset + 30 + localNameLength + localExtraLength;
    if (localVariableEnd > buffer.length || !safeZipExtraFields(buffer, localOffset + 30 + localNameLength, localExtraLength)) return { safe: false, reason: 'ZIP_UNSAFE_LOCAL_EXTRA_FIELDS', entry: name, entries };
    let localName;
    try { localName = decodeZipName(buffer.subarray(localOffset + 30, localOffset + 30 + localNameLength), localFlags); } catch { return { safe: false, reason: 'ZIP_LOCAL_FILENAME_ENCODING_INVALID', entries }; }
    const usesDataDescriptor = (flags & 0x0008) !== 0;
    const localMetadataMatches = usesDataDescriptor
      ? ([0, crc32].includes(localCrc) && [0, compressedSize].includes(localCompressedSize) && [0, uncompressedSize].includes(localUncompressedSize))
      : (localCrc === crc32 && localCompressedSize === compressedSize && localUncompressedSize === uncompressedSize);
    if (localFlags !== flags || localMethod !== method || localName !== name || !localMetadataMatches) return { safe: false, reason: 'ZIP_LOCAL_CENTRAL_MISMATCH', entry: name, entries };
    const dataStart = localVariableEnd;
    const dataEnd = dataStart + compressedSize;
    if (dataStart < localOffset + 30 || dataEnd > buffer.length || dataEnd > centralOffset) return { safe: false, reason: 'ZIP_DATA_BOUNDS', entry: name, entries };
    let descriptorEnd = dataEnd;
    if (usesDataDescriptor) {
      let descriptorOffset = dataEnd;
      if (descriptorOffset + 4 <= centralOffset && buffer.readUInt32LE(descriptorOffset) === 0x08074b50) descriptorOffset += 4;
      if (descriptorOffset + 12 > centralOffset) return { safe: false, reason: 'ZIP_DATA_DESCRIPTOR_MISSING', entry: name, entries };
      const descriptorCrc = buffer.readUInt32LE(descriptorOffset);
      const descriptorCompressed = buffer.readUInt32LE(descriptorOffset + 4);
      const descriptorUncompressed = buffer.readUInt32LE(descriptorOffset + 8);
      if (descriptorCrc !== crc32 || descriptorCompressed !== compressedSize || descriptorUncompressed !== uncompressedSize) return { safe: false, reason: 'ZIP_DATA_DESCRIPTOR_MISMATCH', entry: name, entries };
      descriptorEnd = descriptorOffset + 12;
    }
    localRecordRanges.push({ start: localOffset, end: descriptorEnd, name });
    entries.push({ name, method, crc32, compressedSize, uncompressedSize, dataStart, dataEnd, descriptorEnd });
    offset = end;
  }
  if (offset !== centralOffset + centralSize) return { safe: false, reason: 'ZIP_DIRECTORY_SIZE_MISMATCH', entries };
  localRecordRanges.sort((left, right) => left.start - right.start || left.end - right.end);
  for (let index = 1; index < localRecordRanges.length; index++) {
    if (localRecordRanges[index].start < localRecordRanges[index - 1].end) {
      return { safe: false, reason: 'ZIP_LOCAL_RECORD_OVERLAP', entry: localRecordRanges[index].name, entries };
    }
  }
  return { safe: true, totalUncompressed, entries };
}

export function readZipEntry(buffer, entry, { maxOutputLength = DEFAULTS.maxEntryBytes } = {}) {
  const source = Buffer.from(buffer).subarray(entry.dataStart, entry.dataEnd);
  let output;
  if (entry.method === 0) {
    if (source.length > maxOutputLength) throw new RangeError('ZIP_ENTRY_OUTPUT_LIMIT');
    output = Buffer.from(source);
  } else if (entry.method === 8) {
    output = inflateRawSync(source, { maxOutputLength });
  } else {
    throw new Error('ZIP_COMPRESSION_UNSUPPORTED');
  }
  if (output.length !== entry.uncompressedSize) throw new Error('ZIP_UNCOMPRESSED_SIZE_MISMATCH');
  if (Number.isInteger(entry.crc32) && calculateZipCrc32(output) !== (entry.crc32 >>> 0)) throw new Error('ZIP_CRC32_MISMATCH');
  return output;
}

export function inspectPdfActiveContent(input) {
  const buffer = Buffer.from(input || []);
  if (buffer.length > 25 * 1024 * 1024) return { safe: false, reason: 'PDF_SIZE_LIMIT' };
  if (!buffer.subarray(0, 5).equals(Buffer.from('%PDF-'))) return { safe: false, reason: 'PDF_MAGIC_INVALID' };
  const text = buffer.toString('latin1');
  const patterns = [/\/JavaScript\b/i, /\/JS\b/i, /\/Launch\b/i, /\/OpenAction\b/i, /\/AA\b/i, /\/EmbeddedFiles\b/i];
  const matches = patterns.filter((pattern) => pattern.test(text)).map((pattern) => pattern.source);
  return matches.length ? { safe: false, reason: 'PDF_ACTIVE_CONTENT', matches } : { safe: true };
}

export function inspectOfficeArchive(input, options = {}) {
  const result = inspectZipBuffer(input, options);
  if (!result.safe) return result;
  const suspicious = result.entries.filter((entry) => /(?:^|\/)(?:vbaProject\.bin|oleObject\d+\.bin)$/i.test(entry.name) || /macrosheets|activex/i.test(entry.name));
  if (suspicious.length) return { safe: false, reason: 'OFFICE_ACTIVE_CONTENT', entries: suspicious.map((item) => item.name) };
  try {
    for (const entry of result.entries) {
      const expanded = readZipEntry(input, entry, { maxOutputLength: Math.min(DEFAULTS.maxEntryBytes, options.maxEntryBytes ?? DEFAULTS.maxEntryBytes) });
      if (expanded.length !== entry.uncompressedSize) return { safe: false, reason: 'ZIP_UNCOMPRESSED_SIZE_MISMATCH', entry: entry.name };
    }
  } catch { return { safe: false, reason: 'ZIP_DECOMPRESSION_INVALID' }; }
  return { safe: true, entries: result.entries.length };
}

export function createQuarantineRecord(buffer, { projectId, reason, now = Date.now() } = {}) {
  if (!projectId || !reason) throw new TypeError('projectId and reason are required');
  const bytes = Buffer.from(buffer || []);
  return Object.freeze({ schema: 'arix.quarantine.v1', projectId: String(projectId), sha256: createHash('sha256').update(bytes).digest('hex'), size: bytes.length, reason: String(reason).slice(0, 128), createdAt: now, status: 'QUARANTINED' });
}

export function verifyQuarantineHash(buffer, record) {
  const actual = Buffer.from(createHash('sha256').update(Buffer.from(buffer || [])).digest('hex'));
  const expected = Buffer.from(String(record?.sha256 || ''));
  return expected.length === actual.length && timingSafeEqual(expected, actual);
}
