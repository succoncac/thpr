/**
 * TH10 Binary Format Specification & Safe Reader/Writer Engine
 * Định dạng tệp nhị phân TH10: Header 64-byte cố định, Cascaded Triple-Stage AES-256-GCM.
 */

export const APP_NAME = "TH10";
export const EXT = ".th";
export const MAGIC_STR = "TH10";
export const MAGIC_BYTES = new Uint8Array([0x54, 0x48, 0x31, 0x30]); // "TH10"
export const FORMAT_VERSION = 1;
export const CANARY = "CANARY_PLACEHOLDER";
export const HEADER_SIZE = 64; // 64 bytes cố định
export const SALT_SIZE = 16;   // 16 bytes salt
export const NONCE_SIZE = 12;  // 12 bytes nonce mỗi tầng (x3 = 36B)
export const TAG_SIZE = 16;    // 16 bytes GCM Auth Tag mỗi tầng (x3 = 48B)
export const MAX_FILE_SIZE = 200 * 1024 * 1024; // 200 MiB giới hạn cứng

export const KDF_LIMITS = {
  MIN_MEM_KIB: 8192,
  MAX_MEM_KIB: 262144,
  MIN_ITERATIONS: 1,
  MAX_ITERATIONS: 10,
  MIN_PARALLELISM: 1,
  MAX_PARALLELISM: 4,
};

export type ErrorCode =
  | 'E_NO_FILE'
  | 'E_NO_PASSWORD'
  | 'E_PASSWORD_MISMATCH'
  | 'E_LIB'
  | 'E_TOO_LARGE'
  | 'E_TOO_SHORT'
  | 'E_BAD_MAGIC'
  | 'E_BAD_VERSION'
  | 'E_BAD_PARAMS'
  | 'E_OOM'
  | 'E_AUTH_FAIL'
  | 'E_PAYLOAD';

export const ERROR_MESSAGES: Record<ErrorCode, string> = {
  E_NO_FILE: "Vui lòng chọn tệp tin cần xử lý.",
  E_NO_PASSWORD: "Vui lòng nhập mật khẩu.",
  E_PASSWORD_MISMATCH: "Mật khẩu xác nhận không khớp.",
  E_LIB: "Không thể tải thư viện mật mã. Vui lòng kiểm tra kết nối mạng.",
  E_TOO_LARGE: "Tệp tin vượt quá kích thước tối đa cho phép (200 MB).",
  E_TOO_SHORT: "Tệp quá ngắn, không đúng cấu trúc định dạng .th.",
  E_BAD_MAGIC: "Tệp không đúng định dạng TH10 (sai Magic header).",
  E_BAD_VERSION: "Phiên bản tệp không được hỗ trợ.",
  E_BAD_PARAMS: "Tham số mật mã trong tệp không an toàn hoặc nằm ngoài giới hạn.",
  E_OOM: "Thiết bị không đủ bộ nhớ RAM để thực thi dẫn xuất khóa.",
  E_AUTH_FAIL: "Sai mật khẩu, hoặc tệp đã bị sửa/hỏng. Không thể phân biệt hai trường hợp này.",
  E_PAYLOAD: "Cấu trúc dữ liệu nội bộ bị hỏng hoặc không hợp lệ.",
};

export class AppError extends Error {
  public code: ErrorCode;
  constructor(code: ErrorCode, customMessage?: string) {
    super(customMessage || ERROR_MESSAGES[code] || "Đã xảy ra lỗi không xác định.");
    this.name = 'AppError';
    this.code = code;
  }
}

/**
 * Xóa an toàn dữ liệu nhạy cảm khỏi bộ nhớ RAM (Memory Wiping)
 */
export function wipe(buffer: ArrayBuffer | ArrayBufferView | null | undefined): void {
  if (!buffer) return;
  try {
    if (buffer instanceof Uint8Array || buffer instanceof Uint16Array || buffer instanceof Uint32Array) {
      buffer.fill(0);
    } else if (buffer instanceof ArrayBuffer) {
      new Uint8Array(buffer).fill(0);
    } else if (ArrayBuffer.isView(buffer)) {
      new Uint8Array(buffer.buffer, buffer.byteOffset, buffer.byteLength).fill(0);
    }
  } catch {
    // Không làm gián đoạn nếu buffer đã detached
  }
}

const textEnc = new TextEncoder();
const textDec = new TextDecoder('utf-8', { fatal: false });

/**
 * Safe DataWriter có kiểm tra biên giới hạn tuyệt đối
 */
export class DataWriter {
  public buffer: Uint8Array;
  public view: DataView;
  public cursor: number = 0;

  constructor(size: number) {
    this.buffer = new Uint8Array(size);
    this.view = new DataView(this.buffer.buffer, this.buffer.byteOffset, this.buffer.byteLength);
  }

  public writeU8(val: number): void {
    if (this.cursor + 1 > this.buffer.byteLength) {
      throw new AppError('E_PAYLOAD', 'Tràn bộ đệm khi ghi dữ liệu 8-bit.');
    }
    this.view.setUint8(this.cursor, val);
    this.cursor += 1;
  }

  public writeU16(val: number): void {
    if (this.cursor + 2 > this.buffer.byteLength) {
      throw new AppError('E_PAYLOAD', 'Tràn bộ đệm khi ghi dữ liệu 16-bit.');
    }
    this.view.setUint16(this.cursor, val, false); // Big-Endian
    this.cursor += 2;
  }

  public writeU32(val: number): void {
    if (this.cursor + 4 > this.buffer.byteLength) {
      throw new AppError('E_PAYLOAD', 'Tràn bộ đệm khi ghi dữ liệu 32-bit.');
    }
    this.view.setUint32(this.cursor, val, false); // Big-Endian
    this.cursor += 4;
  }

  public writeBytes(bytes: Uint8Array): void {
    if (this.cursor + bytes.byteLength > this.buffer.byteLength) {
      throw new AppError('E_PAYLOAD', 'Tràn bộ đệm khi ghi chuỗi byte nhị phân.');
    }
    this.buffer.set(bytes, this.cursor);
    this.cursor += bytes.byteLength;
  }
}

/**
 * Safe DataReader có kiểm tra biên giới hạn tuyệt đối
 */
export class DataReader {
  public buffer: Uint8Array;
  public view: DataView;
  public cursor: number = 0;

  constructor(input: ArrayBuffer | Uint8Array) {
    if (input instanceof Uint8Array) {
      this.buffer = input;
    } else {
      this.buffer = new Uint8Array(input);
    }
    this.view = new DataView(this.buffer.buffer, this.buffer.byteOffset, this.buffer.byteLength);
  }

  public remaining(): number {
    return this.buffer.byteLength - this.cursor;
  }

  public readU8(): number {
    if (this.cursor + 1 > this.buffer.byteLength) {
      throw new AppError('E_PAYLOAD', 'Vượt quá giới hạn bộ đệm khi đọc 8-bit.');
    }
    const val = this.view.getUint8(this.cursor);
    this.cursor += 1;
    return val;
  }

  public readU16(): number {
    if (this.cursor + 2 > this.buffer.byteLength) {
      throw new AppError('E_PAYLOAD', 'Vượt quá giới hạn bộ đệm khi đọc 16-bit.');
    }
    const val = this.view.getUint16(this.cursor, false); // Big-Endian
    this.cursor += 2;
    return val;
  }

  public readU32(): number {
    if (this.cursor + 4 > this.buffer.byteLength) {
      throw new AppError('E_PAYLOAD', 'Vượt quá giới hạn bộ đệm khi đọc 32-bit.');
    }
    const val = this.view.getUint32(this.cursor, false); // Big-Endian
    this.cursor += 4;
    return val;
  }

  public readBytes(length: number): Uint8Array {
    if (length < 0 || this.cursor + length > this.buffer.byteLength) {
      throw new AppError('E_PAYLOAD', 'Vượt quá giới hạn bộ đệm khi trích xuất mảng byte.');
    }
    const slice = this.buffer.subarray(this.cursor, this.cursor + length);
    this.cursor += length;
    return slice;
  }
}

export interface Header64 {
  magic: string;
  version: number;
  flags: number;
  memKiB: number;
  iterations: number;
  parallelism: number;
  salt: Uint8Array;     // 16 bytes
  nonce1: Uint8Array;   // 12 bytes
  nonce2: Uint8Array;   // 12 bytes
  nonce3: Uint8Array;   // 12 bytes
  rawBytes: Uint8Array; // Exactly 64 bytes
}

/**
 * Xây dựng Header cố định 64 bytes
 */
export function buildHeader64(
  memKiB: number,
  iterations: number,
  parallelism: number,
  salt: Uint8Array,
  nonce1: Uint8Array,
  nonce2: Uint8Array,
  nonce3: Uint8Array
): Header64 {
  if (salt.byteLength !== SALT_SIZE) {
    throw new AppError('E_PAYLOAD', 'Kích thước Salt bắt buộc phải là 16 bytes.');
  }
  if (nonce1.byteLength !== NONCE_SIZE || nonce2.byteLength !== NONCE_SIZE || nonce3.byteLength !== NONCE_SIZE) {
    throw new AppError('E_PAYLOAD', 'Mỗi Nonce bắt buộc phải có kích thước 12 bytes.');
  }

  const writer = new DataWriter(HEADER_SIZE);
  writer.writeBytes(MAGIC_BYTES);   // 0..3: "TH10"
  writer.writeU8(FORMAT_VERSION);    // 4: version = 1
  writer.writeU8(0);                 // 5: flags = 0
  writer.writeU32(memKiB);           // 6..9: memKiB
  writer.writeU8(iterations);        // 10: iterations
  writer.writeU8(parallelism);       // 11: parallelism
  writer.writeBytes(salt);           // 12..27: salt (16B)
  writer.writeBytes(nonce1);         // 28..39: nonce1 (12B)
  writer.writeBytes(nonce2);         // 40..51: nonce2 (12B)
  writer.writeBytes(nonce3);         // 52..63: nonce3 (12B)

  const rawBytes = writer.buffer;
  return {
    magic: MAGIC_STR,
    version: FORMAT_VERSION,
    flags: 0,
    memKiB,
    iterations,
    parallelism,
    salt,
    nonce1,
    nonce2,
    nonce3,
    rawBytes,
  };
}

/**
 * Phân tích và kiểm tra chặt chẽ Header cố định 64 bytes
 */
export function parseHeader64(rawBuffer: Uint8Array): Header64 {
  if (rawBuffer.byteLength < HEADER_SIZE) {
    throw new AppError('E_TOO_SHORT');
  }

  const reader = new DataReader(rawBuffer.subarray(0, HEADER_SIZE));
  const magicBytes = reader.readBytes(4);
  const magic = textDec.decode(magicBytes);
  if (magic !== MAGIC_STR) {
    throw new AppError('E_BAD_MAGIC');
  }

  const version = reader.readU8();
  if (version !== FORMAT_VERSION) {
    throw new AppError('E_BAD_VERSION');
  }

  const flags = reader.readU8();

  const memKiB = reader.readU32();
  const iterations = reader.readU8();
  const parallelism = reader.readU8();

  // Bắt buộc kiểm tra tham số KDF TRƯỚC khi thực thi
  if (
    memKiB < KDF_LIMITS.MIN_MEM_KIB ||
    memKiB > KDF_LIMITS.MAX_MEM_KIB ||
    iterations < KDF_LIMITS.MIN_ITERATIONS ||
    iterations > KDF_LIMITS.MAX_ITERATIONS ||
    parallelism < KDF_LIMITS.MIN_PARALLELISM ||
    parallelism > KDF_LIMITS.MAX_PARALLELISM
  ) {
    throw new AppError('E_BAD_PARAMS');
  }

  const salt = new Uint8Array(reader.readBytes(SALT_SIZE));
  const nonce1 = new Uint8Array(reader.readBytes(NONCE_SIZE));
  const nonce2 = new Uint8Array(reader.readBytes(NONCE_SIZE));
  const nonce3 = new Uint8Array(reader.readBytes(NONCE_SIZE));

  const rawBytes = rawBuffer.subarray(0, HEADER_SIZE);

  return {
    magic,
    version,
    flags,
    memKiB,
    iterations,
    parallelism,
    salt,
    nonce1,
    nonce2,
    nonce3,
    rawBytes,
  };
}

export interface InternalPayload {
  filename: string;
  mimeType: string;
  content: Uint8Array;
}

/**
 * Đóng gói Payload với padding ngẫu nhiên lên 64 KiB hoặc 1 MiB
 */
export function packPayload(
  filename: string,
  mimeType: string,
  contentBytes: Uint8Array
): Uint8Array {
  // Chuẩn hóa & cắt giới hạn an toàn
  const fnClean = filename.slice(0, 255);
  let fnEncoded = textEnc.encode(fnClean);
  if (fnEncoded.length > 255) {
    fnEncoded = fnEncoded.subarray(0, 255);
  }

  const mimeClean = (mimeType || 'application/octet-stream').slice(0, 127);
  let mimeEncoded = textEnc.encode(mimeClean);
  if (mimeEncoded.length > 127) {
    mimeEncoded = mimeEncoded.subarray(0, 127);
  }

  const canaryEncoded = textEnc.encode(CANARY);
  const canaryLen = canaryEncoded.length;
  if (canaryLen > 255) {
    throw new AppError('E_PAYLOAD', 'Kích thước Canary token vượt quá 255 bytes.');
  }

  const contentLen = contentBytes.byteLength;
  const rawPayloadLen = 2 + fnEncoded.length + 2 + mimeEncoded.length + 1 + canaryLen + 4 + contentLen;

  // Quy tắc Padding: 64 KiB nếu <= 16 MiB, ngược lại 1 MiB
  const BLOCK_SIZE = contentLen <= 16 * 1024 * 1024 ? 64 * 1024 : 1024 * 1024;
  const remainder = rawPayloadLen % BLOCK_SIZE;
  const paddedLen = remainder === 0 ? rawPayloadLen : rawPayloadLen + (BLOCK_SIZE - remainder);

  const writer = new DataWriter(paddedLen);
  writer.writeU16(fnEncoded.length);
  writer.writeBytes(fnEncoded);
  writer.writeU16(mimeEncoded.length);
  writer.writeBytes(mimeEncoded);
  writer.writeU8(canaryLen);
  writer.writeBytes(canaryEncoded);
  writer.writeU32(contentLen);
  writer.writeBytes(contentBytes);

  // Điền phần padding ngẫu nhiên bằng CSPRNG
  const paddingBytesNeeded = paddedLen - rawPayloadLen;
  if (paddingBytesNeeded > 0) {
    const padSlice = writer.buffer.subarray(rawPayloadLen, paddedLen);
    // crypto.getRandomValues có giới hạn 65536 bytes mỗi lần gọi
    const CHUNK_SIZE = 65536;
    for (let i = 0; i < padSlice.byteLength; i += CHUNK_SIZE) {
      const end = Math.min(i + CHUNK_SIZE, padSlice.byteLength);
      crypto.getRandomValues(padSlice.subarray(i, end) as any);
    }
  }

  return writer.buffer;
}

/**
 * Bóc tách và xác thực Payload sau khi giải mã 3 tầng
 */
export function unpackPayload(decryptedPlaintext: Uint8Array): InternalPayload {
  const reader = new DataReader(decryptedPlaintext);

  // 1. Tên tệp
  const fnLen = reader.readU16();
  if (fnLen > 255 || reader.remaining() < fnLen) {
    throw new AppError('E_PAYLOAD');
  }
  const fnBytes = reader.readBytes(fnLen);
  const rawFilename = textDec.decode(fnBytes);

  // 2. MIME type
  const mimeLen = reader.readU16();
  if (mimeLen > 127 || reader.remaining() < mimeLen) {
    throw new AppError('E_PAYLOAD');
  }
  const mimeBytes = reader.readBytes(mimeLen);
  const mimeType = textDec.decode(mimeBytes) || 'application/octet-stream';

  // 3. Canary Token
  const canaryLen = reader.readU8();
  if (reader.remaining() < canaryLen) {
    throw new AppError('E_PAYLOAD');
  }
  const canaryBytes = reader.readBytes(canaryLen);
  const canaryStr = textDec.decode(canaryBytes);
  if (canaryStr !== CANARY) {
    // Canary không khớp -> Payload bị hỏng hoặc giải mã sai
    throw new AppError('E_AUTH_FAIL');
  }

  // 4. Kích thước nội dung gốc
  const contentLen = reader.readU32();
  if (reader.remaining() < contentLen) {
    throw new AppError('E_PAYLOAD');
  }

  // Trích xuất nội dung thực của tệp (bỏ qua phần padding ngẫu nhiên phía sau)
  const content = new Uint8Array(reader.readBytes(contentLen));

  const filename = sanitizeFilename(rawFilename);

  return {
    filename,
    mimeType,
    content,
  };
}

/**
 * Làm sạch tên tệp giải mã, chống Path Traversal và Bidi Spoofing
 */
export function sanitizeFilename(filename: string): string {
  if (!filename || typeof filename !== 'string') {
    return 'decrypted.bin';
  }

  let clean = filename
    // 1. Loại bỏ ký tự điều khiển ASCII (0x00-0x1F, 0x7F)
    .replace(/[\x00-\x1F\x7F]/g, '')
    // 2. Loại bỏ các ký tự định hướng văn bản Bidi (U+202A–202E, U+2066–2069)
    .replace(/[\u202A-\u202E\u2066-\u2069]/g, '')
    // 3. Loại bỏ ký tự phân tách đường dẫn và ký tự cấm: \ / : * ? " < > |
    .replace(/[\\/:*?"<>|]/g, '_')
    // 4. Loại bỏ dấu chấm đầu tiên (ẩn tệp Unix / traversal)
    .replace(/^\.+/, '')
    .trim();

  // 5. Giới hạn độ dài tối đa 120 ký tự
  clean = clean.slice(0, 120).trim();

  return clean.length > 0 ? clean : 'decrypted.bin';
}

/**
 * Tạo tên tệp ngẫu nhiên định dạng th-<8 hex>.th
 */
export function generateRandomOutputFilename(): string {
  const randBytes = new Uint8Array(4);
  crypto.getRandomValues(randBytes);
  const hex = Array.from(randBytes, b => b.toString(16).padStart(2, '0')).join('');
  return `th-${hex}.th`;
}
