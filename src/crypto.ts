/**
 * TH10 Cryptography Engine: Argon2id KDF + HKDF-SHA-256 + Triple Cascaded AES-256-GCM
 */

import { argon2id } from 'hash-wasm';
import {
  AppError,
  Header64,
  HEADER_SIZE,
  SALT_SIZE,
  NONCE_SIZE,
  wipe,
} from './format';

const textEnc = new TextEncoder();

export interface DerivedKdfResult {
  masterKey: Uint8Array;
  memKiB: number;
  iterations: number;
  parallelism: number;
}

export interface StageKeys {
  key1: CryptoKey;
  key2: CryptoKey;
  key3: CryptoKey;
}

/**
 * Microtask yield để giải phóng UI Event loop cho thanh tiến trình
 */
export function yieldEventLoop(): Promise<void> {
  return new Promise(resolve => setTimeout(resolve, 0));
}

/**
 * Dẫn xuất Master Key 32 bytes từ mật khẩu và salt qua Argon2id
 * Hỗ trợ tự động fallback 1 lần nếu thiết bị thiếu RAM khi mã hóa (65536 -> 32768 KiB)
 */
export async function deriveMasterKey(
  password: string,
  salt: Uint8Array,
  targetMemKiB?: number,
  targetIterations?: number,
  targetParallelism?: number
): Promise<DerivedKdfResult> {
  if (!password || password.length === 0) {
    throw new AppError('E_NO_PASSWORD');
  }

  // Chuẩn hóa mật khẩu theo chuẩn Unicode NFKC
  const normalizedPassword = password.normalize("NFKC");

  // Thiết lập tham số KDF mặc định hoặc theo chỉ định từ Header
  let memKiB = targetMemKiB || 65536; // 64 MB mặc định
  const iterations = targetIterations || 3;
  const parallelism = targetParallelism || 1;

  try {
    const rawResult = await argon2id({
      password: normalizedPassword,
      salt: salt,
      parallelism: parallelism,
      iterations: iterations,
      memorySize: memKiB,
      hashLength: 32, // 32 bytes (256-bit) Master Key
      outputType: 'binary',
    });

    const masterKey = rawResult instanceof Uint8Array ? rawResult : new Uint8Array(rawResult);
    return { masterKey, memKiB, iterations, parallelism };
  } catch (err: unknown) {
    const errMsg = String((err as Error)?.message || '').toLowerCase();
    const isOom = errMsg.includes('memory') || errMsg.includes('allocate') || (err as Error)?.name === 'RangeError';

    // Thử lại 1 lần duy nhất với 32768 KiB nếu đang trong luồng mã hóa (targetMemKiB không truyền)
    if (isOom && !targetMemKiB && memKiB > 32768) {
      memKiB = 32768; // Thử lại với 32 MB
      try {
        const rawResult = await argon2id({
          password: normalizedPassword,
          salt: salt,
          parallelism: parallelism,
          iterations: iterations,
          memorySize: memKiB,
          hashLength: 32,
          outputType: 'binary',
        });
        const masterKey = rawResult instanceof Uint8Array ? rawResult : new Uint8Array(rawResult);
        return { masterKey, memKiB, iterations, parallelism };
      } catch {
        throw new AppError('E_OOM');
      }
    }

    if (isOom) {
      throw new AppError('E_OOM');
    }

    throw new AppError('E_LIB', `Lỗi thư viện mật mã KDF: ${(err as Error)?.message || 'Không thể thực thi Argon2id.'}`);
  }
}

/**
 * Tách Master Key thành 3 khóa AES-GCM 256-bit độc lập qua HKDF-SHA-256
 */
export async function deriveStageKeys(
  masterKey: Uint8Array,
  salt: Uint8Array,
  usage: 'encrypt' | 'decrypt'
): Promise<StageKeys> {
  let hkdfKey: CryptoKey | null = null;
  try {
    hkdfKey = await crypto.subtle.importKey(
      "raw",
      masterKey as unknown as BufferSource,
      "HKDF",
      false,
      ["deriveKey"]
    );

    const keyUsage: KeyUsage[] = usage === 'encrypt' ? ['encrypt'] : ['decrypt'];

    const [key1, key2, key3] = await Promise.all([
      crypto.subtle.deriveKey(
        {
          name: "HKDF",
          hash: "SHA-256",
          salt: salt as unknown as BufferSource,
          info: textEnc.encode("TH10|stage1|v1") as unknown as BufferSource,
        },
        hkdfKey,
        { name: "AES-GCM", length: 256 },
        false,
        keyUsage
      ),
      crypto.subtle.deriveKey(
        {
          name: "HKDF",
          hash: "SHA-256",
          salt: salt as unknown as BufferSource,
          info: textEnc.encode("TH10|stage2|v1") as unknown as BufferSource,
        },
        hkdfKey,
        { name: "AES-GCM", length: 256 },
        false,
        keyUsage
      ),
      crypto.subtle.deriveKey(
        {
          name: "HKDF",
          hash: "SHA-256",
          salt: salt as unknown as BufferSource,
          info: textEnc.encode("TH10|stage3|v1") as unknown as BufferSource,
        },
        hkdfKey,
        { name: "AES-GCM", length: 256 },
        false,
        keyUsage
      ),
    ]);

    return { key1, key2, key3 };
  } finally {
    // Xóa sạch master key nguyên bản trong RAM
    wipe(masterKey);
  }
}

/**
 * Tạo AAD 65 bytes = 64B header + 1B stage index
 */
function createStageAad(header64: Uint8Array, stageIndex: number): Uint8Array {
  const aad = new Uint8Array(HEADER_SIZE + 1);
  aad.set(header64, 0);
  aad[HEADER_SIZE] = stageIndex;
  return aad;
}

/**
 * Mã hóa 3 tầng lồng nhau Triple-Stage Cascaded AES-256-GCM
 * Stage 1 (Payload trong cùng) -> Stage 2 -> Stage 3 (Lớp ngoài cùng)
 */
export async function encryptCascade(
  payload: Uint8Array,
  stageKeys: StageKeys,
  header: Header64
): Promise<Uint8Array> {
  let stage1Cipher: Uint8Array | null = null;
  let stage2Cipher: Uint8Array | null = null;
  let stage3Cipher: Uint8Array | null = null;

  try {
    const aad1 = createStageAad(header.rawBytes, 1);
    const aad2 = createStageAad(header.rawBytes, 2);
    const aad3 = createStageAad(header.rawBytes, 3);

    // --- TẦNG 1 (Trong cùng) ---
    const enc1 = await crypto.subtle.encrypt(
      { name: "AES-GCM", iv: header.nonce1 as unknown as BufferSource, additionalData: aad1 as unknown as BufferSource, tagLength: 128 },
      stageKeys.key1,
      payload as unknown as BufferSource
    );
    stage1Cipher = new Uint8Array(enc1);
    // Xóa ngay payload plaintext khỏi RAM
    wipe(payload);

    // --- TẦNG 2 ---
    const enc2 = await crypto.subtle.encrypt(
      { name: "AES-GCM", iv: header.nonce2 as unknown as BufferSource, additionalData: aad2 as unknown as BufferSource, tagLength: 128 },
      stageKeys.key2,
      stage1Cipher as unknown as BufferSource
    );
    stage2Cipher = new Uint8Array(enc2);
    // Xóa ciphertext trung gian tầng 1
    wipe(stage1Cipher);
    stage1Cipher = null;

    // --- TẦNG 3 (Lớp giáp ngoài) ---
    const enc3 = await crypto.subtle.encrypt(
      { name: "AES-GCM", iv: header.nonce3 as unknown as BufferSource, additionalData: aad3 as unknown as BufferSource, tagLength: 128 },
      stageKeys.key3,
      stage2Cipher as unknown as BufferSource
    );
    stage3Cipher = new Uint8Array(enc3);
    // Xóa ciphertext trung gian tầng 2
    wipe(stage2Cipher);
    stage2Cipher = null;

    // Lắp ráp tệp TH10 hoàn chỉnh: 64B Header + Stage3 Ciphertext
    const finalPackage = new Uint8Array(HEADER_SIZE + stage3Cipher.byteLength);
    finalPackage.set(header.rawBytes, 0);
    finalPackage.set(stage3Cipher, HEADER_SIZE);

    return finalPackage;
  } finally {
    wipe(stage1Cipher);
    wipe(stage2Cipher);
  }
}

/**
 * Giải mã 3 tầng theo chiều ngược lại:
 * Stage 3 (ngoài) -> Stage 2 -> Stage 1 (trong cùng)
 */
export async function decryptCascade(
  fileBytes: Uint8Array,
  stageKeys: StageKeys,
  header: Header64
): Promise<Uint8Array> {
  if (fileBytes.byteLength < HEADER_SIZE + 16 * 3) {
    throw new AppError('E_TOO_SHORT');
  }

  const stage3Ciphertext = fileBytes.subarray(HEADER_SIZE);
  let stage2Cipher: Uint8Array | null = null;
  let stage1Cipher: Uint8Array | null = null;
  let decryptedPayload: Uint8Array | null = null;

  const aad1 = createStageAad(header.rawBytes, 1);
  const aad2 = createStageAad(header.rawBytes, 2);
  const aad3 = createStageAad(header.rawBytes, 3);

  try {
    // --- GỠ TẦNG 3 ---
    try {
      const dec3 = await crypto.subtle.decrypt(
        { name: "AES-GCM", iv: header.nonce3 as unknown as BufferSource, additionalData: aad3 as unknown as BufferSource, tagLength: 128 },
        stageKeys.key3,
        stage3Ciphertext as unknown as BufferSource
      );
      stage2Cipher = new Uint8Array(dec3);
    } catch {
      throw new AppError('E_AUTH_FAIL');
    }

    // --- GỠ TẦNG 2 ---
    try {
      const dec2 = await crypto.subtle.decrypt(
        { name: "AES-GCM", iv: header.nonce2 as unknown as BufferSource, additionalData: aad2 as unknown as BufferSource, tagLength: 128 },
        stageKeys.key2,
        stage2Cipher as unknown as BufferSource
      );
      stage1Cipher = new Uint8Array(dec2);
    } catch {
      throw new AppError('E_AUTH_FAIL');
    } finally {
      wipe(stage2Cipher);
      stage2Cipher = null;
    }

    // --- GỠ TẦNG 1 ---
    try {
      const dec1 = await crypto.subtle.decrypt(
        { name: "AES-GCM", iv: header.nonce1 as unknown as BufferSource, additionalData: aad1 as unknown as BufferSource, tagLength: 128 },
        stageKeys.key1,
        stage1Cipher as unknown as BufferSource
      );
      decryptedPayload = new Uint8Array(dec1);
    } catch {
      throw new AppError('E_AUTH_FAIL');
    } finally {
      wipe(stage1Cipher);
      stage1Cipher = null;
    }

    return decryptedPayload;
  } finally {
    wipe(stage2Cipher);
    wipe(stage1Cipher);
  }
}

/**
 * Kiểm thử tự động khi khởi động (Self-Test):
 * Chạy 1 micro Argon2id + 1 vòng AES-GCM với HKDF để đảm bảo môi trường Web Crypto & WASM sẵn sàng
 */
export async function runSelfTest(): Promise<boolean> {
  try {
    // 1. Kiểm thử Web Crypto
    if (!crypto || !crypto.subtle || typeof crypto.getRandomValues !== 'function') {
      return false;
    }

    // 2. Micro Argon2id test (8192 KiB, 1 iteration)
    const testSalt = new Uint8Array(SALT_SIZE);
    crypto.getRandomValues(testSalt);

    const testKdf = await argon2id({
      password: "selftest-password",
      salt: testSalt,
      iterations: 1,
      parallelism: 1,
      memorySize: 8192,
      hashLength: 32,
      outputType: 'binary',
    });

    if (!testKdf || testKdf.length !== 32) {
      return false;
    }

    // 3. Micro HKDF & AES-GCM round-trip
    const testMaster = new Uint8Array(testKdf);
    const testKeys = await deriveStageKeys(testMaster, testSalt, 'encrypt');
    const testNonce = new Uint8Array(NONCE_SIZE);
    crypto.getRandomValues(testNonce);

    const testPlain = textEnc.encode("test-vector");
    const testEnc = await crypto.subtle.encrypt(
      { name: "AES-GCM", iv: testNonce },
      testKeys.key1,
      testPlain
    );

    const decryptKeys = await deriveStageKeys(new Uint8Array(testKdf), testSalt, 'decrypt');
    const testDec = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv: testNonce },
      decryptKeys.key1,
      testEnc
    );

    const recovered = new TextDecoder().decode(testDec);
    return recovered === "test-vector";
  } catch (err) {
    console.warn("Self-test thất bại:", err);
    return false;
  }
}
