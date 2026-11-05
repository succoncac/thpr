import { test, describe } from 'node:test';
import assert from 'node:assert';
import {
  HEADER_SIZE,
  MAGIC_STR,
  FORMAT_VERSION,
  buildHeader64,
  parseHeader64,
  packPayload,
  unpackPayload,
  sanitizeFilename,
  generateRandomOutputFilename,
  DataReader,
  DataWriter,
  AppError,
} from '../src/format';
import {
  deriveMasterKey,
  deriveStageKeys,
  encryptCascade,
  decryptCascade,
} from '../src/crypto';

describe('TH10 Format & Boundary Tests', () => {
  test('Header64 builds and parses exactly 64 bytes', () => {
    const salt = new Uint8Array(16).fill(0xaa);
    const nonce1 = new Uint8Array(12).fill(0x11);
    const nonce2 = new Uint8Array(12).fill(0x22);
    const nonce3 = new Uint8Array(12).fill(0x33);

    const header = buildHeader64(65536, 3, 1, salt, nonce1, nonce2, nonce3);
    assert.strictEqual(header.rawBytes.byteLength, 64);
    assert.strictEqual(header.magic, 'TH10');
    assert.strictEqual(header.version, 1);
    assert.strictEqual(header.flags, 0);
    assert.strictEqual(header.memKiB, 65536);
    assert.strictEqual(header.iterations, 3);
    assert.strictEqual(header.parallelism, 1);

    const parsed = parseHeader64(header.rawBytes);
    assert.strictEqual(parsed.magic, 'TH10');
    assert.strictEqual(parsed.version, 1);
    assert.strictEqual(parsed.memKiB, 65536);
    assert.deepStrictEqual(parsed.salt, salt);
    assert.deepStrictEqual(parsed.nonce1, nonce1);
    assert.deepStrictEqual(parsed.nonce2, nonce2);
    assert.deepStrictEqual(parsed.nonce3, nonce3);
  });

  test('DataReader rejects buffer overreads cleanly without crashing RangeError', () => {
    const tinyBuf = new Uint8Array(5);
    const reader = new DataReader(tinyBuf);
    assert.strictEqual(reader.readU8(), 0);
    assert.strictEqual(reader.readU32(), 0);
    // Overread beyond 5 bytes
    assert.throws(() => reader.readU8(), (err: any) => err instanceof AppError && err.code === 'E_TOO_SHORT');
  });

  test('packPayload and unpackPayload preserves data, canary, and applies padding', () => {
    const originalContent = new TextEncoder().encode('Hello TH10 Military Cryptography!');
    const packed = packPayload('my_document.pdf', 'application/pdf', originalContent);

    // Padding ensures total length is a multiple of 64 KiB (65536) for small files
    assert.strictEqual(packed.byteLength % 65536, 0);

    const unpacked = unpackPayload(packed);
    assert.strictEqual(unpacked.filename, 'my_document.pdf');
    assert.strictEqual(unpacked.mimeType, 'application/pdf');
    assert.strictEqual(unpacked.canary, 'CANARY_PLACEHOLDER');
    assert.deepStrictEqual(unpacked.content, originalContent);
  });

  test('sanitizeFilename removes bidi, traversal, and control chars', () => {
    // Path traversal and dangerous characters
    assert.strictEqual(sanitizeFilename('../../../etc/passwd'), '______etc_passwd');
    // Bidi override characters (e.g. \u202E)
    assert.strictEqual(sanitizeFilename('test\u202Eexe.pdf'), 'testexe.pdf');
    // Leading dots
    assert.strictEqual(sanitizeFilename('...hidden_file.txt'), 'hidden_file.txt');
    // Empty input fallback
    assert.strictEqual(sanitizeFilename(''), 'decrypted.bin');
  });

  test('generateRandomOutputFilename matches th-<8 hex>.th pattern', () => {
    const fn = generateRandomOutputFilename();
    assert.match(fn, /^th-[0-9a-f]{8}\.th$/);
  });
});

describe('TH10 Cryptography Cascade End-to-End Tests', () => {
  test('3-stage cascaded AES-256-GCM encrypts and decrypts with KDF', async () => {
    const password = 'SuperSecurePassword2026!';
    const salt = new Uint8Array(16);
    crypto.getRandomValues(salt);
    const nonce1 = new Uint8Array(12);
    crypto.getRandomValues(nonce1);
    const nonce2 = new Uint8Array(12);
    crypto.getRandomValues(nonce2);
    const nonce3 = new Uint8Array(12);
    crypto.getRandomValues(nonce3);

    // Use fast params for unit test execution
    const kdf = await deriveMasterKey(password, salt, 8192, 1, 1);
    const encStageKeys = await deriveStageKeys(kdf.masterKey, salt, 'encrypt');
    const header = buildHeader64(kdf.memKiB, kdf.iterations, kdf.parallelism, salt, nonce1, nonce2, nonce3);

    const secretData = new TextEncoder().encode('Confidential Top Secret Mission 2026');
    const packed = packPayload('intel.docx', 'application/vnd.openxmlformats', secretData);

    // Encrypt
    const encryptedFile = await encryptCascade(packed, encStageKeys, header);
    assert(encryptedFile.byteLength > HEADER_SIZE);

    // Decrypt flow
    const parsedHeader = parseHeader64(encryptedFile.subarray(0, HEADER_SIZE));
    const decKdf = await deriveMasterKey(password, parsedHeader.salt, parsedHeader.memKiB, parsedHeader.iterations, parsedHeader.parallelism);
    const decStageKeys = await deriveStageKeys(decKdf.masterKey, parsedHeader.salt, 'decrypt');

    const stage3Cipher = encryptedFile.subarray(HEADER_SIZE);
    const decryptedPayload = await decryptCascade(stage3Cipher, parsedHeader, decStageKeys);

    const unpacked = unpackPayload(decryptedPayload);
    assert.strictEqual(unpacked.filename, 'intel.docx');
    assert.deepStrictEqual(unpacked.content, secretData);
  });

  test('Tampering with ciphertext causes authentication failure (E_AUTH_FAIL)', async () => {
    const password = 'CorrectPassword123!';
    const salt = new Uint8Array(16).fill(0x55);
    const nonce1 = new Uint8Array(12).fill(0x66);
    const nonce2 = new Uint8Array(12).fill(0x77);
    const nonce3 = new Uint8Array(12).fill(0x88);

    const kdf = await deriveMasterKey(password, salt, 8192, 1, 1);
    const encStageKeys = await deriveStageKeys(kdf.masterKey, salt, 'encrypt');
    const header = buildHeader64(kdf.memKiB, kdf.iterations, kdf.parallelism, salt, nonce1, nonce2, nonce3);

    const packed = packPayload('test.txt', 'text/plain', new Uint8Array([1, 2, 3, 4]));
    const encryptedFile = await encryptCascade(packed, encStageKeys, header);

    // Tamper with one byte in ciphertext
    const tampered = new Uint8Array(encryptedFile);
    tampered[HEADER_SIZE + 10] ^= 0xff;

    const parsedHeader = parseHeader64(tampered.subarray(0, HEADER_SIZE));
    const decKdf = await deriveMasterKey(password, parsedHeader.salt, parsedHeader.memKiB, parsedHeader.iterations, parsedHeader.parallelism);
    const decStageKeys = await deriveStageKeys(decKdf.masterKey, parsedHeader.salt, 'decrypt');

    const stage3Cipher = tampered.subarray(HEADER_SIZE);
    await assert.rejects(
      async () => {
        await decryptCascade(stage3Cipher, parsedHeader, decStageKeys);
      },
      (err: any) => err instanceof AppError && err.code === 'E_AUTH_FAIL'
    );
  });
});
