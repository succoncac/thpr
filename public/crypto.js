/**
 * TH10 Cryptography Cascade Engine (crypto.js)
 * Argon2id KDF + HKDF-SHA-256 + Triple Cascaded AES-256-GCM
 */

(function (global) {
  'use strict';

  var F = global.TH10Format;
  if (!F && typeof require !== 'undefined') {
    try {
      F = require('./format.js');
    } catch (_) {}
  }

  var textEnc = new TextEncoder();

  /**
   * Giải phóng event loop để UI không bị đơ và thanh tiến trình có thể render
   */
  function yieldEventLoop() {
    return new Promise(function (resolve) {
      setTimeout(resolve, 0);
    });
  }

  /**
   * Lấy đối tượng argon2id an toàn từ window.hashwasm hoặc global
   */
  function getArgon2idFn() {
    if (global.hashwasm && typeof global.hashwasm.argon2id === 'function') {
      return global.hashwasm.argon2id;
    }
    if (typeof global.argon2id === 'function') {
      return global.argon2id;
    }
    return null;
  }

  /**
   * Kiểm tra thư viện Argon2 WASM đã sẵn sàng chưa
   */
  function isArgon2Ready() {
    return getArgon2idFn() !== null;
  }

  /**
   * Dẫn xuất Master Key 32 bytes từ mật khẩu và salt qua Argon2id
   * Hỗ trợ tự động fallback 1 lần nếu thiết bị thiếu RAM (65536 -> 32768 KiB)
   */
  async function deriveMasterKey(password, salt, targetMemKiB, targetIterations, targetParallelism) {
    if (!password || password.length === 0) {
      throw new F.AppError('E_NO_PASSWORD');
    }

    var argon2idFn = getArgon2idFn();
    if (!argon2idFn) {
      throw new F.AppError('E_LIB');
    }

    // Chuẩn hóa mật khẩu Unicode NFKC (hỗ trợ tiếng Việt có dấu chuẩn xác)
    var normalizedPassword = password.normalize("NFKC");

    var memKiB = targetMemKiB || 65536; // 64 MB mặc định
    var iterations = targetIterations || 3;
    var parallelism = targetParallelism || 1;

    try {
      var keyBinary = await argon2idFn({
        password: normalizedPassword,
        salt: salt,
        parallelism: parallelism,
        iterations: iterations,
        memorySize: memKiB,
        hashLength: 32,
        outputType: "binary",
      });

      return {
        masterKey: new Uint8Array(keyBinary),
        memKiB: memKiB,
        iterations: iterations,
        parallelism: parallelism,
      };
    } catch (err) {
      // Nếu đang trong pha mã hóa mặc định và gặp lỗi bộ nhớ OOM -> Thử lại 1 lần với 32768 KiB
      if (!targetMemKiB && memKiB === 65536) {
        try {
          var fallbackMemKiB = 32768; // 32 MB
          var fallbackKeyBinary = await argon2idFn({
            password: normalizedPassword,
            salt: salt,
            parallelism: parallelism,
            iterations: iterations,
            memorySize: fallbackMemKiB,
            hashLength: 32,
            outputType: "binary",
          });

          return {
            masterKey: new Uint8Array(fallbackKeyBinary),
            memKiB: fallbackMemKiB,
            iterations: iterations,
            parallelism: parallelism,
          };
        } catch (_) {
          throw new F.AppError('E_OOM');
        }
      }
      throw new F.AppError('E_OOM');
    }
  }

  /**
   * Dẫn xuất 3 khóa AES-GCM 256-bit độc lập qua HKDF-SHA-256
   */
  async function deriveStageKeys(masterKey, salt, usage) {
    var hkdfKey = null;
    try {
      hkdfKey = await crypto.subtle.importKey(
        "raw",
        masterKey,
        "HKDF",
        false,
        ["deriveKey"]
      );

      var keyUsage = usage === 'encrypt' ? ['encrypt'] : ['decrypt'];

      var keys = await Promise.all([
        crypto.subtle.deriveKey(
          {
            name: "HKDF",
            hash: "SHA-256",
            salt: salt,
            info: textEnc.encode("TH10|stage1|v1"),
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
            salt: salt,
            info: textEnc.encode("TH10|stage2|v1"),
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
            salt: salt,
            info: textEnc.encode("TH10|stage3|v1"),
          },
          hkdfKey,
          { name: "AES-GCM", length: 256 },
          false,
          keyUsage
        ),
      ]);

      return {
        key1: keys[0],
        key2: keys[1],
        key3: keys[2],
      };
    } finally {
      F.wipe(masterKey);
    }
  }

  /**
   * Tạo AAD 65 bytes = 64B Header + 1B Stage Index
   */
  function createStageAad(headerRawBytes, stageIndex) {
    var aad = new Uint8Array(F.HEADER_SIZE + 1);
    aad.set(headerRawBytes, 0);
    aad[F.HEADER_SIZE] = stageIndex;
    return aad;
  }

  /**
   * Mã hóa tuần tự 3 tầng AES-256-GCM lồng nhau:
   * Payload -> Stage 1 (trong cùng) -> Stage 2 -> Stage 3 (ngoài cùng)
   */
  async function encryptCascade(payload, stageKeys, header) {
    var stage1Cipher = null;
    var stage2Cipher = null;
    var stage3Cipher = null;

    try {
      var aad1 = createStageAad(header.rawBytes, 1);
      var aad2 = createStageAad(header.rawBytes, 2);
      var aad3 = createStageAad(header.rawBytes, 3);

      // --- TẦNG 1 (Trong cùng) ---
      var enc1 = await crypto.subtle.encrypt(
        { name: "AES-GCM", iv: header.nonce1, additionalData: aad1, tagLength: 128 },
        stageKeys.key1,
        payload
      );
      stage1Cipher = new Uint8Array(enc1);
      F.wipe(payload);

      // --- TẦNG 2 ---
      var enc2 = await crypto.subtle.encrypt(
        { name: "AES-GCM", iv: header.nonce2, additionalData: aad2, tagLength: 128 },
        stageKeys.key2,
        stage1Cipher
      );
      stage2Cipher = new Uint8Array(enc2);
      F.wipe(stage1Cipher);
      stage1Cipher = null;

      // --- TẦNG 3 (Lớp giáp ngoài) ---
      var enc3 = await crypto.subtle.encrypt(
        { name: "AES-GCM", iv: header.nonce3, additionalData: aad3, tagLength: 128 },
        stageKeys.key3,
        stage2Cipher
      );
      stage3Cipher = new Uint8Array(enc3);
      F.wipe(stage2Cipher);
      stage2Cipher = null;

      // Đóng gói tệp .th hoàn chỉnh: 64B Header + Stage3 Ciphertext
      var finalPackage = new Uint8Array(F.HEADER_SIZE + stage3Cipher.byteLength);
      finalPackage.set(header.rawBytes, 0);
      finalPackage.set(stage3Cipher, F.HEADER_SIZE);

      return finalPackage;
    } finally {
      F.wipe(stage1Cipher);
      F.wipe(stage2Cipher);
    }
  }

  /**
   * Giải mã tuần tự 3 tầng AES-256-GCM từ ngoài vào trong:
   * FileBytes -> Stage 3 (ngoài) -> Stage 2 -> Stage 1 (trong cùng)
   */
  async function decryptCascade(fileBytes, stageKeys, header) {
    if (fileBytes.byteLength < F.HEADER_SIZE + 16 * 3) {
      throw new F.AppError('E_TOO_SHORT');
    }

    var stage3Ciphertext = fileBytes.subarray(F.HEADER_SIZE);
    var stage2Cipher = null;
    var stage1Cipher = null;
    var decryptedPayload = null;

    var aad1 = createStageAad(header.rawBytes, 1);
    var aad2 = createStageAad(header.rawBytes, 2);
    var aad3 = createStageAad(header.rawBytes, 3);

    try {
      // --- GỠ TẦNG 3 ---
      try {
        var dec3 = await crypto.subtle.decrypt(
          { name: "AES-GCM", iv: header.nonce3, additionalData: aad3, tagLength: 128 },
          stageKeys.key3,
          stage3Ciphertext
        );
        stage2Cipher = new Uint8Array(dec3);
      } catch (_) {
        throw new F.AppError('E_AUTH_FAIL');
      }

      // --- GỠ TẦNG 2 ---
      try {
        var dec2 = await crypto.subtle.decrypt(
          { name: "AES-GCM", iv: header.nonce2, additionalData: aad2, tagLength: 128 },
          stageKeys.key2,
          stage2Cipher
        );
        stage1Cipher = new Uint8Array(dec2);
      } catch (_) {
        throw new F.AppError('E_AUTH_FAIL');
      } finally {
        F.wipe(stage2Cipher);
        stage2Cipher = null;
      }

      // --- GỠ TẦNG 1 ---
      try {
        var dec1 = await crypto.subtle.decrypt(
          { name: "AES-GCM", iv: header.nonce1, additionalData: aad1, tagLength: 128 },
          stageKeys.key1,
          stage1Cipher
        );
        decryptedPayload = new Uint8Array(dec1);
      } catch (_) {
        throw new F.AppError('E_AUTH_FAIL');
      } finally {
        F.wipe(stage1Cipher);
        stage1Cipher = null;
      }

      return decryptedPayload;
    } finally {
      F.wipe(stage2Cipher);
      F.wipe(stage1Cipher);
    }
  }

  /**
   * Chạy Self-Test khi khởi động kiểm tra tính toàn vẹn của WebCrypto và Argon2
   */
  async function runSelfTest() {
    var argon2idFn = getArgon2idFn();
    if (!argon2idFn) {
      throw new F.AppError('E_LIB');
    }

    // 1. Kiểm tra nhanh Argon2id với 8192 KiB và 1 vòng
    var testSalt = new Uint8Array(16);
    crypto.getRandomValues(testSalt);
    var testKeyBin = await argon2idFn({
      password: "th10-selftest",
      salt: testSalt,
      parallelism: 1,
      iterations: 1,
      memorySize: 8192,
      hashLength: 32,
      outputType: "binary",
    });
    var masterKey = new Uint8Array(testKeyBin);

    // 2. Kiểm tra nhanh vòng AES-256-GCM
    var rawKey = await crypto.subtle.importKey(
      "raw",
      masterKey,
      { name: "AES-GCM", length: 256 },
      false,
      ["encrypt", "decrypt"]
    );

    var testIv = new Uint8Array(12);
    crypto.getRandomValues(testIv);
    var testPlain = textEnc.encode("TH10_SELF_TEST_OK");
    var testEnc = await crypto.subtle.encrypt(
      { name: "AES-GCM", iv: testIv },
      rawKey,
      testPlain
    );
    var testDec = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv: testIv },
      rawKey,
      testEnc
    );

    var roundTripStr = new TextDecoder().decode(testDec);
    F.wipe(masterKey);
    F.wipe(testPlain);

    if (roundTripStr !== "TH10_SELF_TEST_OK") {
      throw new Error("Self-test verification mismatch.");
    }

    return true;
  }

  // ============================================================================
  // EXPORT
  // ============================================================================
  var TH10Crypto = {
    yieldEventLoop: yieldEventLoop,
    isArgon2Ready: isArgon2Ready,
    deriveMasterKey: deriveMasterKey,
    deriveStageKeys: deriveStageKeys,
    createStageAad: createStageAad,
    encryptCascade: encryptCascade,
    decryptCascade: decryptCascade,
    runSelfTest: runSelfTest,
  };

  if (typeof module !== 'undefined' && module.exports) {
    module.exports = TH10Crypto;
  }
  global.TH10Crypto = TH10Crypto;

})(typeof window !== 'undefined' ? window : globalThis);
