/**
 * TH Crypt - Military-Grade Client-Side File Encryption & Decryption (.th format)
 * Optimized for static hosting (Cloudflare Pages, Workers, Vercel)
 *
 * Cryptographic Standard (Kerckhoffs's Principle Compliant):
 *   - Key Derivation: Argon2id (WebAssembly-accelerated, memory-hard KDF)
 *     Resistant to GPU, ASIC, FPGA, and AI-driven distributed brute-force attacks.
 *   - Symmetric Cipher: AES-256-GCM (Authenticated Encryption with 128-bit auth tag)
 *     Quantum-resistant against Grover's algorithm (effective 128-bit quantum security).
 *   - Binary Package v2:
 *     [MAGIC_HEADER(11B: "TH_CRYPT_V2")][ORIGINAL_EXT(10B)][ARGON2_PARAMS(8B)][SALT(16B)][IV(12B)][ENCRYPTED_PAYLOAD]
 *   - Zero Password Leakage: Passwords exist solely in volatile memory during derivation.
 */

import { argon2id } from 'hash-wasm';

// Binary Format Specification (V2)
const MAGIC_HEADER_STRING_V2 = "TH_CRYPT_V2";
const MAGIC_HEADER_STRING_V1 = "TH_CRYPT_V1";
const enc = new TextEncoder();

const MAGIC_HEADER_V2 = enc.encode(MAGIC_HEADER_STRING_V2); // 11 bytes: [84, 72, 95, 67, 82, 89, 80, 84, 95, 86, 50]
const MAGIC_HEADER_SIZE = 11; // 11 bytes
const EXTENSION_SIZE = 10;    // 10 bytes (null-padded UTF-8)
const PARAMS_SIZE = 8;        // 8 bytes (4B memoryCost in KB, 2B iterations, 2B parallelism)
const SALT_SIZE = 16;         // 16 bytes CSPRNG
const IV_SIZE = 12;           // 12 bytes CSPRNG
const HEADER_SIZE_V2 = MAGIC_HEADER_SIZE + EXTENSION_SIZE + PARAMS_SIZE + SALT_SIZE + IV_SIZE; // 57 bytes

// High-security Argon2id parameters (Browser memory-hard benchmarked)
// 64 MB RAM per attempt (65536 KB), 3 iterations, 1 parallelism
const DEFAULT_ARGON2_MEMORY = 65536; // 64 MB memory cost (defeats GPU/ASIC/AI farms)
const DEFAULT_ARGON2_ITERATIONS = 3; // Time cost
const DEFAULT_ARGON2_PARALLELISM = 1;

// State management
const state = {
  encrypt: {
    file: null,
    downloadUrl: null,
    downloadFilename: '',
  },
  decrypt: {
    file: null,
    downloadUrl: null,
    downloadFilename: '',
  }
};

// Utilities
function formatBytes(bytes, decimals = 2) {
  if (bytes === 0) return '0 Bytes';
  const k = 1024;
  const dm = decimals < 0 ? 0 : decimals;
  const sizes = ['Bytes', 'KB', 'MB', 'GB', 'TB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return parseFloat((bytes / Math.pow(k, i)).toFixed(dm)) + ' ' + sizes[i];
}

function getFileExtension(filename) {
  if (!filename || typeof filename !== 'string') return '';
  const lastDot = filename.lastIndexOf('.');
  if (lastDot === -1 || lastDot === filename.length - 1) return '';
  return filename.substring(lastDot + 1).toLowerCase();
}

function getBaseName(filename) {
  if (!filename || typeof filename !== 'string') return 'file';
  const lastDot = filename.lastIndexOf('.');
  if (lastDot === -1) return filename;
  return filename.substring(0, lastDot);
}

/**
 * Defensive Asynchronous File Reader using FileReader with Promise
 */
function readFileAsArrayBuffer(file) {
  return new Promise((resolve, reject) => {
    if (!file || !(file instanceof Blob)) {
      return reject(new Error('Tệp tin không tồn tại hoặc không hợp lệ. Vui lòng chọn lại!'));
    }

    if (typeof file.size !== 'number' || file.size < 0) {
      return reject(new Error('Không thể xác định kích thước tệp tin. Vui lòng thử lại!'));
    }

    const reader = new FileReader();

    reader.onload = () => {
      if (reader.result instanceof ArrayBuffer) {
        resolve(reader.result);
      } else {
        reject(new Error('Định dạng dữ liệu trả về không tương thích (cần ArrayBuffer).'));
      }
    };

    reader.onerror = () => {
      const err = reader.error;
      const errMsg = err ? (err.message || '') : '';
      const errName = err ? (err.name || '') : '';

      if (
        errName === 'NotFoundError' ||
        errMsg.toLowerCase().includes('could not be found') ||
        errMsg.toLowerCase().includes('not found') ||
        (err && err.code === 8)
      ) {
        reject(new Error('Không tìm thấy tệp tin hoặc tệp đã bị di chuyển / thay đổi trên hệ thống. Vui lòng chọn lại tệp!'));
      } else if (errName === 'NotReadableError') {
        reject(new Error('Không thể đọc tệp tin (tệp có thể đang bị khóa bởi ứng dụng khác hoặc quyền truy cập bị từ chối).'));
      } else if (errName === 'SecurityError') {
        reject(new Error('Trình duyệt từ chối quyền truy cập vào tệp tin này vì lý do bảo mật.'));
      } else {
        reject(new Error(errMsg || errName || 'Lỗi xảy ra trong quá trình đọc tệp tin.'));
      }
    };

    reader.onabort = () => {
      reject(new Error('Quá trình đọc tệp tin đã bị gián đoạn hoặc hủy bỏ bởi người dùng.'));
    };

    try {
      reader.readAsArrayBuffer(file);
    } catch (readErr) {
      const msg = readErr ? (readErr.message || '') : '';
      if (readErr.name === 'NotFoundError' || msg.toLowerCase().includes('could not be found')) {
        reject(new Error('Không tìm thấy tệp tin hoặc tệp đã bị di chuyển / thay đổi trên hệ thống. Vui lòng chọn lại!'));
      } else {
        reject(new Error('Không thể khởi tạo đọc tệp: ' + msg));
      }
    }
  });
}

/**
 * High-Assurance Memory-Hard Key Derivation using Argon2id (WASM)
 * Derives a cryptographic 256-bit AES key.
 */
async function deriveArgon2idKey(password, salt, memoryCost = DEFAULT_ARGON2_MEMORY, iterations = DEFAULT_ARGON2_ITERATIONS, parallelism = DEFAULT_ARGON2_PARALLELISM) {
  const derivedKeyBytes = await argon2id({
    password: password,
    salt: salt,
    parallelism: parallelism,
    iterations: iterations,
    memorySize: memoryCost, // in KiB
    hashLength: 32,         // 256-bit raw key
    outputType: 'binary'
  });

  return await window.crypto.subtle.importKey(
    'raw',
    derivedKeyBytes,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt']
  );
}

/**
 * Fallback Key Derivation using PBKDF2 (for backward compatibility with V1 files)
 */
async function deriveLegacyPBKDF2Key(password, salt) {
  const passwordBuffer = enc.encode(password);
  const baseKey = await window.crypto.subtle.importKey(
    'raw',
    passwordBuffer,
    { name: 'PBKDF2' },
    false,
    ['deriveKey']
  );

  return await window.crypto.subtle.deriveKey(
    {
      name: 'PBKDF2',
      salt: salt,
      iterations: 100000,
      hash: 'SHA-256'
    },
    baseKey,
    { name: 'AES-GCM', length: 256 },
    false,
    ['decrypt']
  );
}

// Encrypt File into .th V2 binary structure with Argon2id + AES-256-GCM
async function processEncryption(file, password, updateStatus) {
  if (!file || !(file instanceof Blob)) {
    throw new Error('Không tìm thấy tệp tin hoặc tệp đã bị hủy. Vui lòng chọn lại tệp!');
  }

  const startTime = performance.now();
  updateStatus('Đang đọc tệp tin...', 25);

  const fileBuffer = await readFileAsArrayBuffer(file);

  updateStatus('Đang tạo mã bảo mật...', 50);
  const salt = window.crypto.getRandomValues(new Uint8Array(SALT_SIZE));
  const iv = window.crypto.getRandomValues(new Uint8Array(IV_SIZE));

  const key = await deriveArgon2idKey(
    password,
    salt,
    DEFAULT_ARGON2_MEMORY,
    DEFAULT_ARGON2_ITERATIONS,
    DEFAULT_ARGON2_PARALLELISM
  );

  updateStatus('Đang tiến hành mã hóa dữ liệu...', 75);
  const encryptedPayload = await window.crypto.subtle.encrypt(
    {
      name: 'AES-GCM',
      iv: iv
    },
    key,
    fileBuffer
  );

  updateStatus('Đang đóng gói tệp .th...', 90);

  // Encode original extension (10 bytes null-padded)
  const ext = getFileExtension(file.name);
  const extBytes = enc.encode(ext);
  const fixedExt = new Uint8Array(EXTENSION_SIZE);
  fixedExt.set(extBytes.subarray(0, EXTENSION_SIZE));

  // Encode Argon2 parameters (8 bytes: 4B memoryCost, 2B iterations, 2B parallelism)
  const paramsBuffer = new ArrayBuffer(PARAMS_SIZE);
  const paramsView = new DataView(paramsBuffer);
  paramsView.setUint32(0, DEFAULT_ARGON2_MEMORY, false);      // Big-Endian uint32
  paramsView.setUint16(4, DEFAULT_ARGON2_ITERATIONS, false);  // Big-Endian uint16
  paramsView.setUint16(6, DEFAULT_ARGON2_PARALLELISM, false); // Big-Endian uint16

  // Assemble full binary package:
  // [MAGIC_HEADER_V2 (11B)][ORIGINAL_EXT (10B)][ARGON2_PARAMS (8B)][SALT (16B)][IV (12B)][ENCRYPTED_PAYLOAD]
  const totalLength = HEADER_SIZE_V2 + encryptedPayload.byteLength;
  const thPackage = new Uint8Array(totalLength);

  let offset = 0;
  // 1. Magic Header V2 (11 bytes: "TH_CRYPT_V2")
  thPackage.set(MAGIC_HEADER_V2, offset);
  offset += MAGIC_HEADER_SIZE;

  // 2. Original Extension (10 bytes)
  thPackage.set(fixedExt, offset);
  offset += EXTENSION_SIZE;

  // 3. Argon2 Parameters (8 bytes)
  thPackage.set(new Uint8Array(paramsBuffer), offset);
  offset += PARAMS_SIZE;

  // 4. Salt (16 bytes)
  thPackage.set(salt, offset);
  offset += SALT_SIZE;

  // 5. IV / Nonce (12 bytes)
  thPackage.set(iv, offset);
  offset += IV_SIZE;

  // 6. Encrypted Payload (Ciphertext + 16-byte GCM Authentication Tag)
  thPackage.set(new Uint8Array(encryptedPayload), offset);

  const duration = Math.round(performance.now() - startTime);
  updateStatus('Mã hóa thành công bằng Argon2id + AES-256-GCM!', 100);

  const outputFilename = `${file.name}.th`;
  const blob = new Blob([thPackage], { type: 'application/octet-stream' });

  return {
    blob,
    filename: outputFilename,
    originalSize: file.size,
    encryptedSize: totalLength,
    duration,
    algorithm: 'Argon2id + AES-256-GCM',
    memoryCost: `${DEFAULT_ARGON2_MEMORY / 1024} MB`
  };
}

// Decrypt .th binary structure back to original file (V2 Argon2id & V1 Backward Compatible)
async function processDecryption(file, password, updateStatus) {
  if (!file || !(file instanceof Blob)) {
    throw new Error('Không tìm thấy tệp tin hoặc tệp đã bị hủy. Vui lòng chọn lại tệp!');
  }

  const startTime = performance.now();
  updateStatus('Đang đọc tệp .th...', 15);

  const fileBuffer = await readFileAsArrayBuffer(file);
  const fileBytes = new Uint8Array(fileBuffer);

  if (fileBytes.byteLength < 46 + 16) {
    throw new Error('Tệp không đúng định dạng .th hoặc dung lượng quá nhỏ để giải mã.');
  }

  updateStatus('Đang xác thực Magic Header...', 30);

  // Check header string
  const headerBytes = fileBytes.subarray(0, MAGIC_HEADER_SIZE);
  const headerString = new TextDecoder().decode(headerBytes);

  let isV2 = (headerString === MAGIC_HEADER_STRING_V2);
  let isV1 = (headerString === MAGIC_HEADER_STRING_V1);

  if (!isV2 && !isV1) {
    throw new Error('Tệp không phải định dạng .th hợp lệ (Sai Magic Header nhận diện).');
  }

  let extString = '';
  let salt;
  let iv;
  let encryptedPayload;
  let key;
  let kdfName = '';

  if (isV2) {
    // V2 Format with Argon2id parameters
    if (fileBytes.byteLength < HEADER_SIZE_V2 + 16) {
      throw new Error('Tệp .th V2 bị thiếu dữ liệu hoặc bị cắt xén.');
    }

    // 1. Extract Extension (10 bytes)
    const extBytes = fileBytes.subarray(11, 21);
    for (let i = 0; i < extBytes.length; i++) {
      if (extBytes[i] === 0) break;
      extString += String.fromCharCode(extBytes[i]);
    }
    extString = extString.trim();

    // 2. Extract Argon2 Parameters (8 bytes)
    const paramsBytes = fileBytes.subarray(21, 29);
    const paramsView = new DataView(paramsBytes.buffer, paramsBytes.byteOffset, paramsBytes.byteLength);
    const memoryCost = paramsView.getUint32(0, false);
    const iterations = paramsView.getUint16(4, false);
    const parallelism = paramsView.getUint16(6, false);

    // 3. Extract Salt (16 bytes)
    salt = fileBytes.subarray(29, 45);

    // 4. Extract IV (12 bytes)
    iv = fileBytes.subarray(45, 57);

    // 5. Extract Ciphertext + Tag
    encryptedPayload = fileBytes.subarray(57);

    updateStatus('Đang mở khóa bảo vệ...', 60);
    kdfName = 'Tiêu chuẩn cao cấp';
    key = await deriveArgon2idKey(password, salt, memoryCost, iterations, parallelism);
  } else {
    // V1 Format with PBKDF2 fallback
    const extBytes = fileBytes.subarray(11, 21);
    for (let i = 0; i < extBytes.length; i++) {
      if (extBytes[i] === 0) break;
      extString += String.fromCharCode(extBytes[i]);
    }
    extString = extString.trim();

    salt = fileBytes.subarray(21, 37);
    iv = fileBytes.subarray(37, 49);
    encryptedPayload = fileBytes.subarray(49);

    updateStatus('Đang mở khóa bảo vệ...', 60);
    kdfName = 'Tương thích V1';
    key = await deriveLegacyPBKDF2Key(password, salt);
  }

  updateStatus('Đang giải mã nội dung...', 80);

  let decryptedBuffer;
  try {
    decryptedBuffer = await window.crypto.subtle.decrypt(
      {
        name: 'AES-GCM',
        iv: iv
      },
      key,
      encryptedPayload
    );
  } catch (err) {
    // Tag mismatch or incorrect key
    throw new Error('Sai mật khẩu hoặc tệp tin đã bị can thiệp/hư hại dù chỉ 1 bit! Không thể giải mã.');
  }

  updateStatus('Khôi phục tệp tin nguyên bản...', 95);

  // Reconstruct file name
  let originalFilename = file.name;
  if (originalFilename.toLowerCase().endsWith('.th')) {
    originalFilename = originalFilename.slice(0, -3);
  } else {
    originalFilename = getBaseName(originalFilename);
  }

  const cleanExt = (extString || '').toLowerCase().replace(/^\./, '');
  if (cleanExt && !originalFilename.toLowerCase().endsWith(`.${cleanExt}`)) {
    originalFilename += `.${cleanExt}`;
  }

  const duration = Math.round(performance.now() - startTime);
  updateStatus('Giải mã thành công!', 100);

  // Derive MIME type for accurate preview and file handling
  const mimeTypes = {
    png: 'image/png',
    jpg: 'image/jpeg',
    jpeg: 'image/jpeg',
    webp: 'image/webp',
    gif: 'image/gif',
    svg: 'image/svg+xml',
    bmp: 'image/bmp',
    ico: 'image/x-icon',
    avif: 'image/avif',
    pdf: 'application/pdf',
    txt: 'text/plain',
    json: 'application/json',
    html: 'text/html',
    mp4: 'video/mp4',
    mp3: 'audio/mpeg',
    zip: 'application/zip'
  };
  const mimeType = mimeTypes[cleanExt] || 'application/octet-stream';
  const blob = new Blob([decryptedBuffer], { type: mimeType });

  return {
    blob,
    filename: originalFilename,
    originalSize: file.size,
    decryptedSize: decryptedBuffer.byteLength,
    extension: cleanExt,
    duration,
    kdf: kdfName
  };
}

// Password Strength Calculator
function checkPasswordStrength(password) {
  if (!password) return { score: 0, text: 'Chưa nhập mật khẩu', color: 'transparent' };
  let score = 0;
  if (password.length >= 8) score++;
  if (password.length >= 12) score++;
  if (/[A-Z]/.test(password) && /[a-z]/.test(password)) score++;
  if (/[0-9]/.test(password) && /[^A-Za-z0-9]/.test(password)) score++;

  switch (score) {
    case 1:
      return { score: 1, text: 'Rất yếu', color: '#f43f5e' };
    case 2:
      return { score: 2, text: 'Trung bình', color: '#f59e0b' };
    case 3:
      return { score: 3, text: 'Tốt', color: '#06b6d4' };
    case 4:
      return { score: 4, text: 'Rất mạnh', color: '#10b981' };
    default:
      return { score: 0, text: 'Yếu', color: '#f43f5e' };
  }
}

// Download Helper
function triggerDownload(blob, filename) {
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.style.display = 'none';
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  setTimeout(() => {
    document.body.removeChild(a);
  }, 1000);
  return url;
}

// Setup Event Listeners
document.addEventListener('DOMContentLoaded', () => {
  // Encrypt DOM Elements
  const encDropzone = document.getElementById('enc-dropzone');
  const encFileInput = document.getElementById('enc-file-input');
  const encPreview = document.getElementById('enc-file-preview');
  const encFileName = document.getElementById('enc-file-name');
  const encFileSize = document.getElementById('enc-file-size');
  const encFileExt = document.getElementById('enc-file-ext');
  const encBtnRemove = document.getElementById('enc-btn-remove');
  const encPasswordInput = document.getElementById('enc-password');
  const encBtnTogglePwd = document.getElementById('enc-btn-toggle-pwd');
  const encBtnAction = document.getElementById('enc-btn-action');
  const encStatusBox = document.getElementById('enc-status-box');
  const encStatusText = document.getElementById('enc-status-text');
  const encProgressFill = document.getElementById('enc-progress-fill');
  const encResultCard = document.getElementById('enc-result-card');
  const encResultDetails = document.getElementById('enc-result-details');
  const encBtnDownload = document.getElementById('enc-btn-download');
  const encErrorBanner = document.getElementById('enc-error-banner');
  const encErrorText = document.getElementById('enc-error-text');

  // Password strength meter bars
  const encStrengthBars = [
    document.getElementById('pwd-bar-1'),
    document.getElementById('pwd-bar-2'),
    document.getElementById('pwd-bar-3'),
    document.getElementById('pwd-bar-4'),
  ];
  const encStrengthLabel = document.getElementById('pwd-strength-label');

  // Decrypt DOM Elements
  const decDropzone = document.getElementById('dec-dropzone');
  const decFileInput = document.getElementById('dec-file-input');
  const decPreview = document.getElementById('dec-file-preview');
  const decFileName = document.getElementById('dec-file-name');
  const decFileSize = document.getElementById('dec-file-size');
  const decFileExt = document.getElementById('dec-file-ext');
  const decBtnRemove = document.getElementById('dec-btn-remove');
  const decPasswordInput = document.getElementById('dec-password');
  const decBtnTogglePwd = document.getElementById('dec-btn-toggle-pwd');
  const decBtnAction = document.getElementById('dec-btn-action');
  const decStatusBox = document.getElementById('dec-status-box');
  const decStatusText = document.getElementById('dec-status-text');
  const decProgressFill = document.getElementById('dec-progress-fill');
  const decResultCard = document.getElementById('dec-result-card');
  const decResultDetails = document.getElementById('dec-result-details');
  const decBtnDownload = document.getElementById('dec-btn-download');
  const decErrorBanner = document.getElementById('dec-error-banner');
  const decErrorText = document.getElementById('dec-error-text');

  // In-Browser Preview DOM Elements
  const decPreviewContainer = document.getElementById('dec-preview-container');
  const decPreviewImage = document.getElementById('dec-preview-image');
  const decPreviewMeta = document.getElementById('dec-preview-meta');

  // Helper to update Encrypt form state
  function updateEncryptBtnState() {
    encBtnAction.disabled = !(state.encrypt.file && encPasswordInput.value.length > 0);
  }

  // Helper to update Decrypt form state
  function updateDecryptBtnState() {
    decBtnAction.disabled = !(state.decrypt.file && decPasswordInput.value.length > 0);
  }

  // --- Encryption File Selection ---
  function setEncryptFile(file) {
    if (!file || !(file instanceof Blob)) return;
    
    if (state.encrypt.downloadUrl) {
      URL.revokeObjectURL(state.encrypt.downloadUrl);
      state.encrypt.downloadUrl = null;
    }

    state.encrypt.file = file;
    encFileName.textContent = file.name || 'file';
    encFileSize.textContent = formatBytes(file.size || 0);
    encFileExt.textContent = getFileExtension(file.name) || 'FILE';
    encPreview.classList.add('active');
    encDropzone.style.display = 'none';
    encErrorBanner.classList.remove('active');
    encResultCard.classList.remove('active');
    updateEncryptBtnState();
  }

  function removeEncryptFile() {
    state.encrypt.file = null;
    if (state.encrypt.downloadUrl) {
      URL.revokeObjectURL(state.encrypt.downloadUrl);
      state.encrypt.downloadUrl = null;
    }
    encFileInput.value = '';
    encPreview.classList.remove('active');
    encDropzone.style.display = 'block';
    encResultCard.classList.remove('active');
    encErrorBanner.classList.remove('active');
    updateEncryptBtnState();
  }

  encDropzone.addEventListener('click', () => {
    encFileInput.click();
  });

  encFileInput.addEventListener('change', (e) => {
    if (!e.target || !e.target.files || e.target.files.length === 0) {
      return;
    }
    setEncryptFile(e.target.files[0]);
  });

  encDropzone.addEventListener('dragover', (e) => {
    e.preventDefault();
    encDropzone.classList.add('drag-active');
  });

  encDropzone.addEventListener('dragleave', () => {
    encDropzone.classList.remove('drag-active');
  });

  encDropzone.addEventListener('drop', (e) => {
    e.preventDefault();
    encDropzone.classList.remove('drag-active');
    if (e.dataTransfer && e.dataTransfer.files && e.dataTransfer.files.length > 0) {
      setEncryptFile(e.dataTransfer.files[0]);
    }
  });

  encBtnRemove.addEventListener('click', removeEncryptFile);

  // Password Input & Strength
  encPasswordInput.addEventListener('input', () => {
    const val = encPasswordInput.value;
    const { score, text, color } = checkPasswordStrength(val);
    encStrengthLabel.textContent = val ? `Độ mạnh: ${text}` : 'Độ mạnh mật khẩu';
    encStrengthBars.forEach((bar, idx) => {
      bar.style.backgroundColor = idx < score ? color : 'rgba(255, 255, 255, 0.1)';
    });
    updateEncryptBtnState();
  });

  encBtnTogglePwd.addEventListener('click', () => {
    const isPwd = encPasswordInput.type === 'password';
    encPasswordInput.type = isPwd ? 'text' : 'password';
    encBtnTogglePwd.innerHTML = isPwd 
      ? `<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19m-6.72-1.07a3 3 0 1 1-4.24-4.24"></path><line x1="1" y1="1" x2="23" y2="23"></line></svg>`
      : `<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"></path><circle cx="12" cy="12" r="3"></circle></svg>`;
  });

  // Action: Encrypt with Argon2id + AES-256-GCM
  encBtnAction.addEventListener('click', async () => {
    if (!state.encrypt.file) {
      encErrorText.textContent = 'Không tìm thấy tệp tin hoặc tệp đã bị di chuyển. Vui lòng chọn lại!';
      encErrorBanner.classList.add('active');
      return;
    }
    if (!encPasswordInput.value) {
      encErrorText.textContent = 'Vui lòng nhập mật khẩu bảo vệ trước khi mã hóa.';
      encErrorBanner.classList.add('active');
      return;
    }

    encBtnAction.disabled = true;
    encErrorBanner.classList.remove('active');
    encResultCard.classList.remove('active');
    encStatusBox.classList.add('active');

    try {
      const result = await processEncryption(
        state.encrypt.file,
        encPasswordInput.value,
        (msg, progress) => {
          encStatusText.textContent = msg;
          encProgressFill.style.width = `${progress}%`;
        }
      );

      // Trigger automatic download for encrypted package
      const downloadUrl = triggerDownload(result.blob, result.filename);
      state.encrypt.downloadUrl = downloadUrl;
      state.encrypt.downloadFilename = result.filename;

      // Display result details
      encResultDetails.innerHTML = `
        Tên tệp: <strong>${result.filename}</strong><br>
        Dung lượng gốc: <strong>${formatBytes(result.originalSize)}</strong> &rarr; Tệp mã hóa: <strong>${formatBytes(result.encryptedSize)}</strong><br>
        Thời gian xử lý: <strong>${result.duration} ms</strong>
      `;
      encResultCard.classList.add('active');
    } catch (err) {
      console.error('Lỗi mã hóa:', err);
      let message = err.message || 'Có lỗi xảy ra trong quá trình mã hóa.';
      if (err.name === 'NotFoundError' || message.toLowerCase().includes('could not be found')) {
        message = 'Không tìm thấy tệp tin hoặc tệp đã bị di chuyển / thay đổi trên hệ thống. Vui lòng chọn lại!';
        removeEncryptFile();
      }
      encErrorText.textContent = message;
      encErrorBanner.classList.add('active');
    } finally {
      setTimeout(() => {
        encStatusBox.classList.remove('active');
        encBtnAction.disabled = false;
        updateEncryptBtnState();
      }, 400);
    }
  });

  encBtnDownload.addEventListener('click', () => {
    if (state.encrypt.downloadUrl && state.encrypt.downloadFilename) {
      const a = document.createElement('a');
      a.href = state.encrypt.downloadUrl;
      a.download = state.encrypt.downloadFilename;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
    }
  });

  // --- Decryption File Selection ---
  function setDecryptFile(file) {
    if (!file || !(file instanceof Blob)) return;

    if (!file.name.toLowerCase().endsWith('.th')) {
      decErrorText.textContent = 'Cảnh báo: Tệp không có đuôi mở rộng .th! Vui lòng chọn tệp .th hợp lệ.';
      decErrorBanner.classList.add('active');
    } else {
      decErrorBanner.classList.remove('active');
    }

    if (state.decrypt.downloadUrl) {
      URL.revokeObjectURL(state.decrypt.downloadUrl);
      state.decrypt.downloadUrl = null;
    }
    if (decPreviewImage) decPreviewImage.src = '';
    if (decPreviewContainer) decPreviewContainer.style.display = 'none';

    state.decrypt.file = file;
    decFileName.textContent = file.name || 'protected.th';
    decFileSize.textContent = formatBytes(file.size || 0);
    decFileExt.textContent = '.TH';
    decPreview.classList.add('active');
    decDropzone.style.display = 'none';
    decResultCard.classList.remove('active');
    updateDecryptBtnState();
  }

  function removeDecryptFile() {
    state.decrypt.file = null;
    if (state.decrypt.downloadUrl) {
      URL.revokeObjectURL(state.decrypt.downloadUrl);
      state.decrypt.downloadUrl = null;
    }
    decFileInput.value = '';
    if (decPreviewImage) decPreviewImage.src = '';
    if (decPreviewContainer) decPreviewContainer.style.display = 'none';
    decPreview.classList.remove('active');
    decDropzone.style.display = 'block';
    decResultCard.classList.remove('active');
    decErrorBanner.classList.remove('active');
    updateDecryptBtnState();
  }

  decDropzone.addEventListener('click', () => {
    decFileInput.click();
  });

  decFileInput.addEventListener('change', (e) => {
    if (!e.target || !e.target.files || e.target.files.length === 0) {
      return;
    }
    setDecryptFile(e.target.files[0]);
  });

  decDropzone.addEventListener('dragover', (e) => {
    e.preventDefault();
    decDropzone.classList.add('drag-active');
  });

  decDropzone.addEventListener('dragleave', () => {
    decDropzone.classList.remove('drag-active');
  });

  decDropzone.addEventListener('drop', (e) => {
    e.preventDefault();
    decDropzone.classList.remove('drag-active');
    if (e.dataTransfer && e.dataTransfer.files && e.dataTransfer.files.length > 0) {
      setDecryptFile(e.dataTransfer.files[0]);
    }
  });

  decBtnRemove.addEventListener('click', removeDecryptFile);

  decPasswordInput.addEventListener('input', () => {
    updateDecryptBtnState();
  });

  decBtnTogglePwd.addEventListener('click', () => {
    const isPwd = decPasswordInput.type === 'password';
    decPasswordInput.type = isPwd ? 'text' : 'password';
    decBtnTogglePwd.innerHTML = isPwd 
      ? `<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19m-6.72-1.07a3 3 0 1 1-4.24-4.24"></path><line x1="1" y1="1" x2="23" y2="23"></line></svg>`
      : `<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"></path><circle cx="12" cy="12" r="3"></circle></svg>`;
  });

  // Action: Decrypt (In-Browser Preview, NO Auto-Download)
  decBtnAction.addEventListener('click', async () => {
    if (!state.decrypt.file) {
      decErrorText.textContent = 'Không tìm thấy tệp tin hoặc tệp đã bị di chuyển. Vui lòng chọn lại!';
      decErrorBanner.classList.add('active');
      return;
    }
    if (!decPasswordInput.value) {
      decErrorText.textContent = 'Vui lòng nhập mật khẩu giải mã.';
      decErrorBanner.classList.add('active');
      return;
    }

    decBtnAction.disabled = true;
    decErrorBanner.classList.remove('active');
    decResultCard.classList.remove('active');
    decStatusBox.classList.add('active');

    try {
      const result = await processDecryption(
        state.decrypt.file,
        decPasswordInput.value,
        (msg, progress) => {
          decStatusText.textContent = msg;
          decProgressFill.style.width = `${progress}%`;
        }
      );

      // Create Object URL for in-browser preview and manual download (NO AUTO-DOWNLOAD)
      const downloadUrl = URL.createObjectURL(result.blob);
      state.decrypt.downloadUrl = downloadUrl;
      state.decrypt.downloadFilename = result.filename;

      // Check if decrypted file is an image format
      const imageExtensions = ['png', 'jpg', 'jpeg', 'webp', 'gif', 'svg', 'bmp', 'ico', 'avif'];
      const fileExt = (result.extension || getFileExtension(result.filename)).toLowerCase().replace(/^\./, '');
      const isImage = imageExtensions.includes(fileExt);

      if (isImage && decPreviewImage && decPreviewContainer) {
        decPreviewImage.src = downloadUrl;
        if (decPreviewMeta) {
          decPreviewMeta.textContent = `${result.filename} (${formatBytes(result.decryptedSize)})`;
        }
        decPreviewContainer.style.display = 'block';
      } else if (decPreviewContainer) {
        decPreviewContainer.style.display = 'none';
        if (decPreviewImage) decPreviewImage.src = '';
      }

      // Display result details with manual download prompt
      decResultDetails.innerHTML = `
        Tên tệp phục hồi: <strong>${result.filename}</strong><br>
        Dung lượng: <strong>${formatBytes(result.decryptedSize)}</strong><br>
        Thời gian xử lý: <strong>${result.duration} ms</strong><br>
        <span style="color: #94a3b8; font-size: 0.85rem; display: inline-block; margin-top: 0.35rem;">
          ${isImage ? '✓ Ảnh đã giải mã và xem trước ở trên. Nhấn nút bên dưới để tải về máy.' : '✓ Tệp đã được giải mã thành công. Nhấn nút bên dưới để tải về máy.'}
        </span>
      `;
      decResultCard.classList.add('active');
    } catch (err) {
      console.error('Lỗi giải mã:', err);
      let message = err.message || 'Lỗi giải mã: Vui lòng kiểm tra lại mật khẩu hoặc tệp tin.';
      if (err.name === 'NotFoundError' || message.toLowerCase().includes('could not be found')) {
        message = 'Không tìm thấy tệp tin hoặc tệp đã bị di chuyển / thay đổi trên hệ thống. Vui lòng chọn lại!';
        removeDecryptFile();
      }
      decErrorText.textContent = message;
      decErrorBanner.classList.add('active');
    } finally {
      setTimeout(() => {
        decStatusBox.classList.remove('active');
        decBtnAction.disabled = false;
        updateDecryptBtnState();
      }, 400);
    }
  });

  decBtnDownload.addEventListener('click', () => {
    if (state.decrypt.downloadUrl && state.decrypt.downloadFilename) {
      const a = document.createElement('a');
      a.href = state.decrypt.downloadUrl;
      a.download = state.decrypt.downloadFilename;
      document.body.appendChild(a);
      a.click();
      setTimeout(() => {
        document.body.removeChild(a);
      }, 1000);
    }
  });
});
