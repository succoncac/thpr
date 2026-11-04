/**
 * TH Crypt - Pure Client-Side File Encryption & Decryption (.th format)
 * Optimized for static hosting (Cloudflare Pages, Vercel, Netlify)
 * Cryptographic Standard:
 *   - Key Derivation: PBKDF2 (SHA-256, 100,000 iterations, 16-byte random salt)
 *   - Cipher: AES-256-GCM (12-byte random IV, authenticated encryption)
 *   - Binary Package: [MAGIC_HEADER(11B)][ORIGINAL_EXT(10B)][SALT(16B)][IV(12B)][ENCRYPTED_PAYLOAD]
 *   - Zero Password Leakage: Password is never stored, logged, or embedded anywhere.
 */

// Binary Format Specification
const MAGIC_HEADER_STRING = "TH_CRYPT_V1";
const enc = new TextEncoder();
const MAGIC_HEADER = enc.encode(MAGIC_HEADER_STRING); // 11 bytes: [84, 72, 95, 67, 82, 89, 80, 84, 95, 86, 49]
const MAGIC_HEADER_SIZE = MAGIC_HEADER.length; // 11 bytes
const EXTENSION_SIZE = 10;                     // 10 bytes (null-padded UTF-8)
const SALT_SIZE = 16;                          // 16 bytes CSPRNG
const IV_SIZE = 12;                            // 12 bytes CSPRNG
const HEADER_SIZE = MAGIC_HEADER_SIZE + EXTENSION_SIZE + SALT_SIZE + IV_SIZE; // 49 bytes
const PBKDF2_ITERATIONS = 100000;

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
  const lastDot = filename.lastIndexOf('.');
  if (lastDot === -1 || lastDot === filename.length - 1) return '';
  return filename.substring(lastDot + 1).toLowerCase();
}

function getBaseName(filename) {
  const lastDot = filename.lastIndexOf('.');
  if (lastDot === -1) return filename;
  return filename.substring(0, lastDot);
}

// Key Derivation with PBKDF2
async function deriveKey(password, salt, keyUsages = ['encrypt']) {
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
      iterations: PBKDF2_ITERATIONS,
      hash: 'SHA-256'
    },
    baseKey,
    { name: 'AES-GCM', length: 256 },
    false,
    keyUsages
  );
}

// Encrypt File into .th binary structure
async function processEncryption(file, password, updateStatus) {
  const startTime = performance.now();
  updateStatus('Đang đọc tệp tin vào bộ nhớ client...', 20);

  const fileBuffer = await file.arrayBuffer();

  updateStatus('Đang sinh Salt và khóa an toàn PBKDF2 (100,000 iterations)...', 45);
  const salt = window.crypto.getRandomValues(new Uint8Array(SALT_SIZE));
  const iv = window.crypto.getRandomValues(new Uint8Array(IV_SIZE));

  const key = await deriveKey(password, salt, ['encrypt']);

  updateStatus('Đang mã hóa AES-256-GCM toàn bộ dữ liệu...', 70);
  const encryptedPayload = await window.crypto.subtle.encrypt(
    {
      name: 'AES-GCM',
      iv: iv
    },
    key,
    fileBuffer
  );

  updateStatus('Đang đóng gói cấu trúc nhị phân .th...', 90);

  // Encode original extension into fixed 10 bytes (null-padded)
  const ext = getFileExtension(file.name);
  const extBytes = enc.encode(ext);
  const fixedExt = new Uint8Array(EXTENSION_SIZE);
  fixedExt.set(extBytes.subarray(0, EXTENSION_SIZE));

  // Assemble full binary package: [MAGIC_HEADER(11B)][ORIGINAL_EXT(10B)][SALT(16B)][IV(12B)][ENCRYPTED_PAYLOAD]
  const totalLength = HEADER_SIZE + encryptedPayload.byteLength;
  const thPackage = new Uint8Array(totalLength);

  let offset = 0;
  // 1. Magic Header (11 bytes: "TH_CRYPT_V1")
  thPackage.set(MAGIC_HEADER, offset);
  offset += MAGIC_HEADER_SIZE;

  // 2. Original Extension (10 bytes)
  thPackage.set(fixedExt, offset);
  offset += EXTENSION_SIZE;

  // 3. Salt (16 bytes)
  thPackage.set(salt, offset);
  offset += SALT_SIZE;

  // 4. IV (12 bytes)
  thPackage.set(iv, offset);
  offset += IV_SIZE;

  // 5. Encrypted Payload (Ciphertext + 16-byte GCM Tag)
  thPackage.set(new Uint8Array(encryptedPayload), offset);

  const duration = Math.round(performance.now() - startTime);
  updateStatus('Mã hóa thành công!', 100);

  // If input was "photo.png", output is "photo.png.th"
  const outputFilename = `${file.name}.th`;
  const blob = new Blob([thPackage], { type: 'application/octet-stream' });

  return {
    blob,
    filename: outputFilename,
    originalSize: file.size,
    encryptedSize: totalLength,
    duration
  };
}

// Decrypt .th binary structure back to original file
async function processDecryption(file, password, updateStatus) {
  const startTime = performance.now();
  updateStatus('Đang đọc tệp .th...', 20);

  const fileBuffer = await file.arrayBuffer();

  if (fileBuffer.byteLength < HEADER_SIZE + 16) {
    throw new Error('Tệp không đúng định dạng .th hoặc dung lượng quá nhỏ để giải mã.');
  }

  updateStatus('Đang xác thực Magic Header (TH_CRYPT_V1)...', 35);
  const fileBytes = new Uint8Array(fileBuffer);

  // 1. Validate Magic Header ("TH_CRYPT_V1")
  for (let i = 0; i < MAGIC_HEADER_SIZE; i++) {
    if (fileBytes[i] !== MAGIC_HEADER[i]) {
      throw new Error('Tệp không phải định dạng .th hợp lệ (Sai Magic Header TH_CRYPT_V1).');
    }
  }

  // 2. Extract Original Extension (10 bytes)
  const extBytes = fileBytes.subarray(MAGIC_HEADER_SIZE, MAGIC_HEADER_SIZE + EXTENSION_SIZE);
  let extString = '';
  for (let i = 0; i < extBytes.length; i++) {
    if (extBytes[i] === 0) break;
    extString += String.fromCharCode(extBytes[i]);
  }
  extString = extString.trim();

  // 3. Extract Salt (16 bytes)
  const saltOffset = MAGIC_HEADER_SIZE + EXTENSION_SIZE;
  const salt = fileBytes.subarray(saltOffset, saltOffset + SALT_SIZE);

  // 4. Extract IV (12 bytes)
  const ivOffset = saltOffset + SALT_SIZE;
  const iv = fileBytes.subarray(ivOffset, ivOffset + IV_SIZE);

  // 5. Extract Encrypted Payload
  const payloadOffset = ivOffset + IV_SIZE;
  const encryptedPayload = fileBytes.subarray(payloadOffset);

  updateStatus('Đang phái sinh khóa từ mật khẩu (PBKDF2)...', 60);
  const key = await deriveKey(password, salt, ['decrypt']);

  updateStatus('Đang giải mã và kiểm tra thẻ xác thực AES-GCM...', 80);

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
    // Web Crypto API throws OperationError when password or tag is incorrect
    throw new Error('Sai mật khẩu hoặc file đã bị sửa đổi/hư hỏng! Không thể giải mã.');
  }

  updateStatus('Khôi phục file gốc nguyên vẹn...', 95);

  // Reconstruct file name
  let originalFilename = file.name;
  if (originalFilename.toLowerCase().endsWith('.th')) {
    originalFilename = originalFilename.slice(0, -3);
  } else {
    originalFilename = getBaseName(originalFilename);
  }

  // If filename doesn't already end with the restored extension, append it
  if (extString && !originalFilename.toLowerCase().endsWith(`.${extString.toLowerCase()}`)) {
    originalFilename += `.${extString}`;
  }

  const duration = Math.round(performance.now() - startTime);
  updateStatus('Giải mã thành công!', 100);

  const blob = new Blob([decryptedBuffer], { type: 'application/octet-stream' });

  return {
    blob,
    filename: originalFilename,
    originalSize: file.size,
    decryptedSize: decryptedBuffer.byteLength,
    extension: extString,
    duration
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
    if (!file) return;
    state.encrypt.file = file;
    encFileName.textContent = file.name;
    encFileSize.textContent = formatBytes(file.size);
    encFileExt.textContent = getFileExtension(file.name) || 'FILE';
    encPreview.classList.add('active');
    encDropzone.style.display = 'none';
    encErrorBanner.classList.remove('active');
    encResultCard.classList.remove('active');
    updateEncryptBtnState();
  }

  function removeEncryptFile() {
    state.encrypt.file = null;
    encFileInput.value = '';
    encPreview.classList.remove('active');
    encDropzone.style.display = 'block';
    updateEncryptBtnState();
  }

  encDropzone.addEventListener('click', () => encFileInput.click());
  encFileInput.addEventListener('change', (e) => {
    if (e.target.files.length > 0) setEncryptFile(e.target.files[0]);
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
    if (e.dataTransfer.files.length > 0) {
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
      ? `<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19m-6.72-1.07a3 3 0 1 1-4.24-4.24"></path><line x1="1" y1="1" x2="23" y2="23"></line></svg>`
      : `<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"></path><circle cx="12" cy="12" r="3"></circle></svg>`;
  });

  // Action: Encrypt
  encBtnAction.addEventListener('click', async () => {
    if (!state.encrypt.file || !encPasswordInput.value) return;

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

      // Trigger automatic download
      const downloadUrl = triggerDownload(result.blob, result.filename);
      state.encrypt.downloadUrl = downloadUrl;
      state.encrypt.downloadFilename = result.filename;

      // Display result details
      encResultDetails.innerHTML = `
        Tên file đã mã hóa: <strong>${result.filename}</strong><br>
        Kích thước gốc: <strong>${formatBytes(result.originalSize)}</strong> &rarr; Kích thước .th: <strong>${formatBytes(result.encryptedSize)}</strong><br>
        Thời gian xử lý: <strong>${result.duration} ms</strong> | Header: <strong>49 bytes</strong>
      `;
      encResultCard.classList.add('active');
    } catch (err) {
      console.error(err);
      encErrorText.textContent = err.message || 'Có lỗi xảy ra trong quá trình mã hóa.';
      encErrorBanner.classList.add('active');
    } finally {
      setTimeout(() => {
        encStatusBox.classList.remove('active');
        encBtnAction.disabled = false;
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
    if (!file) return;

    if (!file.name.toLowerCase().endsWith('.th')) {
      decErrorText.textContent = 'Cảnh báo: Tệp không có đuôi mở rộng .th! Vui lòng chọn tệp .th hợp lệ.';
      decErrorBanner.classList.add('active');
    } else {
      decErrorBanner.classList.remove('active');
    }

    state.decrypt.file = file;
    decFileName.textContent = file.name;
    decFileSize.textContent = formatBytes(file.size);
    decFileExt.textContent = '.TH';
    decPreview.classList.add('active');
    decDropzone.style.display = 'none';
    decResultCard.classList.remove('active');
    updateDecryptBtnState();
  }

  function removeDecryptFile() {
    state.decrypt.file = null;
    decFileInput.value = '';
    decPreview.classList.remove('active');
    decDropzone.style.display = 'block';
    updateDecryptBtnState();
  }

  decDropzone.addEventListener('click', () => decFileInput.click());
  decFileInput.addEventListener('change', (e) => {
    if (e.target.files.length > 0) setDecryptFile(e.target.files[0]);
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
    if (e.dataTransfer.files.length > 0) {
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
      ? `<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19m-6.72-1.07a3 3 0 1 1-4.24-4.24"></path><line x1="1" y1="1" x2="23" y2="23"></line></svg>`
      : `<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"></path><circle cx="12" cy="12" r="3"></circle></svg>`;
  });

  // Action: Decrypt
  decBtnAction.addEventListener('click', async () => {
    if (!state.decrypt.file || !decPasswordInput.value) return;

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

      // Trigger automatic download
      const downloadUrl = triggerDownload(result.blob, result.filename);
      state.decrypt.downloadUrl = downloadUrl;
      state.decrypt.downloadFilename = result.filename;

      // Display result details
      decResultDetails.innerHTML = `
        Tên file đã phục hồi: <strong>${result.filename}</strong><br>
        Định dạng gốc: <strong>.${result.extension || 'file'}</strong><br>
        Dung lượng sau giải mã: <strong>${formatBytes(result.decryptedSize)}</strong> (Lossless 100%)<br>
        Thời gian xử lý: <strong>${result.duration} ms</strong>
      `;
      decResultCard.classList.add('active');
    } catch (err) {
      console.error(err);
      decErrorText.textContent = err.message || 'Lỗi giải mã: Vui lòng kiểm tra lại mật khẩu hoặc tệp tin.';
      decErrorBanner.classList.add('active');
    } finally {
      setTimeout(() => {
        decStatusBox.classList.remove('active');
        decBtnAction.disabled = false;
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
      document.body.removeChild(a);
    }
  });
});
