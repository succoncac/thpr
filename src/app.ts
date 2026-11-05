/**
 * TH10 Production Client Controller (app.js)
 * Zero-Error, Bulletproof Robustness, Memory Wiping, and Pure textContent Safety
 */

import {
  MAX_FILE_SIZE,
  HEADER_SIZE,
  SALT_SIZE,
  NONCE_SIZE,
  AppError,
  buildHeader64,
  parseHeader64,
  packPayload,
  unpackPayload,
  generateRandomOutputFilename,
  wipe,
} from './format';

import {
  deriveMasterKey,
  deriveStageKeys,
  encryptCascade,
  decryptCascade,
  runSelfTest,
  yieldEventLoop,
} from './crypto';

// ============================================================================
// STATE & MEMORY LIFECYCLE MANAGEMENT
// ============================================================================
let isBusy = false;
let isLibraryReady = false;

interface ActiveUrlRecord {
  url: string;
  timeoutId: number;
}

const activeBlobUrls: ActiveUrlRecord[] = [];

function registerBlobUrl(blob: Blob): string {
  const url = URL.createObjectURL(blob);
  const timeoutId = window.setTimeout(() => {
    revokeUrl(url);
  }, 60000); // Tự động thu hồi sau 60 giây
  activeBlobUrls.push({ url, timeoutId });
  return url;
}

function revokeUrl(urlToRevoke: string): void {
  const index = activeBlobUrls.findIndex(item => item.url === urlToRevoke);
  if (index !== -1) {
    const item = activeBlobUrls[index];
    window.clearTimeout(item.timeoutId);
    URL.revokeObjectURL(item.url);
    activeBlobUrls.splice(index, 1);
  }
}

function revokeAllUrls(): void {
  while (activeBlobUrls.length > 0) {
    const item = activeBlobUrls.pop();
    if (item) {
      window.clearTimeout(item.timeoutId);
      URL.revokeObjectURL(item.url);
    }
  }
}

// Giải phóng toàn bộ URL khi người dùng rời trang
window.addEventListener('pagehide', () => {
  revokeAllUrls();
});

// ============================================================================
// TIỆN ÍCH HỖ TRỢ AN TOÀN
// ============================================================================
function formatBytes(bytes: number, decimals: number = 2): string {
  if (bytes === 0) return '0 Bytes';
  const k = 1024;
  const dm = decimals < 0 ? 0 : decimals;
  const sizes = ['Bytes', 'KB', 'MB', 'GB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return parseFloat((bytes / Math.pow(k, i)).toFixed(dm)) + ' ' + sizes[i];
}

async function readFileBytes(file: File): Promise<Uint8Array> {
  if (typeof file.arrayBuffer === 'function') {
    try {
      const buf = await file.arrayBuffer();
      return new Uint8Array(buf);
    } catch {
      // Fallback nếu trình duyệt gặp lỗi
    }
  }
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onload = () => {
      if (reader.result instanceof ArrayBuffer) {
        resolve(new Uint8Array(reader.result));
      } else {
        reject(new AppError('E_PAYLOAD', 'Không thể đọc tệp dưới dạng ArrayBuffer.'));
      }
    };
    reader.onerror = () => reject(new AppError('E_PAYLOAD', 'Lỗi truy cập hệ thống tệp.'));
    reader.readAsArrayBuffer(file);
  });
}

function triggerDownload(url: string, filename: string): void {
  const anchor = document.createElement('a');
  anchor.style.display = 'none';
  anchor.href = url;
  anchor.download = filename;
  document.body.appendChild(anchor);
  anchor.click();
  setTimeout(() => {
    if (document.body.contains(anchor)) {
      document.body.removeChild(anchor);
    }
  }, 1000);
}

function evaluatePasswordStrength(password: string): { score: number; text: string; color: string } {
  if (!password) return { score: 0, text: 'Chưa nhập mật khẩu', color: 'transparent' };
  let score = 0;
  if (password.length >= 8) score++;
  if (password.length >= 14) score++;
  if (/[A-Z]/.test(password) && /[a-z]/.test(password)) score++;
  if (/[0-9]/.test(password) && /[^A-Za-z0-9]/.test(password)) score++;

  switch (score) {
    case 1:
      return { score: 1, text: 'Rất yếu', color: '#f43f5e' };
    case 2:
      return { score: 2, text: 'Trung bình', color: '#f59e0b' };
    case 3:
      return { score: 3, text: 'Mạnh', color: '#06b6d4' };
    case 4:
      return { score: 4, text: 'Rất mạnh', color: '#10b981' };
    default:
      return { score: 0, text: 'Yếu', color: '#f43f5e' };
  }
}

// ============================================================================
// KHỞI TẠO DOM VÀ SỰ KIỆN GIAO DIỆN
// ============================================================================
document.addEventListener('DOMContentLoaded', async () => {
  // DOM - Thông báo thư viện
  const libStatusNotice = document.getElementById('lib-status-notice') as HTMLElement;
  const btnRetryLib = document.getElementById('btn-retry-lib') as HTMLButtonElement;

  // DOM - Mã Hóa
  const encDropzone = document.getElementById('enc-dropzone') as HTMLElement;
  const encFileInput = document.getElementById('enc-file-input') as HTMLInputElement;
  const encFilePreview = document.getElementById('enc-file-preview') as HTMLElement;
  const encFileName = document.getElementById('enc-file-name') as HTMLElement;
  const encFileSize = document.getElementById('enc-file-size') as HTMLElement;
  const encBtnRemove = document.getElementById('enc-btn-remove') as HTMLButtonElement;
  const encPassword = document.getElementById('enc-password') as HTMLInputElement;
  const encBtnTogglePwd = document.getElementById('enc-btn-toggle-pwd') as HTMLButtonElement;
  const encBtnAction = document.getElementById('enc-btn-action') as HTMLButtonElement;
  const encStatusBox = document.getElementById('enc-status-box') as HTMLElement;
  const encStatusText = document.getElementById('enc-status-text') as HTMLElement;
  const encProgressFill = document.getElementById('enc-progress-fill') as HTMLElement;
  const encResultCard = document.getElementById('enc-result-card') as HTMLElement;
  const encResultFilename = document.getElementById('enc-result-filename') as HTMLElement;
  const encResultSize = document.getElementById('enc-result-size') as HTMLElement;
  const encResultTime = document.getElementById('enc-result-time') as HTMLElement;
  const encBtnDownload = document.getElementById('enc-btn-download') as HTMLButtonElement;
  const encErrorBanner = document.getElementById('enc-error-banner') as HTMLElement;
  const encErrorText = document.getElementById('enc-error-text') as HTMLElement;

  const encStrengthBars = [
    document.getElementById('pwd-bar-1') as HTMLElement,
    document.getElementById('pwd-bar-2') as HTMLElement,
    document.getElementById('pwd-bar-3') as HTMLElement,
    document.getElementById('pwd-bar-4') as HTMLElement,
  ];
  const encStrengthLabel = document.getElementById('pwd-strength-label') as HTMLElement;

  // DOM - Giải Mã
  const decDropzone = document.getElementById('dec-dropzone') as HTMLElement;
  const decFileInput = document.getElementById('dec-file-input') as HTMLInputElement;
  const decFilePreview = document.getElementById('dec-file-preview') as HTMLElement;
  const decFileName = document.getElementById('dec-file-name') as HTMLElement;
  const decFileSize = document.getElementById('dec-file-size') as HTMLElement;
  const decBtnRemove = document.getElementById('dec-btn-remove') as HTMLButtonElement;
  const decPassword = document.getElementById('dec-password') as HTMLInputElement;
  const decBtnTogglePwd = document.getElementById('dec-btn-toggle-pwd') as HTMLButtonElement;
  const decBtnAction = document.getElementById('dec-btn-action') as HTMLButtonElement;
  const decStatusBox = document.getElementById('dec-status-box') as HTMLElement;
  const decStatusText = document.getElementById('dec-status-text') as HTMLElement;
  const decProgressFill = document.getElementById('dec-progress-fill') as HTMLElement;
  const decResultCard = document.getElementById('dec-result-card') as HTMLElement;
  const decResultFilename = document.getElementById('dec-result-filename') as HTMLElement;
  const decResultSize = document.getElementById('dec-result-size') as HTMLElement;
  const decResultMime = document.getElementById('dec-result-mime') as HTMLElement;
  const decResultTime = document.getElementById('dec-result-time') as HTMLElement;
  const decBtnDownload = document.getElementById('dec-btn-download') as HTMLButtonElement;
  const decErrorBanner = document.getElementById('dec-error-banner') as HTMLElement;
  const decErrorText = document.getElementById('dec-error-text') as HTMLElement;

  // Trạng thái cục bộ
  let selectedEncryptFile: File | null = null;
  let selectedDecryptFile: File | null = null;
  let lastEncryptDownloadUrl: string | null = null;
  let lastEncryptDownloadName: string = '';
  let lastDecryptDownloadUrl: string | null = null;
  let lastDecryptDownloadName: string = '';

  function setFormBusy(busy: boolean): void {
    isBusy = busy;
    encBtnAction.disabled = busy || !selectedEncryptFile || encPassword.value.length === 0 || !isLibraryReady;
    decBtnAction.disabled = busy || !selectedDecryptFile || decPassword.value.length === 0 || !isLibraryReady;
    encPassword.disabled = busy;
    decPassword.disabled = busy;
    encBtnRemove.disabled = busy;
    decBtnRemove.disabled = busy;
  }

  function updateActionButtons(): void {
    if (isBusy) return;
    encBtnAction.disabled = !isLibraryReady || !selectedEncryptFile || encPassword.value.length === 0;
    decBtnAction.disabled = !isLibraryReady || !selectedDecryptFile || decPassword.value.length === 0;
  }

  // Khởi động Self-Test
  async function performSelfTest(): Promise<void> {
    libStatusNotice.style.display = 'block';
    libStatusNotice.textContent = 'Đang kiểm tra môi trường mật mã học...';
    btnRetryLib.style.display = 'none';

    try {
      const ok = await runSelfTest();
      if (ok) {
        isLibraryReady = true;
        libStatusNotice.style.display = 'none';
        updateActionButtons();
      } else {
        throw new Error('Self-test thất bại');
      }
    } catch {
      isLibraryReady = false;
      libStatusNotice.style.display = 'block';
      libStatusNotice.textContent = 'Lỗi khởi động module mật mã WebAssembly. Vui lòng thử tải lại.';
      btnRetryLib.style.display = 'inline-block';
      updateActionButtons();
    }
  }

  btnRetryLib.addEventListener('click', performSelfTest);
  await performSelfTest();

  // --- MÃ HÓA: Chọn file & Kéo thả ---
  function selectEncryptFile(file: File): void {
    if (file.size > MAX_FILE_SIZE) {
      encErrorText.textContent = `Tệp tin vượt quá dung lượng tối đa cho phép (${formatBytes(MAX_FILE_SIZE)}).`;
      encErrorBanner.classList.add('active');
      return;
    }

    encErrorBanner.classList.remove('active');
    encResultCard.classList.remove('active');
    selectedEncryptFile = file;

    encFileName.textContent = file.name || 'unnamed';
    encFileSize.textContent = formatBytes(file.size);
    encFilePreview.classList.add('active');
    encDropzone.style.display = 'none';
    updateActionButtons();
  }

  function clearEncryptFile(): void {
    selectedEncryptFile = null;
    encFileInput.value = '';
    encPassword.value = '';
    encStrengthLabel.textContent = 'Chưa nhập mật khẩu';
    encStrengthLabel.style.color = 'var(--text-muted)';
    encStrengthBars.forEach(bar => { bar.style.backgroundColor = 'rgba(255, 255, 255, 0.08)'; });
    encFilePreview.classList.remove('active');
    encDropzone.style.display = 'block';
    encResultCard.classList.remove('active');
    encErrorBanner.classList.remove('active');
    updateActionButtons();
  }

  encDropzone.addEventListener('click', () => {
    if (!isBusy) encFileInput.click();
  });

  encFileInput.addEventListener('change', () => {
    if (encFileInput.files && encFileInput.files.length > 0) {
      selectEncryptFile(encFileInput.files[0]);
    }
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
      selectEncryptFile(e.dataTransfer.files[0]);
    }
  });

  encBtnRemove.addEventListener('click', clearEncryptFile);

  encPassword.addEventListener('input', () => {
    const val = encPassword.value;
    const { score, text, color } = evaluatePasswordStrength(val);
    encStrengthLabel.textContent = val ? text : 'Chưa nhập mật khẩu';
    encStrengthLabel.style.color = val ? color : 'var(--text-muted)';
    encStrengthBars.forEach((bar, index) => {
      bar.style.backgroundColor = index < score ? color : 'rgba(255, 255, 255, 0.08)';
    });
    updateActionButtons();
  });

  encBtnTogglePwd.addEventListener('click', () => {
    encPassword.type = encPassword.type === 'password' ? 'text' : 'password';
  });

  // Thực thi Mã Hóa TH10
  encBtnAction.addEventListener('click', async () => {
    if (isBusy || !selectedEncryptFile || encPassword.value.length === 0) return;

    setFormBusy(true);
    encErrorBanner.classList.remove('active');
    encResultCard.classList.remove('active');
    encStatusBox.classList.add('active');
    encStatusText.textContent = 'Đang đọc tệp tin...';
    encProgressFill.style.width = '15%';

    const startTime = performance.now();
    let rawFileBytes: Uint8Array | null = null;
    let payload: Uint8Array | null = null;
    let masterKeyBytes: Uint8Array | null = null;

    try {
      await yieldEventLoop();
      rawFileBytes = await readFileBytes(selectedEncryptFile);

      encStatusText.textContent = 'Đang đóng gói và thêm padding an toàn...';
      encProgressFill.style.width = '30%';
      await yieldEventLoop();

      payload = packPayload(
        selectedEncryptFile.name || 'document',
        selectedEncryptFile.type || 'application/octet-stream',
        rawFileBytes
      );
      // Xóa tệp thô khỏi RAM ngay lập tức
      wipe(rawFileBytes);
      rawFileBytes = null;

      encStatusText.textContent = 'Đang dẫn xuất khóa Argon2id...';
      encProgressFill.style.width = '55%';
      await yieldEventLoop();

      const salt = new Uint8Array(SALT_SIZE);
      const nonce1 = new Uint8Array(NONCE_SIZE);
      const nonce2 = new Uint8Array(NONCE_SIZE);
      const nonce3 = new Uint8Array(NONCE_SIZE);
      crypto.getRandomValues(salt);
      crypto.getRandomValues(nonce1);
      crypto.getRandomValues(nonce2);
      crypto.getRandomValues(nonce3);

      const kdfResult = await deriveMasterKey(encPassword.value, salt);
      masterKeyBytes = kdfResult.masterKey;

      encStatusText.textContent = 'Đang thực thi mã hóa 3 tầng lồng nhau...';
      encProgressFill.style.width = '80%';
      await yieldEventLoop();

      const header = buildHeader64(
        kdfResult.memKiB,
        kdfResult.iterations,
        kdfResult.parallelism,
        salt,
        nonce1,
        nonce2,
        nonce3
      );

      const stageKeys = await deriveStageKeys(masterKeyBytes, salt, 'encrypt');
      masterKeyBytes = null; // Đã được wipe bên trong deriveStageKeys

      const finalCipherBytes = await encryptCascade(payload, stageKeys, header);
      payload = null;

      encProgressFill.style.width = '100%';
      encStatusText.textContent = 'Mã hóa hoàn tất!';
      await yieldEventLoop();

      const durationMs = Math.round(performance.now() - startTime);
      const outputFilename = generateRandomOutputFilename();
      const outputBlob = new Blob([finalCipherBytes as unknown as BlobPart], { type: 'application/octet-stream' });

      if (lastEncryptDownloadUrl) {
        revokeUrl(lastEncryptDownloadUrl);
      }
      lastEncryptDownloadUrl = registerBlobUrl(outputBlob);
      lastEncryptDownloadName = outputFilename;

      // Hiển thị kết quả an toàn bằng textContent
      encResultFilename.textContent = outputFilename;
      encResultSize.textContent = `${formatBytes(selectedEncryptFile.size)} → ${formatBytes(finalCipherBytes.byteLength)}`;
      encResultTime.textContent = `${durationMs} ms`;
      encResultCard.classList.add('active');

      // Tự động kích hoạt tải xuống
      triggerDownload(lastEncryptDownloadUrl, outputFilename);
    } catch (err: unknown) {
      const msg = err instanceof AppError ? err.message : (err as Error)?.message || 'Đã xảy ra lỗi không xác định trong quá trình mã hóa.';
      encErrorText.textContent = msg;
      encErrorBanner.classList.add('active');
    } finally {
      wipe(rawFileBytes);
      wipe(payload);
      wipe(masterKeyBytes);
      setTimeout(() => {
        encStatusBox.classList.remove('active');
        setFormBusy(false);
      }, 300);
    }
  });

  encBtnDownload.addEventListener('click', () => {
    if (lastEncryptDownloadUrl && lastEncryptDownloadName) {
      triggerDownload(lastEncryptDownloadUrl, lastEncryptDownloadName);
    }
  });

  // --- GIẢI MÃ: Chọn file & Kéo thả ---
  function selectDecryptFile(file: File): void {
    decErrorBanner.classList.remove('active');
    decResultCard.classList.remove('active');
    selectedDecryptFile = file;

    decFileName.textContent = file.name || 'protected.th';
    decFileSize.textContent = formatBytes(file.size);
    decFilePreview.classList.add('active');
    decDropzone.style.display = 'none';
    updateActionButtons();
  }

  function clearDecryptFile(): void {
    selectedDecryptFile = null;
    decFileInput.value = '';
    decPassword.value = '';
    decFilePreview.classList.remove('active');
    decDropzone.style.display = 'block';
    decResultCard.classList.remove('active');
    decErrorBanner.classList.remove('active');
    updateActionButtons();
  }

  decDropzone.addEventListener('click', () => {
    if (!isBusy) decFileInput.click();
  });

  decFileInput.addEventListener('change', () => {
    if (decFileInput.files && decFileInput.files.length > 0) {
      selectDecryptFile(decFileInput.files[0]);
    }
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
      selectDecryptFile(e.dataTransfer.files[0]);
    }
  });

  decBtnRemove.addEventListener('click', clearDecryptFile);
  decPassword.addEventListener('input', updateActionButtons);

  decBtnTogglePwd.addEventListener('click', () => {
    decPassword.type = decPassword.type === 'password' ? 'text' : 'password';
  });

  // Thực thi Giải Mã TH10
  decBtnAction.addEventListener('click', async () => {
    if (isBusy || !selectedDecryptFile || decPassword.value.length === 0) return;

    setFormBusy(true);
    decErrorBanner.classList.remove('active');
    decResultCard.classList.remove('active');
    decStatusBox.classList.add('active');
    decStatusText.textContent = 'Đang đọc tệp tin .th...';
    decProgressFill.style.width = '15%';

    const startTime = performance.now();
    let fileBytes: Uint8Array | null = null;
    let decryptedPayload: Uint8Array | null = null;
    let masterKeyBytes: Uint8Array | null = null;

    try {
      await yieldEventLoop();
      fileBytes = await readFileBytes(selectedDecryptFile);

      if (fileBytes.byteLength < HEADER_SIZE + 16 * 3) {
        throw new AppError('E_TOO_SHORT');
      }

      decStatusText.textContent = 'Đang kiểm tra cấu trúc Header...';
      decProgressFill.style.width = '30%';
      await yieldEventLoop();

      const header = parseHeader64(fileBytes);

      decStatusText.textContent = 'Đang dẫn xuất khóa phục hồi...';
      decProgressFill.style.width = '55%';
      await yieldEventLoop();

      const kdfResult = await deriveMasterKey(
        decPassword.value,
        header.salt,
        header.memKiB,
        header.iterations,
        header.parallelism
      );
      masterKeyBytes = kdfResult.masterKey;

      decStatusText.textContent = 'Đang bóc tách 3 tầng mã hóa...';
      decProgressFill.style.width = '80%';
      await yieldEventLoop();

      const stageKeys = await deriveStageKeys(masterKeyBytes, header.salt, 'decrypt');
      masterKeyBytes = null; // Đã wipe

      decryptedPayload = await decryptCascade(fileBytes, stageKeys, header);
      // Xóa dữ liệu tệp mã hóa khỏi RAM
      wipe(fileBytes);
      fileBytes = null;

      decStatusText.textContent = 'Đang xác thực Canary & giải nén Payload...';
      decProgressFill.style.width = '95%';
      await yieldEventLoop();

      const payload = unpackPayload(decryptedPayload);
      wipe(decryptedPayload);
      decryptedPayload = null;

      decProgressFill.style.width = '100%';
      decStatusText.textContent = 'Giải mã thành công!';
      await yieldEventLoop();

      const durationMs = Math.round(performance.now() - startTime);
      const outBlob = new Blob([payload.content as unknown as BlobPart], { type: 'application/octet-stream' });

      if (lastDecryptDownloadUrl) {
        revokeUrl(lastDecryptDownloadUrl);
      }
      lastDecryptDownloadUrl = registerBlobUrl(outBlob);
      lastDecryptDownloadName = payload.filename;

      // Hiển thị kết quả giải mã an toàn qua textContent
      decResultFilename.textContent = payload.filename;
      decResultSize.textContent = formatBytes(payload.content.byteLength);
      decResultMime.textContent = payload.mimeType;
      decResultTime.textContent = `${durationMs} ms`;
      decResultCard.classList.add('active');

      // Tự động tải xuống file giải mã
      triggerDownload(lastDecryptDownloadUrl, payload.filename);
    } catch (err: unknown) {
      const msg = err instanceof AppError ? err.message : (err as Error)?.message || 'Sai mật khẩu, hoặc tệp đã bị sửa/hỏng. Không thể phân biệt hai trường hợp này.';
      decErrorText.textContent = msg;
      decErrorBanner.classList.add('active');
    } finally {
      wipe(fileBytes);
      wipe(decryptedPayload);
      wipe(masterKeyBytes);
      setTimeout(() => {
        decStatusBox.classList.remove('active');
        setFormBusy(false);
      }, 300);
    }
  });

  decBtnDownload.addEventListener('click', () => {
    if (lastDecryptDownloadUrl && lastDecryptDownloadName) {
      triggerDownload(lastDecryptDownloadUrl, lastDecryptDownloadName);
    }
  });
});
