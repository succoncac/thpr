/**
 * TH10 Production Application Controller (app.js)
 * Standalone Client Controller - Zero-Error, Bulletproof Robustness, Memory Wiping
 */

(function () {
  'use strict';

  var F = window.TH10Format;
  var C = window.TH10Crypto;
  var U = window.TH10UI;

  // ============================================================================
  // STATE MANAGEMENT & URL LIFECYCLE
  // ============================================================================
  var isBusy = false;
  var isLibraryReady = false;

  var activeBlobUrls = [];

  function registerBlobUrl(blob) {
    var url = URL.createObjectURL(blob);
    var timeoutId = window.setTimeout(function () {
      revokeUrl(url);
    }, 60000); // Tự động thu hồi sau 60 giây
    activeBlobUrls.push({ url: url, timeoutId: timeoutId });
    return url;
  }

  function revokeUrl(urlToRevoke) {
    for (var i = 0; i < activeBlobUrls.length; i++) {
      if (activeBlobUrls[i].url === urlToRevoke) {
        window.clearTimeout(activeBlobUrls[i].timeoutId);
        URL.revokeObjectURL(activeBlobUrls[i].url);
        activeBlobUrls.splice(i, 1);
        break;
      }
    }
  }

  function revokeAllActiveUrls() {
    while (activeBlobUrls.length > 0) {
      var item = activeBlobUrls.pop();
      if (item) {
        window.clearTimeout(item.timeoutId);
        URL.revokeObjectURL(item.url);
      }
    }
  }

  window.addEventListener('pagehide', revokeAllActiveUrls);

  // ============================================================================
  // DOM ELEMENT SELECTORS
  // ============================================================================
  var libStatusNotice = document.getElementById('lib-status-notice');
  var btnRetryLib = document.getElementById('btn-retry-lib');

  // Encryption Elements
  var encDropzone = document.getElementById('enc-dropzone');
  var encFileInput = document.getElementById('enc-file-input');
  var encFilePreview = document.getElementById('enc-file-preview');
  var encFileName = document.getElementById('enc-file-name');
  var encFileSize = document.getElementById('enc-file-size');
  var encBtnRemove = document.getElementById('enc-btn-remove');

  var encPassword = document.getElementById('enc-password');
  var encConfirmPassword = document.getElementById('enc-confirm-password');
  var encTogglePwd = document.getElementById('enc-toggle-pwd');
  var encToggleConfirmPwd = document.getElementById('enc-toggle-confirm-pwd');
  var pwdStrengthLabel = document.getElementById('pwd-strength-label');

  var encBtnSubmit = document.getElementById('enc-btn-submit');
  var encProgressContainer = document.getElementById('enc-progress-container');
  var encProgressFill = document.getElementById('enc-progress-fill');
  var encStatusText = document.getElementById('enc-status-text');

  var encResultCard = document.getElementById('enc-result-card');
  var encResultFilename = document.getElementById('enc-result-filename');
  var encResultSize = document.getElementById('enc-result-size');
  var encResultTime = document.getElementById('enc-result-time');
  var encBtnDownload = document.getElementById('enc-btn-download');
  var encErrorBanner = document.getElementById('enc-error-banner');
  var encErrorText = document.getElementById('enc-error-text');

  // Decryption Elements
  var decDropzone = document.getElementById('dec-dropzone');
  var decFileInput = document.getElementById('dec-file-input');
  var decFilePreview = document.getElementById('dec-file-preview');
  var decFileName = document.getElementById('dec-file-name');
  var decFileSize = document.getElementById('dec-file-size');
  var decBtnRemove = document.getElementById('dec-btn-remove');

  var decPassword = document.getElementById('dec-password');
  var decTogglePwd = document.getElementById('dec-toggle-pwd');

  var decBtnSubmit = document.getElementById('dec-btn-submit');
  var decProgressContainer = document.getElementById('dec-progress-container');
  var decProgressFill = document.getElementById('dec-progress-fill');
  var decStatusText = document.getElementById('dec-status-text');

  var decResultCard = document.getElementById('dec-result-card');
  var decResultFilename = document.getElementById('dec-result-filename');
  var decResultSize = document.getElementById('dec-result-size');
  var decResultTime = document.getElementById('dec-result-time');
  var decBtnDownload = document.getElementById('dec-btn-download');
  var decErrorBanner = document.getElementById('dec-error-banner');
  var decErrorText = document.getElementById('dec-error-text');

  // Selected File States
  var selectedEncryptFile = null;
  var selectedDecryptFile = null;
  var lastEncryptDownloadUrl = null;
  var lastEncryptDownloadName = 'encrypted.th';
  var lastDecryptDownloadUrl = null;
  var lastDecryptDownloadName = 'decrypted.bin';

  // ============================================================================
  // INITIALIZATION & SELF-TEST GATE
  // ============================================================================
  async function initializeApp() {
    setActionsDisabled(true);
    if (libStatusNotice) {
      libStatusNotice.style.display = 'flex';
      var noticeSpan = libStatusNotice.querySelector('span');
      if (noticeSpan) noticeSpan.textContent = 'Đang nạp và kiểm tra tính toàn vẹn thư viện mật mã...';
    }
    if (btnRetryLib) {
      btnRetryLib.style.display = 'none';
    }

    try {
      if (!C.isArgon2Ready()) {
        throw new F.AppError('E_LIB');
      }

      await C.runSelfTest();

      isLibraryReady = true;
      if (libStatusNotice) {
        libStatusNotice.style.display = 'none';
      }
      if (U && typeof U.setupTabs === 'function') {
        U.setupTabs();
      }
      setActionsDisabled(false);
    } catch (err) {
      isLibraryReady = false;
      setActionsDisabled(true);
      if (libStatusNotice) {
        libStatusNotice.style.display = 'flex';
        var span = libStatusNotice.querySelector('span');
        if (span) {
          span.textContent = 'Lỗi khởi tạo thư viện mật mã. Vui lòng thử tải lại trang hoặc kiểm tra kết nối.';
        }
      }
      if (btnRetryLib) {
        btnRetryLib.style.display = 'inline-block';
      }
    }
  }

  function setActionsDisabled(disabled) {
    if (encBtnSubmit) encBtnSubmit.disabled = disabled;
    if (decBtnSubmit) decBtnSubmit.disabled = disabled;
    if (encFileInput) encFileInput.disabled = disabled;
    if (decFileInput) decFileInput.disabled = disabled;
  }

  if (btnRetryLib) {
    btnRetryLib.addEventListener('click', function () {
      initializeApp();
    });
  }

  // ============================================================================
  // PASSWORD VISIBILITY & ENTROPY METER
  // ============================================================================
  function setupPasswordToggle(inputElem, toggleBtn) {
    if (!inputElem || !toggleBtn) return;
    toggleBtn.addEventListener('click', function () {
      if (inputElem.type === 'password') {
        inputElem.type = 'text';
        toggleBtn.setAttribute('aria-label', 'Ẩn mật khẩu');
        toggleBtn.classList.add('active');
      } else {
        inputElem.type = 'password';
        toggleBtn.setAttribute('aria-label', 'Hiện mật khẩu');
        toggleBtn.classList.remove('active');
      }
    });
  }

  setupPasswordToggle(encPassword, encTogglePwd);
  setupPasswordToggle(encConfirmPassword, encToggleConfirmPwd);
  setupPasswordToggle(decPassword, decTogglePwd);

  if (encPassword && pwdStrengthLabel) {
    encPassword.addEventListener('input', function () {
      var pwd = encPassword.value;
      var bits = U.calculateEntropy(pwd);
      var info = U.getStrengthLabel(bits);
      pwdStrengthLabel.textContent = info.label;
      pwdStrengthLabel.className = 'pwd-strength-txt ' + info.cls;
    });
  }

  // ============================================================================
  // FILE SELECTION & DRAG-AND-DROP
  // ============================================================================
  function setupDropzone(dropzone, fileInput, onFileSelected) {
    if (!dropzone || !fileInput) return;

    dropzone.addEventListener('click', function () {
      if (!isBusy) fileInput.click();
    });

    dropzone.addEventListener('keydown', function (e) {
      if ((e.key === 'Enter' || e.key === ' ') && !isBusy) {
        e.preventDefault();
        fileInput.click();
      }
    });

    ['dragenter', 'dragover'].forEach(function (eventName) {
      dropzone.addEventListener(eventName, function (e) {
        e.preventDefault();
        e.stopPropagation();
        if (!isBusy) dropzone.classList.add('drag-active');
      });
    });

    ['dragleave', 'drop'].forEach(function (eventName) {
      dropzone.addEventListener(eventName, function (e) {
        e.preventDefault();
        e.stopPropagation();
        dropzone.classList.remove('drag-active');
      });
    });

    dropzone.addEventListener('drop', function (e) {
      if (isBusy) return;
      var dt = e.dataTransfer;
      if (dt && dt.files && dt.files.length > 0) {
        onFileSelected(dt.files[0]);
      }
    });

    fileInput.addEventListener('change', function () {
      if (fileInput.files && fileInput.files.length > 0) {
        onFileSelected(fileInput.files[0]);
      }
    });
  }

  // Encrypt File Setup
  setupDropzone(encDropzone, encFileInput, function (file) {
    if (file.size > F.MAX_FILE_SIZE) {
      showEncryptError('E_TOO_LARGE');
      return;
    }
    selectedEncryptFile = file;
    hideEncryptError();
    encDropzone.style.display = 'none';
    encFilePreview.style.display = 'flex';
    encFileName.textContent = file.name;
    encFileSize.textContent = U.formatBytes(file.size);
  });

  if (encBtnRemove) {
    encBtnRemove.addEventListener('click', function (e) {
      e.stopPropagation();
      selectedEncryptFile = null;
      encFileInput.value = '';
      encFilePreview.style.display = 'none';
      encDropzone.style.display = 'flex';
      encResultCard.style.display = 'none';
      hideEncryptError();
    });
  }

  // Decrypt File Setup
  setupDropzone(decDropzone, decFileInput, function (file) {
    if (file.size > F.MAX_FILE_SIZE) {
      showDecryptError('E_TOO_LARGE');
      return;
    }
    if (file.size < F.HEADER_SIZE + 48) {
      showDecryptError('E_TOO_SHORT');
      return;
    }
    selectedDecryptFile = file;
    hideDecryptError();
    decDropzone.style.display = 'none';
    decFilePreview.style.display = 'flex';
    decFileName.textContent = file.name;
    decFileSize.textContent = U.formatBytes(file.size);
  });

  if (decBtnRemove) {
    decBtnRemove.addEventListener('click', function (e) {
      e.stopPropagation();
      selectedDecryptFile = null;
      decFileInput.value = '';
      decFilePreview.style.display = 'none';
      decDropzone.style.display = 'flex';
      decResultCard.style.display = 'none';
      if (U && typeof U.clearDecryptedPreview === 'function') {
        U.clearDecryptedPreview();
      }
      hideDecryptError();
    });
  }

  // ============================================================================
  // ERROR BANNER HELPERS (PURE textContent)
  // ============================================================================
  function showEncryptError(codeOrMsg) {
    var msg = F.ERROR_MESSAGES[codeOrMsg] || codeOrMsg;
    encErrorText.textContent = msg;
    encErrorBanner.style.display = 'flex';
  }

  function hideEncryptError() {
    encErrorBanner.style.display = 'none';
    encErrorText.textContent = '';
  }

  function showDecryptError(codeOrMsg) {
    var msg = F.ERROR_MESSAGES[codeOrMsg] || codeOrMsg;
    decErrorText.textContent = msg;
    decErrorBanner.style.display = 'flex';
  }

  function hideDecryptError() {
    decErrorBanner.style.display = 'none';
    decErrorText.textContent = '';
  }

  // ============================================================================
  // BUFFER READING HELPER
  // ============================================================================
  function readFileBuffer(file) {
    if (typeof file.arrayBuffer === 'function') {
      return file.arrayBuffer();
    }
    return new Promise(function (resolve, reject) {
      var reader = new FileReader();
      reader.onload = function () {
        resolve(reader.result);
      };
      reader.onerror = function () {
        reject(new Error("Không thể đọc tệp tin."));
      };
      reader.readAsArrayBuffer(file);
    });
  }

  // ============================================================================
  // ENCRYPTION EXECUTION FLOW
  // ============================================================================
  if (encBtnSubmit) {
    encBtnSubmit.addEventListener('click', async function () {
      if (isBusy || !isLibraryReady) return;

      hideEncryptError();
      encResultCard.style.display = 'none';

      // 1. Kiểm tra đầu vào
      if (!selectedEncryptFile) {
        showEncryptError('E_NO_FILE');
        return;
      }

      var password = encPassword.value;
      var confirmPassword = encConfirmPassword.value;

      // NGAY LẬP TỨC XÓA SẠCH VÀ BLUR Ô MẬT KHẨU KHỎI DOM (CHỐNG SHOULDER SURFING & EXTENSION DOM SNIFFING)
      encPassword.value = '';
      encConfirmPassword.value = '';
      encPassword.blur();
      encConfirmPassword.blur();
      if (pwdStrengthLabel) {
        pwdStrengthLabel.textContent = 'Đã xóa an toàn khỏi DOM';
        pwdStrengthLabel.className = 'pwd-strength-txt strength-none';
      }

      if (!password) {
        showEncryptError('E_NO_PASSWORD');
        return;
      }

      if (password !== confirmPassword) {
        password = '';
        confirmPassword = '';
        showEncryptError('E_PASSWORD_MISMATCH');
        return;
      }

      if (selectedEncryptFile.size > F.MAX_FILE_SIZE) {
        password = '';
        confirmPassword = '';
        showEncryptError('E_TOO_LARGE');
        return;
      }

      isBusy = true;
      setActionsDisabled(true);
      encProgressContainer.style.display = 'block';
      encProgressFill.style.width = '15%';
      encStatusText.textContent = 'Đang đọc tệp tin vào bộ nhớ...';

      var rawFileBuffer = null;
      var payload = null;
      var masterKey = null;

      var startTime = performance.now();

      try {
        await C.yieldEventLoop();

        // 2. Đọc tệp
        rawFileBuffer = await readFileBuffer(selectedEncryptFile);
        var fileBytes = new Uint8Array(rawFileBuffer);

        encProgressFill.style.width = '35%';
        encStatusText.textContent = 'Đang đóng gói cấu trúc và đệm ngẫu nhiên...';
        await C.yieldEventLoop();

        // 3. Đóng gói Payload
        var mime = selectedEncryptFile.type || 'application/octet-stream';
        payload = F.packPayload(selectedEncryptFile.name, mime, fileBytes);

        // 4. Sinh Salt và 3 Nonces CSPRNG
        var salt = new Uint8Array(F.SALT_SIZE);
        crypto.getRandomValues(salt);
        var nonce1 = new Uint8Array(F.NONCE_SIZE);
        crypto.getRandomValues(nonce1);
        var nonce2 = new Uint8Array(F.NONCE_SIZE);
        crypto.getRandomValues(nonce2);
        var nonce3 = new Uint8Array(F.NONCE_SIZE);
        crypto.getRandomValues(nonce3);

        encProgressFill.style.width = '55%';
        encStatusText.textContent = 'Đang dẫn xuất khóa bảo mật cao Argon2id...';
        await C.yieldEventLoop();

        // 5. Dẫn xuất Master Key qua Argon2id
        var kdf = await C.deriveMasterKey(password, salt);
        masterKey = kdf.masterKey;

        // Xây dựng Header 64 byte
        var header = F.buildHeader64(
          kdf.memKiB,
          kdf.iterations,
          kdf.parallelism,
          salt,
          nonce1,
          nonce2,
          nonce3
        );

        encProgressFill.style.width = '75%';
        encStatusText.textContent = 'Đang thực thi mã hóa 3 tầng AES-256-GCM...';
        await C.yieldEventLoop();

        // 6. Dẫn xuất 3 Stage Keys và Mã hóa 3 tầng
        var stageKeys = await C.deriveStageKeys(masterKey, salt, 'encrypt');
        masterKey = null;

        var finalCipherBytes = await C.encryptCascade(payload, stageKeys, header);
        payload = null;

        encProgressFill.style.width = '100%';
        encStatusText.textContent = 'Mã hóa hoàn tất!';
        await C.yieldEventLoop();

        var durationMs = Math.round(performance.now() - startTime);
        var outputFilename = F.generateRandomOutputFilename();
        var outputBlob = new Blob([finalCipherBytes], { type: 'application/octet-stream' });

        if (lastEncryptDownloadUrl) {
          revokeUrl(lastEncryptDownloadUrl);
        }
        lastEncryptDownloadUrl = registerBlobUrl(outputBlob);
        lastEncryptDownloadName = outputFilename;

        // 7. Hiển thị kết quả bằng pure textContent
        encResultFilename.textContent = outputFilename;
        encResultSize.textContent = U.formatBytes(selectedEncryptFile.size) + ' → ' + U.formatBytes(finalCipherBytes.byteLength);
        encResultTime.textContent = durationMs + ' ms';
        encResultCard.style.display = 'block';

      } catch (err) {
        if (err && err.code) {
          showEncryptError(err.code);
        } else {
          showEncryptError('Đã xảy ra lỗi trong quá trình mã hóa: ' + (err.message || 'Lỗi không xác định'));
        }
      } finally {
        F.wipe(rawFileBuffer);
        F.wipe(payload);
        F.wipe(masterKey);

        isBusy = false;
        setActionsDisabled(false);
        encProgressContainer.style.display = 'none';
        encProgressFill.style.width = '0%';
      }
    });
  }

  // Tải xuống kết quả mã hóa
  if (encBtnDownload) {
    encBtnDownload.addEventListener('click', function () {
      if (!lastEncryptDownloadUrl) return;
      var a = document.createElement('a');
      a.href = lastEncryptDownloadUrl;
      a.download = lastEncryptDownloadName;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
    });
  }

  // ============================================================================
  // DECRYPTION EXECUTION FLOW
  // ============================================================================
  if (decBtnSubmit) {
    decBtnSubmit.addEventListener('click', async function () {
      if (isBusy || !isLibraryReady) return;

      hideDecryptError();
      decResultCard.style.display = 'none';

      // 1. Kiểm tra đầu vào
      if (!selectedDecryptFile) {
        showDecryptError('E_NO_FILE');
        return;
      }

      var password = decPassword.value;

      // NGAY LẬP TỨC XÓA SẠCH VÀ BLUR Ô MẬT KHẨU KHỎI DOM (CHỐNG SHOULDER SURFING & EXTENSION DOM SNIFFING)
      decPassword.value = '';
      decPassword.blur();

      if (!password) {
        showDecryptError('E_NO_PASSWORD');
        return;
      }

      if (selectedDecryptFile.size > F.MAX_FILE_SIZE) {
        password = '';
        showDecryptError('E_TOO_LARGE');
        return;
      }

      if (selectedDecryptFile.size < F.HEADER_SIZE + 48) {
        password = '';
        showDecryptError('E_TOO_SHORT');
        return;
      }

      isBusy = true;
      setActionsDisabled(true);
      decProgressContainer.style.display = 'block';
      decProgressFill.style.width = '15%';
      decStatusText.textContent = 'Đang đọc tệp tin mã hóa...';

      var encryptedBuffer = null;
      var decryptedPayload = null;
      var masterKey = null;

      var startTime = performance.now();

      try {
        await C.yieldEventLoop();

        // 2. Đọc tệp .th
        encryptedBuffer = await readFileBuffer(selectedDecryptFile);
        var fileBytes = new Uint8Array(encryptedBuffer);

        decProgressFill.style.width = '30%';
        decStatusText.textContent = 'Đang kiểm tra Header 64 byte và tham số KDF...';
        await C.yieldEventLoop();

        // 3. Phân tích Header và kiểm tra giới hạn KDF
        var header = F.parseHeader64(fileBytes);

        decProgressFill.style.width = '55%';
        decStatusText.textContent = 'Đang dẫn xuất khóa giải mã Argon2id (' + (header.memKiB / 1024) + ' MB)...';
        await C.yieldEventLoop();

        // 4. Dẫn xuất Master Key từ mật khẩu với tham số lưu trong Header
        var kdf = await C.deriveMasterKey(
          password,
          header.salt,
          header.memKiB,
          header.iterations,
          header.parallelism
        );
        masterKey = kdf.masterKey;

        decProgressFill.style.width = '75%';
        decStatusText.textContent = 'Đang gỡ bỏ 3 tầng bảo vệ AES-256-GCM...';
        await C.yieldEventLoop();

        // 5. Dẫn xuất 3 Stage Keys và Giải mã 3 tầng
        var stageKeys = await C.deriveStageKeys(masterKey, header.salt, 'decrypt');
        masterKey = null;

        decryptedPayload = await C.decryptCascade(fileBytes, stageKeys, header);

        decProgressFill.style.width = '90%';
        decStatusText.textContent = 'Đang xác thực Canary và bóc tách nội dung...';
        await C.yieldEventLoop();

        // 6. Bóc tách Payload & Xác thực Canary
        var payload = F.unpackPayload(decryptedPayload);
        decryptedPayload = null;

        decProgressFill.style.width = '100%';
        decStatusText.textContent = 'Giải mã thành công!';
        await C.yieldEventLoop();

        var durationMs = Math.round(performance.now() - startTime);
        var outBlob = new Blob([payload.content], { type: 'application/octet-stream' });

        if (lastDecryptDownloadUrl) {
          revokeUrl(lastDecryptDownloadUrl);
        }
        lastDecryptDownloadUrl = registerBlobUrl(outBlob);
        lastDecryptDownloadName = payload.filename;

        // 7. Hiển thị kết quả an toàn qua pure textContent
        decResultFilename.textContent = payload.filename;
        decResultSize.textContent = U.formatBytes(selectedDecryptFile.size) + ' → ' + U.formatBytes(payload.content.byteLength);
        decResultTime.textContent = durationMs + ' ms';

        // Render preview an toàn (ảnh, video, audio, text)
        if (U && typeof U.renderDecryptedPreview === 'function') {
          U.renderDecryptedPreview(payload.content, payload.mimeType, lastDecryptDownloadUrl);
        }

        decResultCard.style.display = 'block';

      } catch (err) {
        if (err && err.code) {
          showDecryptError(err.code);
        } else {
          showDecryptError('E_AUTH_FAIL');
        }
      } finally {
        F.wipe(encryptedBuffer);
        F.wipe(decryptedPayload);
        F.wipe(masterKey);

        isBusy = false;
        setActionsDisabled(false);
        decProgressContainer.style.display = 'none';
        decProgressFill.style.width = '0%';
      }
    });
  }

  // Tải xuống kết quả giải mã
  if (decBtnDownload) {
    decBtnDownload.addEventListener('click', function () {
      if (!lastDecryptDownloadUrl) return;
      var a = document.createElement('a');
      a.href = lastDecryptDownloadUrl;
      a.download = lastDecryptDownloadName;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
    });
  }

  // Khởi động ứng dụng khi trang đã sẵn sàng
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', initializeApp);
  } else {
    initializeApp();
  }

})();
