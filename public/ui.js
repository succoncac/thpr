/**
 * TH10 UI Controller & DOM Safety Helper (ui.js)
 * Pure textContent, Zero innerHTML, High-Contrast Accessible Feedback,
 * Tab Switcher (Encrypt & Decrypt Only), Anti-Copy Protection with Input Exceptions,
 * and In-App PWA Install Support
 */

(function (global) {
  'use strict';

  function formatBytes(bytes) {
    if (typeof bytes !== 'number' || isNaN(bytes) || bytes <= 0 || !isFinite(bytes)) {
      return '0 B';
    }
    var k = 1024;
    var sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
    var i = Math.floor(Math.log(bytes) / Math.log(k));
    if (i < 0) i = 0;
    if (i >= sizes.length) i = sizes.length - 1;
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
  }

  function calculateEntropy(pwd) {
    if (!pwd || typeof pwd !== 'string') return 0;
    var pool = 0;
    if (/[a-z]/.test(pwd)) pool += 26;
    if (/[A-Z]/.test(pwd)) pool += 26;
    if (/[0-9]/.test(pwd)) pool += 10;
    if (/[^a-zA-Z0-9]/.test(pwd)) pool += 33;
    if (pool === 0) pool = 10;
    return Math.round(pwd.length * (Math.log(pool) / Math.LN2));
  }

  function getStrengthLabel(bits) {
    if (bits === 0) return { label: 'Chưa nhập mật khẩu', cls: 'strength-none' };
    if (bits < 40) return { label: 'Yếu (< 40 bit)', cls: 'strength-weak' };
    if (bits < 60) return { label: 'Trung bình (40-60 bit)', cls: 'strength-medium' };
    if (bits < 80) return { label: 'Mạnh (60-80 bit)', cls: 'strength-strong' };
    return { label: 'Cực mạnh (> 80 bit)', cls: 'strength-extreme' };
  }

  /**
   * Thiết lập Tab Switcher giữa 2 chế độ:
   * 1. Mã hóa tệp tin (encrypt)
   * 2. Giải mã tệp tin (decrypt)
   */
  function setupTabs(onTabChange) {
    var tabEnc = document.getElementById('tab-encrypt');
    var tabDec = document.getElementById('tab-decrypt');
    var panelEnc = document.getElementById('panel-encrypt');
    var panelDec = document.getElementById('panel-decrypt');

    if (!tabEnc || !tabDec || !panelEnc || !panelDec) return;
    if (tabEnc._hasTabListener) return;
    tabEnc._hasTabListener = true;

    function switchMode(mode) {
      if (mode === 'encrypt') {
        tabEnc.classList.add('active');
        tabEnc.setAttribute('aria-selected', 'true');
        tabDec.classList.remove('active');
        tabDec.setAttribute('aria-selected', 'false');

        panelEnc.classList.add('panel-active');
        panelDec.classList.remove('panel-active');
      } else {
        tabDec.classList.add('active');
        tabDec.setAttribute('aria-selected', 'true');
        tabEnc.classList.remove('active');
        tabEnc.setAttribute('aria-selected', 'false');

        panelDec.classList.add('panel-active');
        panelEnc.classList.remove('panel-active');
      }

      if (typeof onTabChange === 'function') {
        onTabChange(mode);
      }
    }

    tabEnc.addEventListener('click', function () {
      switchMode('encrypt');
    });

    tabDec.addEventListener('click', function () {
      switchMode('decrypt');
    });

    return {
      switchMode: switchMode
    };
  }

  /**
   * Cơ chế Chống Sao chép An toàn (Anti-Copy Protection with Input Exceptions):
   * - Chặn contextmenu (chuột phải) và sự kiện copy toàn trang để chống cào giao diện.
   * - NGOẠI LỆ BẮT BUỘC: Giữ nguyên 100% quyền bôi đen, nhập liệu, copy/paste trong thẻ <input> và <textarea>.
   */
  function setupAntiCopyProtection() {
    if (global.__th10AntiCopyInstalled) return;
    global.__th10AntiCopyInstalled = true;

    function isInputElement(target) {
      if (!target) return false;
      var tag = (target.tagName || '').toUpperCase();
      if (tag === 'INPUT' || tag === 'TEXTAREA') return true;
      if (target.isContentEditable) return true;
      if (target.closest && target.closest('input, textarea, [contenteditable="true"], .allow-copy')) {
        return true;
      }
      return false;
    }

    // Chặn chuột phải ngoại trừ trên input/textarea
    document.addEventListener('contextmenu', function (e) {
      if (isInputElement(e.target)) {
        return; // Cho phép chuột phải để dán, sao chép mật khẩu bình thường
      }
      e.preventDefault();
    }, true);

    // Chặn sự kiện copy ngoại trừ trên input/textarea
    document.addEventListener('copy', function (e) {
      if (isInputElement(e.target)) {
        return; // Cho phép sao chép nội dung trong input/textarea
      }
      e.preventDefault();
    }, true);

    // Chặn sự kiện cut ngoại trừ trên input/textarea
    document.addEventListener('cut', function (e) {
      if (isInputElement(e.target)) {
        return;
      }
      e.preventDefault();
    }, true);
  }

  /**
   * Xử lý nút Cài đặt PWA (In-App Install Prompt)
   */
  function setupPWAInstall() {
    var installBtn = document.getElementById('btn-pwa-install');
    if (!installBtn) return;
    if (installBtn._hasPwaListener) return;
    installBtn._hasPwaListener = true;

    var deferredPrompt = null;

    // Kiểm tra xem ứng dụng đã cài đặt ở chế độ standalone chưa
    var isStandalone = window.matchMedia('(display-mode: standalone)').matches ||
      (window.navigator && window.navigator.standalone === true);

    if (isStandalone) {
      installBtn.style.display = 'none';
      return;
    }

    window.addEventListener('beforeinstallprompt', function (e) {
      e.preventDefault();
      deferredPrompt = e;
      installBtn.style.display = 'inline-flex';
    });

    installBtn.addEventListener('click', async function () {
      if (!deferredPrompt) {
        // Hướng dẫn nếu trên iOS Safari
        var isIOS = /iphone|ipad|ipod/.test(navigator.userAgent.toLowerCase());
        if (isIOS) {
          alert('Để cài đặt ứng dụng trên iPhone/iPad:\n1. Bấm nút Chia sẻ (biểu tượng hình vuông có mũi tên lên ở Safari).\n2. Chọn "Thêm vào Màn hình chính" (Add to Home Screen).');
        }
        return;
      }

      deferredPrompt.prompt();
      var choiceResult = await deferredPrompt.userChoice;
      if (choiceResult && choiceResult.outcome === 'accepted') {
        installBtn.style.display = 'none';
      }
      deferredPrompt = null;
    });

    window.addEventListener('appinstalled', function () {
      installBtn.style.display = 'none';
      deferredPrompt = null;
    });
  }

  /**
   * Render an toàn media preview (Image, Audio, Video, Text)
   * Sử dụng pure DOM nodes và textContent (Zero innerHTML)
   */
  function renderDecryptedPreview(contentBytes, mimeType, blobUrl) {
    var previewContainer = document.getElementById('dec-preview-container');
    var previewMime = document.getElementById('dec-preview-mime');
    var previewViewport = document.getElementById('dec-preview-viewport');

    if (!previewContainer || !previewViewport) return;

    // Xóa sạch nội dung cũ
    while (previewViewport.firstChild) {
      previewViewport.removeChild(previewViewport.firstChild);
    }

    if (previewMime) {
      previewMime.textContent = mimeType || 'application/octet-stream';
    }

    var normalizedMime = (mimeType || '').toLowerCase();

    // 1. Hình ảnh
    if (normalizedMime.startsWith('image/')) {
      var img = document.createElement('img');
      img.src = blobUrl;
      img.alt = 'Ảnh xem trước đã giải mã';
      previewViewport.appendChild(img);
      previewContainer.style.display = 'block';
      return;
    }

    // 2. Video
    if (normalizedMime.startsWith('video/')) {
      var video = document.createElement('video');
      video.src = blobUrl;
      video.controls = true;
      video.preload = 'metadata';
      previewViewport.appendChild(video);
      previewContainer.style.display = 'block';
      return;
    }

    // 3. Audio
    if (normalizedMime.startsWith('audio/')) {
      var audio = document.createElement('audio');
      audio.src = blobUrl;
      audio.controls = true;
      previewViewport.appendChild(audio);
      previewContainer.style.display = 'block';
      return;
    }

    // 4. Văn bản / JSON / Code / Markdown
    var isTextual = normalizedMime.startsWith('text/') ||
      normalizedMime.includes('json') ||
      normalizedMime.includes('javascript') ||
      normalizedMime.includes('xml') ||
      normalizedMime.includes('csv');

    if (isTextual && contentBytes.byteLength <= 500 * 1024) { // Dưới 500 KB để tránh đơ DOM
      try {
        var textContent = new TextDecoder('utf-8', { fatal: true }).decode(contentBytes);
        var pre = document.createElement('pre');
        pre.className = 'custom-scrollbar allow-copy';
        pre.textContent = textContent;
        previewViewport.appendChild(pre);
        previewContainer.style.display = 'block';
        return;
      } catch (_) {
        // Không phải UTF-8 hợp lệ
      }
    }

    // Các tệp nhị phân khác: ẩn khung preview
    previewContainer.style.display = 'none';
  }

  function clearDecryptedPreview() {
    var previewContainer = document.getElementById('dec-preview-container');
    var previewViewport = document.getElementById('dec-preview-viewport');
    if (previewContainer) previewContainer.style.display = 'none';
    if (previewViewport) {
      while (previewViewport.firstChild) {
        previewViewport.removeChild(previewViewport.firstChild);
      }
    }
  }

  var TH10UI = {
    formatBytes: formatBytes,
    calculateEntropy: calculateEntropy,
    getStrengthLabel: getStrengthLabel,
    setupTabs: setupTabs,
    setupAntiCopyProtection: setupAntiCopyProtection,
    setupPWAInstall: setupPWAInstall,
    renderDecryptedPreview: renderDecryptedPreview,
    clearDecryptedPreview: clearDecryptedPreview,
  };

  if (typeof module !== 'undefined' && module.exports) {
    module.exports = TH10UI;
  }
  global.TH10UI = TH10UI;

})(typeof window !== 'undefined' ? window : globalThis);
