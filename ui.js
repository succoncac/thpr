/**
 * TH10 UI Controller & DOM Safety Helper (ui.js)
 * Pure textContent, Zero innerHTML, High-Contrast Accessible Feedback,
 * Tab Switcher, and Safe Media Preview Renderer
 */

(function (global) {
  'use strict';

  function formatBytes(bytes) {
    if (bytes === 0) return '0 B';
    var k = 1024;
    var sizes = ['B', 'KB', 'MB', 'GB'];
    var i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
  }

  function calculateEntropy(pwd) {
    if (!pwd) return 0;
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
   * Thiết lập Tab Switcher giữa Mã hóa và Giải mã
   */
  function setupTabs() {
    var tabEnc = document.getElementById('tab-encrypt');
    var tabDec = document.getElementById('tab-decrypt');
    var panelEnc = document.getElementById('panel-encrypt');
    var panelDec = document.getElementById('panel-decrypt');

    if (!tabEnc || !tabDec || !panelEnc || !panelDec) return;

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
    }

    tabEnc.addEventListener('click', function () {
      switchMode('encrypt');
    });

    tabDec.addEventListener('click', function () {
      switchMode('decrypt');
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
        pre.className = 'custom-scrollbar';
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
    renderDecryptedPreview: renderDecryptedPreview,
    clearDecryptedPreview: clearDecryptedPreview,
  };

  if (typeof module !== 'undefined' && module.exports) {
    module.exports = TH10UI;
  }
  global.TH10UI = TH10UI;

})(typeof window !== 'undefined' ? window : globalThis);
