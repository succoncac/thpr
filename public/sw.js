/**
 * TH10 Progressive Web App Service Worker (sw.js)
 * High-performance offline caching with Network-First strategy for HTML navigations
 * Guarantees zero stale deployments when updated on Cloudflare Pages.
 */

const CACHE_NAME = 'th10-core-v1.2.0';

const PRECACHE_ASSETS = [
  '/',
  '/index.html',
  '/style.css',
  '/manifest.json',
  '/format.js',
  '/crypto.js',
  '/ui.js',
  '/app.js',
  '/vendor/hash-wasm.min.js',
  '/icon.svg',
  '/pwa-192x192.png',
  '/pwa-512x512.png',
  '/pwa-maskable-512x512.png',
  '/apple-touch-icon.png'
];

// 1. Install Event: Cache all core assets and immediately activate
self.addEventListener('install', (event) => {
  event.waitUntil(
    caches.open(CACHE_NAME).then((cache) => {
      return cache.addAll(PRECACHE_ASSETS).catch((err) => {
        console.warn('[TH10 SW] Precache partial error (ignored):', err);
      });
    }).then(() => self.skipWaiting())
  );
});

// 2. Activate Event: Wipe outdated caches and claim clients immediately
self.addEventListener('activate', (event) => {
  event.waitUntil(
    caches.keys().then((cacheNames) => {
      return Promise.all(
        cacheNames.map((name) => {
          if (name !== CACHE_NAME) {
            return caches.delete(name);
          }
        })
      );
    }).then(() => self.clients.claim())
  );
});

// 3. Fetch Event:
// - Navigation requests (HTML): Network-First (fetches latest from Cloudflare, falls back to cache if offline)
// - Other assets: Stale-While-Revalidate
self.addEventListener('fetch', (event) => {
  const req = event.request;

  // Only handle GET requests
  if (req.method !== 'GET') return;

  const url = new URL(req.url);

  // Ignore cross-origin non-http(s) schemes (e.g. chrome-extension, blob, data)
  if (!url.protocol.startsWith('http')) return;

  // Strategy A: HTML navigation requests (Network-First)
  if (req.mode === 'navigate') {
    event.respondWith(
      fetch(req)
        .then((networkRes) => {
          if (networkRes && networkRes.status === 200) {
            const clone = networkRes.clone();
            caches.open(CACHE_NAME).then((cache) => cache.put(req, clone));
          }
          return networkRes;
        })
        .catch(() => {
          return caches.match(req).then((cached) => cached || caches.match('/index.html'));
        })
    );
    return;
  }

  // Strategy B: Static assets (Stale-While-Revalidate)
  event.respondWith(
    caches.match(req).then((cachedRes) => {
      const fetchPromise = fetch(req)
        .then((networkRes) => {
          if (networkRes && networkRes.status === 200) {
            const clone = networkRes.clone();
            caches.open(CACHE_NAME).then((cache) => cache.put(req, clone));
          }
          return networkRes;
        })
        .catch(() => cachedRes);

      return cachedRes || fetchPromise;
    })
  );
});
