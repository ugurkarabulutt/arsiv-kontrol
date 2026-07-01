self.addEventListener('install', () => self.skipWaiting());
self.addEventListener('activate', event => event.waitUntil(self.clients.claim()));

// Ağ isteklerini uygulamanın mevcut davranışına bırakır; yalnızca kurulabilirlik sağlar.
self.addEventListener('fetch', () => {});
