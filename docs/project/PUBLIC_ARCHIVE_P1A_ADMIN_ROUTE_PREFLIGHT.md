# Public Arşiv P1A Paralel `/admin` Route Preflight

Tarih: 2026-07-31
Durum: P1B öncesi repo-temelli uygulama planı, docs-only; production/deploy config değişikliği hariç

## Amaç

Bu doküman P1B'de uygulanacak paralel `/admin` route değişikliğini, mevcut canlı root admin davranışını değiştirmeden planlar. `arsiv.ibrahimlive.ai` aktif kullanılan bir sistemdir; yaklaşık 39 ekip kullanıcısının login, denetim, onaya gönderme, onay/red, feedback, bildirim, standartlar, raporlama, dashboard ve kullanıcı yönetimi akışları korunmalıdır.

Bu P1A adımında kod yazılmadı, DB migration yapılmadı, DB'ye bağlanılıp veri değiştirilmedi, production deploy yapılmadı, push yapılmadı ve mevcut root `/` davranışına dokunulmadı.

## Okunan Repo Bağlamı

P1A preflight için şu dosyalar incelendi:

- `AGENTS.md`
- `CURRENT_HANDOFF.md`
- `docs/project/PUBLIC_ARCHIVE_DECISION_LOCK.md`
- `docs/project/PUBLIC_ARCHIVE_ADMIN_TRANSITION_PLAN.md`
- `docs/project/PUBLIC_ARCHIVE_ADMIN_REGRESSION_CHECKLIST.md`
- `docs/project/PUBLIC_ARCHIVE_ROLLBACK_PLAN.md`
- `docs/project/PUBLIC_ARCHIVE_PUBLIC_LANGUAGE_GUARD.md`
- `docs/project/PUBLIC_ARCHIVE_ROUTE_AUDIT.md`
- `package.json`
- `server.js`
- `index.html`
- `scripts/check-frontend.js`
- `vercel.json`
- `manifest.webmanifest`
- `sw.js`
- `authorization.js`
- `public-archive-demo.js`
- `data/qa-seed.js` varlığı
- `test/` ve mevcut check/test script kayıtları

Çalışma ağacı bu inceleme başlamadan önce zaten kirliydi. Mevcut dirty tracked dosyalar ve untracked public demo dosyaları bu P1A adımında değiştirilmedi. 2026-07-31 tekrar kontrolünde `vercel.json` da dirty tracked dosyalar arasında göründü; bu dosyaya P1A'da dokunulmadı ve P1B için production/deploy config değişikliği ayrı onay kapısına alındı.

## A. Current Route Map

### Runtime ve Entry

Mevcut server entry dosyası `server.js` dosyasıdır. `package.json` içinde:

- `main`: `server.js`
- `npm start`: `node server.js`
- `npm run dev`: `node --watch server.js`
- `npm run check`: `node --check server.js && node scripts/check-frontend.js && node --test`

Uygulama Express app olarak kuruludur ve dosya sonunda:

- Yerel/Render benzeri runtime için `app.listen(PORT, ...)`
- Vercel/serverless için `module.exports = app`

bulunur.

### Express Middleware Sırası

`server.js` içinde mevcut sıra özetle şöyledir:

1. `express.json({ limit: '10mb' })`
2. `express.urlencoded({ extended: true, limit: '10mb' })`
3. `app.set('trust proxy', 1)`
4. `cookie-session`
5. `/icons` static serving
6. `/favicon.ico`
7. `/manifest.webmanifest`
8. `/sw.js`
9. `/health`
10. Auth, kullanıcı, standart, history, onay, feedback, bildirim, rapor, AI yardımcı ve analiz API'leri
11. `PUBLIC_ARCHIVE_DEMO=1` ise demo public archive router
12. Error handler
13. `app.get('*', ...)` ile `index.html` fallback

Bu Express fallback nedeniyle yerel/Render benzeri runtime'da bilinmeyen bütün GET path'leri `index.html` döndürür. Bu kapsamda mevcut durumda `/`, `/admin`, `/admin/`, `/admin/gecmis`, `/admin/onay` gibi path'ler `index.html` döndürür.

### Vercel Route Sırası

`vercel.json` içinde production routing şu şekilde yapılandırılmıştır:

1. `/health` -> `/server.js`
2. `/api/(.*)` -> `/server.js`
3. `/manifest.webmanifest` -> static manifest
4. `/sw.js` -> static service worker
5. `/icons/(.*)` -> static icons
6. `/favicon.ico` -> static favicon
7. `/(.*)` -> `/index.html`

Güncel `vercel.json` ayrıca static manifest, `sw.js`, final index route ve top-level headers için `Cache-Control: no-store, no-cache, must-revalidate, proxy-revalidate` davranışı içeriyor.

Bu önemli bir ayrımdır: Vercel üzerinde `/`, `/admin` ve `/admin/*` şu an Express fallback'e değil, Vercel static catch-all üzerinden `index.html` dosyasına gider. Bu davranış pratikte paralel `/admin` açılışını bugün de mümkün kılar.

P1B kapsam kuralı gereği `vercel.json` production/deploy config sayılmalı ve P1B'de değiştirilmemelidir. İleride root public cutover'a yaklaşırken `/admin` ve `/admin/(.*)` explicit Vercel route'ları gerekebilir; bu ayrı ve açık onaylı bir P1C/P1B-Vercel adımı olarak planlanmalıdır.

### Mevcut Root Davranışı

Mevcut root `/`, public arşiv değildir. Root, `index.html` tek sayfalı ekip/admin uygulamasını servis eder. Login ekranı, normal kullanıcı paneli, admin paneli, süper admin alanları, metin denetimi, onaya gönderme, onay/red, feedback, bildirimler, standartlar, raporlar ve kullanıcı yönetimi aynı frontend dosyası içindedir.

P1B'de kesin korunacak davranış:

- `/` mevcut haliyle `index.html` döndürmeye devam eder.
- Root public arşiv açılmaz.
- `ADMIN_ROOT_LEGACY_ENABLED=true` davranışı korunur.

### Static Asset Serving

Express tarafında static asset davranışı:

- `app.use('/icons', express.static(path.join(__dirname, 'icons')))`
- `GET /favicon.ico` -> `icons/favicon.ico`
- `GET /manifest.webmanifest` -> `manifest.webmanifest`
- `GET /sw.js` -> `sw.js`

Vercel tarafında static asset davranışı:

- `/manifest.webmanifest` static
- `/sw.js` static
- `/icons/(.*)` static
- `/favicon.ico` -> `/icons/favicon.ico`

`index.html` içinde asset path'leri absolute root path kullanıyor:

- `/manifest.webmanifest`
- `/favicon.ico`
- `/icons/favicon-32.png`
- `/icons/favicon-16.png`
- `/icons/apple-touch-icon.png`
- `/icons/social-preview.png`
- `/sw.js`

Bu nedenle `/admin` altında servis edildiğinde asset path'leri `/admin/icons/...` gibi yanlış çözülmez. P1B için asset base path değişikliği gerekmiyor.

### SPA/Fallback Davranışı

Admin frontend gerçek URL router kullanmıyor. `index.html` içinde sekmeler JavaScript ile yönetiliyor:

- `showTab('analiz')`
- `showTab('gecmis')`
- `showTab('bildirim')`
- `showTab('standartlar')`
- `showTab('dash')`
- `showTab('onay')`
- `showTab('feedback')`
- `showTab('alerts')`
- `showTab('kullanici')`
- `showTab('kurallar')`
- `showTab('profil')`
- `showTab('ayarlar')`

`location.pathname`, hash route, `history.pushState` veya `replaceState` tab navigation için kullanılmıyor. Bu yüzden mevcut admin deep link mantığı dosya/path bazlı değil, tek HTML dosyasını yükleme bazlıdır.

Sonuç:

- `/admin` refresh -> `index.html` yüklenirse çalışır.
- `/admin/gecmis` refresh -> `index.html` yüklenirse uygulama açılır, ancak otomatik geçmiş sekmesine gitmez.
- `/admin/onay` refresh -> `index.html` yüklenirse uygulama açılır, ancak otomatik onay sekmesine gitmez.

P1B hedefi deep link path'lerinin en azından blank/404 üretmeden admin app'i açmasıdır. Sekme state'ini URL'ye bağlamak P1B kapsamına alınmamalıdır; bu ayrı ve daha riskli bir frontend davranış değişikliğidir.

### API Route Map

Mevcut API route'ları root/admin path ayrımından bağımsız `/api/...` altındadır. Frontend çağrılarının tamamı absolute `/api/...` path kullanır. Bu iyi bir durumdur; `/admin` altında relative API kırılması beklenmez.

Oturumsuz veya sistem route'ları:

- `GET /health`
- `POST /api/auth/login`
- `GET /api/auth/me` logged-out durumda `{ loggedIn: false }` döndürür
- `GET /api/cron/daily-report` auth middleware kullanmaz, `CRON_SECRET` ile korunur

Auth gerektiren ekip API'leri:

- `POST /api/auth/logout`
- `POST /api/auth/change-password`
- `GET /api/standards`
- `POST /api/standards/:id/read`
- `POST /api/standards/read-visible`
- `GET /api/history`
- `GET /api/history/:id`
- `POST /api/history/:id/feedback`
- `POST /api/history/:id/submit`
- `POST /api/history/merged-draft`
- `POST /api/history/submit-merged`
- `POST /api/pdf`
- `GET /api/my-notifications`
- `POST /api/my-notifications/:id/resolution-response`
- `POST /api/my-notifications/:id/read`
- `POST /api/my-notifications/read-all`
- `POST /api/ai/helper`
- `POST /api/analyze`
- `POST /api/extract-file-text`
- `POST /api/analyze-file`
- `POST /api/analyze-batch`

Admin API'leri:

- `GET /api/security/default-admin`
- `GET /api/users`
- `PUT /api/users/:id`
- `POST /api/users/:id/notify`
- `GET /api/rules`
- `PUT /api/rules`
- `POST /api/rules/reset`
- `POST /api/standards`
- `GET /api/history/approval-board`
- `POST /api/feedback/work-package.pdf`
- `GET /api/history/csv`
- `POST /api/history/:id/approve`
- `POST /api/history/:id/reject`
- `GET /api/alerts`
- `POST /api/alerts/:id/read`
- `POST /api/alerts/read-all`
- `POST /api/alerts/:id/respond`
- `POST /api/alerts/resolve-bulk`
- `GET /api/stats`
- `GET /api/ai/reports`
- `POST /api/ai/reports/generate`
- `POST /api/ai/insight`

Süper admin API'leri:

- `POST /api/users`
- `DELETE /api/users/:id`
- `GET /api/notification-log`
- `GET /api/resolution-responses`

P1B route değişikliği bu API'lerin path'ini, auth middleware'ini veya response shape'ini değiştirmemelidir.

## B. Admin Runtime Dependencies

### Auth ve Session

Auth/session davranışı `server.js` içinde `cookie-session` ile yönetilir:

- Cookie adı: `arsiv_session`
- `httpOnly: true`
- `sameSite: 'lax'`
- Production/Vercel ortamında `secure: true`
- Cookie path açıkça daraltılmadığı için varsayılan domain/path davranışı root ve `/admin` arasında session paylaşımına uygundur.

Login route'u path bağımlı değildir:

- `POST /api/auth/login`
- Başarılı login sonrası session'a `userId`, `username`, `name`, `role` yazılır.

Frontend login sonrası URL redirect yapmaz; `enterApp(user)` çağrılır ve `showTab('analiz')` ile uygulama içi ekrana geçilir. Logout da URL redirect yapmaz; session temizlenir ve login screen tekrar görünür.

P1B'de auth/session core'a dokunulmamalıdır. `/admin` paralel route için cookie path veya session seçenekleri değiştirilmemelidir.

### Role ve Yetki

Role mantığı `authorization.js` ve `server.js` middleware'leriyle çalışır:

- `user`
- `admin`
- `super_admin`

`admin` kullanıcı adı her zaman `super_admin` kabul edilir. Admin yetkisi `isAdminRole`, süper admin yetkisi `isSuperAdminRole` ile ayrılır.

Frontend yalnız görünürlüğü yönetir; gerçek koruma API middleware'lerindedir:

- `auth`
- `admin`
- `superAdmin`

P1B'de bu middleware'lerin davranışı değişmemelidir.

### Static Asset Bağımlılıkları

Admin app'in çalışması için şu dosyalar erişilebilir kalmalıdır:

- `index.html`
- `/manifest.webmanifest`
- `/sw.js`
- `/favicon.ico`
- `/icons/*`

`index.html` inline CSS/JS içerir; ayrı JS bundle yoktur. Bu yüzden `/admin` altında build output veya asset base path değişikliği gerekmiyor.

### Service Worker ve Manifest

`index.html`, service worker'ı absolute `/sw.js` path'iyle kaydediyor. `manifest.webmanifest` içinde:

- `start_url: "/"`
- `scope: "/"`

`sw.js` fetch event'inde response değiştirmiyor; sadece kurulabilirlik sağlar. P1B için bunu değiştirmemek en güvenli yoldur.

Ancak root public cutover fazında risk vardır:

- Admin PWA scope'u `/` kalırsa ileride public root ile aynı scope'u paylaşır.
- `start_url: "/"` public root sonrası kullanıcıyı admin yerine public arşive götürebilir.

Bu risk P1B'de çözülmemeli; P1B sadece not etmeli ve root public cutover öncesi ayrı karar konusu yapmalıdır.

### Frontend Router Bağımlılığı

Admin frontend URL router kullanmadığı için `/admin` altındaki deep linkler yalnız HTML fallback gerektirir. Sekme açma state'i URL'den okunmaz. P1B'de bu davranış korunmalıdır.

### API Path Bağımlılığı

Frontend API çağrıları absolute `/api/...` kullandığı için `/admin` altında çalışmaya uygundur. P1B'de yeni relative API path eklenmemelidir.

### Environment Bağımlılığı

Mevcut ortam değişkenleri:

- `OPENAI_API_KEY`
- `SUPABASE_URL`
- `SUPABASE_KEY`
- `SESSION_SECRET`
- `PORT`
- `CRON_SECRET`
- `OPENAI_TIMEOUT_MS`
- Demo bağlamında `PUBLIC_ARCHIVE_DEMO`
- Demo bağlamında `PUBLIC_ARCHIVE_BASE_URL`

P1B için önerilen yeni flag'ler:

- `ADMIN_PARALLEL_ROUTE_ENABLED`
- `ADMIN_ROOT_LEGACY_ENABLED`
- `PUBLIC_ARCHIVE_ENABLED`
- `PUBLIC_ARCHIVE_INDEXING`
- `PUBLIC_ARCHIVE_USE_PUBLIC_QA`

Bu flag'ler `server.js` içinde env constants bölümünde okunmalıdır. P1B'de public flag'ler yalnız default/guard olarak tanımlanmalı; public route açmamalıdır.

## C. Parallel `/admin` Feasibility

Paralel `/admin` route mevcut root davranışı bozulmadan mümkündür.

Gerekçe:

- `index.html` tek dosyalı SPA'dır.
- Frontend route state'i URL path'e bağlı değildir.
- API call'ları absolute `/api/...` kullanır.
- Asset path'leri absolute `/icons`, `/manifest.webmanifest`, `/sw.js`, `/favicon.ico` kullanır.
- Cookie-session path bağımlı yapılandırılmamıştır; root ve `/admin` aynı session'ı görebilir.
- Express fallback bugün zaten `/admin/*` için `index.html` döndürür.
- Vercel catch-all bugün zaten `/admin/*` için `index.html` döndürür.

Ancak P1B'de bu davranış broad catch-all'a güvenerek bırakılmamalıdır. İleri public root ayrımı için `/admin` ve `/admin/*` route'ları açıkça tanımlanmalıdır.

Önerilen P1B sonucu:

- `/` değişmeden mevcut admin/login app'i döndürür.
- `/admin` açıkça mevcut admin/login app'i döndürür.
- `/admin/` açıkça mevcut admin/login app'i döndürür.
- `/admin/*` açıkça mevcut admin/login app'i döndürür.
- `/api/*` JSON/API route olarak kalır.
- `/health` JSON kalır.
- Static assets aynı kalır.
- Public root açılmaz.
- DB/migration yoktur.

Risk seviyesi doğru uygulanırsa düşüktür; çünkü P1B davranışı mevcut catch-all'ın zaten yaptığı şeyi açık ve test edilebilir hale getirir. Asıl risk Vercel route sırası ve ileride public root eklendiğinde catch-all'ın yanlış hedefe gitmesidir.

## D. Exact Files To Touch In P1B

P1B'de önerilen dar dosya listesi aşağıdadır. Bu liste production/deploy config dosyalarını hariç tutar.

### `server.js`

Neden dokunulacak:

- Feature flag okuma helper'ları burada tanımlanmalı.
- Express runtime için `/admin` ve `/admin/*` explicit route'ları burada eklenmeli.
- Admin HTML döndüren küçük bir helper burada tutulmalı.
- Route sırası burada güvence altına alınmalı.

P1B'de yapılacaklar:

- Env constants bölümünde flag helper ekle:
  - `ADMIN_PARALLEL_ROUTE_ENABLED`
  - `ADMIN_ROOT_LEGACY_ENABLED`
  - `PUBLIC_ARCHIVE_ENABLED`
  - `PUBLIC_ARCHIVE_INDEXING`
  - `PUBLIC_ARCHIVE_USE_PUBLIC_QA`
- `sendAdminIndex(req, res)` benzeri küçük helper ile `index.html` döndür.
- `/admin` ve `/admin/*` route'larını API route'ları ve public archive router/catch-all ile çakışmayacak sırada ekle.
- P1B'de root `/` davranışını değiştirme.
- P1B'de public archive route açma.
- P1B'de auth/session middleware değiştirme.

Önerilen route sırası:

1. Static assets
2. `/health`
3. Tüm `/api/*` route'ları
4. Explicit `/admin` ve `/admin/*` admin index fallback
5. Public archive router yalnız ileriki fazda ve flag ile
6. Error handler
7. Legacy root/catch-all fallback

Not: Express'te route sırası önemlidir. `/api/*` hiçbir zaman HTML fallback tarafından yutulmamalıdır.

### `scripts/check-frontend.js`

Neden dokunulacak:

- P1B'nin regresyon kalkanı burada olmalıdır.
- Mevcut check script zaten `index.html`, `server.js`, `manifest.webmanifest`, `sw.js` ve ikonları statik olarak doğruluyor.
- P1B sonrası `/admin` route explicitliği ve root legacy korunumu statik check'e eklenmelidir.

P1B'de yapılacaklar:

- `server.js` içinde `ADMIN_PARALLEL_ROUTE_ENABLED` ve `ADMIN_ROOT_LEGACY_ENABLED` okunduğunu assert et.
- `server.js` içinde `/admin` ve `/admin/*` explicit fallback bulunduğunu assert et.
- `vercel.json` production/deploy config olduğu için P1B'de değişmediğini varsay; yalnız mevcut route sırasının `/api/(.*)` -> `/server.js` ve final `/(.*)` -> `/index.html` davranışını koruduğunu okuyup raporla.
- `/api/(.*)` route'unun final catch-all'dan önce olduğunu assert et.
- Root public flag varsayılanının P1B'de kapalı olduğunu assert et.
- Frontend API çağrılarının absolute `/api/...` davranışına dair statik kontrol ekle veya mevcut coverage'ı genişlet.

### Ayrı Onay Gerektiren Production/Deploy Config: `vercel.json`

`vercel.json` P1A incelemesinde önemli bir route yüzeyi olarak belirlendi, fakat P1B dokunulacak dosyası değildir.

Neden ayrı tutulacak:

- Production routing davranışını doğrudan belirler.
- Şu anda `/admin` ve `/admin/*` final static catch-all sayesinde `index.html` alır.
- Bu dosyada yapılacak explicit `/admin` route değişikliği production/deploy config değişikliği sayılır.
- Kullanıcı bu adımda production config/deploy dosyalarına dokunulmamasını özellikle istemiştir.

İleride ayrı onayla yapılabilecek P1C/P1B-Vercel adımı:

- `/admin` -> `/index.html` route'u final catch-all'dan önce eklenir.
- `/admin/(.*)` -> `/index.html` route'u final catch-all'dan önce eklenir.
- `/health`, `/api/(.*)` ve static asset route'ları bu route'lardan önce kalır.
- `/admin` için `X-Robots-Tag: noindex, nofollow` header'ı ayrıca planlanır.

Bu ayrı adım yapılana kadar P1B'nin amacı Express/runtime davranışını explicit hale getirmek ve mevcut Vercel catch-all'ın root legacy davranışını bozmadığını doğrulamaktır.

### P1B'de Muhtemelen Dokunulmayacak Ama Smoke Edilecek Dosyalar

Bu dosyalar P1B implementation değişikliği gerektirmemeli; ancak test yüzeyidir:

- `index.html`
- `manifest.webmanifest`
- `sw.js`
- `icons/*`

Gerekçe:

- `index.html` zaten `/admin` altında çalışmaya uygun absolute asset/API path kullanıyor.
- Manifest ve service worker root-scope riskini taşır; fakat P1B'de değiştirmek installed-app davranışını etkileyebilir.
- Root public cutover öncesi ayrıca ele alınmalıdır.

## E. Files Not To Touch

P1B paralel `/admin` route uygulaması sırasında şu dosyalara dokunulmamalıdır:

- `schema.sql`
- Herhangi bir migration dosyası veya yeni migration klasörü
- Supabase SQL veya DB seed dosyaları
- `analysis-core.js`
- `authorization.js`
- `test/fixtures/quality-regression-cases.json`
- `test/analysis-core.test.js`
- `test/authorization.test.js`
- `test/quality-regression-cases.test.js`
- `public-archive-demo.js`
- `archive-public.css`
- `data/qa-seed.js`
- `demo-public-preview/`
- `scripts/build-archive-demo-static.js`
- `vercel.json`
- `render.yaml`
- Production deploy config'i olarak yorumlanabilecek secret/env dosyaları
- `.env`
- `.env.example` varsa
- Admin business logic'i içeren history/onay/feedback/bildirim/standart/rapor fonksiyonları
- Auth/session core davranışını değiştiren kod blokları

Özellikle yapılmayacaklar:

- DB migration yok.
- DB write yok.
- Onaylanan `history` kayıtlarını public'e aktarma yok.
- Public `public_qa` okuma yok.
- Public root açma yok.
- Root admin'i redirect etme yok.
- Auth cookie path değiştirme yok.
- Existing API route path değiştirme yok.
- Existing admin tabs veya role visibility yeniden yazımı yok.

## F. P1B Implementation Steps

P1B küçük ve geri alınabilir olmalıdır.

1. Preflight baseline al:
   - `git status -sb`
   - Mevcut dirty/untracked dosyaları not et.
   - İlgisiz değişiklikleri revert etme.

2. `server.js` içinde flag helper ekle:
   - Boolean env parsing küçük ve deterministic olmalı.
   - Default durumlar P1B için:
     - `ADMIN_PARALLEL_ROUTE_ENABLED=true`
     - `ADMIN_ROOT_LEGACY_ENABLED=true`
     - `PUBLIC_ARCHIVE_ENABLED=false`
     - `PUBLIC_ARCHIVE_INDEXING=false`
     - `PUBLIC_ARCHIVE_USE_PUBLIC_QA=false`
   - Public flags okunabilir ama route açmamalı.

3. `server.js` içinde admin index helper ekle:
   - Tek sorumluluk: `index.html` döndürmek.
   - İstenirse admin route response'a noindex header eklemek.
   - Session/auth kontrolü ekleme; mevcut login screen zaten logged-out kullanıcıyı karşılıyor.

4. `server.js` içinde explicit `/admin` route ekle:
   - `ADMIN_PARALLEL_ROUTE_ENABLED=true` ise `/admin` `index.html` döndürür.
   - `/admin/` aynı davranmalıdır.
   - Root `/` bu adımda aynı kalır.

5. `server.js` içinde explicit `/admin/*` fallback ekle:
   - Browser refresh blank/404 üretmemeli.
   - `/admin/gecmis`, `/admin/onay`, `/admin/kullanici` gibi path'ler admin app'i açmalı.
   - Bu path'lerin otomatik sekme açması P1B kapsamı değildir.

6. `vercel.json` dosyasını değiştirme:
   - Bu dosya production/deploy config sayılır.
   - P1B'de yalnız mevcut route sırası okunup not edilir.
   - Mevcut durumda `/api/(.*)` server'a, final `/(.*)` `index.html` dosyasına gider; bu nedenle Vercel üzerinde `/admin` broad catch-all ile HTML alabilir.
   - Explicit Vercel `/admin` route'u ayrı onaylı P1C/P1B-Vercel adımıdır.

7. `scripts/check-frontend.js` içine P1B statik kontrolleri ekle:
   - Admin route explicit.
   - Vercel route order mevcut root legacy davranışını bozmayacak şekilde okunuyor.
   - API route'lar admin/fallback route'larından önce.
   - Root legacy kapatılmamış.
   - Public archive route P1B'de aktif edilmemiş.

8. Local verification çalıştır:
   - `git diff --check`
   - `npm run check`
   - Gerekirse `npm test`
   - Gerekirse `node --check server.js`

9. Local/manual smoke test yap:
   - `/`
   - `/admin`
   - `/admin/`
   - `/admin/gecmis`
   - `/admin/onay`
   - `/api/auth/me`
   - `/health`
   - `/favicon.ico`
   - `/manifest.webmanifest`
   - `/sw.js`
   - `/icons/favicon-32.png`

10. P1B sonunda production deploy/push yapma:
    - Kullanıcı ayrıca onay vermedikçe deploy yok.
    - Kullanıcı ayrıca onay vermedikçe push yok.
    - DB yok.
    - Migration yok.

## G. Regression Checklist Mapping

P1B sonrası `PUBLIC_ARCHIVE_ADMIN_REGRESSION_CHECKLIST.md` içinden en az şu maddeler test edilmelidir.

### Zorunlu Route Smoke

- `/` paralel fazda mevcut admin/login app'i döndürür.
- `/admin` mevcut admin/login app'i döndürür.
- `/admin/` mevcut admin/login app'i döndürür.
- `/admin/gecmis` veya seçilen deep-link test path admin app'i döndürür.
- `/admin/onay` veya seçilen admin deep-link test path admin app'i döndürür.
- Bilinmeyen admin deep link blank page üretmez.
- `/api/auth/me` HTML değil JSON döndürür.
- `/api/history` HTML değil JSON/401 döndürür.
- `/health` health JSON döndürür.
- `/favicon.ico`, `/manifest.webmanifest`, `/sw.js`, `/icons/*` beklenmedik 404 vermez.

### Zorunlu Auth/Session Smoke

- Logged-out `/` mevcut login'i gösterir.
- Logged-out `/admin` aynı login davranışını gösterir.
- Normal kullanıcı login olur.
- Admin login olur.
- Süper admin login olur.
- Logout session'ı temizler.
- Browser refresh valid session'ı korur.
- Kullanıcı `/` üzerinden login olup `/admin` açınca session beklenen şekilde görünür.
- Kullanıcı `/admin` üzerinden login olup `/` açınca paralel fazda session beklenen şekilde görünür.
- `GET /api/auth/me` iki adresten aynı kullanıcı kimliğini döndürür.

### Zorunlu API Path Smoke

Network katmanında şu çağrıların `/admin` altından absolute `/api/...` gittiği doğrulanmalıdır:

- `/api/auth/login`
- `/api/auth/logout`
- `/api/auth/me`
- `/api/analyze`
- `/api/extract-file-text`
- `/api/analyze-file`
- `/api/history`
- `/api/history/:id`
- `/api/history/:id/submit`
- `/api/history/merged-draft`
- `/api/history/submit-merged`
- `/api/history/approval-board`
- `/api/history/:id/approve`
- `/api/history/:id/reject`
- `/api/history/:id/feedback`
- `/api/alerts`
- `/api/my-notifications`
- `/api/standards`
- `/api/stats`
- `/api/users`
- `/api/rules`

### Zorunlu UI Smoke

En azından bir normal kullanıcı, bir admin ve bir süper admin ile:

- Normal kullanıcı paneli açılır.
- Admin paneli açılır.
- Süper admin paneli açılır.
- Metin denetimi ekranı yüklenir.
- History listeleme çalışır.
- Bildirimler yüklenir.
- Standartlar ekranı yüklenir.
- Dashboard yüklenir.
- İş panosu yüklenir.
- Kullanıcı yönetimi süper admin için görünür.
- Mobil login ve mobil menü çalışır.

### Tam Regression İçin P1B Sonrası Ek Testler

P1B production'a yaklaşmadan önce tam checklist ayrıca çalışmalıdır:

- Metin denetimi
- Onaya gönderme
- Onaylama
- Reddetme
- Feedback gönderme
- Feedback okuma
- Bildirimler
- Standartlar
- Raporlama/dashboard
- History detail
- Kullanıcı yönetimi
- Upload
- Uzun metin chunk akışı
- PDF/CSV varsa indirme
- Eski linklerden erişim
- Asset path

## H. Rollback Steps

P1B küçük bir route explicitliği olduğu için rollback iki seviyeli planlanmalıdır.

### Tercih Edilen Rollback: Tek Commit Revert

Eğer P1B yalnız `server.js` ve `scripts/check-frontend.js` dosyalarına dokunursa en temiz rollback tek commit revert'tir.

Rollback sonrası beklenen güvenli durum:

- `/` mevcut admin/login app'i döndürür.
- `/api/*` mevcut davranışını korur.
- `/health` ok döndürür.
- `/admin` Express explicit route kalksa bile mevcut broad catch-all davranışına döner.
- DB değişikliği olmadığı için veri rollback gerekmez.

### Feature Flag Rollback

Express/runtime içinde:

- `ADMIN_PARALLEL_ROUTE_ENABLED=false` yapılırsa explicit `/admin` route kapatılabilir.
- `ADMIN_ROOT_LEGACY_ENABLED=true` korunur.
- `PUBLIC_ARCHIVE_ENABLED=false` korunur.
- `PUBLIC_ARCHIVE_INDEXING=false` korunur.

Vercel static routes env flag okuyamaz. P1B kapsamında `vercel.json` değişmeyeceği için Vercel config rollback gerekmez. İleride ayrı onayla explicit Vercel `/admin` route'u eklenirse o adımın rollback'i ayrıca tek config revert olarak planlanmalıdır.

### Rollback Tetikleyicileri

Şu durumlardan biri görülürse rollback yapılmalıdır:

- `/` login/admin app açılmıyor.
- `/admin` blank page veya 404 veriyor.
- `/api/auth/me` HTML döndürüyor.
- `/api/history` HTML fallback'e düşüyor.
- Kullanıcı login/logout yapamıyor.
- Session `/` ve `/admin` arasında tutarsız.
- Static assets 404 veriyor.
- Mobil login bozuluyor.
- Admin iş panosu, feedback veya bildirimler yüklenmiyor.

## I. Verification Commands

P1B sonrası önerilen komutlar:

```bash
git status -sb
git diff --check
npm run check
npm test
node --check server.js
```

`npm run check` zaten şunları kapsar:

- `node --check server.js`
- `node scripts/check-frontend.js`
- `node --test`

Bu nedenle P1B'de asıl zorunlu komutlar:

```bash
git diff --check
npm run check
```

P1B sonrası manuel/local smoke route listesi:

```text
GET /
GET /admin
GET /admin/
GET /admin/gecmis
GET /admin/onay
GET /api/auth/me
GET /health
GET /favicon.ico
GET /manifest.webmanifest
GET /sw.js
GET /icons/favicon-32.png
```

Beklenenler:

- `/`, `/admin`, `/admin/`, `/admin/gecmis`, `/admin/onay` HTML `index.html` döndürür.
- `/api/auth/me` JSON döndürür.
- `/health` JSON `{ "status": "ok" }` döndürür.
- Asset route'ları doğru content type ve HTTP 200 döndürür.

Login smoke testleri için mümkünse production dışı ortam kullanılmalıdır. Canlı ortamda test yapılacaksa ayrıca kullanıcı onayı gerekir.

## J. Go / No-Go Criteria

### P1B'ye Geçmek İçin Go Şartları

- P1A dokümanı okunup onaylandı.
- P1B scope yalnız route explicitliği ve regression check ile sınırlı.
- DB/migration/public archive kapsam dışı kaldı.
- Mevcut dirty worktree durumu net biliniyor.
- P1B'de dokunulacak dosyalar net:
  - `server.js`
  - `scripts/check-frontend.js`
- P1B'de dokunulmayacak dosyalar net:
  - `schema.sql`
  - DB/migration dosyaları
  - `vercel.json`
  - `render.yaml`
  - `authorization.js`
  - `analysis-core.js`
  - `index.html` unless an observed blocker proves unavoidable
  - `manifest.webmanifest`
  - `sw.js`
  - public demo files
- Root `/` legacy davranışı korunacak.
- `/admin` paralel route olacak.
- Public root açılmayacak.
- `PUBLIC_ARCHIVE_ENABLED=false`.
- `PUBLIC_ARCHIVE_INDEXING=false`.

### No-Go Şartları

Şu durumlardan biri varsa P1B uygulanmamalı:

- P1B ile beraber public root açılması isteniyorsa.
- P1B ile beraber DB migration isteniyorsa.
- P1B ile beraber auth/session cookie davranışı değiştirilecekse.
- P1B ile beraber admin tab/router rewrite yapılacaksa.
- P1B ile beraber `history` -> `public_qa` yayın akışı kodlanacaksa.
- Çalışma ağacındaki mevcut dirty değişikliklerin kaynağı belirsiz ve P1B dosyalarıyla çakışıyorsa.
- `vercel.json` route sırası mevcut davranışı okuyarak doğrulanamıyorsa.
- `npm run check` P1B sonrası geçmiyorsa.

## P1B İçin Kısa Sonuç

Mevcut repo yapısı paralel `/admin` route için uygundur. Hatta bugünkü broad fallback davranışı nedeniyle `/admin` muhtemelen zaten `index.html` döndürmektedir. Ancak P1B'nin değeri bu davranışı rastlantısal catch-all sonucundan çıkarıp explicit, test edilebilir ve root public cutover'a dayanıklı hale getirmektir.

P1B'nin en güvenli kapsamı:

- `server.js`: flag helper + explicit Express `/admin` fallback.
- `scripts/check-frontend.js`: Express route order ve guard regression check.

P1B kapsamında `vercel.json` değiştirilmemelidir. Vercel explicit `/admin` route'u gerekirse ayrı onaylı P1C/P1B-Vercel adımı olarak ele alınmalıdır.

P1B'de root public açılmamalı, DB/migration yapılmamalı, auth/session değiştirilmemeli ve mevcut admin business logic'e dokunulmamalıdır.

## Public Language Guard ve `robots.txt` `/admin` İstisnası

Public language guard public HTML ve public API response'larında `admin` kelimesini fail etmelidir. Ancak `robots.txt` teknik bir crawler yönergesi olduğu için `/admin` path'i burada kontrollü istisna olmalıdır.

Kural:

- Public HTML body, metadata, JSON-LD ve public API response içinde `admin` kelimesi görünürse fail.
- Public sitemap içinde `/admin` veya `/admin/*` varsa fail.
- `robots.txt` içinde yalnız teknik path olarak `Disallow: /admin` veya `Disallow: /admin/` bulunması fail olmamalı.
- `robots.txt` içinde insan okuyucuya dönük açıklama metni olarak iç operasyon dili yazılmamalı.
- `/admin` için asıl koruma robots disallow değil, `X-Robots-Tag: noindex, nofollow` veya eşdeğer noindex davranışı olmalıdır.

Bu ayrım yapılmazsa public language guard, doğru bir `robots.txt` güvenlik yönergesini yanlış pozitif olarak fail edebilir.
