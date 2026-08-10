# Public Arşiv Route ve API Audit

Tarih: 2026-07-30
Durum: Salt-okunur audit, güvenli `/admin` geçiş modeliyle güncellendi, kodlanmadı

## Mevcut Root Davranışı

Mevcut uygulamada root `/` public arşiv değil, ekip uygulamasıdır.

`server.js` route sırası özetle şöyledir:

- `app.use(express.json(...))`, `app.use(express.urlencoded(...))`, `cookieSession`.
- Public statik varlıklar: `/icons`, `/favicon.ico`, `/manifest.webmanifest`, `/sw.js`.
- Otuumsuz sağlık kontrolü: `/health`.
- Mevcut tüm auth, kullanıcı, kural, standart, history, onay, alert, rapor, analiz ve dosya API'leri.
- Sadece `PUBLIC_ARCHIVE_DEMO=1` ise demo public archive router.
- Son fallback: `app.get('*', ...)` ile her bilinmeyen path için `index.html`.

Bu nedenle production'da `PUBLIC_ARCHIVE_DEMO` kapalıysa:

- `/` -> `index.html`
- `/admin` -> yine `index.html` fallback
- `/admin/herhangi-bir-path` -> yine `index.html` fallback

Frontend tarafı URL route okumuyor; `showTab('analiz')` ile tek SPA içinde sekme değiştiriyor. Login sonrası her kullanıcı analiz ekranına gönderiliyor. Admin yetkileri sekme görünürlüğüyle frontend'de, API güvenliğiyle backend'de ayrılıyor.

## `index.html` Public Root İçin Uygun Değil

`index.html` şu an admin/ekip uygulamasıdır ve root public arşiv olarak kullanılamaz:

- `<title>Arşiv Kontrol AI</title>` ve meta alanları iç operasyon ürününü anlatıyor.
- Root canonical `https://arsiv.ibrahimlive.ai/` ama içerik ekip uygulaması.
- Login ekranı ve üst bar public yasaklı iç terimler içeriyor.
- Admin menüleri, kullanıcı yönetimi, kurallar, onaylar, uyarılar, raporlar ve analiz akışları aynı dosyada.
- Public arşiv için gereken soru detay, kategori, konu, sitemap, robots ve noindex mantığı bu dosyanın ana yapısı değil.

Sonuç: Public root için `index.html` taşınmalı veya yalnız `/admin` altında servis edilmeli. Root'a ayrı public HTML renderer/router gelmeli.

## Mevcut Demo Public Router

Current worktree'de `public-archive-demo.js`, `archive-public.css`, `data/qa-seed.js`, `scripts/build-archive-demo-static.js` ve `demo-public-preview/` görülüyor.

Demo router şu route'ları tanımlıyor:

- `/archive-public.css`
- `/`
- `/arama`
- `/soru/:slug`
- `/konu/:slug`
- `/kategori/:slug`
- `/admin`

Gözlemler:

- Demo `history` tablosunu okumuyor; `data/qa-seed` fixture'ını okuyor.
- Demo HTML-first render üretiyor ve canonical/JSON-LD başlangıç yaklaşımı içeriyor.
- Demo yalnız `PUBLIC_ARCHIVE_DEMO=1` iken bağlanıyor.
- Aynı env açıkken `startupReady = Promise.resolve()` yapılıyor; yani Supabase seed/kolon tespit akışı bypass ediliyor.
- Demo search route'u için noindex yok.
- Demo sitemap.xml ve robots.txt üretmiyor.
- Demo `/admin` sadece `index.html` dosyasını döndürüyor; `/admin/*` fallback yok.
- Demo production veri modeli değildir; `public_qa` katmanına bağlı değildir.

Bu dosyalar MVP için fikir verebilir, fakat doğrudan production mimarisi olarak alınmamalıdır.

## Güvenli Geçiş Route Modeli

İlk implementation root davranışını değiştirmemeli:

- `/` mevcut admin/login uygulaması olarak kalır.
- `/admin` mevcut admin/login uygulamasının paralel adresi olur.
- `/admin/*` mevcut admin/login uygulamasının refresh ve deep-link fallback'i olur.
- Public root feature flag kapalı kalır.

Root public geçişi yalnız `/admin` doğrulandıktan sonra yapılmalı:

- `/` public arşiv olur.
- `/admin` admin panel olarak kalır.
- Eski admin deep linkleri güvenli şekilde eşleşebiliyorsa `/admin` altına yönlendirilir.
- Bilinmeyen public path'ler admin'e yönlendirilmez.

## `/admin` Altına Taşıma Riskleri

1. Fallback sırası: Public router `/` yakalayınca `app.get('*')` artık admin root varsayımıyla çalışmamalı. `/admin` ve `/admin/*` açıkça `index.html` döndürmeli.
2. API route çakışması: Public catch-all, `/api/*`, `/health`, `/favicon.ico`, `/manifest.webmanifest`, `/sw.js`, `/icons/*`, `/sitemap.xml`, `/robots.txt` öncesinde çalışmamalı.
3. SPA refresh: `/admin`, `/admin/gecmis`, `/admin/onay` gibi gelecekte route eklenirse refresh aynı admin app'i döndürmeli.
4. Asset path: `index.html` içindeki `/icons/*`, `/manifest.webmanifest`, `/sw.js`, `/api/*` absolute path olduğu için `/admin` altında çalışır; göreli path eklenirse kırılır.
5. Service worker scope: Mevcut `/sw.js` root scope ile kayıt oluyor. Public root geldikten sonra admin service worker public sayfaları kontrol etmemeli. Admin PWA gerekirse scope `/admin/` olacak şekilde ayrılmalı veya admin altında service worker kapatılmalı.
6. Canonical/OG meta: Admin `index.html` artık root canonical taşımamalı. `/admin` için `noindex` uygulanmalı.
7. Public yasaklı terim sızıntısı: Public root yanlışlıkla `index.html` döndürürse public yasaklı iç terimler görünür.
8. Auth cookie: `cookie-session` path default olarak domain geneli çalışır. Public sayfalar session cookie görse bile user state'i render etmemeli.
9. Unauthorized davranış: `/admin` login ekranı döndürmeli; `/api/*` 401 JSON döndürmeye devam etmeli.
10. E2E onay akışı: `taslak -> bekliyor -> onaylandi/reddedildi` route taşımadan etkilenmemeli.
11. CSV/PDF indirme: `/api/history/csv`, `/api/pdf`, `/api/feedback/work-package.pdf` mutlak API path'lerinde kalmalı.
12. Cron: `/api/cron/daily-report` public route altında kalmamalı; secret kontrolü korunmalı.
13. Demo env riski: `PUBLIC_ARCHIVE_DEMO=1` production'da yanlış açılırsa seed atlanır ve fixture tabanlı public demo root'a oturur.
14. Untracked bağımlılık riski: `server.js` `public-archive-demo` require ediyor; dosya commit kapsamına girmezse deploy/runtime kırılabilir.

## Mevcut API Sınıflandırması

### Public veya Otuumsuz Kalabilir

| Route | Mevcut durum | Not |
| --- | --- | --- |
| `GET /health` | Otuumsuz | Monitoring için kalmalı. DB veya kullanıcı verisi döndürmemeli. |
| `GET /favicon.ico` | Otuumsuz | Public asset. |
| `GET /manifest.webmanifest` | Otuumsuz | Public asset; admin taşınınca kapsam ve isim yeniden değerlendirilmeli. |
| `GET /sw.js` | Otuumsuz | Public/admin scope riski var. |
| `GET /icons/*` | Otuumsuz | Public asset. |
| `GET /` | Şu an admin SPA | Hedefte public arşiv ana sayfası. |
| `GET /arama` | Demo'da var | Hedefte public arama, `noindex,follow`. |
| `GET /soru/:slug` | Demo'da var | Hedefte published public detay. |
| `GET /konu/:slug` | Demo'da var | Hedefte published public konu koleksiyonu. |
| `GET /kategori/:slug` | Demo'da var | Hedefte published public kategori koleksiyonu. |
| `GET /sitemap.xml` | Yok | Hedefte sadece published canonical URL'ler. |
| `GET /robots.txt` | Yok | Hedefte sitemap referansı ve crawler sınırları. |

### Auth Gerektiren Ekip Kullanıcı API'leri

Bu route'lar public olmamalı, fakat normal ekip kullanıcısı erişimi devam etmeli:

- `POST /api/auth/logout`
- `GET /api/auth/me`
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

Not: `POST /api/auth/login` doğal olarak oturumsuz çağrılır, ancak yalnız `/admin` login için kullanılmalıdır. Public arşiv kullanıcı login'i gibi sunulmamalı.

### Admin Kalması Gereken API'ler

Bu route'lar kesinlikle public olmamalı:

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

### Süper Admin Kalması Gereken API'ler

- `POST /api/users`
- `DELETE /api/users/:id`
- `GET /api/notification-log`
- `GET /api/resolution-responses`

### Secret veya Sistem Route'u

- `GET /api/cron/daily-report`: Auth middleware kullanmıyor, `CRON_SECRET` ile korunuyor. Public site navigation, sitemap veya robots içinde görünmemeli.

## Public API Olursa Nasıl Ayrılmalı

İlk MVP için public HTML route'ların server-side `public_qa` okuması yeterlidir. Public JSON API şart değil.

Gerekirse yalnız şu route'lar eklenmeli:

- `GET /api/public/search?q=&page=`
- `GET /api/public/qa/:slug`
- `GET /api/public/categories`
- `GET /api/public/topics`

Bu API'ler yalnız `public_qa.status = 'published'` verisi döndürmeli. `source_history_id`, kullanıcı bilgileri, skorlar, hata sayımları, hash, onaylayan ve iç meta alanları response içinde olmamalı.

## `history` Alanları Public'e Asla Çıkmamalı

Public response ve public HTML içinde doğrudan `history` alanı basılmamalı. Özellikle şu alanlar yasak:

- `history.id`
- `history.user_id`
- `history.username`
- `history.name`
- `history.filename`
- `history.score`
- `history.total_errors`
- `history.cat_counts`
- `history.summary`
- `history.original_text`
- `history.corrected_text`
- `history.status`
- `history.approved_by`
- `history.approved_at`
- `history.text_hash`
- `history.prompt_version`
- `history.rules_hash`
- `history.created_at`

Public'te soru, cevap ve özet gerekiyorsa bunlar `public_qa.question`, `public_qa.answer`, `public_qa.summary` gibi editoryal alanlardan gelmeli. `source_history_id` sadece iç ilişki olarak tutulmalı, public response'a çıkmamalı.

## Minimum Route Kabul Kriterleri

- Paralel geçiş fazında `/` mevcut admin SPA/login davranışını korur.
- Paralel geçiş fazında `/admin` login veya mevcut ekip ekranını döndürür.
- Paralel geçiş fazında `/admin/*` refresh ile düşmez.
- `/api/history` auth olmadan 401 döndürür.
- `/api/users`, `/api/stats`, `/api/alerts`, `/api/rules`, `/api/history/csv` auth/admin olmadan veri döndürmez.
- Public root cutover fazında `/` public arşiv HTML döndürür, admin SPA döndürmez.
- Public root cutover fazında `/admin` ve `/admin/*` admin SPA/login davranışını korur.
- Public root cutover fazında eski admin linkleri yalnız güvenli eşleşme varsa `/admin` altına redirect edilir.
- Public root cutover fazında `/soru/:slug` yalnız published kayıtları gösterir.
- Draft, review, archived, rejected veya unpublished kayıtlar public 404 döndürür.
- Public HTML içinde yasaklı iç terimler bulunmaz.
- Public route'lar `history` tablosundan doğrudan okumaz.

## Feature Flag Route Matrix

| Faz | `/` | `/admin` | Public routes | Indexing |
| --- | --- | --- | --- | --- |
| Başlangıç | Mevcut admin | Paralel admin | Kapalı | Kapalı |
| `/admin` doğrulama | Mevcut admin | Paralel admin | Kapalı | Kapalı |
| Public preview | Mevcut admin | Paralel admin | Açık, noindex | Kapalı |
| Root cutover | Public arşiv | Admin | Açık | Önce kapalı |
| SEO onayı | Public arşiv | Admin | Açık | Açık |

Flag karşılıkları:

- Başlangıç: `ADMIN_PARALLEL_ROUTE_ENABLED=true`, `ADMIN_ROOT_LEGACY_ENABLED=true`, `PUBLIC_ARCHIVE_ENABLED=false`, `PUBLIC_ARCHIVE_INDEXING=false`.
- Public preview: `PUBLIC_ARCHIVE_ENABLED=true`, `PUBLIC_ARCHIVE_INDEXING=false`, `PUBLIC_ARCHIVE_USE_PUBLIC_QA=true`.
- Root cutover: `ADMIN_ROOT_LEGACY_ENABLED=false`, `PUBLIC_ARCHIVE_ENABLED=true`, `PUBLIC_ARCHIVE_USE_PUBLIC_QA=true`.
