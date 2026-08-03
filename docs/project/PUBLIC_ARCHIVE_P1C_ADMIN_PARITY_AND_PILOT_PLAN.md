# Public Archive P1C-A Admin Parity and Pilot Plan

Tarih: 2026-07-31
Durum: Deployment parity, diff hygiene ve pilot preflight, docs-only

## Kapsam

Bu dokuman P1B ile eklenen paralel `/admin` Express/runtime route davranisinin production'a guvenli tasinabilmesi icin diff hygiene, Vercel/runtime parity, service worker cache riski ve sinirli kullanici pilot planini tanimlar.

Bu adimda kod yazilmadi, DB migration yapilmadi, DB'ye baglanilmadi, production deploy yapilmadi, push yapilmadi, `vercel.json` ve `render.yaml` degistirilmedi, root `/` davranisina dokunulmadi ve public root arsiv aktif edilmedi.

## A. P1B Status Summary

P1B yerel/Express runtime icin uygulandi.

P1B ile beklenen davranis:

- `/` mevcut root admin/login app davranisini korur.
- `/admin` mevcut admin/login app icin paralel route olur.
- `/admin/` mevcut admin/login app icin paralel route olur.
- `/admin/*` browser refresh ve deep-link benzeri path'lerde `index.html` alir.
- `/api/*` HTML fallback tarafindan yutulmaz.
- Static asset route'lari korunur:
  - `/icons`
  - `/favicon.ico`
  - `/manifest.webmanifest`
  - `/sw.js`
- Public root arsiv P1B'de acilmaz.
- DB, migration, auth/session core ve admin business logic degismez.

P1B son yerel dogrulama ozeti:

- `git diff --check`: basarili, yalniz mevcut Windows LF/CRLF uyarilari goruldu.
- `npm.cmd run check`: basarili, 80/80 test gecti.
- Local smoke test: `/`, `/admin`, `/admin/`, `/admin/smoke-test`, `/api/auth/me`, `/manifest.webmanifest`, `/sw.js`, `/favicon.ico` basarili.

Onemli not: P1B production deploy edilmedi ve push yapilmadi.

## B. P1B Diff Hygiene Review

### P1B'ye Ait Exact Degisiklik Bloklari

`server.js` icindeki P1B bloklari:

- `ADMIN_PARALLEL_ROUTE_ENABLED` env flag okuma satiri:
  - Mevcut konum: `server.js` env/constants bolumu.
  - Beklenen davranis: flag yoksa veya `1` ise `/admin` explicit route acik; `ADMIN_PARALLEL_ROUTE_ENABLED=0` ise explicit Express route kapali.
- `sendAdminIndex(req, res)` helper'i:
  - `X-Robots-Tag: noindex, nofollow` header'i set eder.
  - `index.html` dosyasini dondurur.
  - Auth/session kontrolu eklemez; mevcut login ekraninin logged-out kullaniciyi karsilamasi korunur.
- Explicit admin route kayitlari:
  - `app.get(['/admin', '/admin/'], sendAdminIndex)`
  - `app.get('/admin/*', sendAdminIndex)`
  - Bu blok tum `/api/*` route'larindan sonra, public archive/demo router'dan ve broad `app.get('*')` fallback'ten once durmalidir.
- Root fallback satiri:
  - `app.get('*', (req, res) => res.sendFile(path.join(__dirname, 'index.html')));`
  - P1B'de aynen korunmalidir.

`scripts/check-frontend.js` icindeki P1B bloklari:

- Statik assert helper'lari:
  - `assert`
  - `indexOfRequired`
  - `escapeRegex`
- Public forbidden word guard yardimcisi:
  - `PUBLIC_FORBIDDEN_WORDS`
  - `publicForbiddenWordHits`
- Root/admin route safety kontrolleri:
  - Root legacy fallback `index.html` donuyor mu?
  - Static asset route marker'lari korunuyor mu?
  - Auth/session API route marker'lari korunuyor mu?
  - `ADMIN_PARALLEL_ROUTE_ENABLED`, `sendAdminIndex`, `/admin`, `/admin/`, `/admin/*` marker'lari var mi?
  - Son `/api/*` route'u `/admin` fallback'ten once mi?
  - `/admin` fallback public archive/demo router, error handler ve broad fallback'ten once mi?
  - Vercel `/api/(.*)` route'u final `/(.*)` catch-all'dan once mi?
  - P1B kapsaminda `vercel.json` icinde explicit `/admin` route eklenmemis mi?
  - `robots.txt` icindeki teknik `Disallow: /admin` satiri public language guard icin false-positive sayilmiyor mu?

### P1B Oncesinden Kalan Unrelated Dirty Degisiklikler

Mevcut calisma agaci P1B'den once de kirliydi. `git diff -- server.js scripts/check-frontend.js` ciktisi yalniz P1B'yi degil, daha onceki islerin henuz commit/push durumuna alinmamis bloklarini da gosteriyor.

`server.js` icinde P1B disi gorunen dirty alanlar:

- `createPublicArchiveRouter` import'u ve `PUBLIC_ARCHIVE_DEMO` router baglantisi.
- `express.urlencoded` limit degisikligi.
- Uzun metin `chunk_draft` / `submitted_part` durumlari.
- `ADMIN_HIDDEN_HISTORY_STATUSES`, `isChunkHistoryRow`, `isHiddenHistoryForRole`.
- `/api/history/merged-draft` ve uzun metin birlesik taslak/onay akislari.
- Duzeltilmis metin duplicate lock mantigi.
- History, CSV, stats ve operational snapshot filtreleri.
- Prompt/kalite standardi degisiklikleri.
- `saveHistory` status davranisi.
- `/api/extract-file-text` ve analiz response shape degisiklikleri.
- `startupReady` icinde `PUBLIC_ARCHIVE_DEMO` ozel durumu.

`scripts/check-frontend.js` icinde P1B disi gorunen dirty alanlar:

- Uzun metin, dosya cikarma, taslak/onaya gonderme ve merged draft kontrolleri.
- Vercel no-store header kontrolleri.
- Duzeltilmis metin duplicate lock kontrolleri.
- Onaya gonderim modal/UX kontrolleri.
- History 200 kayit limiti regresyon kontrolu.
- Chunk draft ve submitted part regresyon kontrolleri.
- Is Panosu onay/red yenileme kontrolleri.

Sonuc: P1B production'a tasinacaksa mevcut calisma agaci oldugu gibi stage/deploy edilmemelidir.

### P1B Commit/Staging Izolasyonu

P1B izole edilmeden production'a tasinmamalidir.

Guvenli izolasyon kurali:

- `server.js` icinden yalniz su bloklar stage edilir:
  - `ADMIN_PARALLEL_ROUTE_ENABLED` satiri.
  - `sendAdminIndex` helper'i.
  - `/admin`, `/admin/`, `/admin/*` route kayitlari.
- `scripts/check-frontend.js` icinden yalniz P1B route safety ve robots technical exception check bloklari stage edilir.
- `vercel.json`, `render.yaml`, DB/migration, public demo/build dosyalari stage edilmez.
- P1B disi dirty degisiklikler ayni commit'e karistirilmaz.

Onerilen pratik:

- Mevcut kirli agactan dogrudan deploy yapma.
- P1B icin ayri branch veya ayri patch hazirla.
- `git add -p server.js scripts/check-frontend.js` kullanilacaksa her hunk tek tek incelenir ve P1B disi hunk'lar skip edilir.
- Daha guvenlisi: temiz branch uzerine yalniz P1B patch'i uygulanir, sonra `git diff --check` ve `npm.cmd run check` calistirilir.

## C. Deployment Runtime Parity Review

Mevcut production hedefi Vercel'dir.

`vercel.json` route sirasi:

1. `/health` -> `/server.js`
2. `/api/(.*)` -> `/server.js`
3. `/manifest.webmanifest` -> static manifest
4. `/sw.js` -> static service worker
5. `/icons/(.*)` -> static icons
6. `/favicon.ico` -> static favicon
7. `/(.*)` -> `/index.html`

Bu siraya gore Vercel production'da:

- `/api/*` istekleri Express app'e ulasir.
- `/health` Express app'e ulasir.
- `/manifest.webmanifest`, `/sw.js`, `/icons/*`, `/favicon.ico` static olarak servis edilir.
- `/`, `/admin`, `/admin/`, `/admin/smoke-test` gibi HTML path'leri final `/(.*)` route'una takilip static `/index.html` alir.

Sonuc:

- Vercel uzerinde `/admin` ve `/admin/*` mevcut `vercel.json` ile Express'e ugramiyor olabilir; daha dogrusu mevcut route config'e gore static catch-all tarafindan yakalanmasi beklenir.
- Bu durumda `server.js` icindeki `sendAdminIndex` helper'i ve `X-Robots-Tag: noindex, nofollow` header'i Vercel production `/admin` HTML cevabinda gorunmeyebilir.
- P1B'nin Vercel production etkisi tam bir route parity degildir. P1B daha cok Express/runtime hazirligidir.
- Vercel uzerinde `/admin` bugun yine acilabilir; fakat bunun nedeni P1B Express route'u degil, final static catch-all'dir.

Render veya dogrudan Node runtime kullanilirsa:

- `/admin` Express app'e gelir.
- `sendAdminIndex` calisir.
- `X-Robots-Tag: noindex, nofollow` header'i gorunur.
- `/admin/*` explicit Express fallback olarak `index.html` dondurur.

## D. Vercel Route/Header Risk

P1B kapsaminda `vercel.json` degistirilmedigi icin Vercel route/header parity boslugu bilerek acik kalir.

Riskler:

- `/admin` production'da `index.html` alabilir, fakat Express `X-Robots-Tag` header'i gorunmeyebilir.
- P1B check script'i `vercel.json` icinde explicit `/admin` route olmadigini bilerek kontrol eder; bu P1B kapsam kuralidir.
- Root public cutover'a yaklasildiginda final `/(.*)` catch-all public root'a veya baska hedefe donerse `/admin`in static catch-all'a guvenmesi yeterli olmaz.
- `/admin` noindex korumasi sadece Express header'a birakilirsa Vercel static catch-all durumunda eksik kalabilir.

P1C-B/Vercel icin ayrilmasi gereken karar:

- Secenek 1: `/admin` ve `/admin/(.*)` static `/index.html` route'u olarak explicit tanimlanir ve Vercel route/header uzerinden `X-Robots-Tag: noindex, nofollow` eklenir.
- Secenek 2: `/admin` ve `/admin/(.*)` `/server.js` hedeflenir; Express `sendAdminIndex` calisir ve header Express'ten gelir.
- Secenek 1 daha az serverless runtime degisikligi yapar, ancak Express P1B route'unu production HTML icin kullanmaz.
- Secenek 2 deployment/runtime parity'yi guclendirir, ancak static HTML yerine Vercel Function path'i kullanir ve daha fazla runtime yuzeyi acar.

P1C-A onerisi:

- P1B production'a tasinmadan once bu bosluk kabul edilebilir risk olarak imzalanmali veya P1C-B/Vercel isi ayrica acilmalidir.
- Public root cutover'dan once P1C-B zorunlu hale gelir.
- P1C-A adiminda `vercel.json` degistirilmemelidir.

## E. Service Worker Cache Risk

`sw.js` mevcut durumda minimaldir:

- `install` event'inde `self.skipWaiting()` calisir.
- `activate` event'inde `self.clients.claim()` calisir.
- `fetch` event'i bos handler ile uygulamanin mevcut network davranisini degistirmez.
- Cache API kullanimi yoktur.
- `index.html` veya `/admin` icin explicit cache yoktur.

`manifest.webmanifest` mevcut durumda:

- `start_url: "/"`
- `scope: "/"`
- `display: "standalone"`

Vercel mevcut config:

- `/sw.js` icin `Cache-Control: no-store, no-cache, must-revalidate, proxy-revalidate`.
- Final `/(.*)` -> `/index.html` route'u icin `Cache-Control: no-store, no-cache, must-revalidate, proxy-revalidate`.
- Top-level headers altinda `/(.*)` icin no-store header'i.

Degerlendirme:

- Mevcut `sw.js` index HTML'i cache'lemedigi icin P1B deploy edilirse service worker kaynakli eski shell cache riski dusuktur.
- Vercel no-store header'lari eski HTML/JS riskini daha da azaltir.
- Ancak root scope service worker vardir: manifest scope `/`, service worker path `/sw.js`.
- Gelecekte root `/` public archive oldugunda mevcut PWA `start_url: "/"` kullanicilari admin yerine public root'a goturebilir.
- Root scope PWA, admin ve public siteyi ayni scope altinda birlestirebilir; bu P1B icin blocker degil ama root public cutover oncesi ayri karar gerektirir.

P1B deploy icin sonuc:

- P1B sadece `/admin` Express/runtime route hazirligi oldugu icin `sw.js` degistirilmemelidir.
- P1B deploy edilirse mevcut kullanicilarin cache nedeniyle farkli davranis gormesi beklenmez; yine de pilotta hard refresh ve normal refresh birlikte denenmelidir.
- Public root gecisinden once service worker, manifest `start_url`, manifest `scope` ve admin/public PWA davranisi ayri P1C/P2 konusu olmalidir.

## F. Limited User Pilot Plan

P1B tum 39 kisilik ekibe duyurulmadan once kucuk pilotla dogrulanmalidir.

Pilot rolleri:

- 1 super admin.
- 1 admin.
- 1 normal ekip kullanicisi.
- 1 mobil kullanici.

Pilot ortam sirasi:

1. Mumkunse preview/staging ortam.
2. Preview/staging mumkun degilse, production icin ayrica acik onay ve kisa test penceresi.
3. Pilot boyunca root `/` mevcut ekip adresi olarak safety net kalir.
4. Pilot kullanicilar yalniz yeni paralel adresi test eder: `/admin`.
5. Pilot sonunda tum ekip yonlendirmesi yapilmaz; once bulgular raporlanir.

Pilot iletisim dili:

- Teknik feature flag dili kullanilmaz.
- Pilot kullaniciya "mevcut sistemin yeni guvenli ekip adresi test ediliyor" denir.
- Sorun olursa kullanici mevcut root `/` adresini kullanmaya devam eder.

## G. Admin Regression Pilot Checklist

Pilot sirasinda asagidaki maddeler `/admin` uzerinden test edilmelidir. Root `/` ise sadece mevcut davranis safety net olarak smoke edilir.

Route ve refresh:

- `/admin` login ekrani veya mevcut session app'i acar.
- `/admin/` ayni sonucu verir.
- `/admin/smoke-test` blank/404 uretmeden app'i acar.
- Sayfa refresh session'i bozmaz.
- Eski root `/` davranisi aynen calisir.
- Asset path'leri kirilmaz.
- API calls absolute `/api/...` gider.

Auth ve session:

- Login.
- Logout.
- Session yenileme.
- `/api/auth/me` JSON dondurur, HTML fallback'e dusmez.
- Root `/` ve `/admin` arasinda session tutarlidir.

Rol ekranlari:

- Normal kullanici paneli.
- Admin paneli.
- Super admin paneli.
- Mobil giris ve mobil menu.

Is akislari:

- Metin denetimi.
- Onaya gonderme.
- Onaylama.
- Reddetme.
- Feedback gonderme.
- Feedback okuma.
- Bildirimler.
- Standartlar.
- Raporlama/dashboard.
- History listeleme.
- Kullanici yonetimi.

Teknik smoke:

- `/manifest.webmanifest` calisir.
- `/sw.js` calisir.
- `/favicon.ico` calisir.
- `/icons/favicon-32.png` calisir.

Basarisizlik kriterleri:

- `/admin` blank page, 404 veya login loop.
- `/api/*` HTML donuyor.
- Root `/` bozuluyor.
- Session root ve `/admin` arasinda tutarsiz.
- Pilot kullanici aktif is akisini tamamlayamiyor.
- Admin/super admin yetki ekranlari yanlis gorunuyor.
- Static asset 404 sebebiyle UI bozuluyor.

## H. Rollback Plan for P1B Deployment

P1B deployment yalniz izole P1B diff'i icerirse rollback basittir.

Birinci seviye rollback:

- P1B commit revert edilir.
- `/` mevcut admin/login app'i dondurmeye devam eder.
- `/api/*` mevcut davranisini korur.
- DB rollback gerekmez.
- Migration rollback gerekmez.

Feature flag rollback:

- Express runtime'da `ADMIN_PARALLEL_ROUTE_ENABLED=0` explicit `/admin` route'unu kapatir.
- Mevcut Vercel config'te `/admin` yine final static catch-all ile `index.html` alabilir; bu nedenle flag rollback sadece Express/runtime route'u etkiler.
- `PUBLIC_ARCHIVE_ENABLED=false` ve `PUBLIC_ARCHIVE_INDEXING=false` korunur.

Vercel parity notu:

- P1B'de `vercel.json` degismedigi icin Vercel config rollback gerekmez.
- Eger ileride P1C-B ile explicit Vercel `/admin` route/header eklenirse o degisiklik icin ayri config revert plani tutulmalidir.

Deployment rollback tetikleyicileri:

- Root `/` bozuldu.
- `/admin` production veya preview'da blank/404 oldu.
- `/api/auth/me` HTML fallback'e dustu.
- Login/logout/session refresh bozuldu.
- Static assets 404 verdi.
- Pilot kullanicilar kritik akislari tamamlayamadi.
- P1B disi dirty degisikliklerin deploy'a karistigi fark edildi.

## I. Go / No-Go Criteria

### Go

P1B preview/staging veya production'a ancak su kosullar saglanirsa tasinabilir:

- P1B diff'i izole edildi.
- `server.js` ve `scripts/check-frontend.js` disinda P1B commit dosyasi yok.
- `server.js` icinde stage edilen kisim yalniz `ADMIN_PARALLEL_ROUTE_ENABLED`, `sendAdminIndex` ve `/admin` route bloklari.
- `scripts/check-frontend.js` icinde stage edilen kisim yalniz P1B route safety ve robots technical exception kontrolleri.
- Root `/` fallback satiri aynen kaldi.
- Public root arsiv aktif edilmedi.
- DB/migration yok.
- Auth/session core degismedi.
- Admin business logic degismedi.
- `vercel.json` degismedi veya P1C-B icin ayri onayla ele alindi.
- `git diff --check` basarili.
- `npm.cmd run check` izole P1B branch/patch uzerinde basarili.
- Local/preview smoke:
  - `/` HTML app.
  - `/admin` HTML app.
  - `/admin/` HTML app.
  - `/admin/smoke-test` HTML app.
  - `/api/auth/me` JSON.
  - `/manifest.webmanifest`, `/sw.js`, `/favicon.ico`, `/icons/favicon-32.png` 200.
- Vercel route/header parity boslugu karar altina alindi.
- Service worker root scope riski P1B icin kabul edildi ve public cutover oncesi ayri aksiyona alindi.
- Rollback yolu net.

### No-Go

Asagidaki durumlardan biri varsa deploy yapilmaz:

- Mevcut kirli calisma agaci oldugu gibi deploy edilmek isteniyor.
- P1B disi dirty degisiklikler P1B commit'ine karisiyor.
- `vercel.json` farki yanlislikla stage edildi.
- `render.yaml`, DB/migration veya public demo/build dosyalari stage edildi.
- Root `/` davranisi degisti.
- Public root arsiv aktif oldu.
- `/api/*` fallback'e dusuyor.
- `npm.cmd run check` gecmiyor.
- Pilot roller icin test kullanicilari ve test penceresi net degil.
- Vercel `/admin` header beklentisi "Express header production'da gorunmeli" olarak kabul ediliyor ama `vercel.json` degistirilmeden deploy planlaniyor.

## J. Recommendation for Next Step

Onerilen siradaki guvenli adim:

1. Mevcut kirli calisma agacindan production deploy yapma.
2. P1B icin izole patch/branch hazirla.
3. Sadece P1B bloklarini stage et:
   - `server.js`: `ADMIN_PARALLEL_ROUTE_ENABLED`, `sendAdminIndex`, `/admin` route'lari.
   - `scripts/check-frontend.js`: P1B route safety ve robots technical exception kontrolleri.
4. Izole patch uzerinde `git diff --check` ve `npm.cmd run check` calistir.
5. Preview/staging route smoke yap.
6. Vercel parity karari ver:
   - P1B deploy'u yalniz Express/runtime hazirligi olarak kabul edilecekse `vercel.json` degismeden devam edilebilir.
   - `/admin` production HTML cevabinda noindex header gorunmesi gerekiyorsa P1C-B/Vercel route/header isi acilmalidir.
7. 1 super admin, 1 admin, 1 normal ekip kullanicisi ve 1 mobil kullanici ile sinirli pilot yap.
8. Pilot temiz gecmeden 39 kisilik ekibe `/admin` yonlendirmesi yapma.

P1C-A sonuc karari:

- P1B teknik olarak yerel/Express runtime icin hazirdir.
- Mevcut `vercel.json` nedeniyle P1B'nin Vercel production etkisi tam deployment parity degildir.
- Production'a gecis oncesi en buyuk risk route kodu degil, diff hygiene ve Vercel route/header beklentisinin yanlis anlasilmasidir.
- Bu nedenle once izole P1B patch'i, sonra preview/staging smoke, sonra pilot onerilir.
