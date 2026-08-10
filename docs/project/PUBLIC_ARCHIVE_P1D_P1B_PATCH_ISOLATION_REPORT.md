# Public Archive P1D P1B Patch Isolation Report

Tarih: 2026-07-31
Durum: P1B diff isolation ve patch hygiene, docs/patch-only

## Kapsam

Bu dokuman mevcut kirli calisma agacindan P1B paralel `/admin` route degisikligini ayirmak icin hazirlandi. Bu adimda uygulama davranisi degistirilmedi; `server.js` veya `scripts/check-frontend.js` uzerinde yeni davranissal edit yapilmadi. DB migration, DB baglantisi, canli veri okuma/yazma, production deploy, push, commit ve staging yapilmadi.

P1D hedefi mevcut calisma agacini production'a tasimak degildir. Hedef, yalniz P1B_REQUIRED degisiklikleri iceren temiz uygulanabilir patch ve izolasyon karar kaydi uretmektir.

## A. Current Working Tree Status

`git status --short` ciktisi:

```text
 M AGENTS.md
 M CURRENT_HANDOFF.md
 M analysis-core.js
 M index.html
 M scripts/check-frontend.js
 M server.js
 M test/analysis-core.test.js
 M vercel.json
?? archive-public.css
?? demo-public-preview/
?? docs/project/
?? public-archive-demo.js
?? scripts/build-archive-demo-static.js
?? tmp/
```

Git ayrica kullanici genel git ignore dosyasina erisememe ve Windows LF/CRLF donusum uyarilari verdi. Bunlar P1B diff siniflandirmesinin kendisini degistirmedi.

P1B ile dogrudan iliskili dirty dosyalar:

- `server.js`: Evet, P1B route bloklari var; ayni dosyada P1B disi cok sayida dirty degisiklik de var.
- `scripts/check-frontend.js`: Evet, P1B route safety kontrolleri var; ayni dosyada P1B disi cok sayida regression check de var.

P1B ile ilgisiz veya P1B scope disi dirty dosyalar:

- `AGENTS.md`
- `CURRENT_HANDOFF.md`
- `analysis-core.js`
- `index.html`
- `test/analysis-core.test.js`
- `vercel.json`
- `archive-public.css`
- `demo-public-preview/`
- `public-archive-demo.js`
- `scripts/build-archive-demo-static.js`
- `tmp/`

`docs/project/` altindaki onceki public archive audit dokumanlari mevcut calisma agacinda untracked gorunuyor. P1D bu klasore iki yeni artifact ekledi:

- `docs/project/PUBLIC_ARCHIVE_P1D_P1B_PATCH_ISOLATION_REPORT.md`
- `docs/project/patches/PUBLIC_ARCHIVE_P1B_ONLY.patch`

Sonuc: Mevcut calisma agaci oldugu gibi stage, commit veya deploy edilmemelidir.

## B. P1B Required Changes

`server.js` icinde P1B_REQUIRED kabul edilen degisiklikler:

- Env/constants bolumunde `ADMIN_PARALLEL_ROUTE_ENABLED` flag okuma satiri.
- `sendAdminIndex(req, res)` helper'i.
- `sendAdminIndex` icinde `/admin` HTML response icin `X-Robots-Tag: noindex, nofollow`.
- `sendAdminIndex` icinde mevcut `index.html` dosyasinin dondurulmesi.
- `ADMIN_PARALLEL_ROUTE_ENABLED` acikken `/admin` ve `/admin/` route kaydi.
- `ADMIN_PARALLEL_ROUTE_ENABLED` acikken `/admin/*` deep-link fallback route kaydi.
- Bu route bloklarinin tum `/api/*` route'larindan sonra, Express error handler'dan ve broad `app.get('*')` fallback'ten once durmasi.
- Root broad fallback satirinin korunmasi: `app.get('*', (req, res) => res.sendFile(path.join(__dirname, 'index.html')));`

`scripts/check-frontend.js` icinde P1B_REQUIRED kabul edilen degisiklikler:

- `server.js` ve `vercel.json` dosyalarinin statik kontrol icin okunmasi.
- `assert`, `indexOfRequired`, `escapeRegex` helper'lari.
- Public language guard testinde kullanilacak yasak kelime listesi ve `robots.txt` teknik `/admin` istisnasini test eden helper.
- Root legacy fallback'in aynen `index.html` dondurdugunu kontrol etmek.
- Static asset route marker'larini kontrol etmek:
  - `/icons`
  - `/favicon.ico`
  - `/manifest.webmanifest`
  - `/sw.js`
- Auth/session API route marker'larini kontrol etmek:
  - `/api/auth/login`
  - `/api/auth/logout`
  - `/api/auth/me`
- `ADMIN_PARALLEL_ROUTE_ENABLED`, `sendAdminIndex`, `/admin`, `/admin/`, `/admin/*` marker'larini kontrol etmek.
- Son `/api/*` route'unun `/admin` fallback'ten once kaldigini kontrol etmek.
- `/admin` fallback'in error handler ve broad root fallback'ten once kaldigini kontrol etmek.
- `vercel.json` icinde `/api/(.*)` route'unun final `/(.*)` catch-all'dan once kaldigini kontrol etmek.
- P1B kapsaminda `vercel.json` icine explicit `/admin` route eklenmedigini kontrol etmek.
- `robots.txt` icindeki teknik `Disallow: /admin` satirinin public language guard icin false-positive sayilmadigini kontrol etmek.
- Normal public HTML benzeri icerikte `admin` kelimesinin yakalandigini kontrol etmek.

P1B-only patch, yukaridaki dar kapsama gore temiz HEAD baz alinarak hazirlandi. Mevcut calisma agacindaki public demo gate'e bagimli check satirlari patch'e alinmadi; cunku temiz P1B kapsaminda public demo dosyalari ve router'i yoktur.

## C. Non-P1B Dirty Changes

`server.js` icindeki P1B disi dirty degisiklikler:

- `createPublicArchiveRouter` import'u.
- `PUBLIC_ARCHIVE_DEMO` router baglantisi.
- `startupReady` icinde `PUBLIC_ARCHIVE_DEMO` ozel durumu.
- `express.urlencoded` limit degisikligi.
- `CHUNK_DRAFT_STATUS`, `SUBMITTED_PART_STATUS`, `SUBMITTED_CORRECTED_HASH_PREFIX`.
- `historyStatusLabel`, `historyStatusForApproval`, `isChunkFilename`, `isChunkHistoryRow`, `isHiddenHistoryForRole`.
- `/api/history` sayfali cekme ve taslak/parca gizleme davranisi.
- `/api/history/:id` hidden status 404 davranisi.
- `/api/history/:id/submit`, `/api/history/merged-draft`, `/api/history/submit-merged`.
- Duzeltilmis metin duplicate lock yardimci fonksiyonlari.
- CSV, stats ve operational snapshot filtreleri.
- Prompt/kalite standardi eklemeleri.
- `maybeCreateLowScoreAlert`.
- `saveHistory` status parametresi ve `taslak` davranisi.
- `/api/analyze`, `/api/analyze-file`, `/api/analyze-batch` response/status degisiklikleri.
- `/api/extract-file-text`.

`scripts/check-frontend.js` icindeki P1B disi dirty degisiklikler:

- Uzun metin chunk kontrolleri.
- `/api/extract-file-text` ve `skipDuplicate` kontrolleri.
- Taslak ve merged draft API akisi kontrolleri.
- Vercel no-store header kontrolleri.
- Duzeltilmis metin duplicate lock kontrolleri.
- Onaya gonderim bekleme/hata UI kontrolleri.
- `/api/history` 200 limit regresyon kontrolu.
- `chunk_draft`, `submitted_part`, merged draft kontrolleri.
- Onaya gonderim modal/UX kontrolleri.
- Sonuc ekraninda tek onay butonu/kopyala butonu kontrolleri.
- Is Panosu onay/red yenileme kontrolleri.
- Kullanici gecmisinde taslak filtreleme/onaya gonderme kontrolleri.

`vercel.json` dirty durumdadir ve P1B kapsaminda production/deploy config dosyasi olarak dokunulmamali, stage edilmemeli ve deploy'a karistirilmamalidir.

Bu P1B disi dirty degisikliklerin hicbiri P1B staging, commit, preview veya production deploy'una karismamalidir.

## D. Hunk Classification

| Dosya | Hunk | Sinif | Gerekce |
| --- | --- | --- | --- |
| `server.js` | `@@ -15,6 +15,7 @@` | UNRELATED | `createPublicArchiveRouter` import'u public demo ile ilgilidir, P1B paralel admin route icin gerekli degildir. |
| `server.js` | `@@ -32,6 +33,7 @@` | P1B_REQUIRED | `ADMIN_PARALLEL_ROUTE_ENABLED` flag'i P1B route kontrolu icin gereklidir. |
| `server.js` | `@@ -119,7 +121,7 @@` | PRE_EXISTING_DIRTY | `express.urlencoded` limit degisikligi P1B route izolasyonu degildir. |
| `server.js` | `@@ -507,6 +509,38 @@` | PRE_EXISTING_DIRTY | History status/chunk helper'lari uzun metin ve onay akisiyle ilgilidir. |
| `server.js` | `@@ -1004,6 +1038,8 @@` | UNCERTAIN | Diff hunk'i auth change-password bolgesinde approval duplicate lock satirlari gosteriyor; P1B ile ilgili degildir ve ayrica manuel inceleme gerektirir. Patch'e alinmadi. |
| `server.js` | `@@ -1224,11 +1260,13 @@` | PRE_EXISTING_DIRTY | `/api/history` sayfali cekme ve status filtreleri P1B route degisikligi degildir. |
| `server.js` | `@@ -1256,7 +1294,14 @@` | PRE_EXISTING_DIRTY | History detail hidden status davranisi P1B disidir. |
| `server.js` | `@@ -1301,6 +1346,291 @@` | PRE_EXISTING_DIRTY | Merged draft, submit ve duplicate lock bloklari P1B disidir. |
| `server.js` | `@@ -1401,7 +1731,7 @@` | PRE_EXISTING_DIRTY | CSV filtreleme P1B disidir. |
| `server.js` | `@@ -1422,6 +1752,14 @@` | PRE_EXISTING_DIRTY | Approval current-row kontrolu ve hidden status guard P1B disidir. |
| `server.js` | `@@ -1825,7 +2163,7 @@` | PRE_EXISTING_DIRTY | Stats filtreleme P1B disidir. |
| `server.js` | `@@ -2012,7 +2350,7 @@` | PRE_EXISTING_DIRTY | Operational snapshot filtreleme P1B disidir. |
| `server.js` | `@@ -2371,7 +2709,11 @@` | PRE_EXISTING_DIRTY | Prompt/kalite standardi metni P1B disidir. |
| `server.js` | `@@ -2386,7 +2728,10 @@` | PRE_EXISTING_DIRTY | Prompt/kalite standardi metni P1B disidir. |
| `server.js` | `@@ -2394,7 +2739,9 @@` | PRE_EXISTING_DIRTY | Prompt/kalite standardi metni P1B disidir. |
| `server.js` | `@@ -2591,7 +2938,19 @@` | PRE_EXISTING_DIRTY | `maybeCreateLowScoreAlert` ve `saveHistory` status hazirligi P1B disidir. |
| `server.js` | `@@ -2603,7 +2962,7 @@` | PRE_EXISTING_DIRTY | `saveHistory` varsayilan status degisikligi P1B disidir. |
| `server.js` | `@@ -2616,14 +2975,7 @@` | PRE_EXISTING_DIRTY | Low score alert davranisi P1B disidir. |
| `server.js` | `@@ -2634,10 +2986,22 @@` | PRE_EXISTING_DIRTY | Analyze endpoint taslak/chunk/file-text davranisi P1B disidir. |
| `server.js` | `@@ -2651,7 +3015,7 @@` | PRE_EXISTING_DIRTY | Analyze-file response status degisikligi P1B disidir. |
| `server.js` | `@@ -2670,7 +3034,7 @@` | PRE_EXISTING_DIRTY | Analyze-batch response status degisikligi P1B disidir. |
| `server.js` | `@@ -2678,6 +3042,23 @@` | UNCERTAIN | Ayni raw hunk icinde P1B_REQUIRED `sendAdminIndex` ve `/admin` routes ile UNRELATED `PUBLIC_ARCHIVE_DEMO` router bloku birlikte duruyor. Patch'e yalniz P1B alt bloku alindi. |
| `server.js` | `@@ -2689,7 +3070,9 @@` | PRE_EXISTING_DIRTY | `startupReady` public demo ozel durumu P1B disidir; root fallback satiri korunmus olsa da burada P1B patch degisikligi yoktur. |
| `scripts/check-frontend.js` | `@@ -2,9 +2,35 @@` | UNCERTAIN | Ayni hunk icinde P1B route safety icin gerekli `server`/`vercelConfig` okumasi ve helper'lar var; mevcut calisma agacinda bu okuma satirlari onceki dirty check'ler tarafindan da kullaniliyor. Temiz patch'te minimum P1B kontrol bagimliligi olarak alindi. |
| `scripts/check-frontend.js` | `@@ -52,4 +78,114 @@` | UNCERTAIN | Ayni raw hunk icinde uzun metin, no-store, onay, history ve P1B route kontrolleri birlikte duruyor. Patch'e yalniz P1B route safety, Vercel route-order ve robots technical exception kontrolleri alindi. |

Siniflandirma sonucu: P1B_REQUIRED bloklar guvenle ayrilabildi; fakat raw hunk'larin bazilari karisik oldugu icin mevcut calisma agacindan dogrudan `git add -p` ile hizli staging risklidir. Temiz patch yolu daha guvenlidir.

## E. P1B-Only Patch Status

Patch olusturuldu:

- `docs/project/patches/PUBLIC_ARCHIVE_P1B_ONLY.patch`

Patch format kontrolu:

- `git apply --cached --check docs/project/patches/PUBLIC_ARCHIVE_P1B_ONLY.patch` basarili oldu.
- Bu kontrol sadece patch'in temiz HEAD/index'e uygulanabilirligini sinadi; staging veya kaynak kod degisikligi yapmadi.
- Patch unified diff formatindadir. Bu formatta bos context satirlari tek boslukla temsil edilir. Icerik trailing whitespace taramasi, bu diff-control satirlari haric, temizdir.

Patch yalniz P1B_REQUIRED degisiklikleri icerir:

- `server.js`:
  - `ADMIN_PARALLEL_ROUTE_ENABLED`
  - `sendAdminIndex`
  - `X-Robots-Tag: noindex, nofollow`
  - `/admin`, `/admin/`, `/admin/*` route kayitlari
- `scripts/check-frontend.js`:
  - P1B route safety kontrolleri
  - Root legacy fallback korunumu
  - Static asset route korunumu
  - Auth/session API route korunumu
  - `/api/*` route'larinin admin fallback tarafindan yutulmamasi
  - `vercel.json` icinde P1B'de explicit `/admin` route eklenmedigi kontrolu
  - `robots.txt` teknik `/admin` path istisnasi public language guard kontrolu

Patch sunlari icermez:

- Public archive demo router veya `PUBLIC_ARCHIVE_DEMO`.
- `public-archive-demo.js`, `archive-public.css`, `demo-public-preview/`.
- `vercel.json` degisikligi.
- `render.yaml` degisikligi.
- DB, migration veya schema degisikligi.
- Auth/session core degisikligi.
- Admin business logic degisikligi.
- Long text, merged draft, duplicate lock, prompt kalite veya feedback regression degisiklikleri.

Patch mevcut kirli calisma agacina uygulanmadi. Patch temiz HEAD veya temiz P1B branch/worktree uzerinde uygulanmak uzere dokuman artifact'i olarak uretildi.

## F. Apply Strategy For Clean Worktree

Bir sonraki adimda destructive islem yapmadan en guvenli yol:

1. Mevcut kirli calisma agacindan production deploy yapma.
2. Temiz bir ortam hazirla:
   - Yeni clean clone, veya
   - Ayrica acilmis temiz `git worktree`, veya
   - Mevcut repo disinda temiz branch checkout'u.
3. Temiz ortamda once calisma agacinin temiz oldugunu dogrula.
4. `docs/project/patches/PUBLIC_ARCHIVE_P1B_ONLY.patch` artifact'indeki patch'i uygula.
5. Uygulama sonrasi diff'in yalniz su iki dosyayi degistirdigini dogrula:
   - `server.js`
   - `scripts/check-frontend.js`
6. Diff icinde yalniz P1B_REQUIRED bloklarin oldugunu dogrula.
7. `vercel.json`, `render.yaml`, DB/migration, public demo/build dosyalari ve admin business logic dosyalari degismemis olmali.
8. Dogrulamalar gecmeden commit, push veya deploy yapma.

Alternatif olarak mevcut kirli agacta manuel patch staging yapilacaksa her hunk tek tek okunmali; ancak raw hunk'lar karisik oldugu icin bu yol hata riski tasir. Temiz worktree/clone uzerinden patch apply daha dusuk risklidir.

## G. Verification Plan For Isolated Patch

Izole patch temiz ortamda uygulandiktan sonra calistirilacak komutlar:

```bash
git status --short
git diff --check
npm.cmd run check
```

`npm.cmd run check` su kontrolleri kapsar:

- `node --check server.js`
- `node scripts/check-frontend.js`
- `node --test`

Gerekirse ek komutlar:

```bash
npm.cmd test
node --check server.js
node scripts/check-frontend.js
```

Local smoke test route listesi:

```text
GET /
GET /admin
GET /admin/
GET /admin/smoke-test
GET /api/auth/me
GET /manifest.webmanifest
GET /sw.js
GET /favicon.ico
```

Beklenen sonuc:

- `/` mevcut admin/login HTML shell'i dondurur.
- `/admin` mevcut admin/login HTML shell'i dondurur.
- `/admin/` mevcut admin/login HTML shell'i dondurur.
- `/admin/smoke-test` 404 veya blank yerine `index.html` dondurur.
- `/api/auth/me` HTML degil JSON dondurur.
- `/manifest.webmanifest`, `/sw.js`, `/favicon.ico` calisir.
- Root `/` davranisi degismez.
- Public root archive aktif olmaz.

Preview/staging veya production'a tasimadan once regression pilot checklist ayrica calistirilmelidir.

## H. Go / No-Go

### Go

P1B-only patch staging/preview icin ancak su kosullar saglanirsa Go olur:

- Patch temiz worktree uzerinde sorunsuz uygulanir.
- Diff yalniz `server.js` ve `scripts/check-frontend.js` dosyalarini degistirir.
- Diff yalniz P1B_REQUIRED bloklari icerir.
- `vercel.json` degismemistir.
- `render.yaml` degismemistir.
- DB/migration dosyasi yoktur.
- Auth/session core degismemistir.
- Admin business logic degismemistir.
- Root `/` fallback korunmustur.
- Public root archive aktif degildir.
- `/api/*` route'lari HTML fallback'e dusmez.
- `git diff --check` basarilidir.
- `npm.cmd run check` basarilidir.
- Local smoke testler basarilidir.
- Vercel route/header parity boslugu P1C dokumanindaki gibi kabul edilmis veya ayri P1C-B olarak acilmistir.

### No-Go

Su durumlardan biri varsa P1B staging/preview veya production'a tasinmamalidir:

- Mevcut kirli calisma agaci oldugu gibi deploy edilmek isteniyor.
- P1B disi dirty degisiklikler patch/commit icine giriyor.
- `vercel.json`, `render.yaml`, public demo/build dosyalari veya DB/migration dosyalari degisiyor.
- Root `/` davranisi degisiyor.
- Public root archive aktif oluyor.
- `/api/auth/me` veya diger `/api/*` route'lari HTML fallback'e dusuyor.
- `npm.cmd run check` gecmiyor.
- `/admin` local smoke testte blank/404/login-loop uretiyor.
- Vercel production'da Express `X-Robots-Tag` header'i beklenecekse ama `vercel.json` degisikligi ayrica planlanmadiysa.

## Sonuc

P1B_REQUIRED bloklar mevcut kirli calisma agacindan guvenle ayrildi ve temiz ortamda uygulanmak uzere `docs/project/patches/PUBLIC_ARCHIVE_P1B_ONLY.patch` olusturuldu. Bu P1D adimi sadece dokuman/patch artifact uretimidir; kaynak kod davranisi degistirilmedi, DB'ye baglanilmadi, migration olusturulmadi, deploy/push/commit/staging yapilmadi.
