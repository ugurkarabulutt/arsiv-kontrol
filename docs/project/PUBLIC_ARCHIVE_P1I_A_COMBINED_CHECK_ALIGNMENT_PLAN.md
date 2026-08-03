# Public Archive P1I-A Combined Check Alignment Plan

Tarih: 2026-08-01
Durum: P1B + P1G combined check alignment plan ve patch artifact, docs/patch-only

## Kapsam

Bu dokuman P1H temiz combined patch dogrulamasinda fail eden `scripts/check-frontend.js` guard'ini P1B-only ve P1B + P1G combined state'leri ayirt edecek sekilde hizalama planidir.

Bu adimda gercek `scripts/check-frontend.js`, `server.js`, `vercel.json`, `index.html`, `sw.js` veya `render.yaml` dosyasi dogrudan degistirilmedi. DB migration yapilmadi, DB'ye baglanilmadi, canli veri okunmadi/yazilmadi, deploy/push/commit/staging yapilmadi. Root `/` davranisina dokunulmadi, public root arsiv aktif edilmedi ve kullanici soru sistemi kodlanmadi.

## A. Current State Summary

P1B:

- Express/runtime icinde paralel `/admin`, `/admin/`, `/admin/*` route hazirligi patch artifact olarak ayrildi.
- Patch artifact: `docs/project/patches/PUBLIC_ARCHIVE_P1B_ONLY.patch`.
- Patch `server.js` ve `scripts/check-frontend.js` dosyalarini hedefliyor.
- P1B-only guard mantigi `vercel.json` icinde explicit `/admin` route olmamasini bekliyordu.

P1G:

- Vercel tarafinda `/admin` noindex/header parity icin minimum patch artifact hazirlandi.
- Patch artifact: `docs/project/patches/PUBLIC_ARCHIVE_P1G_VERCEL_ADMIN_NOINDEX.patch`.
- Patch yalniz `vercel.json` icinde `/admin` ve `/admin/(.*)` static `/index.html` route'larini ekliyor.
- Her iki route `X-Robots-Tag: noindex, nofollow` ve `Cache-Control: no-store, no-cache, must-revalidate, proxy-revalidate` header'larini tasiyor.

P1H:

- Temiz worktree uzerinde once P1B patch, sonra P1G patch uygulandi.
- Patch apply basarili oldu ve manuel edit yapilmadi.
- Degisen dosyalar yalniz `server.js`, `scripts/check-frontend.js`, `vercel.json` oldu.
- `vercel.json` parse ve route order kontrolleri basariliydi.
- Local smoke test basariliydi.
- `npm.cmd run check` fail etti.

P1H sonucu:

- Combined patch route davranisi acisindan umut verici ancak check guard uyumsuzlugu nedeniyle No-Go.
- Preview/staging adimina gecmeden once check alignment gerekir.

## B. P1H No-Go Root Cause

P1H'de `npm.cmd run check` su zinciri calistirdi:

```bash
node --check server.js && node scripts/check-frontend.js && node --test
```

`node --check server.js` gecti. Failure `node scripts/check-frontend.js` asamasinda oldu.

Fail eden hata:

```text
Error: P1B vercel.json icinde explicit /admin route eklememeli; bu ayri P1C adimidir.
```

Kok neden:

- Bu guard P1B-only donemi icin dogruydu.
- P1B tek basina `vercel.json` degistirmemeliydi.
- P1G ise bilincli olarak `vercel.json` icine explicit `/admin` ve `/admin/(.*)` route'larini ekler.
- Eski guard P1B-only ile P1B + P1G combined state'i ayirt edemedigi icin P1G'nin beklenen diff'ini otomatik fail saydi.

Bu, P1G route patch'inin tek basina hatali oldugunu kanitlamaz. Check script'in durum farkini taniyamadigini gosterir.

## C. Existing Guard Analysis

Mevcut eski guard:

```js
assert(!routes.some(route => route.src === '/admin' || route.src === '/admin/(.*)'), 'P1B vercel.json icinde explicit /admin route eklememeli; bu ayri P1C adimidir.');
```

Bu guard neyi koruyordu:

- P1B-only patch'in sadece Express/runtime hazirligi oldugunu.
- P1B icinde `vercel.json` route/config degisikligi yapilmadigini.
- P1B patch commit/deploy kapsaminda production route config'in yanlislikla karismadigini.

Bu guard P1B-only state icin hala gerekli mi?

- Evet, P1B-only state'te explicit admin Vercel route olmamasi fail sebebi olmamalidir.
- Ancak P1B-only diff isolation icin `vercel.json` degisikligi ayri patch olarak tutulmalidir.
- Eski guard'in amaci korunmali, fakat P1G combined state'i taniyacak state machine eklenmelidir.

Neden P1G combined state'te fail ediyor:

- P1G patch'in dogru ve bilincli ciktisi `/admin` ve `/admin/(.*)` route'laridir.
- Eski guard bu iki route'u ayirt etmeden yasakli kabul eder.
- Bu nedenle combined state icin guard tamamen kaldirilmaz; yerine strict route/header/order assertion seti konur.

## D. Required New Check Behavior

Yeni check iki guvenli durumu desteklemelidir.

Durum 1: P1B-only state

- `vercel.json` icinde `/admin` veya `/admin/(.*)` yoktur.
- Bu durum pass edebilir.
- P1B Express/runtime kontrolleri aynen kalir:
  - `ADMIN_PARALLEL_ROUTE_ENABLED`
  - `sendAdminIndex`
  - `/admin`, `/admin/`, `/admin/*`
  - `/api/*` route'larinin admin fallback'ten once kalmasi
  - root legacy fallback'in korunmasi
- Vercel tarafinda `/api/(.*)` route'u final catch-all'dan once kalmalidir.

Durum 2: P1B + P1G combined state

- `vercel.json` icinde `/admin` ve `/admin/(.*)` birlikte vardir.
- Bu durum otomatik fail olmamalidir.
- Bunun yerine strict kontroller calismalidir:
  - route order
  - route dest
  - noindex header
  - cache-control header
  - `/api/*` sirasi
  - static asset sirasi
  - final catch-all hedefi
  - root `/` icin beklenmeyen explicit route olmamasi

Durum 3: partial veya malformed state

- Sadece `/admin` var, `/admin/(.*)` yoksa fail.
- Sadece `/admin/(.*)` var, `/admin` yoksa fail.
- `/admin` veya `/admin/(.*)` header eksikse fail.
- Dest `/index.html` degilse fail.
- Admin route final catch-all'dan sonra ise fail.
- `/api/(.*)` veya static asset route'lari admin route'larindan sonra kalirsa fail.
- Beklenmeyen `/admin/` gibi ek admin route pattern'i varsa fail.

## E. State Machine

### NO_EXPLICIT_ADMIN_VERCEL_ROUTES

Tanim:

- `routes` icinde `src` degeri `/admin` veya `/admin/(.*)` olan route yoktur.
- `src` degeri `/admin` ile baslayan baska route da yoktur.

Beklenen sonuc:

- Pass.
- Bu P1B-only state olarak kabul edilir.
- Eski "P1B vercel.json degistirmemeli" niyeti korunur, ancak explicit route yoklugu fail sayilmaz.

### EXPLICIT_ADMIN_VERCEL_ROUTES_PRESENT

Tanim:

- `routes` icinde tam olarak bir `/admin` route'u vardir.
- `routes` icinde tam olarak bir `/admin/(.*)` route'u vardir.
- Beklenmeyen baska `/admin...` route'u yoktur.

Beklenen sonuc:

- Ancak strict combined-state assertion seti gecerse pass.
- Bu P1G uygulanmis combined state olarak kabul edilir.

### PARTIAL_OR_MALFORMED_ADMIN_VERCEL_ROUTES

Tanim:

- `/admin` veya `/admin/(.*)` route'larindan sadece biri vardir.
- Route tekrarli veya beklenmeyen admin-like pattern vardir.
- Dest, header veya route order yanlistir.

Beklenen sonuc:

- Fail.
- Bu state preview/staging icin No-Go'dur.

## F. Strict Combined-State Assertions

P1G combined state tespit edilirse yeni check su kontrolleri yapmalidir.

Route varligi:

- `/admin` route'u tam olarak bir kez bulunmali.
- `/admin/(.*)` route'u tam olarak bir kez bulunmali.
- Beklenmeyen baska `/admin...` route'u olmamali.

Route order:

- `/api/(.*)` route'u `/admin` ve `/admin/(.*)` route'larindan once olmali.
- `/manifest.webmanifest` route'u admin route'larindan once olmali.
- `/sw.js` route'u admin route'larindan once olmali.
- `/icons/(.*)` route'u admin route'larindan once olmali.
- `/favicon.ico` route'u admin route'larindan once olmali.
- `/admin` route'u `/admin/(.*)` route'undan once olmali.
- `/admin` route'u final `/(.*)` catch-all'dan once olmali.
- `/admin/(.*)` route'u final `/(.*)` catch-all'dan once olmali.

Route dest:

- `/admin` dest degeri `/index.html` olmali.
- `/admin/(.*)` dest degeri `/index.html` olmali.
- Final `/(.*)` catch-all dest degeri `/index.html` kalmali.
- `/api/(.*)` dest degeri `/server.js` kalmali.
- Static asset route dest degerleri korunmali.

Headers:

- `/admin` route headers icinde `X-Robots-Tag: noindex, nofollow` olmali.
- `/admin/(.*)` route headers icinde `X-Robots-Tag: noindex, nofollow` olmali.
- `/admin` route `Cache-Control` header'i `no-store`, `no-cache`, `must-revalidate`, `proxy-revalidate` token'larini icermeli.
- `/admin/(.*)` route `Cache-Control` header'i ayni token'lari icermeli.

Root ve API korumasi:

- Root `/` icin explicit Vercel route eklenmemeli.
- Root legacy shell final catch-all uzerinden kalmali.
- `/api/*` HTML fallback'e dusecek route order riski olmamali.
- Static asset route'lari admin noindex patch tarafindan etkilenmemeli.

## G. Patch Artifact Status

Patch olusturuldu:

```text
docs/project/patches/PUBLIC_ARCHIVE_P1I_CHECK_FRONTEND_ALIGNMENT.patch
```

Patch yalniz `scripts/check-frontend.js` degisikligi icerir.

Patch sunlari icermez:

- `server.js`
- `vercel.json`
- `index.html`
- `sw.js`
- `render.yaml`
- DB/schema/migration dosyalari
- Public archive root uygulamasi
- User question intake uygulamasi

Patch gercek `scripts/check-frontend.js` dosyasina uygulanmadi. Sadece artifact olarak uretildi.

## H. Expected Diff

Beklenen diff yalniz `scripts/check-frontend.js` dosyasindadir.

Degisecek blok:

- Eski single assertion:
  - explicit `/admin` veya `/admin/(.*)` route gorunce otomatik fail.

Yerine gelecek blok:

- `routeIndex` ve `routeBySrc` helper'lari.
- Root `/` icin beklenmeyen explicit route guard'i.
- Admin-like route tespiti.
- P1B-only state icin pass.
- P1G combined state icin strict route/header/order/dest assertion'lari.
- Partial veya malformed admin route state icin fail.

Beklenen davranis:

- P1B-only state: pass.
- P1B + P1G combined state: ancak route/header/order dogruysa pass.
- Partial/malformed state: fail.

## I. Verification Plan

Bir sonraki temiz worktree dogrulamasinda onerilen sira:

1. `docs/project/patches/PUBLIC_ARCHIVE_P1B_ONLY.patch`
2. `docs/project/patches/PUBLIC_ARCHIVE_P1G_VERCEL_ADMIN_NOINDEX.patch`
3. `docs/project/patches/PUBLIC_ARCHIVE_P1I_CHECK_FRONTEND_ALIGNMENT.patch`

Patch'ler uygulandiktan sonra:

```bash
git diff --name-only
```

Beklenen degisen dosyalar:

```text
server.js
scripts/check-frontend.js
vercel.json
```

Beklenen degismeyen dosyalar:

- `render.yaml`
- `index.html`
- `sw.js`
- `manifest.webmanifest`
- `schema.sql`
- DB/schema/migration dosyalari
- auth/session core dosyalari
- admin business logic dosyalari
- public demo/build dosyalari

Config ve whitespace:

```bash
node -e "JSON.parse(require('fs').readFileSync('vercel.json','utf8')); console.log('vercel.json parse ok')"
git diff --check
```

Tam check:

```bash
npm.cmd run check
```

Local smoke:

- `GET /`
- `GET /admin`
- `GET /admin/`
- `GET /admin/smoke-test`
- `GET /api/auth/me`
- `GET /manifest.webmanifest`
- `GET /sw.js`
- `GET /favicon.ico`

Beklenen smoke:

- `/` 200 HTML, root legacy shell korunur.
- `/admin`, `/admin/`, `/admin/smoke-test` 200 HTML.
- Express local `/admin` response'larinda `X-Robots-Tag: noindex, nofollow` gorulur.
- `/api/auth/me` JSON doner, HTML fallback'e dusmez.
- Static asset route'lari 200 doner.
- Public root arsiv aktif olmaz.

Not:

- Local Express smoke Vercel route/header parity'yi tek basina kanitlamaz.
- P1I sonrasinda P1J veya P1I-B olarak Vercel preview/staging smoke gerekir.

## J. Rollback Plan

P1I patch ayri geri alinabilir:

- Yalniz `scripts/check-frontend.js` icindeki check alignment bloklarini etkiler.
- `server.js` runtime davranisindan bagimsizdir.
- `vercel.json` route/header patch'inden bagimsizdir.
- Rollback icin P1I patch hunk'i revert edilir.

Rollback sonrasi:

- P1B-only check eski strict "vercel.json admin route olmamali" haline doner.
- P1G combined state tekrar `npm.cmd run check` fail eder.
- Runtime veya production route davranisi degismez; sadece local guard davranisi degisir.

## K. Go / No-Go Criteria

### Go

P1I-A patch artifact su kosullarda sonraki temiz worktree dogrulamasina alinabilir:

- Patch yalniz `scripts/check-frontend.js` degistiriyor.
- P1B-only state'i kabul ediyor.
- P1G combined state'i strict sekilde dogruluyor.
- Partial veya malformed admin Vercel state fail ediyor.
- Guard tamamen gevsetilmiyor.
- Root `/` davranisi etkilenmiyor.
- Public root aktif olmuyor.
- `vercel.json` degistirilmiyor.
- `server.js` degistirilmiyor.
- DB/migration veya user question scope karismiyor.

### No-Go

Asagidaki durumlardan biri varsa P1I patch ilerletilmemelidir:

- Patch birden fazla dosyaya yayiliyorsa.
- Guard tamamen kaldiriliyor veya gevsetiliyorsa.
- P1B-only state bozuluyorsa.
- P1G combined state strict dogrulanmiyorsa.
- Partial/malformed state pass ediyorsa.
- `/api/*` route order riski yakalanmiyorsa.
- Static asset route order riski yakalanmiyorsa.
- Root `/` icin yeni explicit route'a izin veriliyorsa.
- Public root veya kullanici soru sistemi bu kapsama sokuluyorsa.
- Dirty ana workspace deploy edilmek isteniyorsa.

## L. P2A Deferred Scope Reminder

Kullanici soru sistemi P1I-A icinde uygulanmadi ve P2A deferred scope olarak kalir.

P2A'da ele alinacak kararlar:

- Oturum acma.
- Soru gonderme.
- Cevap takip.
- Admin/ekip cevaplama.
- Public arsive aday yapma.
- Kullanici soru yazdiginda once arsivde benzer cevaplari gosterme.
- Chatbot gibi gorunmeme.
- Kullanici sorularinin sitemap disinda ve noindex kalmasi.
- Ozel soru-cevaplarin public API response'larina dusmemesi.
- Public arsive aktarimin otomatik degil, ayri yayin karariyla yapilmasi.

## Sonuc

P1H No-Go sebebi combined patch davranisindan degil, `scripts/check-frontend.js` icindeki eski P1B-only Vercel guard'inin P1G state'ini taniyamamasindan kaynaklandi. P1I-A icin yeni check state machine'i tasarlandi ve yalniz `scripts/check-frontend.js` degisikligi iceren patch artifact olusturuldu. Bu artifact gercek koda uygulanmadi; deploy, push, commit, staging, DB migration, DB baglantisi, root public aktivasyonu veya kullanici soru sistemi uygulamasi yapilmadi.
