# Public Archive P1G Vercel Admin Noindex Patch Plan

Tarih: 2026-07-31
Durum: Vercel `/admin` noindex route/header patch plani, docs/patch artifact only

## Kapsam

Bu dokuman P1B paralel `/admin` route hazirliginin Vercel production/preview ortaminda noindex/nofollow header garantisi kazanmasi icin minimum `vercel.json` patch planini tanimlar.

Bu adimda gercek `vercel.json` dosyasi degistirilmedi. Kod yazilmadi, `server.js`, `scripts/check-frontend.js`, `index.html`, `sw.js`, `render.yaml` degistirilmedi. DB migration yapilmadi, DB'ye baglanilmadi, canli veri okunmadi/yazilmadi, deploy/push/commit/staging yapilmadi. Root `/` davranisina dokunulmadi, public root arsiv aktif edilmedi ve kullanici soru sistemi kodlanmadi.

## A. Current State Summary

P1B:

- Express/runtime icinde paralel `/admin`, `/admin/`, `/admin/*` route hazirligi yapildi.
- Root `/` legacy admin shell davranisi korunacak sekilde tasarlandi.
- `/admin` HTML response'lari icin Express tarafinda `X-Robots-Tag: noindex, nofollow` eklendi.

P1E:

- P1B-only patch temiz worktree uzerinde uygulandi.
- Diff yalniz `server.js` ve `scripts/check-frontend.js` dosyalarini degistirdi.
- `git diff --check`, `npm.cmd run check` ve local smoke test basarili oldu.
- `vercel.json`, `render.yaml`, DB/schema/migration dosyalari degismedi.
- Production deploy, push, commit yapilmadi.

P1F:

- Mevcut Vercel config altinda `/admin` HTML path'lerinin Express'e degil final static `/(.*)` catch-all route'una dusmesi muhtemel bulundu.
- Bu durumda `server.js` icindeki `X-Robots-Tag` local Express'te calissa da production `/admin` response'unda garanti kabul edilemez.
- `/api/*` route'lari mevcut configte `/server.js` hedefine gider; bu kritik siralama korunmalidir.
- Static asset route'lari admin noindex planindan etkilenmemelidir.

Current working tree notu:

- Mevcut calisma agaci kirlidir.
- Current `vercel.json`, `HEAD:vercel.json` ile ayni degildir.
- Current `vercel.json` icinde P1G disi cache/no-store header dirty degisiklikleri vardir.
- Bu nedenle mevcut calisma agaci oldugu gibi stage/commit/deploy edilmemelidir.

## B. Current Vercel Route Map

Current `vercel.json` route sirasi:

| Sira | Route | Hedef | Not |
| ---: | --- | --- | --- |
| 1 | `/health` | `/server.js` | Health Express/Vercel Function tarafina gider. |
| 2 | `/api/(.*)` | `/server.js` | Tum API route'lari Express/Vercel Function tarafina gider. |
| 3 | `/manifest.webmanifest` | `/manifest.webmanifest` | Static manifest. Current dirty dosyada no-store route header'i var. |
| 4 | `/sw.js` | `/sw.js` | Static service worker. Current dirty dosyada no-store route header'i var. |
| 5 | `/icons/(.*)` | `/icons/$1` | Static icon dosyalari. |
| 6 | `/favicon.ico` | `/icons/favicon.ico` | Static favicon. |
| 7 | `/(.*)` | `/index.html` | Tum kalan HTML path'leri static `index.html` alir. Current dirty dosyada no-store route header'i var. |

Current `vercel.json` icinde explicit `/admin`, `/admin/` veya `/admin/(.*)` route'u yoktur.

`HEAD:vercel.json` farki:

- HEAD baseline route sirasi aynidir.
- HEAD baseline'da manifest, `sw.js`, final catch-all ve top-level `headers` icin current no-store dirty degisiklikleri yoktur.
- P1G patch artifact'i P1G disi cache/no-store dirty diff'lerini icermez; yalniz `/admin` route-level header eklemeyi hedefler.

## C. /admin Current Production Behavior

Mevcut route siralamasina gore:

- `/admin`, `/admin/` ve `/admin/smoke-test` `/health` ile eslesmez.
- `/api/(.*)` ile eslesmez.
- Static asset route'lariyla eslesmez.
- `/favicon.ico` ile eslesmez.
- Bu path'ler final `/(.*)` catch-all route'una duser.
- Final catch-all static `/index.html` dondurur.

Sonuc:

- Vercel production/preview ortaminda `/admin` muhtemelen static `index.html` ile acilir.
- Bu acilis P1B Express route'unun production'da calistigini kanitlamaz.
- `/admin` response header'lari final static route ve Vercel config tarafindan belirlenir.

## D. Noindex/Header Problem

P1B `server.js` icinde `/admin` icin su mantigi ekledi:

```js
res.set('X-Robots-Tag', 'noindex, nofollow');
```

Bu header Express/runtime response'unda calisir. Local smoke testte goruldu.

Vercel production riski:

- Current Vercel route map `/admin` isteklerini `/server.js` hedefine gondermiyor.
- `/admin` final static `/(.*)` catch-all ile `/index.html` alabilir.
- Bu durumda `server.js` helper'i calismaz.
- `server.js` kaynakli `X-Robots-Tag` production `/admin` response'unda garanti degildir.

Bu risk P1B Express patch'in yanlis oldugu anlamina gelmez; Vercel route/header parity'nin ayri bir config katmani oldugunu gosterir.

## E. Option Analysis

### Secenek A: Top-level `headers` ile `/admin` noindex eklemek

Taslak:

```json
{
  "source": "/admin",
  "headers": [
    { "key": "X-Robots-Tag", "value": "noindex, nofollow" }
  ]
}
```

ve:

```json
{
  "source": "/admin/(.*)",
  "headers": [
    { "key": "X-Robots-Tag", "value": "noindex, nofollow" }
  ]
}
```

Artlar:

- Route hedefi degismez.
- Root `/` davranisi degismez.
- `/api/*` route sirasi degismez.
- Static asset route'lari degismez.
- Rollback tek `vercel.json` hunk revert ile kolaydir.

Eksiler:

- Current config zaten `routes` icinde route-level header kullaniyor; sadece top-level `headers`a guvenmek mevcut route matching ile preview dogrulamasi olmadan kesin garanti sayilmamalidir.
- `/admin/` ve deep path pattern davranisi mutlaka preview'da header ile dogrulanmalidir.
- `/admin` path'inin final catch-all ile static `index.html` almaya devam etmesi explicit hale gelmez.

39 kullanici etkisi:

- Dusuk. Kullanici tarafinda HTML hedefi degismez.

`/api/*` etkisi:

- Beklenen etki yok.

Static asset etkisi:

- Beklenen etki yok.

Root `/` etkisi:

- Beklenen etki yok.

Rollback kolayligi:

- Yuksek.

Preview/staging dogrulama kolayligi:

- Orta. Header varligi network response ile dogrulanmalidir.

Oneri:

- Tek basina ilk tercih degil. Route-level header stili current config ile daha uyumludur.

### Secenek B: `routes` icinde explicit `/admin` static route + route-level headers

Taslak:

```json
{
  "src": "/admin",
  "headers": {
    "X-Robots-Tag": "noindex, nofollow",
    "Cache-Control": "no-store, no-cache, must-revalidate, proxy-revalidate"
  },
  "dest": "/index.html"
}
```

ve:

```json
{
  "src": "/admin/(.*)",
  "headers": {
    "X-Robots-Tag": "noindex, nofollow",
    "Cache-Control": "no-store, no-cache, must-revalidate, proxy-revalidate"
  },
  "dest": "/index.html"
}
```

Route sirasi:

- `/health`, `/api/(.*)`, manifest, `sw.js`, icons ve favicon route'larindan sonra.
- Final `/(.*)` catch-all'dan once.

Artlar:

- `/admin` ve `/admin/*` davranisi explicit hale gelir.
- Static `index.html` hedefi korunur.
- `server.js` runtime yuzeyi artmaz.
- 39 kullanici icin function latency/startup riski eklenmez.
- `X-Robots-Tag` ve admin path cache davranisi ayni route object icinde tanimlanir.
- Root `/` final catch-all davranisi aynen kalir.

Eksiler:

- `vercel.json` route sirasi degisir; preview smoke zorunludur.
- Express P1B route'u production static path icin hala calismaz; Vercel tarafinda esdeger noindex garanti edilir.
- `/admin/(.*)` pattern'inin `/admin/` path'ini kapsadigi preview'da mutlaka dogrulanmalidir.

39 kullanici etkisi:

- Dusuk. Hedef yine `index.html`; auth/session ve admin business logic degismez.

`/api/*` etkisi:

- Beklenen etki yok, cunku `/api/(.*)` route'u daha once kalir.

Static asset etkisi:

- Beklenen etki yok, cunku asset route'lari daha once kalir.

Root `/` etkisi:

- Beklenen etki yok, cunku root final catch-all aynen kalir.

Rollback kolayligi:

- Yuksek. Tek `vercel.json` hunk revert yeterlidir.

Preview/staging dogrulama kolayligi:

- Yuksek. `/admin`, `/admin/`, `/admin/smoke-test` response header'lari dogrudan kontrol edilir.

Oneri:

- Onerilen minimum P1G patch budur.

### Secenek C: `/admin` route'larini `/server.js` hedefine rewrite etmek

Taslak:

```json
{ "src": "/admin", "dest": "/server.js" }
{ "src": "/admin/(.*)", "dest": "/server.js" }
```

Artlar:

- Production `/admin` Express app'e gider.
- `server.js` icindeki P1B `X-Robots-Tag` dogrudan calisir.
- Local Express ve Vercel production route parity daha gucludur.

Eksiler:

- Static HTML shell yerine Vercel Function yolu kullanilir.
- Latency, cold start ve startup/env bagimliligi artar.
- HTML shell icin Supabase/env/startup yuzeyi daha kritik hale gelir.
- 39 aktif kullanici icin daha fazla runtime risk tasir.

39 kullanici etkisi:

- Orta. HTML shell hedefi ayni olsa da runtime yolu degisir.

`/api/*` etkisi:

- Route sirasi dogruysa beklenen etki yok; ancak yanlis siralama API fallback riskini artirabilir.

Static asset etkisi:

- Route sirasi dogruysa beklenen etki yok.

Root `/` etkisi:

- Beklenen etki yok, fakat Express/runtime kaynakli admin HTML davranisi root'tan farkli hale gelebilir.

Rollback kolayligi:

- Orta/yuksek. Tek `vercel.json` hunk revert gerekir.

Preview/staging dogrulama kolayligi:

- Orta. Header disinda function latency ve runtime davranisi da izlenmelidir.

Oneri:

- P1G minimum patch icin onerilmez. Daha sonra tam Express parity hedeflenirse ayrica degerlendirilebilir.

### Secenek D: Static `index.html` icine meta robots eklemek

Artlar:

- Header config gerekmeden HTML icinde robots sinyali olabilir.

Eksiler:

- Tek `index.html` root `/` icin de kullaniliyor.
- Root `/` gecis dogrulanana kadar legacy admin shell; ileride public canonical arsiv olacak.
- Global meta robots public SEO'yu bozabilir.
- Path bazli meta robots static tek HTML ile guvenilir degildir.
- Kullaniciya gorunen HTML degisikligi ve frontend risk yuzeyi acar.

39 kullanici etkisi:

- Potansiyel olarak orta, cunku uygulama shell'i degisir.

`/api/*` etkisi:

- Yok.

Static asset etkisi:

- Yok.

Root `/` etkisi:

- Yuksek risk. Root HTML de etkilenir.

Rollback kolayligi:

- Orta. `index.html` revert gerekir.

Preview/staging dogrulama kolayligi:

- Dusuk/orta. HTML head path bazli degilse yanlis sinyal kolay kacar.

Oneri:

- Onerilmez.

### Secenek E: Vercel degisikligi yapmamak

Artlar:

- En dusuk anlik degisiklik.
- Root `/`, `/api/*`, static asset route'lari hic etkilenmez.
- P1B patch yalniz Express/runtime hazirligi olarak kalir.

Eksiler:

- Production `/admin` noindex/nofollow garanti degildir.
- P1B local smoke sonucu production header garantisi gibi raporlanamaz.
- Public root cutover oncesi ayni konu tekrar bloker olur.

39 kullanici etkisi:

- Yok.

`/api/*` etkisi:

- Yok.

Static asset etkisi:

- Yok.

Root `/` etkisi:

- Yok.

Rollback kolayligi:

- Degisiklik olmadigi icin rollback yoktur.

Preview/staging dogrulama kolayligi:

- Kolay, fakat noindex hedefi dogrulanamaz.

Oneri:

- P1B production pilotu icin noindex zorunlu kabul edilmeyecekse gecici olarak kabul edilebilir.
- Public root cutover oncesi kabul edilemez.

## F. Recommended Minimal Patch

Onerilen minimum patch: Secenek B.

Yalniz `vercel.json` icinde, final `/(.*)` catch-all'dan once iki explicit route eklenir:

- `/admin`
- `/admin/(.*)`

Her iki route:

- Static `/index.html` dondurur.
- `X-Robots-Tag: noindex, nofollow` header'i verir.
- `Cache-Control: no-store, no-cache, must-revalidate, proxy-revalidate` header'ini korur.

Bu patch sunlari yapmaz:

- `/api/(.*)` route'unu degistirmez.
- `/health` route'unu degistirmez.
- `/manifest.webmanifest`, `/sw.js`, `/icons/(.*)`, `/favicon.ico` route'larini degistirmez.
- Root `/` catch-all route'unu degistirmez.
- Public root archive'i aktif etmez.
- `server.js` veya auth/session core'a dokunmaz.
- Admin business logic'e dokunmaz.

Neden route-level header:

- Current `vercel.json` zaten `routes` icinde `headers` object kullaniyor.
- Bu stil, top-level `headers` uyumluluguna tek basina guvenmekten daha acik ve test edilebilir.
- `/admin` HTML hedefi explicit olur; final catch-all'a gizli bagimlilik azalir.

## G. Patch Artifact Status

Patch olusturuldu:

```text
docs/project/patches/PUBLIC_ARCHIVE_P1G_VERCEL_ADMIN_NOINDEX.patch
```

Patch yalniz `vercel.json` degisikligi icerir.

Patch sunlari icermez:

- `server.js`
- `scripts/check-frontend.js`
- `index.html`
- `sw.js`
- `render.yaml`
- DB/schema/migration dosyalari
- Public archive veya user question intake kodu

Patch mevcut calisma agacina uygulanmadi. Yalniz artifact olarak eklendi.

## H. Expected Diff

Beklenen diff yalniz `vercel.json` uzerindedir.

Beklenen hunk:

- `/favicon.ico` route'undan sonra.
- Final `/(.*)` catch-all'dan once.
- Iki yeni route object:
  - `src: "/admin"`
  - `src: "/admin/(.*)"`
- Iki route da `dest: "/index.html"` kullanir.
- Iki route da `X-Robots-Tag: noindex, nofollow` header'i tasir.
- Iki route da admin path icin no-store cache header'i tasir.

Beklenen davranis:

- `GET /` final catch-all ile ayni legacy shell'i almaya devam eder.
- `GET /admin` explicit admin route ile static `index.html` alir ve noindex header tasir.
- `GET /admin/` `/admin/(.*)` route'u ile static `index.html` alir ve noindex header tasir.
- `GET /admin/smoke-test` `/admin/(.*)` route'u ile static `index.html` alir ve noindex header tasir.
- `GET /api/auth/me` daha onceki `/api/(.*)` route'u nedeniyle `/server.js` tarafina gitmeye devam eder.

## I. Verification Plan For Clean Worktree

Temiz worktree stratejisi:

1. Mevcut kirli calisma agacindan deploy yapma.
2. Temiz clone veya temiz git worktree hazirla.
3. Gerekiyorsa once P1B-only patch'i uygula.
4. Sonra P1G Vercel patch artifact'ini uygula.
5. Diff'in yalniz beklenen dosyalari degistirdigini dogrula.

P1G patch tek basina uygulanacaksa beklenen changed file:

```text
vercel.json
```

Komutlar:

```bash
git status --short
git apply --check docs/project/patches/PUBLIC_ARCHIVE_P1G_VERCEL_ADMIN_NOINDEX.patch
git diff --check
```

JSON/config parse kontrolu:

```bash
node -e "JSON.parse(require('fs').readFileSync('vercel.json','utf8')); console.log('vercel.json ok')"
```

Vercel config validation:

- Mumkunse deploy yapmadan Vercel CLI local config/build validasyonu ayrica degerlendirilebilir.
- `vercel.cmd build` gibi komutlar `.vercel/output` uretebilir ve env bagimliliklari isteyebilir; bu nedenle ayri onayli local/preview hazirlik adimi olarak ele alinmalidir.
- Production deploy bu planin parcasi degildir.

`npm.cmd run check`:

- P1G patch yalniz `vercel.json` degistirdigi icin code-level zorunlu check degildir.
- P1B patch ile birlikte preview/staging adayina alinacaksa tam regresyon icin yine `npm.cmd run check` calistirilmelidir.

Local smoke:

- Normal `npm start` veya Express local server Vercel `routes` config'ini birebir kullanmaz.
- Bu nedenle local Express smoke P1B route davranisini dogrular, P1G Vercel header davranisini kesin kanitlamaz.
- `vercel dev` denenebilir, fakat production parity icin Vercel preview smoke gerekir.

Vercel preview smoke:

- `GET /`
- `GET /admin`
- `GET /admin/`
- `GET /admin/smoke-test`
- `GET /api/auth/me`
- `GET /manifest.webmanifest`
- `GET /sw.js`
- `GET /favicon.ico`

Beklenen preview sonuc:

- `/` 200 HTML ve legacy admin shell.
- `/admin`, `/admin/`, `/admin/smoke-test` 200 HTML.
- `/admin`, `/admin/`, `/admin/smoke-test` response header'inda `X-Robots-Tag: noindex, nofollow`.
- `/api/auth/me` JSON; HTML fallback degil.
- `/manifest.webmanifest`, `/sw.js`, `/favicon.ico` 200 ve beklenen content-type.
- Root `/` public archive'e donusmemis.
- Static assets etkilenmemis.

## J. Rollback Plan

P1G patch rollback'i:

- Tek dosya `vercel.json` revert yeterlidir.
- Eklenen iki route object kaldirilir:
  - `/admin`
  - `/admin/(.*)`
- DB rollback gerekmez.
- Auth/session rollback gerekmez.
- Admin business logic rollback gerekmez.
- P1B patch'ten bagimsizdir.

Rollback sonrasi beklenen:

- `/admin` tekrar final `/(.*)` catch-all'a duser.
- Root `/` davranisi degismez.
- `/api/*` route'lari `/server.js` hedefini korur.
- Static asset route'lari korunur.

Rollback tetikleyicileri:

- `/admin` veya `/admin/` preview'da 404/blank/HTML olmayan response dondururse.
- `/api/auth/me` HTML fallback'e duserse.
- `/manifest.webmanifest`, `/sw.js`, `/favicon.ico` bozulursa.
- Root `/` beklenmeyen header/route degisikligi alirsa.
- Pilot kullanicilarda login/session loop gorulurse.

## K. Go / No-Go Criteria

### Go

P1G patch preview/staging icin su kosullarda Go olur:

- Patch yalniz `vercel.json` degistiriyor.
- `/admin` noindex/header stratejisi net.
- `/api/*` route sirasi etkilenmiyor.
- Static asset route'lari etkilenmiyor.
- Root `/` etkilenmiyor.
- Public root archive aktif degil.
- Auth/session core degismiyor.
- Admin business logic degismiyor.
- Rollback tek dosya.
- `git apply --check` basarili.
- `git diff --check` basarili.
- Preview smoke basarili.
- `/admin`, `/admin/`, `/admin/smoke-test` header'lari goruluyor.
- `/api/*` HTML fallback'e dusmuyor.

### No-Go

Asagidaki durumlardan biri varsa P1G patch preview/staging veya production'a alinmamalidir:

- `/api/*` etkileniyorsa.
- Root `/` davranisi degisiyorsa.
- Static asset route'lari etkileniyorsa.
- Top-level headers ve routes uyumlulugu belirsizken sadece top-level header cozumune guveniliyorsa.
- Patch birden fazla dosyaya tasiyorsa.
- Mevcut kirli workspace deploy edilmek isteniyorsa.
- P1G disi dirty `vercel.json` degisiklikleri patch/commit icine karisiyorsa.
- Kullanici soru sistemi bu kapsama sokuluyorsa.
- Public root archive aktif edilmek isteniyorsa.
- DB migration veya `public_qa` modeli bu adima eklenmek isteniyorsa.

## L. P2A Deferred Scope Reminder

Kullanici soru sistemi P2A'da ele alinacak ayri deferred scope olarak kalir.

P2A kapsaminda detaylandirilacak kararlar:

- Oturum acma.
- Soru gonderme.
- Cevap takip.
- Admin/ekip cevaplama.
- Public arsive aday yapma.
- Kullanici soru yazdiginda once arsivde benzer cevaplari gosterme.
- Chatbot gibi gorunmeme.
- Kullanici sorularini sitemap disinda ve noindex tutma.
- Public arsive otomatik aktarim yapmama.

Bu P1G icinde:

- Kullanici soru sistemi kodlanmadi.
- Route eklenmedi.
- DB tablosu veya migration olusturulmadi.
- `public_qa` modeli kodlanmadi.

## Sonuc

P1G icin onerilen minimum cozum `vercel.json` icinde final catch-all'dan once explicit `/admin` ve `/admin/(.*)` static route'lari eklemek ve bu route'lara `X-Robots-Tag: noindex, nofollow` vermektir. Bu, `/api/*`, static asset route'lari ve root `/` davranisini degistirmeden Vercel tarafinda admin noindex/header parity hedefler. Patch artifact'i olusturuldu ancak gercek `vercel.json` dosyasina uygulanmadi; deploy/push/commit/staging yapilmadi.
