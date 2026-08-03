# Public Archive P1I-B Clean Three-Patch Verification

Tarih: 2026-08-01
Durum: P1B + P1G + P1I clean worktree verification, Go for preview/staging planning

## Kapsam

Bu dokuman P1B Express/runtime `/admin` patch'i, P1G Vercel `/admin` noindex route/header patch'i ve P1I check alignment patch'inin temiz worktree uzerinde birlikte uygulanabilirligini dogrular.

Bu adimda production deploy yapilmadi, push yapilmadi, commit yapilmadi, staging yapilmadi, DB migration yapilmadi, DB'ye baglanilmadi, canli veri okunmadi/yazilmadi, auth/session core degistirilmedi, admin business logic degistirilmedi, root `/` public arsive cevrilmedi, public root arsiv aktif edilmedi ve kullanici soru sistemi kodlanmadi.

## A. Clean Worktree Method

Ana calisma agaci kirli oldugu icin destructive islem yapilmadi:

- `git reset` kullanilmadi.
- `git checkout` ile geri alma yapilmadi.
- `git clean` kullanilmadi.
- `git stash` kullanilmadi.
- Ana dirty dosyalar revert edilmedi.

Temiz worktree su path'te olusturuldu:

```text
C:\Users\ugur\Desktop\arsiv-kontrol-p1i-b-clean
```

Worktree detached HEAD olarak su commit'ten olusturuldu:

```text
e6ee312ad601aef5743a56fa2e8d813dba1da458
```

Olusturma komutu:

```bash
git worktree add --detach C:\Users\ugur\Desktop\arsiv-kontrol-p1i-b-clean HEAD
```

Ilk clean worktree kontrolu:

```text
## HEAD (no branch)
```

Ana workspace path:

```text
C:\Users\ugur\Desktop\arsiv-kontrol
```

Patch dosyalari ana workspace icinden absolute path ile kullanildi; cunku docs/patch artifact'leri ana workspace'te untracked durumdadir.

## B. Patch Apply Order

Patch'ler temiz worktree icinde kullanicinin belirttigi sirayla uygulandi.

1. P1B Express/runtime patch:

```text
C:\Users\ugur\Desktop\arsiv-kontrol\docs\project\patches\PUBLIC_ARCHIVE_P1B_ONLY.patch
```

Sonuc:

```text
apply success
```

2. P1G Vercel noindex route/header patch:

```text
C:\Users\ugur\Desktop\arsiv-kontrol\docs\project\patches\PUBLIC_ARCHIVE_P1G_VERCEL_ADMIN_NOINDEX.patch
```

Sonuc:

```text
apply success
```

3. P1I check alignment patch:

```text
C:\Users\ugur\Desktop\arsiv-kontrol\docs\project\patches\PUBLIC_ARCHIVE_P1I_CHECK_FRONTEND_ALIGNMENT.patch
```

Sonuc:

```text
apply success
```

Patch apply asamasinda failure olmadi. Manuel edit veya fix denemesi yapilmadi.

## C. Changed Files After Patch

Uc patch uygulandiktan sonra temiz worktree `git diff --name-only` ciktisi:

```text
scripts/check-frontend.js
server.js
vercel.json
```

Beklenen dosya siniri saglandi:

- `server.js`: P1B Express/runtime `/admin` route hazirligi.
- `scripts/check-frontend.js`: P1B route safety kontrolleri ve P1I combined-state check alignment.
- `vercel.json`: P1G `/admin` noindex route/header patch'i.

Diff stat:

```text
scripts/check-frontend.js | 116 ++++++++++++++++++++++++++++++++++++++++++++++
server.js                 |  11 +++++
vercel.json               |  16 +++++++
3 files changed, 143 insertions(+)
```

## D. Files Confirmed Untouched

Asagidaki dosyalar patch sonrasi degismedi:

- `render.yaml`
- `index.html`
- `sw.js`
- `manifest.webmanifest`
- `schema.sql`
- `package.json`
- `package-lock.json`

`git diff -- package.json package-lock.json` ciktisi bostu. `npm.cmd ci` sonrasinda package veya lock dosyasi degismedi.

DB/schema/migration dosyalari degismedi:

- `schema.sql` degismedi.
- Migration dosyasi olusturulmadi.
- `public_qa` veya user question model dosyasi olusturulmadi.

Kapsam disi alanlar degismedi:

- Auth/session core icin ek dosya degisikligi yok.
- Admin business logic icin P1B disi yeni degisiklik yok.
- Public demo/build dosyalari degismedi.
- Root `/` public arsive cevrilmedi.
- Eski route kaldirma veya redirect eklenmedi.

Dependency notu:

- Clean worktree icinde `node_modules` yoktu.
- `package-lock.json` mevcut oldugu icin `npm.cmd ci` calistirildi.
- `npm.cmd ci` yalniz clean worktree dependency kurulumu icin kullanildi.
- `package.json` ve `package-lock.json` degismedi.

## E. Vercel Route Order Verification

Patched `vercel.json` JSON parse basarili oldu:

```text
vercel json parse ok
```

Route index kontrolu:

| Route | Index | Hedef | Header |
| --- | ---: | --- | --- |
| `/api/(.*)` | 1 | `/server.js` | yok |
| `/manifest.webmanifest` | 2 | `/manifest.webmanifest` | yok |
| `/sw.js` | 3 | `/sw.js` | yok |
| `/icons/(.*)` | 4 | `/icons/$1` | yok |
| `/favicon.ico` | 5 | `/icons/favicon.ico` | yok |
| `/admin` | 6 | `/index.html` | `X-Robots-Tag`, `Cache-Control` |
| `/admin/(.*)` | 7 | `/index.html` | `X-Robots-Tag`, `Cache-Control` |
| `/(.*)` | 8 | `/index.html` | yok |

Kontrol sonucu:

```text
ROUTE_ORDER_AND_HEADERS_OK=true
```

Dogrulanan siralama ve headerlar:

- `/api/(.*)` route'u `/admin` route'larindan once.
- `/manifest.webmanifest` route'u `/admin` route'larindan once.
- `/sw.js` route'u `/admin` route'larindan once.
- `/icons/(.*)` route'u `/admin` route'larindan once.
- `/favicon.ico` route'u `/admin` route'larindan once.
- `/admin` route'u final `/(.*)` catch-all'dan once.
- `/admin/(.*)` route'u final `/(.*)` catch-all'dan once.
- `/admin` route dest degeri `/index.html`.
- `/admin/(.*)` route dest degeri `/index.html`.
- `/admin` route header'inda `X-Robots-Tag: noindex, nofollow`.
- `/admin/(.*)` route header'inda `X-Robots-Tag: noindex, nofollow`.
- `/admin` route `Cache-Control` header'i `no-store`, `no-cache`, `must-revalidate`, `proxy-revalidate` token'larini iceriyor.
- `/admin/(.*)` route `Cache-Control` header'i ayni token'lari iceriyor.
- Final `/(.*)` catch-all hala `/index.html`.
- Root `/` davranisini degistiren ayri route eklenmedi.
- `/api/*` fallback'e dusecek bir route siralama hatasi gorulmedi.

## F. Check Alignment Verification

Patched `scripts/check-frontend.js` icinde yeni state mantigi bulundu.

Kontrol edilen markerlar:

- `routeIndex`
- `routeBySrc`
- `explicitRootRoutes`
- `adminVercelRoutes`
- `adminDeepVercelRoutes`
- `adminLikeVercelRoutes`
- `unexpectedAdminVercelRoutes`
- `Vercel admin route lari partial olmamali`
- `X-Robots-Tag`
- `Cache-Control`

Alignment sonucu:

- P1B-only state bozulmuyor; explicit `/admin` Vercel route yoksa otomatik fail yok.
- P1B + P1G combined state otomatik fail olmuyor.
- Combined state strict route/header/order/dest kontrolu yapiyor.
- Partial veya malformed admin Vercel route state fail olur.
- Guard tamamen gevsetilmedi; P1G uygulanmissa daha siki kontroller calisir.

P1H'de fail eden eski hata artik `npm.cmd run check` sirasinda gorulmedi:

```text
Error: P1B vercel.json icinde explicit /admin route eklememeli; bu ayri P1C adimidir.
```

## G. Verification Results

### `git diff --check`

Temiz worktree sonucu:

```text
success, exit code 0
```

Whitespace error gorulmedi.

### `npm.cmd ci`

Clean worktree dependency hazirligi:

```text
added 144 packages, and audited 145 packages
1 low severity vulnerability
multer@1.4.5-lts.2 deprecation warning
```

Bu sadece clean worktree dependency kurulumu icindir. Kaynak dosya veya lock dosyasi degistirmedi.

### `npm.cmd run check`

Sonuc:

```text
success, exit code 0
Frontend/PWA dogrulamasi: basarili
tests 79
pass 79
fail 0
```

Calisan script:

```text
node --check server.js && node scripts/check-frontend.js && node --test
```

P1H'deki eski check failure'i gorulmedi.

### JSON parse/config kontrolu

```text
vercel json parse ok
ROUTE_ORDER_AND_HEADERS_OK=true
```

### Local HTTP Smoke Test

Local smoke test canli DB'ye baglanmadan yapildi.

Yontem:

- Express app ayni Node sureci icinde gecici localhost portunda calistirildi.
- `@supabase/supabase-js` module load asamasinda fake/stub client ile karsilandi.
- Gercek Supabase/canli DB baglantisi kurulmadı.
- Ilk smoke denemesinde route cevaplari dogru alindi, ancak Node v24 `fetch` kapanisinda handle assertion verdi.
- Ayni smoke test Node `http` modulu ile tekrar calistirildi ve exit code `0` verdi.

Final smoke sonucu:

| Route | Status | Content-Type | X-Robots-Tag | Sonuc |
| --- | ---: | --- | --- | --- |
| `GET /` | 200 | `text/html; charset=UTF-8` | yok | Root legacy HTML shell korundu |
| `GET /admin` | 200 | `text/html; charset=UTF-8` | `noindex, nofollow` | Express admin route calisti |
| `GET /admin/` | 200 | `text/html; charset=UTF-8` | `noindex, nofollow` | Express admin route calisti |
| `GET /admin/smoke-test` | 200 | `text/html; charset=UTF-8` | `noindex, nofollow` | Deep path admin fallback calisti |
| `GET /api/auth/me` | 200 | `application/json; charset=utf-8` | yok | JSON dondu, HTML fallback'e dusmedi |
| `GET /manifest.webmanifest` | 200 | `application/manifest+json` | yok | Static manifest calisti |
| `GET /sw.js` | 200 | `application/javascript; charset=UTF-8` | yok | Static service worker calisti |
| `GET /favicon.ico` | 200 | `image/x-icon` | yok | Favicon calisti |

Smoke sonucu:

```text
success, exit code 0
```

## H. Root/Admin Behavior

Root `/` korundu:

- `GET /` 200 HTML dondurdu.
- Root response icinde `X-Robots-Tag` yoktu.
- Root public archive aktif edilmedi.
- Root route legacy shell davranisini koruyor.

Parallel `/admin` Express runtime calisti:

- `GET /admin` 200 HTML dondurdu.
- `GET /admin/` 200 HTML dondurdu.
- `GET /admin/smoke-test` 200 HTML dondurdu.
- Uc `/admin` response'u da `X-Robots-Tag: noindex, nofollow` aldi.

`/api/*` fallback'e dusmedi:

- `GET /api/auth/me` 200 JSON dondurdu.
- Response HTML degildi.
- Logged-out durumda `{"loggedIn":false}` davranisi korundu.

Static asset route'lari calisti:

- `/manifest.webmanifest`
- `/sw.js`
- `/favicon.ico`

## I. Vercel Preview Requirement

Local Express smoke P1B runtime davranisini dogrular, fakat P1G Vercel production/header parity icin yeterli degildir.

Neden:

- Local Express server `vercel.json` route matching motorunu birebir calistirmaz.
- Local `/admin` header'i Express `sendAdminIndex` helper'indan gelir.
- P1G'nin asil hedefi Vercel preview/production static route response'unda `/admin` noindex header'ini garanti etmektir.
- Bu garanti ancak Vercel preview/staging smoke ile network response header seviyesinde dogrulanabilir.

Sonraki preview kontrolleri:

- `GET /`
- `GET /admin`
- `GET /admin/`
- `GET /admin/smoke-test`
- `GET /api/auth/me`
- `GET /manifest.webmanifest`
- `GET /sw.js`
- `GET /favicon.ico`
- `/admin` response headers
- `/api/*` HTML fallback'e dusuyor mu
- root `/` legacy shell korunuyor mu

## J. P2A Deferred Scope Reminder

Kullanici soru sistemi P1I-B icinde uygulanmadi ve P2A deferred scope olarak kalir.

P2A karar notlari:

- Kullanicilar oturum acabilecek.
- Kullanicilar soru gonderebilecek.
- Kullanicilar kendi sorularini ve cevaplarini takip edebilecek.
- Ekip/admin arkada cevaplayabilecek.
- Uygun cevaplar public arsive aday yapilabilecek.
- Akis: kullanici sorusu -> ekip cevabi -> public arsive aday yap -> `public_qa` draft -> preview -> published.
- Kullanici soru yazdiginda once arsivde benzer cevaplar gosterilecek.
- Sistem chatbot gibi gorunmeyecek.
- Bu kapsam P1I-B icinde kodlanmayacak; P2A docs-only mimari adiminda ele alinacak.

## K. Go / No-Go Criteria

### Go

P1I-B sonucu asagidaki kosullar saglandigi icin P1J preview/staging smoke planina gecmek icin Go kabul edilebilir:

- 3 patch apply basarili.
- Diff yalniz `server.js`, `scripts/check-frontend.js`, `vercel.json`.
- `vercel.json` parse basarili.
- Route ordering dogru.
- `scripts/check-frontend.js` alignment dogru.
- `git diff --check` basarili.
- `npm.cmd run check` basarili.
- Local smoke basarili.
- Root `/` korunuyor.
- `/api/*` fallback'e dusmuyor.

### No-Go

Asagidaki durumlardan biri olsaydi P1I-B No-Go olurdu:

- Patch apply fail.
- Diff beklenmeyen dosyalari iceriyor.
- `vercel.json` parse fail.
- Route order hatali.
- Check alignment hatali.
- `npm.cmd run check` fail.
- `/api/*` etkileniyor.
- Root `/` degisiyor.
- Testler fail.
- Dirty ana workspace deploy edilmek isteniyor.

## L. Next Recommended Step

Onerilen siradaki guvenli adim: P1J Vercel preview/staging smoke planı.

Gerekce:

- P1I-B clean worktree dogrulamasi artik P1B + P1G + P1I combined patch setinin local ve static check seviyesinde temiz oldugunu gosterdi.
- Kalan ana risk local Express degil, Vercel preview/production route/header parity'dir.
- `/admin` production parity kapanmadan canli gecis veya 39 kullaniciya pilot genisletmesi yapilmamalidir.
- P2A user question intake architecture docs-only olarak daha sonra veya paralel planlanabilir, fakat admin route parity kapanmadan uygulama/DB koduna gecilmemelidir.

P1J icin beklenen kapsam:

- Deploy/push/production olmadan preview/staging smoke planini yazmak.
- Gerekirse ayrica onayli Vercel preview deploy adimini planlamak.
- Preview URL uzerinde `/`, `/admin`, `/admin/`, `/admin/smoke-test`, `/api/auth/me`, static asset route'lari ve `/admin` response header'larini dogrulamak.

## Sonuc

P1B, P1G ve P1I patch'leri temiz worktree uzerinde sirayla basariyla uygulandi. Diff yalniz `server.js`, `scripts/check-frontend.js` ve `vercel.json` dosyalarini icerdi. `vercel.json` parse ve route/header order dogrulamasi basarili oldu. `scripts/check-frontend.js` alignment dogrulandi. `git diff --check`, `npm.cmd run check` ve local HTTP smoke test basarili oldu. Production deploy, push, commit, staging, DB migration, DB baglantisi, canli veri islemi, public root aktivasyonu veya kullanici soru sistemi uygulamasi yapilmadi.
