# Public Archive P1H Clean Combined Patch Verification

Tarih: 2026-07-31
Durum: P1B + P1G combined patch clean worktree verification, No-Go due check guard conflict

## Kapsam

Bu dokuman P1B Express/runtime `/admin` patch'i ile P1G Vercel `/admin` noindex route/header patch'inin temiz worktree uzerinde birlikte uygulanabilirligini dogrular.

Bu adimda production deploy yapilmadi, push yapilmadi, commit yapilmadi, staging yapilmadi, DB migration yapilmadi, DB'ye baglanilmadi, canli veri okunmadi/yazilmadi, auth/session core degistirilmedi, admin business logic degistirilmedi, root `/` public archive'e cevrilmedi, public root archive aktif edilmedi ve kullanici soru sistemi kodlanmadi.

## A. Clean Worktree Method

Ana calisma agaci kirli oldugu icin destructive islem yapilmadi:

- `git reset` kullanilmadi.
- `git checkout` ile geri alma yapilmadi.
- `git clean` kullanilmadi.
- `git stash` kullanilmadi.
- Ana dirty dosyalar revert edilmedi.

Temiz worktree su path'te olusturuldu:

```text
C:\Users\ugur\Desktop\arsiv-kontrol-p1h-clean
```

Worktree detached HEAD olarak su commit'ten olusturuldu:

```text
e6ee312ad601aef5743a56fa2e8d813dba1da458
```

Olusturma komutu:

```bash
git worktree add --detach C:\Users\ugur\Desktop\arsiv-kontrol-p1h-clean HEAD
```

Ana workspace path:

```text
C:\Users\ugur\Desktop\arsiv-kontrol
```

Patch dosyalari ana workspace icinden absolute path ile kullanildi; cunku docs/patch artifact'leri ana workspace'te untracked durumdadir.

## B. Patch Apply Order

Patch'ler temiz worktree icinde sirayla uygulandi.

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

Patch apply asamasinda failure olmadi. Manuel edit veya fix denemesi yapilmadi.

## C. Changed Files After Patch

Patch'ler uygulandiktan sonra temiz worktree `git diff --name-only` ciktisi:

```text
scripts/check-frontend.js
server.js
vercel.json
```

Beklenen dosya siniri saglandi:

- `server.js`: P1B Express/runtime `/admin` route hazirligi.
- `scripts/check-frontend.js`: P1B route safety kontrolleri.
- `vercel.json`: P1G `/admin` noindex route/header patch'i.

Diff stat:

```text
scripts/check-frontend.js | 66 +++++++++++++++++++++++++++++++++++++++++++++++
server.js                 | 11 ++++++++
vercel.json               | 16 ++++++++++++
3 files changed, 93 insertions(+)
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

DB/schema/migration dosyalari degismedi:

- `schema.sql` degismedi.
- Migration dosyasi olusturulmadi.
- `public_qa` veya user question model dosyasi olusturulmadi.

Kapsam disi alanlar degismedi:

- Auth/session core icin ek dosya degisikligi yok.
- Admin business logic icin P1B disi yeni degisiklik yok.
- Public demo/build dosyalari degismedi.
- Root `/` public archive'e cevrilmedi.

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

| Route | Index | Hedef |
| --- | ---: | --- |
| `/api/(.*)` | 1 | `/server.js` |
| `/manifest.webmanifest` | 2 | `/manifest.webmanifest` |
| `/sw.js` | 3 | `/sw.js` |
| `/icons/(.*)` | 4 | `/icons/$1` |
| `/favicon.ico` | 5 | `/icons/favicon.ico` |
| `/admin` | 6 | `/index.html` |
| `/admin/(.*)` | 7 | `/index.html` |
| `/(.*)` | 8 | `/index.html` |

Kontrol sonucu:

```text
ROUTE_ORDER_OK=true
```

Dogrulanan siralama:

- `/api/(.*)` route'u `/admin` route'larindan once.
- `/manifest.webmanifest` route'u `/admin` route'larindan once.
- `/sw.js` route'u `/admin` route'larindan once.
- `/icons/(.*)` route'u `/admin` route'larindan once.
- `/favicon.ico` route'u `/admin` route'larindan once.
- `/admin` route'u final `/(.*)` catch-all'dan once.
- `/admin/(.*)` route'u final `/(.*)` catch-all'dan once.
- Final `/(.*)` catch-all hala `/index.html`.
- Root `/` davranisini degistiren ayri route eklenmedi.
- `/api/*` fallback'e dusecek bir route siralama hatasi gorulmedi.

Patched `vercel.json` P1G hunk'i:

```diff
+    {
+      "src": "/admin",
+      "headers": {
+        "X-Robots-Tag": "noindex, nofollow",
+        "Cache-Control": "no-store, no-cache, must-revalidate, proxy-revalidate"
+      },
+      "dest": "/index.html"
+    },
+    {
+      "src": "/admin/(.*)",
+      "headers": {
+        "X-Robots-Tag": "noindex, nofollow",
+        "Cache-Control": "no-store, no-cache, must-revalidate, proxy-revalidate"
+      },
+      "dest": "/index.html"
+    },
```

## F. Verification Results

### `git diff --check`

Sonuc:

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
failed, exit code 1
```

Komut:

```bash
npm.cmd run check
```

Calisan script:

```text
node --check server.js && node scripts/check-frontend.js && node --test
```

Failure noktasi:

```text
Error: P1B vercel.json icinde explicit /admin route eklememeli; bu ayri P1C adimidir.
    at assert (...\scripts\check-frontend.js:11:25)
    at Object.<anonymous> (...\scripts\check-frontend.js:116:1)
```

Yorum:

- `node --check server.js` asamasi gecti; zincir `scripts/check-frontend.js` asamasinda durdu.
- `node --test` asamasina gecilmedi.
- Failure P1B ve P1G patch'lerinin davranissal catismasindan degil, P1B safety check'inin eski kapsami korumasindan kaynaklaniyor.
- P1B check'i P1B sirasinda `vercel.json` icinde explicit `/admin` route olmamasini dogru sekilde enforce ediyordu.
- P1G ise artik bilincli olarak `vercel.json` icine explicit `/admin` ve `/admin/(.*)` route ekliyor.
- Bu nedenle combined P1B + P1G aday diff'i su haliyle No-Go kabul edilmelidir.
- Manuel fix veya check guncellemesi yapilmadi.

### Local HTTP Smoke Test

Local smoke test canli DB'ye baglanmadan yapildi.

Yontem:

- Express app ayni Node sureci icinde gecici localhost portunda calistirildi.
- `@supabase/supabase-js` module load asamasinda fake/stub client ile karsilandi.
- Gercek Supabase/canli DB baglantisi kurulmadi.
- Ilk smoke script kapanista Node v24 handle assertion verdi; route cevaplari alinmisti.
- Ayni smoke, daha sakin server close akisi ile tekrar calistirildi ve exit code `0` verdi.

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

## G. Root/Admin Behavior

Root `/` korundu:

- `GET /` 200 HTML dondurdu.
- Root response icinde `X-Robots-Tag` yoktu.
- Root public archive aktif edilmedi.
- Root route final legacy shell davranisini koruyor.

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

## H. Vercel Preview Requirement

Local Express smoke P1B runtime davranisini dogrular, fakat P1G Vercel production/header parity icin yeterli degildir.

Neden:

- Local Express server `vercel.json` route matching motorunu birebir calistirmaz.
- Local `/admin` header'i Express `sendAdminIndex` helper'indan gelir.
- P1G'nin asil hedefi Vercel production/preview static route response'unda `/admin` noindex header'ini garanti etmektir.
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

## I. P2A Deferred Scope Reminder

Kullanici soru sistemi P1H icinde uygulanmadi ve P2A deferred scope olarak kalir.

P2A karar notlari:

- Kullanicilar oturum acabilecek.
- Kullanicilar soru gonderebilecek.
- Kullanicilar kendi sorularini ve cevaplarini takip edebilecek.
- Ekip/admin arkada cevaplayabilecek.
- Uygun cevaplar public arsive aday yapilabilecek.
- Akis: kullanici sorusu -> ekip cevabi -> public arsive aday yap -> `public_qa` draft -> preview -> published.
- Kullanici soru yazdiginda once arsivde benzer cevaplar gosterilecek.
- Sistem chatbot gibi gorunmeyecek.
- Bu kapsam P1H icinde kodlanmayacak; P2A docs-only mimari adiminda ele alinacak.

## J. Go / No-Go Criteria

### Go

P1H combined patch ancak su kosullar saglaninca Go olur:

- Patch apply basarili.
- Diff yalniz `server.js`, `scripts/check-frontend.js`, `vercel.json`.
- `vercel.json` parse basarili.
- Route ordering dogru.
- `git diff --check` basarili.
- `npm.cmd run check` basarili.
- Local smoke basarili.
- Root `/` korunuyor.
- `/api/*` fallback'e dusmuyor.

### Current P1H Result

Mevcut P1H sonucu:

```text
No-Go
```

No-Go sebebi:

- `npm.cmd run check` fail etti.
- Failure nedeni `scripts/check-frontend.js` icindeki P1B guard'inin P1G ile uyumsuz kalmasidir:

```text
P1B vercel.json icinde explicit /admin route eklememeli; bu ayri P1C adimidir.
```

Basarili olan kontroller:

- P1B patch apply basarili.
- P1G patch apply basarili.
- Diff yalniz beklenen uc dosya.
- `vercel.json` parse basarili.
- Route ordering dogru.
- `git diff --check` basarili.
- Local Express smoke basarili.

Fail olan kontrol:

- `npm.cmd run check`.

Manuel fix yapilmadi. P1H sonucunda combined patch preview/staging icin henuz Go degildir.

### No-Go

Asagidaki durumlardan biri varsa combined patch ilerletilmemelidir:

- Patch apply fail.
- Diff beklenmeyen dosyalari iceriyor.
- `vercel.json` parse fail.
- Route order hatali.
- `/api/*` etkileniyor.
- Root `/` degisiyor.
- Testler fail.
- Dirty ana workspace deploy edilmek isteniyor.
- `scripts/check-frontend.js` P1G sonrasi route beklentisini tanimadan preview/staging'e cikilmak isteniyor.

## K. Next Recommended Step

Onerilen siradaki guvenli adim: P1I-A combined check alignment docs/patch plan.

Gerekce:

- P1H, P1B + P1G patch'lerinin uygulanabilir oldugunu ve route davranisinin dogru siralandigini gosterdi.
- Ancak P1B check guard'i P1G sonrasinda eski kuralda kaliyor.
- Bu nedenle preview/staging smoke'a gecmeden once `scripts/check-frontend.js` kontrol kapsami P1G'yi taniyacak sekilde planlanmali.
- Bu plan, P1B-only durumunda "vercel.json admin route olmamali" guard'ini koruyup P1G combined durumda "vercel.json admin route olmali ve dogru sirada olmali" guard'ina gecis stratejisini netlestirmeli.
- Kod degisikligi yine ayri onayla ve temiz patch olarak yapilmali.

Sonraki iki secenek:

1. P1I-A combined check alignment docs/patch plan.
2. P1I-B Vercel preview/staging smoke plan.

Oncelik:

- Once P1I-A onerilir, cunku `npm.cmd run check` fail eden bir combined patch ile preview/staging'e gecmek dogru degildir.
- P2A user question intake architecture docs-only olarak daha sonra veya paralel planlanabilir, fakat admin route parity kapanmadan uygulama/DB koduna gecilmemelidir.

## Sonuc

P1B ve P1G patch'leri temiz worktree uzerinde sirayla basariyla uygulandi. Diff yalniz `server.js`, `scripts/check-frontend.js` ve `vercel.json` dosyalarini icerdi. `vercel.json` parse ve route order dogrulamasi basarili oldu. `git diff --check` basarili oldu. Local Express smoke test basarili oldu ve root `/`, `/admin`, `/api/auth/me`, manifest, service worker ve favicon route'lari beklenen response'lari verdi.

Ancak `npm.cmd run check` fail etti. Failure, P1B check script'inin P1G ile bilincli olarak eklenen explicit `/admin` Vercel route'larini hala yasaklamasindan kaynaklaniyor. Bu nedenle P1H current result No-Go'dur. Deploy, push, commit, staging, DB migration, DB baglantisi, canli veri islemi, public root aktivasyonu veya kullanici soru sistemi uygulamasi yapilmadi.
