# Public Archive P1K Preview Candidate Preparation

Tarih: 2026-08-01
Durum: P1B + P1G + P1I preview candidate clean worktree preparation, deploy yok

## Kapsam

Bu dokuman P1B Express/runtime `/admin` patch'i, P1G Vercel `/admin` noindex route/header patch'i ve P1I check alignment patch'inin Vercel preview'a aday olabilecek temiz bir worktree uzerinde tekrar hazirlanip dogrulanmasini kaydeder.

Bu adimda production deploy yapilmadi, push yapilmadi, commit yapilmadi, staging/deployment yapilmadi, DB migration yapilmadi, DB'ye baglanilmadi, canli veri okunmadi/yazilmadi, feedback kapatilmadi, auth/session core degistirilmedi, admin business logic degistirilmedi, root `/` public arsive cevrilmedi, public root arsiv aktif edilmedi, kullanici soru sistemi kodlanmadi, `public_qa` migration/model olusturulmadi ve feedback fix kodlanmadi.

## A. Clean Worktree Method

Ana calisma agaci kirli oldugu icin destructive islem yapilmadi:

- `git reset` kullanilmadi.
- `git checkout` ile geri alma yapilmadi.
- `git clean` kullanilmadi.
- `git stash` kullanilmadi.
- Ana dirty dosyalar revert edilmedi.

Temiz preview candidate worktree su path'te olusturuldu:

```text
C:\Users\ugur\Desktop\arsiv-kontrol-p1k-preview-candidate
```

Worktree detached HEAD olarak su commit'ten olusturuldu:

```text
e6ee312ad601aef5743a56fa2e8d813dba1da458
```

Olusturma komutu:

```bash
git worktree add --detach C:\Users\ugur\Desktop\arsiv-kontrol-p1k-preview-candidate HEAD
```

Ilk clean worktree kontrolu:

```text
## HEAD (no branch)
```

Patch dosyalari ana workspace icinden absolute path ile kullanildi; cunku docs/patch artifact'leri ana workspace'te untracked durumdadir.

## B. Patch Apply Order

Patch'ler temiz preview candidate worktree icinde su sirayla uygulandi:

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

## C. Preview Candidate Changed Files

Uc patch uygulandiktan sonra preview candidate worktree `git diff --name-only` ciktisi:

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

`git diff -- render.yaml index.html sw.js manifest.webmanifest schema.sql package.json package-lock.json` ciktisi bostu.

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

## E. Vercel Route/Header Verification

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
ROUTE_HEADER_OK=true
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
- `/api/*` fallback'e dusecek route ordering riski gorulmedi.

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

- P1B-only state destekleniyor.
- P1B + P1G combined state otomatik fail olmuyor.
- Combined state strict route/header/order/dest kontrolu yapiyor.
- Partial veya malformed admin Vercel route state fail olur.
- Guard tamamen gevsetilmedi.
- P1H'de gorulen eski check hatasi `npm.cmd run check` sirasinda gorulmedi.

## G. Local Verification Results

### `git diff --check`

Temiz preview candidate worktree sonucu:

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

P1H'de gorulen eski check failure'i gorulmedi.

### Local HTTP Smoke Test

Local smoke test canli DB'ye baglanmadan yapildi.

Yontem:

- Express app ayni Node sureci icinde gecici localhost portunda calistirildi.
- `@supabase/supabase-js` module load asamasinda fake/stub client ile karsilandi.
- Gercek Supabase/canli DB baglantisi kurulmadı.
- Smoke test Node `http` modulu ile calistirildi ve exit code `0` verdi.

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

## H. Preview Smoke Requirement

Local Express smoke P1B runtime davranisini dogrular, fakat P1G Vercel preview/header parity icin yeterli degildir.

Neden:

- Local Express server `vercel.json` route matching motorunu birebir calistirmaz.
- Local `/admin` header'i Express `sendAdminIndex` helper'indan gelir.
- P1G'nin asil hedefi Vercel preview static route response'unda `/admin` noindex header'ini garanti etmektir.
- Bu garanti ancak gercek Vercel preview smoke ile network response header seviyesinde dogrulanabilir.

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

## I. Active Feedback Quality Track

8 acik feedback ayri QF1 kalite hattinda ele alinacak. Bu P1K icinde feedback fix yapilmadi, feedback kapatilmadi, DB'ye baglanilmadi ve canli veri okunmadi/yazilmadi.

QF1 kalite hattinda ele alinacak riskler:

- Kaynakta olmayan icerik ekleme.
- `Tevbe/Tovbe` sure baglami.
- `Yunus/Yunus` sure referansi tutarliligi.
- Ikinci denetimde farkli sonuc cikmasi.
- Cift virgul.
- Noktalama/idempotency sorunlari.

Bu kalite hatti public arsiv oncesi ayrica kapatilmalidir, fakat P1K preview candidate hattina karistirilmamalidir.

## J. P2A Deferred Scope Reminder

Kullanici soru sistemi P1K icinde uygulanmadi ve P2A deferred scope olarak kalir.

P2A karar notlari:

- Kullanicilar oturum acabilecek.
- Kullanicilar soru gonderebilecek.
- Kullanicilar kendi sorularini ve cevaplarini takip edebilecek.
- Ekip/admin arkada cevaplayabilecek.
- Uygun cevaplar public arsive aday yapilabilecek.
- Akis: kullanici sorusu -> ekip cevabi -> public arsive aday yap -> `public_qa` draft -> preview -> published.
- Kullanici soru yazdiginda once arsivde benzer cevaplar gosterilecek.
- Sistem chatbot gibi gorunmeyecek.
- Bu kapsam P1K icinde kodlanmayacak; P2A docs-only mimari adiminda ele alinacak.

## K. Go / No-Go Criteria

### Go

P1K preview candidate su kosullar saglandigi icin P1L Vercel preview deployment/smoke execution adimina hazir kabul edilebilir:

- 3 patch apply basarili.
- Diff yalniz `server.js`, `scripts/check-frontend.js`, `vercel.json`.
- `vercel.json` parse basarili.
- Route/header dogrulamasi basarili.
- `scripts/check-frontend.js` alignment dogru.
- `git diff --check` basarili.
- `npm.cmd run check` basarili.
- Local smoke basarili.
- Root `/` korunuyor.
- `/api/*` fallback'e dusmuyor.
- Public root aktif degil.

### No-Go

Asagidaki durumlardan biri olsaydi P1K No-Go olurdu:

- Patch apply fail.
- Diff beklenmeyen dosyalari iceriyor.
- `vercel.json` parse fail.
- Route order/header hatali.
- Check alignment hatali.
- `npm.cmd run check` fail.
- `/api/*` etkileniyor.
- Root `/` degisiyor.
- Static assets bozuluyor.
- Dirty ana workspace deploy edilmek isteniyor.
- Kullanici sistemi veya feedback fix bu kapsama sokuluyor.

## L. Next Recommended Step

Onerilen sira:

1. P1L Vercel preview deployment/smoke execution.
2. QF1 active feedback quality fix plan.
3. P2A user question intake architecture docs-only.
4. Public frontend MVP.

Gerekce:

- P1K preview candidate worktree, izole patch setinin deploy oncesi lokal kapilarini tekrar gecti.
- Kalan risk local Express degil, Vercel preview response seviyesinde `/admin` header parity'dir.
- Gercek preview smoke gecmeden 39 aktif kullaniciya pilot genisletme veya root public gecis planina gecilmemelidir.
- QF1 kalite hatti public arsiv oncesi onemlidir, fakat preview candidate route/header hattina karistirilmamalidir.
- P2A user question intake ve Public frontend MVP daha sonra ayri docs-only mimari adimlarla ilerlemelidir.

## Sonuc

P1K preview candidate worktree temiz HEAD `e6ee312ad601aef5743a56fa2e8d813dba1da458` uzerinden hazirlandi. P1B, P1G ve P1I patch'leri sirayla basariyla uygulandi. Diff yalniz `server.js`, `scripts/check-frontend.js` ve `vercel.json` dosyalarini icerdi. `vercel.json` parse ve route/header dogrulamasi basarili oldu. `scripts/check-frontend.js` alignment dogrulandi. `git diff --check`, `npm.cmd run check` ve local HTTP smoke test basarili oldu. Production deploy, push, commit, staging, DB migration, DB baglantisi, canli veri islemi, feedback kapatma, public root aktivasyonu veya kullanici soru sistemi uygulamasi yapilmadi.
