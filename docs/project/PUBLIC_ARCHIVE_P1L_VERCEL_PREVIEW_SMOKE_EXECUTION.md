# Public Archive P1L Vercel Preview Smoke Execution

Tarih: 2026-08-01

Durum: Vercel preview olusturuldu. `/admin` header parity smoke gecti. Genel karar
No-Go; preview API runtime `SESSION_SECRET` eksikligi nedeniyle `/api/auth/me` icin
500 dondu.

Kapsam kilidi:
- Bu adim production deploy degildir.
- Production alias verilmedi.
- `arsiv.ibrahimlive.ai` production davranisina dokunulmadi.
- Root `/` public arsive cevrilmedi.
- DB migration yapilmadi.
- DB'ye baglanilmadi ve canli veri okunmadi/yazilmadi.
- Feedback konusu P1L kapsami disinda tutuldu; feedback okunmadi, islenmedi,
  kapatilmadi veya yeni bir kalite hatti acilmadi.
- Kullanici soru sistemi kodlanmadi; P2A deferred scope olarak kaldi.

## A. Preview Candidate Source

Kullanilan temiz preview candidate worktree:

```text
C:\Users\ugur\Desktop\arsiv-kontrol-p1k-preview-candidate
```

Worktree commit:

```text
e6ee312ad601aef5743a56fa2e8d813dba1da458
```

Preview candidate patch seti:

1. `docs/project/patches/PUBLIC_ARCHIVE_P1B_ONLY.patch`
2. `docs/project/patches/PUBLIC_ARCHIVE_P1G_VERCEL_ADMIN_NOINDEX.patch`
3. `docs/project/patches/PUBLIC_ARCHIVE_P1I_CHECK_FRONTEND_ALIGNMENT.patch`

Patch seti sonrasi beklenen ve dogrulanan diff siniri yalniz su dosyalardi:

```text
scripts/check-frontend.js
server.js
vercel.json
```

Preview adayina `index.html`, `sw.js`, `manifest.webmanifest`, `render.yaml`,
`schema.sql`, `package.json`, `package-lock.json`, DB/schema/migration dosyalari,
auth/session core, admin business logic veya public demo/build dosyalari karismadi.

## B. Pre-Preview Local Gates

Preview deploy denenmeden once temiz worktree uzerinde lokal kapilar tekrar calisti.

| Kontrol | Sonuc |
| --- | --- |
| `git diff --name-only` | Basarili; yalniz `scripts/check-frontend.js`, `server.js`, `vercel.json` |
| `git diff --check` | Basarili; whitespace hatasi yok |
| `vercel.json` JSON parse | Basarili |
| `vercel.json` route/header order | Basarili; `ROUTE_HEADER_OK=true` |
| `npm.cmd run check` | Basarili; 79 pass, 0 fail |

Route/header order ozeti:

| Route | Index |
| --- | ---: |
| `/api/(.*)` | 1 |
| `/manifest.webmanifest` | 2 |
| `/sw.js` | 3 |
| `/icons/(.*)` | 4 |
| `/favicon.ico` | 5 |
| `/admin` | 6 |
| `/admin/(.*)` | 7 |
| `/(.*)` final catch-all | 8 |

Dogulanan kritik noktalar:
- `/api/(.*)` admin route'larindan once kaldi.
- Static asset route'lari admin route'larindan once kaldi.
- `/admin` ve `/admin/(.*)` final catch-all'dan once kaldi.
- Iki admin route'unun `dest` degeri `/index.html`.
- Iki admin route'unda `X-Robots-Tag: noindex, nofollow` var.
- Iki admin route'unda `Cache-Control` icinde `no-store`, `no-cache`,
  `must-revalidate`, `proxy-revalidate` var.
- Final catch-all halen `/index.html`.
- Root `/` davranisini degistiren ekstra route yok.

## C. Preview Deployment Method

Vercel CLI ile production olmayan preview deployment olusturuldu.

Kullanilan yontem:
- CLI: `vercel.cmd`
- `--prod` kullanilmadi.
- Production alias verilmedi.
- Push yapilmadi.
- Commit yapilmadi.
- Staging veya production promote islemi yapilmadi.

P1K worktree icinde `.vercel/project.json` bulunmadigi icin mevcut Vercel proje
kimlikleri ortam degiskeni olarak verildi:

```text
VERCEL_ORG_ID=team_bI6Hmzu66dIGVXeUSUa1aAcJ
VERCEL_PROJECT_ID=prj_7lUegiN6Nyu0ey81tI1fbtnmrvoj
```

Olusturulan preview deployment:

```text
Deployment ID: dpl_CvwQxCWehpo94Zw9jQ8RqkYNjDit
Preview URL: https://arsiv-kontrol-5tr08bh1p-ugurkarabulutts-projects.vercel.app
Inspector: https://vercel.com/ugurkarabulutts-projects/arsiv-kontrol/CvwQxCWehpo94Zw9jQ8RqkYNjDit
Target: preview
Status: Ready
```

Production deploy yapilmadi ve `arsiv.ibrahimlive.ai` alias'i degistirilmedi.

## D. Vercel Preview Smoke Results

Preview URL:

```text
https://arsiv-kontrol-5tr08bh1p-ugurkarabulutts-projects.vercel.app
```

| Path | Status | Content-Type | Expected Header | Actual Header | Sonuc |
| --- | ---: | --- | --- | --- | --- |
| `/` | 200 | `text/html; charset=utf-8` | Root legacy HTML | `X-Robots-Tag: noindex` preview global header | Pass |
| `/admin` | 200 | `text/html; charset=utf-8` | `X-Robots-Tag: noindex, nofollow`; strict no-cache | `X-Robots-Tag: noindex, nofollow`; `Cache-Control: no-store, no-cache, must-revalidate, proxy-revalidate` | Pass |
| `/admin/` | 200 | `text/html; charset=utf-8` | `X-Robots-Tag: noindex, nofollow`; strict no-cache | `X-Robots-Tag: noindex, nofollow`; `Cache-Control: no-store, no-cache, must-revalidate, proxy-revalidate` | Pass |
| `/admin/smoke-test` | 200 | `text/html; charset=utf-8` | `X-Robots-Tag: noindex, nofollow`; strict no-cache | `X-Robots-Tag: noindex, nofollow`; `Cache-Control: no-store, no-cache, must-revalidate, proxy-revalidate` | Pass |
| `/api/auth/me` | 500 | `text/plain; charset=utf-8` | JSON veya non-HTML auth response; index fallback degil | `FUNCTION_INVOCATION_FAILED`; HTML fallback degil | Fail |
| `/manifest.webmanifest` | 200 | `application/manifest+json; charset=utf-8` | Manifest icerigi korunmali | Manifest icerigi dondu; preview global `X-Robots-Tag: noindex` var | Pass |
| `/sw.js` | 200 | `application/javascript; charset=utf-8` | JS icerigi korunmali | JS icerigi dondu; preview global `X-Robots-Tag: noindex` var | Pass |
| `/favicon.ico` | 200 | `image/vnd.microsoft.icon` | ICO/binary icerik korunmali | 3481 byte ICO dondu; preview global `X-Robots-Tag: noindex` var | Pass |

Not: Vercel preview ortaminda root ve static asset response'larinda global
`X-Robots-Tag: noindex` goruldu. Bu durum `/admin` icin hedeflenen
`noindex, nofollow` header'inin gectigi gercegini degistirmiyor; ancak root/static
header beklentisi production ile birebir ayni kabul edilmemeli.

## E. /admin Header Parity Result

`/admin`, `/admin/` ve `/admin/smoke-test` Vercel preview'da beklenen HTML shell'i
dondu.

Header sonucu:
- `X-Robots-Tag: noindex, nofollow` gorundu.
- `Cache-Control: no-store, no-cache, must-revalidate, proxy-revalidate` gorundu.
- `Content-Type: text/html; charset=utf-8` gorundu.

Sonuc: `/admin` Vercel route/header parity hedefi preview'da gecti.

## F. /api Fallback Result

`/api/auth/me` HTML fallback'e dusmedi; `index.html` donmedi.

Ancak API smoke basarili kabul edilemez:

```text
Status: 500
Content-Type: text/plain; charset=utf-8
Body: A server error has occurred / FUNCTION_INVOCATION_FAILED
```

Vercel log sonucu:

```text
Error: SESSION_SECRET Vercel ortaminda zorunludur.
```

Yorum:
- Route ordering acisindan `/api/auth/me` HTML fallback'e dusmedi.
- Preview runtime environment hazir degil; `SESSION_SECRET` eksikligi nedeniyle
  server function ayaga kalkamadi.
- Bu nedenle P1L genel karari Go degil.
- Production'a gecis veya pilot, preview API runtime env netlesmeden yapilmamali.

## G. Root Legacy Result

`GET /` 200 HTML dondu ve legacy ekip/admin shell korunmus gorundu.

Root HTML marker kontrolu:
- Public archive demo marker'i gorulmedi.
- Public archive ana sayfasi aktif gorulmedi.
- Login/admin shell marker'i goruldu.

Sonuc: Root `/` public arsive cevrilmedi.

## H. Static Asset Result

Static asset route'lari preview smoke'da 200 dondu.

| Path | Status | Content-Type | Sonuc |
| --- | ---: | --- | --- |
| `/manifest.webmanifest` | 200 | `application/manifest+json; charset=utf-8` | Pass |
| `/sw.js` | 200 | `application/javascript; charset=utf-8` | Pass |
| `/favicon.ico` | 200 | `image/vnd.microsoft.icon` | Pass |

`/icons/*` route'u P1L smoke listesinde dogrudan cagrilmadi; ancak `vercel.json`
route order kontrolunde `/icons/(.*)` static route'unun admin route'larindan once
kaldigi dogrulandi.

## I. Go / No-Go

Genel karar: No-Go.

Gecen kontroller:
- Preview deployment olusturuldu.
- Patch seti izole kaldı.
- Root `/` legacy shell olarak korundu.
- `/admin`, `/admin/`, `/admin/smoke-test` 200 HTML dondu.
- `/admin` response'larinda `X-Robots-Tag: noindex, nofollow` gorundu.
- `/admin` response'larinda strict `Cache-Control` gorundu.
- `/api/auth/me` HTML fallback'e dusmedi.
- Static asset route'lari 200 dondu.
- Production deploy yapilmadi.
- Production alias verilmedi.

No-Go sebebi:
- `/api/auth/me` preview ortaminda 500 dondu.
- Vercel loglarinda `SESSION_SECRET` eksikligi goruldu.
- Bu, preview ortaminda admin/auth runtime'in henuz dogrulanamadigi anlamina gelir.

Production icin sonuc:
- Bu preview deployment production'a promote edilmemeli.
- 39 kisilik ekibe `/admin` pilotu baslatilmamali.
- Production icin ayrica acik onay gerekir.

## J. Next Recommended Step

Bir sonraki guvenli adim: P1L-fix Preview Env Readiness Plan.

Onerilen siralama:

1. Preview ortaminda gerekli runtime environment degiskenlerinin durumunu sadece
   onayli ve kontrollu bir adimda netlestir.
2. `SESSION_SECRET` eksikligi giderilmeden yeni preview smoke Go kabul edilmesin.
3. Gerekli env hazirligi tamamlandiktan sonra ayni izole patch setiyle yeniden
   preview deployment olusturulsun.
4. `/`, `/admin`, `/admin/`, `/admin/smoke-test`, `/api/auth/me`,
   `/manifest.webmanifest`, `/sw.js`, `/favicon.ico` smoke matrisi tekrar calissin.
5. P1M limited admin pilot ancak preview API smoke da gectikten sonra planlansin.

P2A deferred scope:
- Kullanici oturum acma, soru gonderme, kendi sorularini ve cevaplarini takip etme,
  ekip/admin cevaplama, public arsive aday yapma ve once benzer arsiv cevaplarini
  gosterme akisi P1L icinde uygulanmadi.
- Sistem chatbot gibi gorunmeyecek karari korunur.
- Bu kapsam P2A docs-only mimari adiminda ele alinmali.
