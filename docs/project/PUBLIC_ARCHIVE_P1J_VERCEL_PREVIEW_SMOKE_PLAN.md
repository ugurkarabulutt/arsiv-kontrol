# Public Archive P1J Vercel Preview Smoke Plan

Tarih: 2026-08-01
Durum: Vercel preview/staging smoke plan, docs-only

## Kapsam

Bu dokuman P1B + P1G + P1I patch setinin Vercel preview/staging ortaminda nasil dogrulanacagini planlar. Bu adimda kod yazilmadi, patch uygulanmadi, DB migration yapilmadi, DB'ye baglanilmadi, canli veri okunmadi/yazilmadi, feedback kapatilmadi, deploy/push/commit/staging yapilmadi, root `/` public arsive cevrilmedi ve kullanici soru sistemi kodlanmadi.

## A. Current State Summary

P1I-B temiz worktree dogrulamasi tamamlandi.

P1I-B sonucu:

- Uc patch temiz worktree uzerinde sirayla basariyla uygulandi.
- Manuel fix/edit yapilmadi.
- Diff yalniz `server.js`, `scripts/check-frontend.js`, `vercel.json` dosyalarini icerdi.
- `vercel.json` parse basarili oldu.
- Route/header kontrolu basarili oldu.
- `/api/(.*)` index `1`, `/admin` index `6`, `/admin/(.*)` index `7`, final `/(.*)` index `8`.
- `/admin` ve `/admin/(.*)` dest degeri `/index.html`.
- `/admin` ve `/admin/(.*)` header'larinda `X-Robots-Tag: noindex, nofollow` var.
- `Cache-Control` header'inda `no-store`, `no-cache`, `must-revalidate`, `proxy-revalidate` var.
- Root `/` davranisini degistiren ekstra route yok.
- `/api/*` fallback'e dusecek route ordering riski gorulmedi.
- `scripts/check-frontend.js` P1B-only ve P1B + P1G combined state'i destekliyor.
- `npm.cmd run check` basarili oldu.
- Test sonucu: `79 pass`, `0 fail`.
- Local smoke test basarili oldu.

Net durum:

- Local/clean patch dogrulama tamam.
- Kalan risk Vercel preview/staging route/header parity.
- Production deploy hala yok.
- Root `/` hala public yapilmayacak.
- Public root arsiv bu hatta aktif edilmeyecek.

## B. Preview Candidate Patch Set

Preview/staging adayi yalniz su uc patch'ten olusmalidir:

1. `docs/project/patches/PUBLIC_ARCHIVE_P1B_ONLY.patch`
2. `docs/project/patches/PUBLIC_ARCHIVE_P1G_VERCEL_ADMIN_NOINDEX.patch`
3. `docs/project/patches/PUBLIC_ARCHIVE_P1I_CHECK_FRONTEND_ALIGNMENT.patch`

Bu patch seti disindaki dirty/unrelated degisiklikler preview/staging'e karismamalidir.

Clean branch/worktree requirement:

- Preview adayi temiz branch veya temiz git worktree uzerinde hazirlanmali.
- Ana dirty workspace oldugu gibi deploy edilmemeli.
- Patch'ler yukaridaki sira ile uygulanmali.
- Patch apply sonrasi manuel fix/edit yapilmamali; apply failure olursa No-Go yazilmali.

Expected changed files:

- `server.js`
- `scripts/check-frontend.js`
- `vercel.json`

Not allowed files:

- `index.html`
- `sw.js`
- `manifest.webmanifest`
- `render.yaml`
- `schema.sql`
- `package.json`
- `package-lock.json`
- DB/schema/migration dosyalari
- auth/session core dosyalari
- admin business logic dosyalari
- public demo/build dosyalari

Bu sinir bozulursa preview/staging No-Go olmalidir.

## C. Local Gates Before Preview

Preview/staging deploy ancak su lokal kapilar gectikten sonra dusunulebilir.

Patch/diff kapisi:

- `git diff --name-only` yalniz beklenen uc dosyayi gostermeli:
  - `server.js`
  - `scripts/check-frontend.js`
  - `vercel.json`
- `git status --short` beklenmeyen tracked veya untracked dosya gostermemeli.
- `package.json` ve `package-lock.json` diff'i bos olmali.

Config kapisi:

- `vercel.json` JSON parse gecmeli.
- `/api/(.*)` route'u `/admin` route'larindan once kalmali.
- `/manifest.webmanifest`, `/sw.js`, `/icons/(.*)`, `/favicon.ico` route'lari `/admin` route'larindan once kalmali.
- `/admin` ve `/admin/(.*)` final `/(.*)` catch-all'dan once kalmali.
- `/admin` ve `/admin/(.*)` dest degeri `/index.html` olmali.
- `/admin` ve `/admin/(.*)` `X-Robots-Tag: noindex, nofollow` almali.
- `/admin` ve `/admin/(.*)` `Cache-Control` icinde `no-store`, `no-cache`, `must-revalidate`, `proxy-revalidate` token'larini tasimali.
- Final `/(.*)` catch-all hala `/index.html` olmali.
- Root `/` davranisini degistiren explicit route eklenmemeli.

Check kapisi:

```bash
git diff --check
npm.cmd run check
```

Beklenen:

- `git diff --check` whitespace hatasi vermemeli.
- `npm.cmd run check` basarili olmali.
- P1H'deki eski check hatasi gorulmemeli:

```text
P1B vercel.json icinde explicit /admin route eklememeli; bu ayri P1C adimidir.
```

Local smoke kapisi:

- `GET /`
- `GET /admin`
- `GET /admin/`
- `GET /admin/smoke-test`
- `GET /api/auth/me`
- `GET /manifest.webmanifest`
- `GET /sw.js`
- `GET /favicon.ico`

Beklenen:

- Root `/` 200 HTML ve legacy shell.
- `/admin`, `/admin/`, `/admin/smoke-test` 200 HTML ve Express local `X-Robots-Tag`.
- `/api/auth/me` JSON, HTML fallback degil.
- Static asset route'lari 200.
- Public root arsiv aktif degil.

## D. Vercel Preview Smoke Matrix

Preview URL olustuktan sonra asagidaki HTTP smoke matrisi calistirilmalidir.

| Route | Expected status | Expected content | Expected headers | No-Go belirtisi |
| --- | ---: | --- | --- | --- |
| `GET /` | 200 | HTML, legacy admin shell | Admin noindex header beklenmez | Public archive ana sayfasi gorunurse veya root degisirse |
| `GET /admin` | 200 | HTML | `X-Robots-Tag: noindex, nofollow`; `Cache-Control` no-store/no-cache/must-revalidate/proxy-revalidate | Header eksikse veya HTML degilse |
| `GET /admin/` | 200 | HTML | `X-Robots-Tag: noindex, nofollow`; `Cache-Control` no-store/no-cache/must-revalidate/proxy-revalidate | Header eksikse veya HTML degilse |
| `GET /admin/smoke-test` | 200 | HTML | `X-Robots-Tag: noindex, nofollow`; `Cache-Control` no-store/no-cache/must-revalidate/proxy-revalidate | Header eksikse, 404/blank ise veya HTML degilse |
| `GET /api/auth/me` | 200, 401 veya 403 kabul edilebilir | JSON veya non-HTML auth response | HTML header beklenmez | `index.html` veya HTML fallback donerse |
| `GET /manifest.webmanifest` | 200 | Manifest JSON benzeri icerik | Static route korunmali | 404, HTML fallback veya bozuk content |
| `GET /sw.js` | 200 | JavaScript | Static route korunmali | 404, HTML fallback veya bozuk content |
| `GET /favicon.ico` | 200 | Binary/ICO content | Static route korunmali | 404, HTML fallback veya text/html |

Route bazli net beklentiler:

`GET /`:

- 200 HTML donmeli.
- Root legacy admin shell korunmali.
- Public archive ana sayfasi gorunmemeli.
- Root `/` public arsive donusmemis olmali.

`GET /admin`, `GET /admin/`, `GET /admin/smoke-test`:

- 200 HTML donmeli.
- `X-Robots-Tag: noindex, nofollow` gorunmeli.
- `Cache-Control` icinde `no-store`, `no-cache`, `must-revalidate`, `proxy-revalidate` gorunmeli.
- Browser refresh ve deep link HTML shell almali.

`GET /api/auth/me`:

- JSON veya non-HTML auth response donmeli.
- 200, 401 veya 403 auth durumuna gore kabul edilebilir.
- `Content-Type` HTML olmamali.
- `index.html` donmemeli.

Static asset routes:

- `/manifest.webmanifest` manifest content type veya JSON benzeri icerik korumali.
- `/sw.js` JS content korumali.
- `/favicon.ico` binary/ico content korumali.

## E. Header Verification Commands

PowerShell ornekleri:

```powershell
$PREVIEW = "https://preview-url.example"
Invoke-WebRequest -Uri "$PREVIEW/" -Method Head
Invoke-WebRequest -Uri "$PREVIEW/admin" -Method Head
Invoke-WebRequest -Uri "$PREVIEW/admin/" -Method Head
Invoke-WebRequest -Uri "$PREVIEW/admin/smoke-test" -Method Head
Invoke-WebRequest -Uri "$PREVIEW/api/auth/me"
Invoke-WebRequest -Uri "$PREVIEW/manifest.webmanifest" -Method Head
Invoke-WebRequest -Uri "$PREVIEW/sw.js" -Method Head
Invoke-WebRequest -Uri "$PREVIEW/favicon.ico" -Method Head
```

PowerShell header odakli ornek:

```powershell
$paths = @("/", "/admin", "/admin/", "/admin/smoke-test", "/api/auth/me", "/manifest.webmanifest", "/sw.js", "/favicon.ico")
foreach ($path in $paths) {
  $response = Invoke-WebRequest -Uri "$PREVIEW$path" -Method Get -MaximumRedirection 0 -SkipHttpErrorCheck
  [PSCustomObject]@{
    Path = $path
    Status = [int]$response.StatusCode
    ContentType = $response.Headers["Content-Type"]
    Robots = $response.Headers["X-Robots-Tag"]
    CacheControl = $response.Headers["Cache-Control"]
    IsHtml = $response.Content -like "*<html*"
  }
}
```

curl ornekleri:

```bash
curl -I "$PREVIEW/"
curl -I "$PREVIEW/admin"
curl -I "$PREVIEW/admin/"
curl -I "$PREVIEW/admin/smoke-test"
curl -i "$PREVIEW/api/auth/me"
curl -I "$PREVIEW/manifest.webmanifest"
curl -I "$PREVIEW/sw.js"
curl -I "$PREVIEW/favicon.ico"
```

Headerlarda aranacaklar:

- `/admin`, `/admin/`, `/admin/smoke-test` icin `X-Robots-Tag: noindex, nofollow`.
- `/admin`, `/admin/`, `/admin/smoke-test` icin `Cache-Control` icinde `no-store`, `no-cache`, `must-revalidate`, `proxy-revalidate`.
- `/admin` route'lari icin HTML content type.
- `/api/auth/me` icin JSON veya non-HTML content type.
- `/api/auth/me` response'u `index.html` olmamali.

## F. Admin Pilot Role Smoke Plan

Preview/staging smoke basarili olsa bile 39 kisilik ekibe acilmadan once kucuk pilot gerekir.

Pilot kullanici tipleri:

- 1 super admin.
- 1 admin.
- 1 normal ekip kullanicisi.
- 1 mobil kullanici.

Pilot test listesi:

- `/admin` login.
- Logout.
- Session refresh.
- Normal kullanici paneli.
- Admin paneli.
- Super admin paneli.
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
- Sayfa refresh.
- Mobil giris.
- `/admin` deep link.
- Asset path.
- API calls.
- Root `/` eski davranis.

Pilot kabul kriteri:

- Tum roller `/admin` altinda kendi beklenen ekranina ulasir.
- Login/logout/session davranisi root legacy akistan farkli kirilma gostermez.
- Normal ekip kullanicisi admin-only ekranlara erisemez.
- Admin ve super admin yetkileri mevcut sinirlari korur.
- Onay/red/feedback/bildirim/standart/rapor akislari preview ortaminda regressionsiz calisir.
- Root `/` legacy adresi pilot boyunca korunur.

## G. Rollback Plan

Preview rollback:

- Production deploy yapilmadigi surece rollback preview branch/worktree atma ile sinirli kalir.
- Preview candidate branch veya worktree silinebilir ya da terk edilebilir.
- Ana dirty workspace'e geri alma islemi uygulanmamalidir.

Patch seti uc dosyayla sinirlidir:

- `server.js`
- `scripts/check-frontend.js`
- `vercel.json`

Patch bazli rollback:

- P1G `vercel.json` patch'i ayri geri alinabilir.
  - `/admin` ve `/admin/(.*)` Vercel route/header hunk'i kaldirilir.
  - Root `/`, `/api/*` ve static asset route'lari eski davranisa doner.
- P1I check alignment ayri geri alinabilir.
  - Yalniz `scripts/check-frontend.js` check mantigi etkilenir.
  - Runtime veya Vercel route davranisi degismez.
- P1B server route ayri geri alinabilir.
  - `ADMIN_PARALLEL_ROUTE_ENABLED`, `sendAdminIndex`, `/admin`, `/admin/`, `/admin/*` Express runtime route'lari kaldirilir.
  - Root legacy fallback eski halini korur.

Production rollback:

- Bu P1J adiminda production deploy yoktur.
- Production'a gecis icin ayrica explicit approval gerekir.
- Production'da sorun cikarsa rollback plani, onayli deploy artifact veya commit revert uzerinden ayrica yurutulmelidir.
- DB rollback gerekmez; bu patch seti DB/migration icermez.

Rollback tetikleyicileri:

- `/admin` header'lari preview'da gorunmezse.
- `/admin/` veya `/admin/smoke-test` 404/blank/HTML olmayan response donerse.
- `/api/auth/me` HTML fallback'e duserse.
- Root `/` public arsive donerse.
- Static asset route'lari bozulursa.
- Pilot kullanicilarda login/session loop gorulurse.

## H. Go / No-Go Criteria

### Go

P1J sonrasinda P1K preview candidate hazirligina su kosullarda gecilebilir:

- Clean patch set diff yalniz uc dosya:
  - `server.js`
  - `scripts/check-frontend.js`
  - `vercel.json`
- Local check'ler gecer:
  - `vercel.json` parse.
  - route/header order.
  - `git diff --check`.
  - `npm.cmd run check`.
  - local smoke.
- Vercel preview deploy yalniz izole patch setinden olusur.
- `GET /` legacy shell dondurur.
- `GET /admin` header'lari dogru.
- `GET /admin/*` header'lari dogru.
- `GET /api/auth/me` HTML fallback degil.
- Static assets saglam.
- Pilot plan hazir.
- Rollback plan hazir.

### No-Go

Asagidaki durumlardan biri varsa preview/staging veya production'a gecilmemelidir:

- Dirty ana workspace deploy edilmek istenirse.
- Patch setine unrelated degisiklik karisirsa.
- `/admin` header gorunmezse.
- `/admin/` veya `/admin/smoke-test` header gorunmezse.
- `/api/auth/me` `index.html` dondururse.
- Root `/` public arsive donerse.
- Static asset route'lari bozulursa.
- Pilot kullanici/test penceresi net degilse.
- Kullanici soru sistemi veya public root bu kapsama alinirsa.
- DB migration veya feedback fix bu hatta karistirilmak istenirse.

## I. Active Feedback Quality Risk Note

Canli Supabase'de 8 acik feedback oldugu notu ayri kalite hatti olarak kayda alindi. Bu P1J icinde DB'ye baglanilmadi, canli veri okunmadi/yazilmadi, feedback kapatilmadi ve feedback fix kodlanmadi.

Bu kalite hattinin sonraki ayri onerisi:

```text
QF1 - Active Feedback Quality Fix Plan
```

QF1 oncelikleri:

1. Kaynakta olmayan icerik ekleme kesinlikle engellenmeli.
   - Ornek: `Tevrat, Incil'de` ifadesine kaynakta olmayan `Kur'an'da` eklenmesi.
2. Sure referansi baglaminda `Tevbe/Tovbe` ayrimi korunmali.
   - `Tevbe 69` gibi referanslarda sure adi degismemeli.
3. `Yunus/Yunus` sure referansi tekrarlarinda tutarlilik saglanmali.
4. Siir/dortluk satir basi buyuk harf kurali baglama gore ele alinmali.
5. Noktalama baglami yanlis donusumleri incelenmeli.
6. Ikinci denetimde farkli sonuc cikmasi determinism/tutarlilik riski olarak ele alinmali.
7. Cift virgul gibi idempotency hatalari engellenmeli.

Bu kalite hatti P1J deploy/smoke hattina karistirilmamalidir. Public arsiv yayinina gecmeden once ozellikle kaynakta olmayan icerik ekleme guard'i ele alinmalidir.

## J. P2A Deferred Scope Reminder

Kullanici soru sistemi P1J icinde uygulanmayacak ve P2A deferred scope olarak kalir.

P2A'da ele alinacak kararlar:

- Oturum acma.
- Soru gonderme.
- Cevap takip.
- Admin/ekip cevaplama.
- Public arsive aday yapma.
- Kullanici soru yazdiginda once arsivde benzer cevaplari gosterme.
- Chatbot gibi gorunmeme.
- Kullanici sorularinin sitemap disinda ve noindex kalmasi.
- Public arsive aktarimin otomatik degil, ayri yayin karariyla yapilmasi.

## K. Next Recommended Step

Onerilen sira:

1. P1K preview candidate clean branch/worktree preparation.
2. QF1 active feedback quality fix plan.
3. P2A user question intake architecture docs-only.
4. Public frontend MVP.

Gerekce:

- P1I-B local/clean patch dogrulamasini kapatti.
- P1J bu patch setinin preview/staging smoke kapilarini netlestirdi.
- Bir sonraki teknik risk, patch setinin Vercel preview response seviyesinde `/admin` header'larini gercekten verip vermedigidir.
- Bu kapanmadan 39 aktif kullanici icin pilot genisletme veya root public gecis planina gecilmemelidir.
- QF1 kalite hatti onemlidir, ozellikle kaynakta olmayan icerik ekleme guard'i public arsiv oncesi ele alinmalidir; ancak P1J preview/smoke hattina karistirilmamalidir.
- P2A kullanici soru sistemi ve Public frontend MVP daha sonra docs-only mimari adimlarla ilerlemelidir.

## Sonuc

P1J, P1B + P1G + P1I patch setinin Vercel preview/staging ortaminda dogrulanmasi icin smoke planini, header kontrol komutlarini, pilot rol planini, rollback stratejisini ve Go/No-Go kriterlerini tanimladi. Bu adimda kod/config degisikligi, patch apply, DB islemi, feedback kapatma, deploy, push, commit veya staging yapilmadi. Root `/` korunacak, public root arsiv aktif edilmeyecek ve kullanici soru sistemi P2A deferred scope olarak kalacaktir.
