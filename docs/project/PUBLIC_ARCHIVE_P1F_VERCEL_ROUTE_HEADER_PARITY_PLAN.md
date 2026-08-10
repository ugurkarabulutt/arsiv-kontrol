# Public Archive P1F Vercel Route Header Parity Plan

Tarih: 2026-07-31
Durum: Vercel route/header parity preflight ve P2A deferred scope kaydi, docs-only

## Kapsam

Bu dokuman P1B-only `/admin` Express/runtime route hazirliginin Vercel production/preview route davranisi ile ne kadar eslestigini degerlendirir. Ayrica kullanici soru gonderme ve cevap takip sistemini P2A docs-only deferred scope olarak kayda alir.

Bu adimda kod yazilmadi, DB migration yapilmadi, DB'ye baglanilmadi, canli veri okunmadi/yazilmadi, production deploy yapilmadi, push yapilmadi, commit yapilmadi, staging yapilmadi, `vercel.json`, `render.yaml`, `server.js`, `scripts/check-frontend.js`, `index.html` ve `sw.js` degistirilmedi. Root `/` davranisi degistirilmedi ve public root arsiv aktif edilmedi.

## A. Current State Summary

P0:

- Public dini soru-cevap arsivi icin mimari karar dokumanlari olusturuldu.
- Ana karar: root `/` ileride public arsiv olacak, mevcut ekip/admin uygulamasi `/admin` altinda kalacak.
- Public gorunurluk `history` tablosundan dogrudan beslenmeyecek; ayri `public_qa` yayin katmani gerekecek.

P1A:

- Repo route preflight yapildi.
- `server.js` Express entry olarak belirlendi.
- Mevcut root `/` tek sayfalik `index.html` admin/ekip uygulamasini servis ediyor.
- Frontend URL-level admin router kullanmiyor; sekmeler uygulama ici state ile calisiyor.
- API cagri path'leri absolute `/api/...` oldugu icin `/admin` altinda relative path kirilmasi beklenmiyor.
- `vercel.json` P1B kapsam disi production/deploy config olarak ayrildi.

P1B:

- Express/runtime icinde paralel `/admin`, `/admin/`, `/admin/*` route hazirligi yapildi.
- `sendAdminIndex` helper'i `index.html` dondurur.
- `/admin` HTML response icin `X-Robots-Tag: noindex, nofollow` eklendi.
- Root `/` legacy davranisi korunacak sekilde tasarlandi.

P1C-A:

- Deployment parity ve pilot preflight docs-only hazirlandi.
- Kritik risk tespit edildi: mevcut `vercel.json` altinda `/admin` istekleri production'da Express'e ugramadan static `index.html` catch-all ile donebilir.
- Bu durumda `server.js` icindeki `X-Robots-Tag` production `/admin` response'unda gorunmeyebilir.

P1D:

- P1B degisiklikleri kirli calisma agacindan izole edildi.
- `docs/project/patches/PUBLIC_ARCHIVE_P1B_ONLY.patch` olusturuldu.
- Patch yalniz P1B_REQUIRED degisiklikleri iceriyor.

P1E:

- P1B-only patch temiz git worktree uzerinde uygulandi.
- Patch sonrasi degisen dosyalar yalniz `server.js` ve `scripts/check-frontend.js` oldu.
- `git diff --check` basarili.
- `npm.cmd run check` basarili; 79 pass, 0 fail.
- Local smoke test basarili:
  - `/` 200 HTML, root legacy shell korundu.
  - `/admin`, `/admin/`, `/admin/smoke-test` 200 HTML ve `X-Robots-Tag: noindex, nofollow`.
  - `/api/auth/me` 200 JSON, HTML fallback'e dusmedi.
  - Static asset route'lari calisti.
- `vercel.json`, `render.yaml`, DB/schema/migration degismedi.
- Production deploy, push, commit yapilmadi.

## B. Current Vercel Route Map

Mevcut `vercel.json` route sirasi:

```json
[
  { "src": "/health", "dest": "/server.js" },
  { "src": "/api/(.*)", "dest": "/server.js" },
  { "src": "/manifest.webmanifest", "dest": "/manifest.webmanifest" },
  { "src": "/sw.js", "dest": "/sw.js" },
  { "src": "/icons/(.*)", "dest": "/icons/$1" },
  { "src": "/favicon.ico", "dest": "/icons/favicon.ico" },
  { "src": "/(.*)", "dest": "/index.html" }
]
```

Mevcut config ayrica static manifest, `sw.js` ve final `/(.*)` index route icin `Cache-Control: no-store, no-cache, must-revalidate, proxy-revalidate` header'i iceriyor. Top-level `headers` altinda da `/(.*)` icin ayni cache header'i var.

Bu route sirasi su anlama gelir:

- `GET /health` Express/Vercel Function tarafina gider: `/server.js`.
- `GET /api/*` Express/Vercel Function tarafina gider: `/server.js`.
- `GET /manifest.webmanifest` static manifest dosyasina gider.
- `GET /sw.js` static service worker dosyasina gider.
- `GET /icons/*` static icons dosyalarina gider.
- `GET /favicon.ico` static favicon dosyasina gider.
- `GET /`, `GET /admin`, `GET /admin/`, `GET /admin/smoke-test` ve diger HTML path'leri final `/(.*)` catch-all ile static `/index.html` dosyasina gider.

Mevcut `vercel.json` icinde explicit `/admin` veya `/admin/(.*)` route yoktur.

## C. /admin Production Parity Risk

Mevcut `vercel.json` route yapisi `/admin` isteklerini Express/server.js tarafina gondermez. `/admin` path'i `/health`, `/api/(.*)`, static asset route'lari veya favicon route'u ile eslesmez; bu nedenle final `/(.*)` route'una duser ve static `/index.html` alir.

Sonuc:

- Production/preview Vercel ortaminda `/admin` muhtemelen calisir, cunku static `index.html` doner.
- Ancak bu calisma P1B Express route'unun calistigi anlamina gelmez.
- `server.js` icindeki `sendAdminIndex` production `/admin` HTML response'u icin devreye girmeyebilir.
- Local/Express runtime ile Vercel production runtime arasinda route/header parity tam degildir.

P1B icin anlami:

- P1B Express/runtime hazirligi teknik olarak dogru ve temiz dogrulandi.
- Fakat Vercel production uzerinde `/admin` noindex header garantisi P1B patch ile tek basina saglanmis kabul edilemez.
- P1B patch preview/staging'e tasinacaksa bu fark bilincli risk olarak kabul edilmeli veya P1G/P1C-B Vercel route/header patch'i ayrica planlanmalidir.

## D. X-Robots-Tag Risk

`server.js` icindeki P1B helper'i:

```js
function sendAdminIndex(req, res) {
  res.set('X-Robots-Tag', 'noindex, nofollow');
  res.sendFile(path.join(__dirname, 'index.html'));
}
```

Bu header Express/runtime tarafinda calisir. P1E local smoke testte `/admin`, `/admin/`, `/admin/smoke-test` response'larinda `X-Robots-Tag: noindex, nofollow` goruldu.

Vercel production riski:

- Mevcut `vercel.json` ile `/admin` static `/index.html` catch-all'a duserse Express helper calismaz.
- Express helper calismadigi icin `server.js` kaynakli `X-Robots-Tag` production `/admin` response'unda gorunmeyebilir.
- Mevcut `vercel.json` top-level `headers` yalniz `Cache-Control` tanimliyor; `X-Robots-Tag` tanimlamiyor.

Risk seviyesi:

- P1B paralel admin route pilotu icin orta risk: `/admin` HTML acilir, fakat noindex header beklentisi production'da garanti olmayabilir.
- Public root cutover oncesi yuksek risk: root public oldugunda `/admin`in indexleme disinda tutulmasi artik sadece iyi uygulama degil, zorunlu koruma olur.

## E. Options For Guaranteeing /admin Noindex

### Secenek 1: Vercel headers kuralini `/admin` icin eklemek

Kavramsal minimum degisiklik:

```json
{
  "source": "/admin",
  "headers": [
    { "key": "X-Robots-Tag", "value": "noindex, nofollow" }
  ]
}
```

ve deep path icin:

```json
{
  "source": "/admin/(.*)",
  "headers": [
    { "key": "X-Robots-Tag", "value": "noindex, nofollow" }
  ]
}
```

Artlar:

- En dusuk davranis degisikligi.
- `/admin` static `index.html` almaya devam eder.
- Express/serverless runtime yuzeyi artmaz.
- 39 kullanici icin route davranisi pratikte bugunku Vercel davranisina yakin kalir.
- Rollback kolaydir: yalniz header kuralini geri almak yeterlidir.

Eksiler:

- Express P1B route'u production HTML icin yine calismayabilir.
- Local/Express parity hala tam olmaz.
- Header kurali Vercel config semantigine baglidir; preview'da mutlaka response header ile dogrulanmalidir.

Riskler:

- Header pattern yanlis yazilirsa `/admin/smoke-test` gibi deep path header almayabilir.
- Final public root cutover'da `/admin` static catch-all'a guvenmek ileride yetersiz kalabilir.

39 kullanici etkisi:

- Dusuk. HTML hedefi degismez; sadece crawler header'i eklenir.

Rollback kolayligi:

- Yuksek. Tek config hunk revert edilebilir.

### Secenek 2: Explicit `/admin` static route + route-level headers

Kavramsal minimum route:

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

Bu route'lar `/api/(.*)` ve static asset route'larindan sonra, final `/(.*)` catch-all'dan once durmalidir.

Artlar:

- `/admin` ve `/admin/*` Vercel route davranisi explicit hale gelir.
- Static `index.html` performans davranisi korunur.
- Header route seviyesinde garanti edilebilir.
- Public root cutover oncesi `/admin` catch-all'a bagimli olmaktan cikar.

Eksiler:

- `vercel.json` route sirasi degisir; production/deploy config degisikligidir.
- Express P1B helper'i production HTML icin yine calismaz; fakat ayni hedef davranisi Vercel config ile explicit edilir.

Riskler:

- Route sirasi yanlis olursa `/api/*` veya static asset route'lari etkilenebilir.
- Yanlis `src` pattern'i `/admin/` veya `/admin/smoke-test` kapsamini eksik birakabilir.

39 kullanici etkisi:

- Dusuk/orta. Hedef yine `index.html`, fakat route config degistigi icin preview smoke zorunludur.

Rollback kolayligi:

- Orta/yuksek. Tek `vercel.json` hunk revert edilebilir.

### Secenek 3: Explicit `/admin` route'u `/server.js` hedefine almak

Kavramsal route:

```json
{ "src": "/admin", "dest": "/server.js" }
{ "src": "/admin/(.*)", "dest": "/server.js" }
```

Artlar:

- Vercel production `/admin` Express app'e gider.
- `server.js` icindeki `sendAdminIndex` ve `X-Robots-Tag` dogrudan production'da calisir.
- Local/Express ve Vercel runtime parity daha guclu olur.

Eksiler:

- `/admin` HTML static degil Vercel Function uzerinden servis edilir.
- Serverless runtime yuzeyi ve latency artabilir.
- Express startup/seed/env bagimliliklari HTML shell response icin daha kritik hale gelir.
- 39 kullanici icin daha fazla runtime riski tasir.

Riskler:

- Env/startup sorunu varsa `/admin` HTML shell de etkilenebilir.
- Serverless fonksiyon davranisi static index'e gore daha fazla degisken icerir.

39 kullanici etkisi:

- Orta. Davranis hala HTML shell donmek olsa da runtime yolu degisir.

Rollback kolayligi:

- Orta. `vercel.json` revert gerekir.

### Secenek 4: Static `index.html` icine meta robots eklemek

Degerlendirme:

- Tek `index.html` hem root `/` hem `/admin` hem ileride public root tarafindan kullanildigi icin global meta robots eklemek uygun degildir.
- Root `/` su an legacy admin shell oldugu icin noindex istenebilir gibi gorunse de ileride root public arsiv canonical kaynak olacak; global noindex ileride public SEO'yu bozar.
- Path'e gore meta robots uretmek static tek HTML ile guvenilir degildir.

Sonuc:

- Bu P1F icin onerilmez.

### Secenek 5: Mevcut haliyle kabul etmek

Artlar:

- Hic config degisikligi yok.
- P1B Express patch preview/staging icin yalniz runtime hazirligi olarak kalir.
- 39 kullanici icin en dusuk anlik degisiklik.

Eksiler:

- Production `/admin` noindex header'i garanti degildir.
- Vercel route/header parity boslugu devam eder.
- Public root cutover oncesi mutlaka tekrar ele alinmasi gerekir.

Riskler:

- `/admin` acilabilir ama production header beklentisi yanlis raporlanabilir.
- Noindex garantisi yokken pilot veya public cutover'a yakin adimlarda yanlis guven hissi olusur.

39 kullanici etkisi:

- Cok dusuk, cunku deploy/config degisikligi yok.

Rollback kolayligi:

- Degisiklik olmadigi icin rollback yoktur.

## F. Recommended P1G/P1C-B Direction

Oneri: P1G/P1C-B once minimal `vercel.json` route/header patch planini docs-only olarak hazirlamali; ardindan ayrica onayla izole `vercel.json` patch'i uretilmelidir.

Net karar:

- P1B-only patch preview/staging'e alinmadan once Vercel etkisi netlesmis olmali.
- `/admin` noindex production'da garanti beklenecekse `vercel.json` patch gerekir.
- En dusuk riskli teknik yon, explicit `/admin` ve `/admin/(.*)` static `/index.html` route'larini final catch-all'dan once eklemek ve bu route'lara `X-Robots-Tag: noindex, nofollow` header'i koymaktir.
- `/api/(.*)`, `/health`, `/manifest.webmanifest`, `/sw.js`, `/icons/(.*)`, `/favicon.ico` route'lari bu admin route'larindan once kalmalidir.
- `/server.js` hedefine explicit `/admin` route almak daha guclu Express parity verir, fakat 39 kullanici icin daha fazla runtime riski tasir; ilk Vercel patch icin oncelikli onerilmez.

Minimum dosya:

- Yalniz `vercel.json`.

Izolasyon stratejisi:

- Mevcut kirli calisma agacindan deploy yapilmaz.
- Temiz worktree/branch uzerinde yalniz `vercel.json` patch'i uygulanir.
- P1B-only patch ile Vercel patch ayri commit/patch olarak tutulur.
- `server.js`, `scripts/check-frontend.js`, `index.html`, `sw.js`, DB/schema/migration dosyalari ayni Vercel patch'e karistirilmaz.

Deploy/push olmadan test:

- `vercel.json` route sirasi statik olarak incelenir.
- `git diff --check` calistirilir.
- Mümkünse Vercel preview deploy ancak ayrica onaylandiktan sonra yapilir; bu P1F kapsaminda yapilmaz.
- Preview olmadan kesin production header sonucu iddia edilmez; sadece config tasarimi onaylanir.

## G. Preview/Staging Verification Plan

P1B patch veya olasi Vercel patch preview/staging'e alinirsa asagidaki kontroller yapilmalidir.

Route smoke:

- `GET /`
- `GET /admin`
- `GET /admin/`
- `GET /admin/smoke-test`
- `GET /api/auth/me`
- `GET /manifest.webmanifest`
- `GET /sw.js`
- `GET /favicon.ico`

Beklenen:

- `GET /` 200 HTML doner ve root legacy admin shell korunur.
- `GET /admin` 200 HTML doner.
- `GET /admin/` 200 HTML doner.
- `GET /admin/smoke-test` 200 HTML doner.
- `/admin`, `/admin/`, `/admin/smoke-test` response header'larinda `X-Robots-Tag: noindex, nofollow` gorulur.
- `GET /api/auth/me` JSON doner; HTML fallback'e dusmez.
- `/manifest.webmanifest`, `/sw.js`, `/favicon.ico` 200 doner.

Header kontrolleri:

- `/admin` noindex header'i var mi?
- `/admin/` noindex header'i var mi?
- `/admin/smoke-test` noindex header'i var mi?
- Root `/` icin beklenmeyen noindex header'i var mi? Bu karar ayrica verilmeli; P1G admin header patch'i root'u hedeflememeli.
- Static asset route'lari cache/content-type davranisini koruyor mu?

API fallback kontrolleri:

- `/api/auth/me` HTML degil JSON donmeli.
- `/api/history` logged-out durumda HTML degil JSON/401 donmeli.
- `/api/*` final `/(.*)` static catch-all'a dusmemeli.

Root legacy kontrolleri:

- `/` eski login/admin shell'i acar.
- `/` public archive'e donusmemis olmalidir.
- Mevcut ekip kullanici akislari root uzerinden calismaya devam etmelidir.

## H. Limited User Pilot Reminder

P1C-A pilot plani korunur. 39 kisilik ekibe genis duyuru yapmadan once sinirli pilot gerekir:

- 1 super admin.
- 1 admin.
- 1 normal ekip kullanicisi.
- 1 mobil kullanici.

Pilot kapsaminda:

- `/admin` login.
- Logout.
- Session yenileme.
- Normal kullanici paneli.
- Admin paneli.
- Super admin paneli.
- Metin denetimi.
- Onaya gonderme.
- Onaylama.
- Reddetme.
- Feedback gonderme/okuma.
- Bildirimler.
- Standartlar.
- Raporlama/dashboard.
- History listeleme.
- Kullanici yonetimi.
- Sayfa refresh.
- Mobil giris.
- Eski root `/` davranisi.
- `/admin` deep link.
- Asset path.
- API calls.

## I. Service Worker / PWA Note

P1B icin service worker riski dusuktur:

- Mevcut `sw.js` minimaldir.
- Cache API ile `index.html` veya `/admin` shell cache'lemiyor.
- `fetch` event'i uygulama response davranisini degistirmiyor.
- Vercel config mevcut HTML/static response'lar icin no-store cache header'lari iceriyor.

Ancak public root cutover oncesi PWA/scope ayrica degerlendirilmelidir:

- `manifest.webmanifest` scope/start_url root `/` etrafinda kurguludur.
- Root `/` public archive oldugunda installed/PWA kullanici akisi admin yerine public root'a gidebilir.
- Admin ve public site ayni root scope altinda kalirsa PWA davranisi karisabilir.
- P1B/P1F icinde `sw.js` veya manifest degistirilmemelidir; bu ayrica planlanmalidir.

## J. P2A Deferred Scope: User Question Intake

Yeni urun karari P2A deferred scope olarak kayda alindi. Bu P1F adiminda uygulanmayacak.

Hedef:

- Kullanicilar oturum acabilecek.
- Kullanicilar soru sorabilecek.
- Kullanicilar kendi sorularini ve cevaplarini kendi hesabindan takip edebilecek.
- Ekip/admin arkada bu sorulari gorebilecek ve cevaplayabilecek.
- Uygun cevaplar daha sonra public arsive aday yapilabilecek.
- Kullanici cevabi dogrudan public'e dusmeyecek.
- Public arsive aktarim icin ayri yayin akisi olacak:
  - kullanici sorusu
  - ekip cevabi
  - public arsive aday yap
  - `public_qa` draft
  - preview
  - published

Urun deneyimi:

- Bu sistem chatbot gibi gorunmeyecek.
- Kullaniciya anlik cevap ureten bir deneyim sunulmayacak.
- Kullanici "soru gonder / cevabini takip et" deneyimi yasayacak.
- Kullanici soru yazdiginda once arsivde benzer cevaplar gosterilmeli.
- Kullanici bu cevaplari okuyabilmeli.
- Cevaplar sorusunu karsilamiyorsa "Sorumu yine de gonder" diyebilmeli.

Gelecekte P2A'da detaylandirilacak route onerisi:

Public:

- `/`
- `/arama`
- `/soru/[slug]`
- `/konu/[slug]`
- `/kategori/[slug]`

Kullanici:

- `/giris`
- `/hesap`
- `/soru-gonder`
- `/sorularim`
- `/sorularim/[id]`

Admin:

- `/admin`
- `/admin/user-questions`
- `/admin/user-questions/[id]`

Gelecekte P2A'da detaylandirilacak veri modeli onerisi:

- `user_profiles`
- `user_questions`
- `user_question_responses`
- `user_question_status_events`

Gelecekte P2A'da ele alinacak status onerileri:

- `submitted`
- `under_review`
- `answered`
- `closed`
- `public_candidate`
- `published_to_archive`
- `rejected`

Public dil karsiliklari:

- `submitted` -> `Sorunuz alindi`
- `under_review` -> `Cevap hazirlaniyor`
- `answered` -> `Cevabiniz hazir`
- `closed` -> `Tamamlandi`

Kesin guvenlik kararlari:

- Kullanici sadece kendi sorularini gorur.
- Baska kullanicilarin ozel sorulari gorunmez.
- Kullanici sorulari sitemap'e girmez.
- `/soru-gonder`, `/sorularim`, `/hesap`, `/giris` noindex olur.
- Public API ozel soru-cevaplari dondurmez.
- Kullanici cevabi `public_qa` tablosuna otomatik aktarilmaz.
- Public arsive aktarim icin ayri ekip/admin karari gerekir.
- Public dilde su ic operasyon kelimeleri gorunmez: `admin`, `denetim`, `onay kuyruğu`, `kalite kontrol`, `AI`, `prompt`, `model`, `test verisi`.

P1F kapsam disi:

- Kullanici sistemi kodlanmayacak.
- Route eklenmeyecek.
- DB tablosu olusturulmayacak.
- Migration yazilmayacak.
- Auth yapisi degistirilmeyecek.
- `public_qa` modeli kodlanmayacak.

## K. Go / No-Go Criteria

### Go

P1B preview/staging'e su kosullarda tasinabilir:

- P1B-only patch temiz ve izole.
- Diff yalniz hedeflenen P1B dosyalarini iceriyor.
- `vercel.json` etkisi anlasildi.
- `/admin` noindex stratejisi net.
- Root `/` legacy admin shell korunuyor.
- `/api/*` fallback'e dusmuyor.
- Static asset route'lari korunuyor.
- DB/migration yok.
- Auth/session core degismiyor.
- Admin business logic degismiyor.
- Rollback yolu belli.
- Sinirli pilot plani hazir.
- P1G/P1C-B Vercel header/route karari alinmis veya bu eksik bilincli risk olarak imzalanmis.

### No-Go

Asagidaki durumlardan biri varsa preview/staging veya production'a gecilmemeli:

- Mevcut kirli calisma agaci deploy edilmek isteniyor.
- P1B disi dirty degisiklikler stage/commit/deploy icine giriyor.
- `vercel.json` etkisi anlasilmadan production'a cikilmak isteniyor.
- `/admin` noindex production'da garanti bekleniyor ama route/header plani yok.
- Root `/` public archive'e cevrilmek isteniyor.
- Kullanici soru sistemi P1B/P1F kapsaminda kodlanmak isteniyor.
- DB migration veya `public_qa` modeli bu adima eklenmek isteniyor.
- `/api/*` HTML fallback'e dusuyor.
- Pilot roller veya rollback penceresi net degil.

## L. Next Recommended Step

Onerilen siradaki adim: P1G/P1C-B Vercel minimal route/header patch plani.

Gerekce:

- P1E, P1B-only patch'in temiz oldugunu kanitladi.
- Kalan ana belirsizlik kod degil Vercel route/header parity.
- `/admin` production noindex garantisi public root cutover oncesi mutlaka netlesmeli.
- Bu karar netlesmeden pilot veya public cutover'a yaklasmak yanlis guven yaratir.

P1G/P1C-B icin onerilen kapsam:

- Docs-first mini plan.
- Sonra ayrica onaylanirsa yalniz `vercel.json` patch'i.
- Minimum hedef: `/admin` ve `/admin/(.*)` icin static `/index.html` route + `X-Robots-Tag: noindex, nofollow`, final catch-all'dan once.
- `/api/(.*)` ve static asset route'lari once kalir.
- Deploy/push/commit ayri onay olmadan yapilmaz.

P2A User Question Intake Architecture ikinci sirada gelmeli:

- Urun olarak onemli, fakat P1B/P1G admin gecis guvenligi tamamlanmadan yeni kullanici soru sistemi ayni anda acilmamali.
- P2A docs-only olarak baslatilabilir; kod/DB/migration icin ayri karar gerekir.

## Sonuc

Mevcut Vercel config altinda `/admin` production'da Express'e ugramadan static `/index.html` catch-all ile donebilir. Bu nedenle `server.js` icindeki `X-Robots-Tag: noindex, nofollow` header'i production `/admin` response'unda garanti kabul edilmemelidir. P1B patch Express/runtime acisindan temizdir, fakat production noindex parity icin P1G/P1C-B Vercel route/header karari gerekir. Kullanici soru sistemi bu turda yalniz P2A deferred scope olarak kayda alindi; uygulanmadi.
