# Public Archive P2D Public Preview Shell Implementation Plan

Tarih: 2026-08-04
Durum: Docs-only implementation plan

## A. Current State

Production durum:

| Route | Current behavior |
| --- | --- |
| `https://arsiv.ibrahimlive.ai/` | Legacy ekip/admin shell olarak calisiyor. |
| `https://arsiv.ibrahimlive.ai/admin` | Production paralel admin shell olarak calisiyor. |
| `https://arsiv.ibrahimlive.ai/admin/` | Admin shell browser refresh fallback calisiyor. |
| `https://arsiv.ibrahimlive.ai/api/*` | API route'lari HTML fallback'e dusmeden calismali. |
| Public root archive | Aktif degil. |
| Root public cutover | Yapilmadi. |

P2D icin ana kisitlar:

- P2D sadece `/public-preview` altinda public preview shell hazirlar.
- Root `/` legacy admin shell olarak kalir.
- `/admin` production admin shell olarak kalir.
- `/api/*` route'lari korunur.
- DB migration yoktur.
- DB baglantisi veya canli veri okuma/yazma yoktur.
- Admin, feedback ve analysis-engine isleri P2D kapsaminda degildir.
- Public root archive bu fazda acilmaz.

Mevcut Express/Vercel modeli:

- `server.js` static asset route'larini acik tanimliyor:
  `/icons`, `/favicon.ico`, `/manifest.webmanifest`, `/sw.js`.
- `server.js` `/admin`, `/admin/`, `/admin/*` icin admin shell fallback
  veriyor ve `X-Robots-Tag: noindex, nofollow` set ediyor.
- `server.js` en sonda broad SPA fallback ile `index.html` donduruyor.
- `vercel.json` `/api/(.*)` route'unu `/server.js` hedefine gonderiyor.
- `vercel.json` statik asset route'larini explicit koruyor.
- `vercel.json` `/admin` ve `/admin/(.*)` route'larini final catch-all'dan
  once explicit noindex/no-cache header'lariyla tanimliyor.
- Final `/(.*)` catch-all halen `/index.html` donduruyor.

## B. P2D Scope

P2D implementation hedefi:

- Public preview shell icin HTML-first server-rendered taslak olusturmak.
- Ilk asamada mock/fixture public-safe icerik kullanmak.
- Public root'u acmadan public UX, tema, arama hero, kart sistemi ve temel
  detay sayfalarini `/public-preview` altinda denemek.
- Public preview output'unu `noindex,nofollow` tutmak.
- Public forbidden word guard'i ilk implementation icine almak.
- `/`, `/admin`, `/api` ve static asset davranislarini bozmamak.

P2D icinde olmayacaklar:

- Root `/` public archive'e cevrilmez.
- `public_qa` DB entegrasyonu yoktur.
- `history` tablosu dogrudan okunmaz.
- Gercek search backend yoktur.
- User question sistemi yoktur.
- Super-admin public management UI yoktur.
- Sitemap generation yoktur.
- Production schema/canonical rollout yoktur.
- Admin veya feedback fix yoktur.
- Yeni dependency yoktur; dependency gerekirse ayri onay gerekir.

## C. Preview Route Model

Onerilen P2D exact route modeli:

| Route | Purpose | Data | Indexing |
| --- | --- | --- | --- |
| `GET /public-preview` | Public home preview shell | Fixture | `noindex,nofollow` |
| `GET /public-preview/soru/ornek-soru` | Question detail preview | Fixture | `noindex,nofollow` |
| `GET /public-preview/konu/hidayet` | Topic preview | Fixture | `noindex,nofollow` |
| `GET /public-preview/kategori/temel-kavramlar` | Category preview | Fixture | `noindex,nofollow` |

Route kurallari:

- Bu route'lar sitemap'e girmez.
- Bu route'lar root `/` davranisini etkilemez.
- Bu route'lar `/admin` veya `/admin/*` davranisini etkilemez.
- Bu route'lar `/api/*` route'larini fallback'e dusurmez.
- Bu route'lar `history` tablosunu dogrudan okumaz.
- Bu route'lar ilk asamada public-safe fixture data ile calisir.

Express icin onerilen route sekli:

```text
/public-preview
/public-preview/soru/:slug
/public-preview/konu/:slug
/public-preview/kategori/:slug
```

Express tarafinda bu route'lar static asset ve `/api/*` route'larindan sonra,
admin route'lari ve final broad fallback ile conflict yaratmayacak sirada
tanitilmalidir. Final `app.get('*')` oncesinde tanitilmazsa preview route'lari
`index.html` admin shell'e dusebilir.

Vercel parity notu:

- Mevcut `vercel.json` final `/(.*)` catch-all ile HTML path'lerini
  `/index.html` dosyasina dondurur.
- Bu nedenle P2D implementation sadece `server.js` route'u eklerse local
  Express smoke gecse bile Vercel preview'da `/public-preview` final catch-all'a
  dusup admin shell dondurebilir.
- Vercel preview smoke hedefleniyorsa `/public-preview` ve
  `/public-preview/(.*)` icin final catch-all'dan once explicit Vercel route
  veya rewrite/header karari gerekir.
- Bu `vercel.json` degisikligi P2D implementation oncesi ayrica onaylanmalidir.

Daha dar MVP alternatifi:

| Route | When to use |
| --- | --- |
| `/public-preview` | Vercel route/header karari ertelenirse tek local preview shell icin. |
| `/public-preview/soru` | Dynamic slug destegi riskli gorulurse static question preview. |
| `/public-preview/konu` | Dynamic slug destegi riskli gorulurse static topic preview. |
| `/public-preview/kategori` | Dynamic slug destegi riskli gorulurse static category preview. |

Oneri:

- Express dynamic route modeli teknik olarak uygundur.
- Vercel preview dogrulamasi isteniyorsa P2D diff boundary icinde
  `vercel.json` icin explicit ve kucuk route/header patch'i ayrica onaylanmali.
- `vercel.json` onayi verilmezse P2D local-only preview olarak kalmali ve
  Vercel preview smoke Go sayilmamalidir.

## D. Feature Flags

Onerilen flags:

| Flag | P2D expected value | Safe default | Purpose |
| --- | --- | --- | --- |
| `PUBLIC_ARCHIVE_PREVIEW_ENABLED` | `true` for preview environment | `false` | `/public-preview` shell'i acar. |
| `PUBLIC_ARCHIVE_ENABLED` | `false` | `false` | Root public archive davranisini kapali tutar. |
| `PUBLIC_ARCHIVE_INDEXING` | `false` | `false` | Public preview ve public root indexing kapali kalir. |
| `PUBLIC_ARCHIVE_USE_PUBLIC_QA` | `false` | `false` | DB-backed `public_qa` yerine fixture kullanilir. |
| `ADMIN_ROOT_LEGACY_ENABLED` | `true` | `true` | Root `/` legacy admin shell olarak kalir. |
| `ADMIN_PARALLEL_ROUTE_ENABLED` | `true` veya mevcut production degeri | `true` | `/admin` paralel route korunur. |

Flag yokken guvenli davranis:

- Root `/` legacy admin shell kalir.
- `/admin` admin shell kalir.
- `/public-preview` 404 veya disabled response verir.
- Public indexing kapali kalir.
- `history` public route tarafindan okunmaz.

P2D icin tavsiye:

- `PUBLIC_ARCHIVE_PREVIEW_ENABLED` default `false` olmali.
- Local veya Vercel preview smoke icin explicit `true` verilmelidir.
- `PUBLIC_ARCHIVE_ENABLED` root public cutover icin ayri fazda kullanilmalidir;
  P2D'de `true` olmamalidir.

## E. Files To Touch / Not Touch

P2D implementation icin olasi touch list:

| File | Why |
| --- | --- |
| `server.js` | Gated `/public-preview` route registration, noindex headers, renderer lazy load. |
| `scripts/check-frontend.js` | Preview route safety, noindex, forbidden word guard, root/admin/API regression. |
| `public-archive-renderer.js` | HTML-first public preview renderer. |
| `public-archive.css` | Public visual token skeleton and preview styling. |
| `data/public-preview-fixtures.js` or `fixtures/public-preview-content.js` | Public-safe mock content for preview. |
| `test/public-archive-renderer.test.js` | Optional renderer/guard unit tests. |
| `vercel.json` | Only if separately approved for Vercel preview route/header parity. |

P2D exact diff boundary implementation oncesi netlestirilmelidir. Onerilen iki
secenek:

1. Local-only P2D:
   - `server.js`
   - `scripts/check-frontend.js`
   - `public-archive-renderer.js`
   - `public-archive.css`
   - fixture file
   - optional test file
2. Vercel-preview-ready P2D:
   - Local-only P2D dosyalari
   - `vercel.json` icin ayrica onaylanmis minimal `/public-preview` route/header patch'i

P2D'de kesin not touch:

- `index.html`
- `sw.js`
- `manifest.webmanifest`
- `schema.sql`
- `package.json`
- `package-lock.json`
- `analysis-core.js`
- feedback/admin business logic files
- DB/schema/migration files
- existing admin UI logic
- root public cutover config
- user question system files

Not:

- Yeni dependency eklenmeyecek. UI/CSS shell repo icindeki sade HTML/CSS ile
  baslamalidir.
- `vercel.json` sadece route/header parity icin ayrica onaylanirsa dokunulur.

## F. Preview Data Strategy

P2D veri stratejisi:

- Ilk preview shell fixture/mock data kullanir.
- DB'ye baglanmaz.
- `public_qa` tablosu gerektirmez.
- `history` tablosunu dogrudan okumaz.
- Production kullanici verisi veya gercek private soru-cevap icerigi kullanmaz.
- Fixture icerik public-safe olmalidir.
- Fixture icerik public forbidden words icermemelidir.
- Dini icerik kisa, guvenli ve kaynak iddiasi tasimayan orneklerden secilmelidir.

Fixture onerileri:

| Type | Slug | Safe purpose |
| --- | --- | --- |
| Question | `ornek-soru` | Layout ve okuma ritmini gosteren kisa cevap. |
| Topic | `hidayet` | Konu merkezi kart/definition yapisini gosteren sade kavram. |
| Category | `temel-kavramlar` | Kategori grid ve related content yapisini gosteren ornek. |
| Guide | `ornek-rehber` | P2D'de kart olarak gorunebilir; detay route sonraya kalabilir. |

Kritik kural:

```text
Kaynakta olmayan dini bilgi public preview icin gercek bilgi gibi sunulmaz.
Fixture metinler urun/UX placeholder amaciyla sade ve sinirli kalir.
```

## G. Noindex and Safety Headers

P2D preview route'lari icin noindex stratejisi:

- Response header:
  `X-Robots-Tag: noindex, nofollow`
- HTML meta:
  `<meta name="robots" content="noindex,nofollow">`
- Sitemap disi.
- `PUBLIC_ARCHIVE_INDEXING=false` iken preview URL'ler indexlenebilir
  davranis gostermemeli.
- Preview canonical, final production public root gibi davranmamalidir.
- P2D preview icin canonical en guvenli sekilde omit edilir veya self-preview
  URL ile sinirli tutulur; final `/soru/...` canonical'i cutover oncesi
  uretilmez.

Vercel notu:

- Noindex header sadece Express'te set edilirse Vercel catch-all altinda
  production/preview'da gorunmeyebilir.
- Vercel preview smoke hedefleniyorsa `/public-preview` ve
  `/public-preview/(.*)` icin Vercel tarafinda da noindex/no-cache header parity
  dogrulanmalidir.

Cache onerisi:

- Preview route'lari icin:
  `Cache-Control: no-store, no-cache, must-revalidate, proxy-revalidate`
- Root `/`, `/admin`, `/api` ve statik asset cache davranislari bu fazda
  degistirilmemelidir.

## H. Public Forbidden Word Guard

Public preview visible output icin forbidden words:

- `AI`
- `prompt`
- `model`
- `admin`
- `denetim`
- `onay kuyruğu`
- `kalite kontrol`
- `test verisi`

Guard kapsam:

| Surface | Rule |
| --- | --- |
| Rendered public HTML | Forbidden word gorunurse fail. |
| Public metadata | Forbidden word gorunurse fail. |
| JSON-LD/schema if emitted | Forbidden word gorunurse fail. |
| Sitemap-visible text | Forbidden word gorunurse fail. |
| Fixture content | Forbidden word gorunurse fail. |
| Internal docs/comments | Guard disi. |
| `/admin` technical path | False-positive sayilmamali. |

Implementation guard prensibi:

- Public renderer output string'i test edilebilir olmalidir.
- `scripts/check-frontend.js` P2D sonrasinda public preview HTML orneklerini
  guard'dan gecirmelidir.
- Guard public UI dilini tarar; admin route configuration icindeki teknik
  `/admin` path'i fail sebebi olmamalidir.
- P2D'de forbidden word guard zayiflatilmamalidir; sadece public output surface
  dogru ayrilmalidir.

## I. Initial UI Scope

P2D'de olacak minimum public preview shell:

- Public layout shell.
- Light/dark/system theme token skeleton.
- Home preview shell.
- Search hero.
- Static veya slow-safe topic chip flow.
- Popular topics mock cards.
- Featured question-answer mock cards.
- Latest question-answer mock list.
- Guide highlight mock cards.
- Category grid mock cards.
- Footer.
- Basic question detail preview page.
- Basic topic preview page.
- Basic category preview page.
- Noindex response/header/meta.
- Public forbidden word check.

P2D'de olmayacaklar:

- Gercek search backend.
- `public_qa` DB integration.
- `history` public read.
- User question system.
- Super-admin public management UI.
- Sitemap generation.
- Schema production rollout.
- Root cutover.
- Complex animation.
- Dependency-heavy UI library.
- Admin/feedback/analysis-engine fixes.

Shell icerik davranisi:

- Ana sayfa landing page gibi degil, arama ve bilgi merkezi gibi hissedilmeli.
- Kartlar dolu gibi gorunmeli ama fixture/preview oldugu product-internal dilde
  yazilmamalidir.
- UI copy public ziyaretciye gore olmalidir; teknik surec dili gosterilmez.

## J. Visual Fidelity Requirements

P2C'den P2D minimum kalite gereksinimleri:

- Warm light mode.
- Deep dark mode.
- Premium, merkezi search hero.
- Readable card system.
- Mobile-first spacing ve typography.
- Sakin topic/kavram akisi.
- No crowded landing page.
- No neon teknoloji gorunumu.
- No agresif SaaS/startup gradient dili.
- No hizli slider.
- No okuma sirasinda dikkat dagitan hareket.
- Consistent radius, spacing, typography.
- `prefers-reduced-motion` icin hareket kapali veya minimal.
- Article/detail sayfalarinda 720-820px okuma rahatligi hedeflenir.
- Mobilde tek kolon, yeterli paragraflar arasi bosluk ve buyuk touch target
  kullanilir.

Visual acceptance:

- Ilk ekranda public urun sinyali net: `IbrahimLive Soru Cevap Arsivi`.
- Ana aksiyon arama alanidir.
- Kategori/kavram akisi bilgi merkezi hissi verir.
- Public sayfa admin shell'e benzememelidir.
- Public sayfa teknik operasyon dili tasimamalidir.

## K. Local Smoke Matrix

P2D implementation sonrasi local smoke:

| Path | Expected |
| --- | --- |
| `GET /` | 200 HTML; legacy admin shell; public archive degil. |
| `GET /admin` | 200 HTML; admin shell. |
| `GET /admin/` | 200 HTML; admin shell. |
| `GET /api/auth/me` | JSON/non-HTML; 500 yok. |
| `GET /public-preview` | Preview flag enabled ise 200 HTML; noindex header/meta. |
| `GET /public-preview/soru/ornek-soru` | 200 HTML; noindex; public-safe fixture. |
| `GET /public-preview/konu/hidayet` | 200 HTML; noindex; public-safe fixture. |
| `GET /public-preview/kategori/temel-kavramlar` | 200 HTML; noindex; public-safe fixture. |
| `GET /manifest.webmanifest` | 200; manifest korunur. |
| `GET /sw.js` | 200; service worker korunur. |
| `GET /favicon.ico` | 200; favicon korunur. |

Local commands:

```bash
git diff --name-only
git diff --check
npm.cmd run check
```

Recommended additional checks:

```bash
node -e "JSON.parse(require('fs').readFileSync('vercel.json','utf8')); console.log('vercel json parse ok')"
```

If a P2D Vercel route patch is included, route order must be checked:

- `/api/(.*)` remains before `/public-preview` routes.
- Static assets remain before `/public-preview` routes.
- `/admin` routes remain intact.
- `/public-preview` routes are before final `/(.*)` catch-all.
- Final `/(.*)` catch-all remains `/index.html`.

## L. Vercel Preview Smoke Matrix

Vercel preview smoke precondition:

- P2D candidate is built from a clean branch/worktree.
- Diff boundary is exactly approved.
- If `/public-preview` is expected to work on Vercel, `vercel.json` route/header
  parity must be explicitly approved and applied.
- No production deploy.
- No production alias.
- No root cutover.

Vercel preview route smoke:

| Path | Expected |
| --- | --- |
| `/` | 200 HTML; legacy admin shell; public root inactive. |
| `/admin` | 200 HTML; admin shell; existing noindex/no-cache header parity intact. |
| `/api/auth/me` | JSON/non-HTML; 500 yok; HTML fallback degil. |
| `/public-preview` | 200 HTML if preview enabled; noindex/nofollow; no admin shell. |
| `/public-preview/soru/ornek-soru` | 200 HTML; noindex/nofollow; fixture question detail. |
| `/public-preview/konu/hidayet` | 200 HTML; noindex/nofollow; fixture topic page. |
| `/public-preview/kategori/temel-kavramlar` | 200 HTML; noindex/nofollow; fixture category page. |
| `/manifest.webmanifest` | 200; manifest korunur. |
| `/sw.js` | 200; JS korunur. |
| `/favicon.ico` | 200; favicon korunur. |

Preview acceptance:

- `/public-preview` admin `index.html` shell'e dusmemeli.
- `/public-preview` sitemap'e girmemeli.
- `/public-preview` public root cutover gibi davranmamali.
- `/api/*` route'lari HTML fallback'e dusmemeli.
- `/admin` header parity gerilememeli.

No-Go:

- `vercel.json` route/header karari olmadan Vercel preview'da
  `/public-preview` final catch-all'a dusuyorsa P2D Vercel smoke gecmis sayilmaz.

## M. Rollback Plan

P2D rollback yollar:

1. `PUBLIC_ARCHIVE_PREVIEW_ENABLED=false`.
2. P2D patch revert.
3. `vercel.json` P2D route/header patch'i ayrica uygulanmissa tek dosya revert.
4. `public-archive-renderer.js`, `public-archive.css` ve fixture dosyalari revert.
5. `scripts/check-frontend.js` P2D guard additions revert.

Rollback etkisi:

- Root `/` etkilenmemelidir.
- `/admin` etkilenmemelidir.
- `/api/*` etkilenmemelidir.
- DB rollback gerekmez.
- Migration rollback gerekmez.
- Sitemap/index rollback gerekmez, cunku P2D sitemap veya indexing uretmez.

Rollback tetikleyicileri:

- `/` legacy admin shell bozulursa.
- `/admin` bozulursa.
- `/api/auth/me` HTML fallback veya 500 verirse.
- `/public-preview` indexlenebilir header/meta ile donerse.
- Public preview forbidden words gosterirse.
- Static assets bozulursa.
- Fixture disinda canli/private data gorunurse.

## N. Deferred Super Admin Management

Super-admin-only public management P2H kapsaminda kalir.

P2D'de yapilmayacak moduller:

- Public Arsiv Yonetimi.
- Public Preview admin paneli.
- Ana Sayfa Bolumleri.
- One Cikan Cevaplar.
- Konu/Kategori Yonetimi.
- Rehber Yazilari.
- SEO/Schema Sagligi.
- Sitemap/Indexing Durumu.
- Yayin Gate Kontrolu.
- Public Dil Guard Sonuclari.
- Redirect Yonetimi.
- User Questions to Public Candidate.

P2D sadece public preview shell'i hazirlar. Super-admin management ihtiyaci
P2H'de ayri diff boundary, role gate ve regression planiyla ele alinmalidir.

## O. Go / No-Go Criteria

P2D implementation Go:

- Exact diff boundary implementation oncesi kabul edildi.
- Preview route model kabul edildi.
- `PUBLIC_ARCHIVE_PREVIEW_ENABLED` safe default ve enable akisi net.
- `PUBLIC_ARCHIVE_ENABLED=false` korunuyor.
- `PUBLIC_ARCHIVE_INDEXING=false` korunuyor.
- Root `/` etkilenmiyor.
- `/admin` etkilenmiyor.
- `/api/*` etkilenmiyor.
- Fixture/mock data public-safe.
- `history` dogrudan okunmuyor.
- Public forbidden word guard included.
- Noindex header/meta included.
- Vercel route/header ihtiyaci net; gerekiyorsa ayri onayli.
- Rollback clear.
- DB/admin/feedback/user-question scope karismiyor.

P2D implementation No-Go:

- Root `/` public yapilmaya calisilirsa.
- `history` tablosu dogrudan public route'tan okunursa.
- Admin/feedback/analysis-engine isi P2D'ye karisirse.
- Preview route'lari indexlenebilir olursa.
- `/api/*` fallback riski dogarsa.
- `/admin` noindex/header parity gerilerse.
- `vercel.json` ihtiyaci belirsizken Vercel preview Go denirse.
- Diff boundary cok genislerse.
- Yeni dependency onaysiz eklenirse.
- User question sistemi bu scope'a alinirsa.

## P. Next Recommended Step

Onerilen sonraki guvenli adim:

```text
P2D-A Public Preview Shell Implementation Candidate
```

P2D-A icin karar:

1. Clean branch/worktree `codex/vercel-arsiv-production` son HEAD'inden
   olusturulsun.
2. Implementation oncesi exact diff boundary tekrar yazilsin.
3. `vercel.json` P2D kapsaminda degisecek mi net onaylansin:
   - Local-only preview ise degismesin.
   - Vercel preview smoke isteniyorsa `/public-preview` route/header parity icin
     minimal patch ayri onaylansin.
4. Ilk implementation fixture data ile, DB'siz ve root cutover'siz yapilsin.
5. `npm.cmd run check`, local smoke ve gerekiyorsa Vercel preview smoke gecmeden
   production veya team communication adimina gecilmesin.

P2D-A baslamadan once netlestirilecek tek kritik karar:

```text
P2D preview sadece local/branch test mi olacak, yoksa Vercel preview URL uzerinde
de dogrulanacak mi?
```

Vercel preview hedefleniyorsa `vercel.json` icin kucuk, izole ve onayli route
patch'i gerekir. Aksi halde mevcut final catch-all `/public-preview` HTML
path'lerini admin `index.html` shell'e dusurebilir.
