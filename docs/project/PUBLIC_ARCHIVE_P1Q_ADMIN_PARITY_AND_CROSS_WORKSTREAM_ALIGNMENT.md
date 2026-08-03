# Public Archive P1Q Admin Parity and Cross-Workstream Alignment

Tarih: 2026-08-03
Durum: Docs-only audit; deploy yok

## A. Current Production State

P1O sonrasi production durumu:

| Route | Durum |
| --- | --- |
| `https://arsiv.ibrahimlive.ai/` | Mevcut legacy ekip/admin shell olarak calisiyor. |
| `https://arsiv.ibrahimlive.ai/admin` | Ayni ekip/admin shell icin yeni paralel adres olarak calisiyor. |
| `https://arsiv.ibrahimlive.ai/admin/` | Admin shell donuyor. |
| `https://arsiv.ibrahimlive.ai/admin/smoke-test` | Browser refresh/deep-link fallback icin admin shell donuyor. |
| `https://arsiv.ibrahimlive.ai/api/auth/me` | JSON donuyor; HTML fallback degil. |

P1O production kaniti:

- Deployment ID: `dpl_HkQbC8e9mKf9zEkmiWX6Hq4NnTAj`
- Deployment URL: `https://arsiv-kontrol-5gtplaomk-ugurkarabulutts-projects.vercel.app`
- Target: `production`
- Root `/` public archive'e cevrilmedi.
- Public root archive aktif degil.
- `/admin`, `/admin/` ve `/admin/smoke-test` production'da
  `X-Robots-Tag: noindex, nofollow` ve strict `Cache-Control` header'lariyla
  dogrulandi.

Bu P1Q adiminda production deploy, live root cutover, DB islemi veya feedback
islemi yapilmadi.

## B. Admin Parity Model

Admin parity modeli:

- `/` ve `/admin` iki ayri uygulama degildir.
- Ikisi de ayni `index.html` tek sayfa admin uygulamasini servis eder.
- Frontend URL-level router kullanmaz; ana gezinme `showTab(...)` ve tab state
  uzerindendir.
- API cagri yolu `/api/...` olarak kalir.
- `/admin/api/...` gibi ikinci bir API namespace acilmaz.
- Asset path'leri absolute root path kullanir:
  `/manifest.webmanifest`, `/sw.js`, `/favicon.ico`, `/icons/...`.
- Admin gelistirmesi tek ortak admin uygulamasina yapilir; `/` ve `/admin`
  icin duplicate kod yazilmaz.

Sonuc:

```text
Admin panelde yapilan dogru tekil bir degisiklik, ayni uygulama shell'i oldugu
icin hem / hem /admin altinda calismalidir. Ancak bu yalniz degisiklik
production'a gerçekten alinmissa gecerlidir.
```

## C. Workspace Dirty Audit

Calistirilan non-destructive komutlar:

```bash
git status --short --untracked-files=all
git diff --name-only
git diff --check
git diff --stat
```

Destructive komut calistirilmadi:

- `git reset` yok.
- `git checkout` yok.
- `git clean` yok.
- `git stash` yok.
- staging/commit/push yok.

Tracked dirty dosyalar:

```text
AGENTS.md
CURRENT_HANDOFF.md
analysis-core.js
index.html
schema.sql
scripts/check-frontend.js
server.js
test/analysis-core.test.js
vercel.json
```

Untracked ana gruplar:

```text
docs/project/**
docs/project/patches/**
archive-public.css
public-archive-demo.js
scripts/build-archive-demo-static.js
demo-public-preview/**
tmp/**
```

Untracked public demo / tmp sayimi:

- `demo-public-preview/**`: 156 generated static HTML/CSS dosyasi.
- `tmp/**`: 4 gecici artifact.

`git diff --stat` tracked ozeti:

```text
9 files changed, 3703 insertions(+), 102 deletions(-)
```

`git diff --check` sonucu:

```text
Exit code 0; whitespace error yok.
```

Gorulen mesajlar line-ending warning sinifindadir:

- `LF will be replaced by CRLF the next time Git touches it`

Bu warning'ler P1Q veya P1O icin hata degildir; ayri line-ending cleanup isi
olmadan production adayina karistirilmamalidir.

### Dirty File Classification

| File/group | Class | P1O production'a dahil mi? | `/admin` rollout ile iliski | Production'a alinmadan once test |
| --- | --- | --- | --- | --- |
| `docs/project/PUBLIC_ARCHIVE_*.md` | A. P1 approved docs/artifacts | Runtime olarak hayir | Karar/evidence dokumani | Docs trailing whitespace, `git diff --check` |
| `docs/project/patches/*.patch` | A. P1 approved patch artifacts | Patch olarak P1O clean candidate'a uygulandi | P1B/P1G/P1I kaynagi | Clean apply, `git apply --check`, clean diff boundary |
| `server.js` | B/C/D/F mixed | Ana workspace haliyle hayir; P1O sadece P1B subset'i aldi | `/admin` Express fallback + diger admin/feedback/public demo degisiklikleri | Clean hunk isolation, `npm.cmd run check`, dual-route smoke |
| `scripts/check-frontend.js` | B/C/D mixed | Ana workspace haliyle hayir; P1O P1I aligned version kullandi | Admin route safety ve diger regression check'leri | P1B-only ve P1B+P1G combined state testleri, `npm.cmd run check` |
| `vercel.json` | B/config risk | Ana workspace haliyle hayir; P1O P1G explicit `/admin` route kullandi | Production route/header parity | Route order/header parse, Vercel preview smoke |
| `index.html` | C. possible admin UI development | P1O ile otomatik gecmedi | Admin UI, feedback UI, auth/session visible state, mobile shell | `/` + `/admin` login/logout/session/deep-link/mobile smoke |
| `analysis-core.js` | D. feedback/analysis engine development | P1O ile otomatik gecmedi | Denetim motoru; route degil | `npm.cmd run check`, source-grounded regression, sample analysis smoke |
| `test/analysis-core.test.js` | D. feedback/analysis tests | P1O ile otomatik gecmedi | Denetim motoru testleri | `npm.cmd run check` |
| `schema.sql` | E. DB/schema/migration related | P1O ile gecmedi; migration calistirilmadi | `content_correction_log`, `ai_reports`, alerts columns | Ayrica DB approval, dry-run/review; P1 admin rollout'a karistirilmaz |
| `archive-public.css` | F. public frontend/demo | P1O ile gecmedi | Public root future scope | Public language guard, noindex, visual QA, route isolation |
| `public-archive-demo.js` | F. public frontend/demo | P1O ile gecmedi | `PUBLIC_ARCHIVE_DEMO` gate altinda demo router | Public route smoke, no `history`, no root cutover |
| `scripts/build-archive-demo-static.js` | F. public frontend/demo build | P1O ile gecmedi | Static public demo artifact generator | Generated output review; production admin deploy'a karismaz |
| `demo-public-preview/**` | F. generated public preview | P1O ile gecmedi | Public frontend demo output | Generated artifact QA; production admin deploy'a karismaz |
| `tmp/**` | G. temp/unknown | P1O ile gecmedi | Feedback/PDF temp artifact olabilir | Sahip/amac dogrulanmadan silinmez veya deploy edilmez |
| `AGENTS.md` | A/G docs/handoff | Runtime olarak hayir | Proje hafizasi | Docs review; line-ending cleanup ayrica |
| `CURRENT_HANDOFF.md` | A/G docs/handoff | Runtime olarak hayir | Aktif is hattini not eder | Docs review; stale production notlari ayrica ayrilir |

### P1O Clean Candidate Comparison

P1O clean worktree path:

```text
C:\Users\ugur\Desktop\arsiv-kontrol-p1o-production-rollout
```

Ana workspace ile P1O clean candidate karsilastirmasi:

| File | Main workspace P1O clean candidate ile ayni mi? | Diff size |
| --- | --- | --- |
| `server.js` | Hayir | `921` additions, `31` deletions |
| `scripts/check-frontend.js` | Hayir | `182` additions, `51` deletions |
| `vercel.json` | Hayir | `17` additions, `13` deletions |

Bu kritik bir hygiene notudur:

```text
Ana workspace su anda production deploy kaynagi olarak kullanilmamalidir.
```

## D. Which Changes Are Already In Production?

Net cevap:

1. P1O production'a giren sey, clean `e6ee312ad601aef5743a56fa2e8d813dba1da458`
   base uzerine uygulanan uc patch setidir:
   - `PUBLIC_ARCHIVE_P1B_ONLY.patch`
   - `PUBLIC_ARCHIVE_P1G_VERCEL_ADMIN_NOINDEX.patch`
   - `PUBLIC_ARCHIVE_P1I_CHECK_FRONTEND_ALIGNMENT.patch`
2. P1O production diff boundary yalniz su dosyalardi:
   - `server.js`
   - `scripts/check-frontend.js`
   - `vercel.json`
3. Baska sohbette yapilmis bir admin/feedback gelistirmesi bu uc patch icinde
   degilse ve clean base commit'te yoksa P1O ile otomatik production'a gecmedi.
4. Gelistirme zaten clean base commit `e6ee312...` icindeyse hem `/` hem
   `/admin` altinda calisir.
5. Gelistirme ana workspace'te dirty olarak duruyorsa production'a gecmis
   kabul edilmemelidir; ayrica temiz patch/branch olarak hazirlanmalidir.

Teknik olmayan ozet:

```text
/admin yeni adresi ayni admin panelini aciyor. Ama baska sohbette yapilan
degisiklikler otomatik olarak bu yeni adrese gecmis sayilmaz. Eger o degisiklik
P1O'da deploy edilen temiz uc dosyalik paketin icinde degilse su an ayri is
olarak ele alinmali ve tekrar temiz sekilde yayina alinmalidir.
```

Ozel risk:

- Ana workspace'teki `vercel.json`, P1O production'da dogrulanan explicit
  `/admin` ve `/admin/(.*)` Vercel noindex route'larini su an tasimiyor.
- Ana workspace yanlislikla deploy edilirse `/admin` noindex/header parity
  gerileyebilir.
- Ana workspace'teki `scripts/check-frontend.js`, gorulen diff'e gore hala
  P1B-only guard mantigini tasiyan bolumler iceriyor; P1O'daki P1I combined
  alignment ile birebir ayni degil.
- Bu nedenle diger admin/feedback calismalari P1O production state uzerine
  rebase/merge edilmeden production'a alinmamalidir.

## E. Admin Development Policy Going Forward

Bundan sonra admin paneli icin kurallar:

1. Admin gelistirmesi tek ortak admin uygulamasina yapilir.
2. `/` ve `/admin` icin ayri frontend veya duplicate logic yazilmaz.
3. API path'leri `/api/...` olarak kalir.
4. `/admin/api/...` hardcode edilmez.
5. Asset path'leri root absolute kalir:
   - `/manifest.webmanifest`
   - `/sw.js`
   - `/favicon.ico`
   - `/icons/...`
6. Browser refresh `/admin` ve `/admin/*` altinda admin shell dondurmelidir.
7. Her admin PR/patch hem `/` hem `/admin` uzerinde smoke edilmelidir.
8. Root `/` public cutover yapilana kadar legacy admin shell olarak korunur.
9. Public root cutover admin gelistirme patch'ine karistirilmaz.
10. Dirty workspace deploy edilmez; temiz branch/worktree ve net diff boundary
    zorunludur.

Admin/feedback gelistirmesi icin merge politikasi:

1. Once hedef production base secilir.
2. P1O `/admin` route/header state'i korunur.
3. Baska sohbetteki degisiklikler hunk bazinda siniflandirilir:
   - admin UI
   - feedback/analysis engine
   - DB/schema
   - public frontend/demo
   - docs/artifact
4. Her is hatti ayri patch/branch olur.
5. Her patch icin expected diff boundary onceden yazilir.
6. `npm.cmd run check` ve dual-route smoke gecmeden production deploy yoktur.

## F. Dual-Route Regression Checklist

Her admin, admin-engine veya feedback/analysis gelistirmesi sonrasinda
zorunlu dual-route regression:

### HTTP route smoke

| Check | Expected |
| --- | --- |
| `GET /` | 200 HTML; legacy admin shell; public archive degil |
| `GET /admin` | 200 HTML; admin shell |
| `GET /admin/` | 200 HTML; admin shell |
| `GET /admin/smoke-test` | 200 HTML; deep-link fallback |
| `GET /api/auth/me` | JSON; HTML fallback degil |
| `GET /manifest.webmanifest` | 200; manifest content |
| `GET /sw.js` | 200; JavaScript |
| `GET /favicon.ico` | 200; favicon |

### Header checks

- `/admin`, `/admin/`, `/admin/smoke-test`:
  - `X-Robots-Tag: noindex, nofollow`
  - `Cache-Control` includes:
    - `no-store`
    - `no-cache`
    - `must-revalidate`
    - `proxy-revalidate`
- `/api/*` must not return `index.html`.

### Role and workflow checks

- Login.
- Logout.
- Session refresh.
- New tab with active session.
- Browser refresh under `/admin`.
- Normal user screen.
- Admin screen.
- Super admin screen.
- Text analysis.
- File upload if touched.
- Submit for approval.
- Approval board.
- Approve safe test record.
- Reject safe test record.
- Feedback send/read if touched.
- Notifications.
- Standards screen.
- Reports/dashboard.
- History listing/detail.
- User management view if touched.
- Mobile login/menu/text input smoke.

### Local commands

For code/admin/engine changes:

```bash
git diff --name-only
git diff --check
npm.cmd run check
```

For Vercel route/header changes:

```bash
node -e "JSON.parse(require('fs').readFileSync('vercel.json','utf8')); console.log('vercel json parse ok')"
```

Then preview smoke before production.

## G. Other Chat Handoff Message

Asagidaki mesaj diger Codex/gelistirme hattina verilebilir:

```text
Production'da paralel /admin adresi acildi:
https://arsiv.ibrahimlive.ai/admin

Root / hala legacy admin panelidir:
https://arsiv.ibrahimlive.ai/

Iki adres ayni admin uygulamasini servis eder. Admin gelistirmeleri tek ortak
admin app'e yapilmali; / ve /admin icin ayri kod yazilmamali.

Her admin veya feedback/denetim motoru degisikligi hem / hem /admin uzerinde
test edilecek. /api/... path'leri korunacak, /admin/api gibi yeni hardcode
path acilmayacak. Asset path'leri /admin altinda kirilmamali.

Feedback/denetim motoru duzeltmeleri ayri is hattidir; /admin gecis patch'ine
karistirilmayacak. Public frontend ve user-question scope da ayri hatta kalacak.

Dirty workspace deploy edilmeyecek. Temiz patch/branch, net diff boundary,
git diff --check, npm.cmd run check, preview smoke ve rollback plani zorunlu.

Public root cutover yapilmayacak. Root / public archive'e ancak /admin
adoption ve ayri public launch gate tamamlandiktan sonra cevrilecek.
```

## H. Risk Notes

1. Ana workspace P1O production state ile ayni degil.
2. Ana workspace'teki `vercel.json` P1O'nun explicit `/admin` noindex
   route'larini su an tasimiyor.
3. Ana workspace'teki `server.js` public demo router import/gate, feedback
   correction package API'leri ve admin route degisikliklerini ayni dosyada
   tasiyor; hunk isolation gerekir.
4. `index.html` buyuk admin UI/feedback UI degisiklikleri tasiyor; P1O ile
   otomatik gecmedi.
5. `analysis-core.js` ve test dosyasi feedback/denetim motoru degisiklikleri
   tasiyor; bu hat admin route rollout'tan ayridir.
6. `schema.sql` DB/schema degisikligi tasiyor; migration approval olmadan
   uygulanmaz.
7. Public demo dosyalari generated artifacttir; root public cutover'a
   karistirilmaz.
8. Gecmis handoff dokumanlari bazi eski production deploy notlari icerir.
   P1O sonrasi aktif production state, P1O execution dokumaniyla esas alinmalidir.

## I. Recommended Sequencing

Onerilen siralama:

1. P1P team `/admin` adoption.
2. P1Q admin cross-workstream alignment. Bu dokumanla tamamlandi.
3. Diger admin/feedback gelistirmelerini ayri patch olarak audit etme.
4. P2B public frontend UX/design system plan.
5. P2A user question intake architecture.
6. Root public cutover en son.

Bu siralama neden onemli:

- Once ekip yeni `/admin` adresine alisir.
- Sonra admin/feedback gelistirmeleri P1O state'i uzerine temiz izole edilir.
- Public frontend ve kullanici soru sistemi admin gecis patch'ine karismaz.
- Root public cutover, aktif ekip calisma alaninin stabil oldugu kanitlandiktan
  sonra yapilir.

## J. Go / No-Go For Future Admin Changes

### Go

Gelecek admin degisikligi production'a alinabilir, ancak yalniz su kosullarla:

- Clean branch/worktree kullanildi.
- Expected diff boundary onceden yazildi.
- P1O `/admin` route/header state'i korunuyor.
- `git diff --check` basarili.
- `npm.cmd run check` basarili.
- `/` legacy shell smoke basarili.
- `/admin` ve `/admin/*` smoke basarili.
- `/admin` noindex/cache headerlari korunuyor.
- `/api/auth/me` JSON; HTML fallback degil.
- Role-based login/workflow smoke basarili.
- Mobile smoke basarili.
- DB/schema degisikligi varsa ayri onay ve ayri migration plan var.
- Public root cutover yok.
- Rollback plani net.

### No-Go

Asagidaki durumlardan biri varsa deploy yapilmaz:

- Dirty ana workspace deploy edilmek istenirse.
- Ana workspace'teki mevcut `vercel.json` P1O `/admin` header state'iyle
  hizalanmadan deploy edilmek istenirse.
- Diff boundary belirsizse.
- Admin UI, feedback engine, DB schema ve public frontend tek patch'e
  karisiyorsa.
- `/api/*` HTML fallback'e dusuyorsa.
- Root `/` public archive'e donuyorsa.
- `/admin` headerlari kayboluyorsa.
- `npm.cmd run check` calistirilmadiysa veya fail olduysa.
- DB migration kullanici onayi olmadan dahil ediliyorsa.
- Feedback kapatma/DB yazimi bu audit hattina sokuluyorsa.

## K. Immediate Next Action

En guvenli sonraki is:

```text
P1P team /admin adoption communication and monitoring
```

Paralel olarak ayrica acilabilecek temiz audit:

```text
P1R dirty admin/feedback workstream isolation audit
```

P1R hedefi:

- Ana workspace'teki `server.js`, `index.html`, `analysis-core.js`,
  `test/analysis-core.test.js`, `schema.sql`, `scripts/check-frontend.js` ve
  `vercel.json` degisikliklerini P1O production state uzerine hunk bazinda
  ayirmak.
- Hangi degisikliklerin tekrar production'a alinmasi gerektigini belirlemek.
- P1O `/admin` route/header parity'yi kaybetmeden temiz patch setleri uretmek.

Bu P1Q icinde P1R uygulanmadi.
