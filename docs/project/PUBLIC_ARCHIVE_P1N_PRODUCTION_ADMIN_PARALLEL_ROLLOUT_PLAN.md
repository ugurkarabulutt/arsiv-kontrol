# Public Archive P1N Production Admin Parallel Rollout Plan

Tarih: 2026-08-03
Durum: Docs-only production rollout plan; deploy yok

## A. Current State

`arsiv.ibrahimlive.ai` aktif production sistemidir ve yaklasik 39 ekip
kullanicisi halen root `/` uzerinden calismaktadir.

Mevcut guvenli gecis karari:

- Root `/` simdilik mevcut ekip/admin paneli olarak kalir.
- `/admin` ayni ekip/admin panelinin yeni paralel adresi olur.
- Public soru-cevap arsivi bu P1N kapsaminda acilmaz.
- Root `/` public arsive bu adimda cevrilmez.
- Eski root davranisi, ekip yeni adrese guvenli sekilde gecene kadar korunur.

Tamamlanan teknik hat:

- P1B Express/runtime tarafinda paralel `/admin`, `/admin/` ve `/admin/*`
  hazirligi icin patch artifact uretildi.
- P1G Vercel tarafinda `/admin` ve `/admin/(.*)` icin noindex ve strict
  cache header patch artifact'i uretildi.
- P1I `scripts/check-frontend.js` check alignment patch artifact'i uretildi;
  P1B-only ve P1B + P1G combined state ayrimi desteklenir.
- P1K clean preview candidate worktree'de uc patch birlikte dogrulandi.
- P1L-fix-C, kullanici tarafindan bildirilen sonuca gore Preview smoke'u
  basariyla kapatti: root legacy shell korundu, `/admin` headerlari dogru,
  `/api/auth/me` 200 JSON `{"loggedIn":false}` dondu, HTML fallback ve
  function startup hatasi gorulmedi.

Repo notu:

- `docs/project/PUBLIC_ARCHIVE_P1L_FIX_C_PREVIEW_ENV_MANUAL_GATE_RETRY.md`
  bu calisma agacinda bulunmadi.
- P1N, mevcut repo dokumanlari ile bu turda kullanici tarafindan bildirilen
  P1L-fix-C sonucuna dayanir.

Ana calisma agaci kirli durumdadir. Bu nedenle production adayi olarak ana
dirty workspace kullanilmamalidir; production candidate yalniz temiz
branch/worktree uzerinde izole uc patch setinden uretilmelidir.

## B. Production Rollout Goal

P1N hedef production davranisi:

| URL | P1N sonrasi hedef davranis |
| --- | --- |
| `https://arsiv.ibrahimlive.ai/` | Mevcut legacy ekip/admin paneli olarak kalir. |
| `https://arsiv.ibrahimlive.ai/admin` | Ayni ekip/admin panelinin yeni paralel adresi olur. |
| `https://arsiv.ibrahimlive.ai/admin/` | Browser refresh uyumlu admin shell doner. |
| `https://arsiv.ibrahimlive.ai/admin/smoke-test` | Deep link/refresh icin admin shell doner. |
| `https://arsiv.ibrahimlive.ai/api/*` | HTML fallback'e dusmeden API olarak kalir. |

Bu adimda public root yoktur. Public arsiv tasarimi ve root cutover ayri
P2B/P-public hattidir.

## C. Candidate Patch Set

Production'a alinacak izole patch seti yalniz su sirayla uygulanmalidir:

1. `docs/project/patches/PUBLIC_ARCHIVE_P1B_ONLY.patch`
2. `docs/project/patches/PUBLIC_ARCHIVE_P1G_VERCEL_ADMIN_NOINDEX.patch`
3. `docs/project/patches/PUBLIC_ARCHIVE_P1I_CHECK_FRONTEND_ALIGNMENT.patch`

Patchlerin amaci:

| Patch | Kapsam |
| --- | --- |
| `PUBLIC_ARCHIVE_P1B_ONLY.patch` | Express/runtime icinde `/admin`, `/admin/`, `/admin/*` paralel fallback; root `/` fallback korunur. |
| `PUBLIC_ARCHIVE_P1G_VERCEL_ADMIN_NOINDEX.patch` | Vercel'de `/admin` ve `/admin/(.*)` static index route'larina `X-Robots-Tag` ve strict cache header ekler. |
| `PUBLIC_ARCHIVE_P1I_CHECK_FRONTEND_ALIGNMENT.patch` | Check scriptini P1B-only ve P1B + P1G combined state'i ayiracak sekilde hizalar. |

## D. Expected Diff Boundary

Production candidate diff'i yalniz su dosyalari icermelidir:

- `server.js`
- `scripts/check-frontend.js`
- `vercel.json`

Production candidate'a karismamasi gereken dosyalar:

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
- public frontend dosyalari
- user question system dosyalari
- feedback fix veya kalite hattina ait degisiklikler

Not: Ana workspace'te `index.html` ve baska dosyalarda dirty degisiklikler
bulunabilir. Bunlar P1N production rollout adayina karistirilmamalidir.

## E. Pre-Production Gates

Production deploy ancak asagidaki kapilarin tamami gecerse dusunulebilir:

| Gate | Beklenen sonuc |
| --- | --- |
| Clean branch/worktree | Ana dirty workspace degil; izole production candidate kullanilir. |
| Patch apply | Uc patch sirayla ve manuel fix olmadan uygulanir. |
| Diff boundary | `git diff --name-only` yalniz `server.js`, `scripts/check-frontend.js`, `vercel.json` gosterir. |
| `vercel.json` parse | JSON parse basarili olur. |
| Route/header order | `/api` ve static routes `/admin` route'larindan once; `/admin` route'lari final catch-all'dan once; final catch-all `/index.html`. |
| `git diff --check` | Whitespace error yok. |
| `npm.cmd run check` | Basarili. |
| Local smoke | `/`, `/admin`, `/admin/`, `/admin/smoke-test`, `/api/auth/me`, manifest, `sw.js`, favicon gecer. |
| Preview smoke | P1L-fix-C sonucu gibi `/admin` headerlari ve `/api/auth/me` JSON dogrulanir. |
| Production env readiness | Production env varliklari valuesuz sekilde hazir kabul edilir; secret degerleri yazilmaz. |
| Human pilot | Admin + ekip uyesi pilotlari tamamlanir veya kullanici acik override verir. |

Production deploy oncesi ozel not:

- P1M dokumanlari repo icinde formal sonuclari pending gosterir.
- Kullanici bu turda ekip, admin ve super admin tarafinda sorun kalmadigini
  bildirdi.
- En temiz kayit icin P1M human results dokumani gercek PASS sonucuyla
  guncellenmeli; alternatif olarak kullanici production rollout icin acik
  override verdigini belirtmelidir.

## F. Production Smoke Matrix

Production rollout yapilirsa canli domain uzerinde hemen su smoke testi
calistirilir:

| Route | Beklenen status | Beklenen content | Beklenen header | No-Go belirtisi |
| --- | ---: | --- | --- | --- |
| `GET https://arsiv.ibrahimlive.ai/` | 200 | HTML legacy ekip/admin shell | Strict cache korunur | Public archive gorunurse veya root shell bozulursa |
| `GET https://arsiv.ibrahimlive.ai/admin` | 200 | HTML | `X-Robots-Tag: noindex, nofollow`; `Cache-Control` no-store/no-cache/must-revalidate/proxy-revalidate | Header eksik, 404/500 veya blank page |
| `GET https://arsiv.ibrahimlive.ai/admin/` | 200 | HTML | Ayni `/admin` headerlari | Header eksik, 404/500 veya blank page |
| `GET https://arsiv.ibrahimlive.ai/admin/smoke-test` | 200 | HTML | Ayni `/admin` headerlari | Deep link 404/500 veya header eksik |
| `GET https://arsiv.ibrahimlive.ai/api/auth/me` | 200/401/403 kabul edilebilir | JSON veya non-HTML auth response | HTML olmamali | 500, `index.html`, HTML fallback |
| `GET https://arsiv.ibrahimlive.ai/manifest.webmanifest` | 200 | Manifest JSON benzeri icerik | Static route korunur | 404 veya HTML fallback |
| `GET https://arsiv.ibrahimlive.ai/sw.js` | 200 | JavaScript | Static route korunur | 404 veya HTML fallback |
| `GET https://arsiv.ibrahimlive.ai/favicon.ico` | 200 | ICO/binary | Static route korunur | 404 veya HTML fallback |

Ek dogrulama:

- Root `/` public arsiv ana sayfasi gostermemelidir.
- `/api/auth/me` logged-out durumda `{"loggedIn":false}` gibi JSON donebilir.
- Admin login/session insan smoke'u ayri rol hesaplariyla denenmelidir.

## G. Production Deployment Safety

Bu P1N adiminda deploy yapilmaz. Sonraki onayli production rollout icin guvenli
strateji:

1. Temiz production candidate branch/worktree hazirlanir.
2. Yalniz uc patch sirayla uygulanir.
3. Diff boundary tekrar dogrulanir.
4. Local gates ve Preview smoke tekrar referanslanir.
5. Production env valuesuz varlik kontrolu yapilir.
6. Kullanici production deploy icin acik onay verir.
7. Vercel production target kullanilir; `arsiv.ibrahimlive.ai` production alias
   davranisi deploy sonrasi hemen dogrulanir.
8. Canli smoke test deploydan hemen sonra calistirilir.
9. Smoke sirasinda root veya API sorunu gorulurse rollout durdurulur ve rollback
   baslatilir.

Production env notu:

- `SESSION_SECRET`, `SUPABASE_URL`, `SUPABASE_KEY` ve `OPENAI_API_KEY` production
  icin gerekli degiskenlerdir.
- Secret degerleri rapora, terminal ozetine, Git'e veya dokumana yazilmaz.
- P1N'de production env degistirilmez.

Service worker/PWA notu:

- `sw.js` mevcut durumda fetch isteklerine mudahale etmez.
- Manifest `start_url` ve `scope` root `/` uzerindedir.
- P1N icin risk dusuktur; public root cutover oncesi PWA scope/cache stratejisi
  tekrar ayri degerlendirilmelidir.

## H. Rollback Plan

Rollback secenekleri:

1. Vercel onceki production deployment'a rollback.
2. Uc patch setini revert etmek.
3. Yalniz P1G `vercel.json` patch'ini geri almak.
4. Yalniz P1B `server.js` runtime route patch'ini geri almak.
5. Yalniz P1I `scripts/check-frontend.js` check alignment patch'ini geri almak.

En hizli production rollback:

- Vercel'de onceki bilinen saglam production deployment'a don.
- Canli `/`, `/api/auth/me`, `/health` ve static asset smoke testlerini tekrar
  calistir.
- Ekip etkilenmisse kisa operasyon notu ile mevcut root adresi kullanmaya devam
  etmeleri soylenir.

Rollback tetikleyicileri:

- `GET /` 404/500 veya blank page.
- `GET /` legacy ekip/admin shell yerine public arsiv gosterir.
- `/admin` 404/500 veya blank page.
- `/admin` noindex/headerlari yok.
- `/admin/smoke-test` deep link bozuk.
- `/api/auth/me` HTML fallback veya `index.html` doner.
- Login/session loop gorulur.
- Static asset route'lari bozulur.
- Mevcut root kullanan aktif ekip kullanicilari etkilenir.

DB rollback gerekmez; P1N patch seti DB migration veya veri yazimi icermez.

## I. Human Pilot Gate

Bilinen pilot durumu:

- P1M teknik Preview smoke gecmistir.
- P1M repo dokumanlari formal insan pilot sonuclarini pending gosterir.
- Kullanici son durumda ekip, admin ve super admin tarafinda sorun kalmadigini
  bildirmistir.

En guvenli karar:

- Production rollout oncesi P1M human results dokumani gercek PASS/FAIL
  sonuclariyla guncellenir.
- Super admin, admin, standard user ve mobile pilot alanlari tamamlanir.
- Login/logout/session, refresh, deep link, role boundary ve temel workflowlar
  PASS olmadan 39-user transition'a gecilmez.

Override yolu:

- Kullanici acik sekilde "P1M formal dokuman pending olsa da production paralel
  /admin rollout icin override veriyorum" derse, P1N production rollout ayri
  onayli adimda yapilabilir.
- Bu override yalniz paralel `/admin` production rollout icindir.
- 39-user transition duyurusu yine ayri asama olarak kalir.

## J. Team Communication Draft

Bu duyuru P1N'de gonderilmeyecek. Production `/admin` smoke basarili olduktan
sonra kullanilabilecek sade ekip metni:

```text
Merhaba,

Arsiv Kontrol icin yeni calisma adresimizi kademeli olarak aciyoruz:

https://arsiv.ibrahimlive.ai/admin

Mevcut adres bir sure daha calismaya devam edecek; sistem kapanmadi ve mevcut
akislariniz korunuyor. Bundan sonraki denemelerinizde mumkunse yeni adresi
kullanmanizi rica ederiz.

Giris, denetim, onaya gonderme, onay/red, bildirimler veya raporlarda bir sorun
gorurseniz lutfen hemen bildirin. Sorun olursa eski adres gecis suresince
calismaya devam edecektir.
```

## K. Go / No-Go Criteria

### Go

Production paralel `/admin` rollout ancak su kosullarla Go olabilir:

- Patch set izole ve sirali.
- Diff yalniz `server.js`, `scripts/check-frontend.js`, `vercel.json`.
- Local check basarili.
- Preview smoke basarili.
- Production env hazir.
- Production smoke plani hazir.
- Rollback plani hazir.
- Root `/` degismeyecek.
- Public archive acilmayacak.
- Admin + ekip pilotu tamam veya kullanici acik override verdi.

### No-Go

Asagidaki durumlardan biri varsa production rollout yapilmaz:

- Dirty workspace deploy edilmek istenirse.
- Diff beklenmeyen dosya icerirse.
- Admin/ekip pilot pending ve override yoksa.
- Preview `/api/auth/me` sorunluysa.
- Production env belirsizse.
- Rollback plani yoksa.
- Root `/` public'e cevrilmek istenirse.
- Public frontend, user question system veya feedback fix bu kapsama sokulursa.

Mevcut P1N karari:

```text
No-Go for immediate production rollout inside P1N.
Reason: P1N docs-only plan/checklist adimidir; deploy icin ayri acik onay gerekir.
Conditional Go for next step after formal human pilot result update or explicit override.
```

## L. Deferred Public Frontend Scope

Public frontend P2B deferred scope olarak kalir.

Hedef kalite cizgisi:

- Ultra premium deneyim.
- Acik/koyu mod.
- Arama merkezli bilgi erisimi.
- Apple sadeligi.
- Linear/Vercel modernligi.
- Stripe component kalitesi.
- Notion benzeri bilgi erisim rahatligi.
- Erisilebilir, yavas ve sakin konu/kavram akisi.
- Mobilde guclu okuma deneyimi.

Public root yalniz `/admin` production gecisi guvenli tamamlandiktan ve ekip
gecisi ayrica dogrulandiktan sonra acilir.

## M. Deferred User Question Scope

Kullanici soru sistemi P2A deferred scope olarak kalir.

P2A karar basliklari:

- Kullanici oturum acabilir.
- Kullanici soru gonderebilir.
- Kullanici kendi sorularini ve cevaplarini takip edebilir.
- Ekip/admin arkada cevaplayabilir.
- Uygun cevap public arsive aday yapilabilir.
- Kullanici soru yazdiginda once benzer arsiv cevaplari gosterilir.
- Sistem chatbot gibi gorunmez.
- Public arsive aktarim otomatik degil, ayri yayin karariyla olur.

Bu P1N icinde uygulanmaz.

## N. Explicit Exclusions

P1N kapsam disi konular:

- Kod degisikligi.
- Patch uygulama.
- Production deploy.
- Production alias.
- Push.
- Commit.
- DB migration.
- DB baglantisi.
- Canli veri okuma/yazma.
- Feedback okuma, kapatma, analiz etme, fix plani veya yeni kalite hatti.
- Auth/session core degisikligi.
- Admin business logic degisikligi.
- Root `/` davranisini public'e cevirme.
- Public root arsiv aktivasyonu.
- Public frontend kodlama.
- Kullanici soru sistemi kodlama.
- `public_qa` migration/model.
- Ana dirty workspace uzerinde destructive git islemi.

## O. Next Recommended Step

Onerilen siradaki guvenli adim:

```text
P1O Production Parallel /admin Rollout Execution - explicit approval required
```

P1O oncesi tercih edilen kucuk is:

1. P1M human pilot results dokumanini son gercek PASS sonuclariyla guncelle.
2. Temiz production candidate branch/worktree hazirla.
3. Uc patch setini sirayla uygula.
4. Diff boundary ve local gates'i tekrar calistir.
5. Kullanici production deploy icin acik onay verirse production rollout yap.
6. Deploydan hemen sonra production smoke matrix'i calistir.

P1O yapilmadan public frontend, root cutover veya 39-user transition duyurusu
baslatilmamalidir.
