# Public Archive P1L-fix Preview Env Readiness Plan

Tarih: 2026-08-01
Durum: Docs-only preview env readiness plan, env degisikligi yok

## Kapsam Kilidi

Bu dokuman P1L preview No-Go sebebini ve sonraki onayli preview env hazirligi
adimini planlar. Bu adimda kod yazilmadi, patch uygulanmadi, Vercel env
eklenmedi veya degistirilmedi, secret uretilmedi, secret degeri okunmadi veya
rapora yazilmadi, DB migration yapilmadi, DB'ye baglanilmadi, canli veri
okunmadi/yazilmadi, production deploy yapilmadi, production alias verilmedi,
push/commit yapilmadi, root `/` davranisi degistirilmedi ve public root arsiv
aktif edilmedi.

Feedback konusu bu hatta kapsam disidir; feedback okunmadi, kapatilmadi,
islenmedi, analiz edilmedi ve yeni kalite hatti acilmadi.

## A. Current P1L No-Go Summary

P1L'de Vercel preview basariyla olusturuldu:

```text
Preview URL: https://arsiv-kontrol-5tr08bh1p-ugurkarabulutts-projects.vercel.app
Deployment ID: dpl_CvwQxCWehpo94Zw9jQ8RqkYNjDit
Target: preview
```

P1L route/header smoke sonucu:

- `/` 200 HTML dondu; legacy root shell korundu.
- `/admin` 200 HTML dondu; `X-Robots-Tag: noindex, nofollow` ve strict
  `Cache-Control` gorundu.
- `/admin/` 200 HTML dondu; headerlar dogruydu.
- `/admin/smoke-test` 200 HTML dondu; headerlar dogruydu.
- `/manifest.webmanifest`, `/sw.js`, `/favicon.ico` 200 dondu.
- `/api/auth/me` HTML fallback'e dusmedi, fakat 500 `FUNCTION_INVOCATION_FAILED`
  dondu.

P1L genel karari No-Go idi. Gerekce: `/admin` route/header parity gecti, ancak
preview API/auth runtime dogrulanamadi.

## B. Root Cause

P1L'deki 500 hatasi bir `/admin` route/header patch hatasi degildir.

Kok neden:

```text
Error: SESSION_SECRET Vercel ortaminda zorunludur.
```

`server.js` Vercel ortaminda `SESSION_SECRET` yoksa module load asamasinda hata
firlatir. Bu nedenle `/api/auth/me` route'u HTML fallback'e dusmeden Vercel
Function seviyesinde 500 verir.

Bu cizgi onemlidir:

- `/api/auth/me` route ordering acisindan dogru sekilde `/server.js` hedefine
  gidiyor.
- Final `index.html` fallback tarafindan yutulmadigi goruldu.
- Function runtime env eksik oldugu icin API response tamamlanamadi.
- `SESSION_SECRET` preview ortaminda hazir olmadan admin/auth preview smoke
  tamamlanmis sayilamaz.

## C. SESSION_SECRET Usage

`SESSION_SECRET` kullanimi `server.js` icindedir.

Kod noktalarinin anlami:

- `server.js:24-27`: `OPENAI_API_KEY`, `SESSION_SECRET`, `SUPABASE_URL`,
  `SUPABASE_KEY` process env'den okunur.
- `server.js:25`: local fallback olarak `arsiv-gizli-v3-2025` tanimli; bu Vercel
  icin kabul edilmez.
- `server.js:41-43`: `process.env.VERCEL` mevcut ve `process.env.SESSION_SECRET`
  yoksa uygulama bilerek hata verir.
- `server.js:126-133`: `cookie-session` `keys: [SESSION_SECRET]` ile imzali
  `arsiv_session` cookie'sini kurar.
- `server.js:1224-1230`: `/api/auth/me` session cookie'yi okuyarak logged-out
  veya logged-in JSON response verir.

Neden required:

- Session cookie imzasi icin sabit ve gizli key gerekir.
- Vercel serverless runtime'da fallback secret kullanmak guvensizdir; farkli
  deployment/runtime davranisi session tutarliligini bozabilir.
- Bu nedenle kod Vercel'de eksik secret'i fail-fast olarak yakalar.

`authorization.js` sadece role helper fonksiyonlarini icerir; env veya secret
okumaz. Auth/session runtime'in env bagimliligi `server.js` icindedir.

## D. Preview Env Readiness Matrix

Secret degerleri bu dokumana yazilmayacak. Bu tablo yalniz env isimlerini,
gereklilik durumunu ve dogrulama yaklasimini gosterir.

| Env name | Preview smoke icin gerekli mi? | Production icin gerekli mi? | Secret mi? | Value rapora yazilacak mi? | Eksikse beklenen hata | Dogrulama yontemi | Production etkisi |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `SESSION_SECRET` | Evet | Evet | Evet | Hayir | Vercel Function startup 500; `SESSION_SECRET Vercel ortaminda zorunludur` | Preview env varliginin onayli kontrolu; redeploy sonrasi `/api/auth/me` smoke | Preview scope ile sinirlanirsa production etkisi yok |
| `SUPABASE_URL` | Evet | Evet | Hayir, ama public rapora yazilmasi gereksiz | Hayir | Startup'ta `SUPABASE_URL / SUPABASE_KEY tanimli degil` ve function failure | Env varligi kontrolu; `/api/auth/me`, login ve protected API smoke | Preview scope ile sinirlanirsa production etkisi yok |
| `SUPABASE_KEY` | Evet | Evet | Evet | Hayir | Supabase client kurulamaz veya API/seed/auth DB islemleri fail eder | Env varligi kontrolu; secret degeri raporlanmadan API smoke | Preview scope ile sinirlanirsa production etkisi yok |
| `OPENAI_API_KEY` | `/api/auth/me` icin hayir; metin denetimi pilotu icin evet | Evet | Evet | Hayir | AI/analiz endpointlerinde `API anahtari tanimli degil` veya fallback/config error | Preview admin pilotta analiz smoke gerekiyorsa env varligi kontrolu | Preview scope ile sinirlanirsa production etkisi yok |
| `OPENAI_TIMEOUT_MS` | Hayir | Hayir | Hayir | Hayir | Eksikse default `70000` kullanilir | Kod default'u yeterli | Yok |
| `ADMIN_PARALLEL_ROUTE_ENABLED` | Hayir; default enabled | Hayir | Hayir | Hayir | `0` verilirse `/admin` Express route kapanabilir | Preview config kontrolu; route smoke | Preview scope ile sinirlanirsa production etkisi yok |
| `PUBLIC_ARCHIVE_DEMO` | Hayir; bu hatta kapali/absent kalmali | Hayir | Hayir | Hayir | `1` olursa public demo router devreye girer ve scope karisabilir | Env yok/`0` olarak tutulur; root smoke public arsiv aktif degil mi kontrol eder | Preview scope ile sinirlanirsa production etkisi yok |
| `CRON_SECRET` | Hayir | Cron endpoint korumasi icin gerekli olabilir | Evet | Hayir | Cron endpoint auth davranisi etkilenebilir; P1L smoke kapsami degil | P1L-fix kapsaminda dogrulanmaz | Degistirilmez |
| `PORT` | Hayir | Hayir | Hayir | Hayir | Vercel otomatik runtime kullanir | Gerek yok | Yok |
| `VERCEL` | Vercel tarafindan otomatik | Vercel tarafindan otomatik | Hayir | Hayir | Yoksa Vercel-specific guard ve secure cookie kosulu farkli davranir | Runtime tarafindan saglanir | Kullanici yonetmez |
| `NODE_ENV` | Hayir | Platform tarafindan yonetilir | Hayir | Hayir | Cookie secure kosulu local/prod farkli olabilir | Platform default'u yeterli | Kullanici yonetmez |

Kodda CORS/origin/site URL icin zorunlu env bulunmadi. Cookie/session security icin
asli uygulama env'i `SESSION_SECRET`; `secure` cookie davranisi Vercel veya
production runtime algisina baglidir.

## E. Vercel Env Scope Plan

Vercel env scope'lari ayri ele alinmalidir.

### Production Env

- Bu P1L-fix adiminda production env degistirilmeyecek.
- `arsiv.ibrahimlive.ai` production davranisina dokunulmayacak.
- Production secret degerleri raporlanmayacak, terminale basilmayacak, git'e
  girmeyecek.

### Preview Env

- P1L No-Go sebebi preview runtime env eksikligidir.
- Hedef, production'a dokunmadan Preview environment icin gerekli env varligini
  saglamaktir.
- `SESSION_SECRET` preview icin eklenirse bu ayri ve acik onayli P1L-fix-B
  adimi olmalidir.
- Preview env update sonrasi yeni preview deployment gerekir; mevcut deployment
  otomatik olarak tam dogrulanmis sayilmaz.

### Development Env

- Local `.env` dosyasi bu adimda okunmadi ve okunmayacak.
- `.env.example` yalniz env isimleri icin incelendi.
- Development secret degerleri docs'a veya patch'e yazilmayacak.

## F. Safe Options

### Secenek A - Vercel Dashboard ile Preview env ekleme

Aciklama: Vercel Dashboard uzerinden yalniz Preview scope'a `SESSION_SECRET`
eklenir. Gerekirse diger preview runtime env varliklari da ayni sekilde kontrol
edilir.

Artlar:
- Secret degeri terminal gecmisine veya loglara girmez.
- Scope secimi gorsel olarak ayrilabilir.
- Production env'e dokunmama disiplini daha kolay korunur.

Eksiler:
- Manuel islem gerektirir.
- Sonrasinda yeni preview deployment gerekir.
- Dashboard'da yanlis scope secimi yapilirsa production etkilenebilir.

Risk:
- Yanlislikla Production scope secilirse production env degisir.
- Secret degeri paylasim kanallarinda yazilirsa guvenlik riski olusur.

Rollback:
- Preview scope env kaldirilir veya dogru degerle yeniden set edilir.
- Sorunlu preview deployment promote edilmez.

39 kullanici etkisi:
- Preview scope ile sinirli kalirsa aktif production kullanicilara etkisi yoktur.

Karar: Onerilir. En dusuk riskli varsayilan yol budur.

### Secenek B - Vercel CLI ile Preview env ekleme

Aciklama: Vercel CLI ile yalniz Preview scope'a env eklenir. Bu adim kullanici
onayi olmadan yapilmayacak.

Artlar:
- Tekrarlanabilir ve kayda gecirilebilir islem akisi saglar.
- Clean worktree/repo disipliniyle birlikte otomasyon kolaydir.

Eksiler:
- Secret degeri yanlis komut yazimiyla shell history/log'a girebilir.
- Scope parametresi yanlis verilirse production etkilenebilir.
- CLI login/proje baglantisi hatalari yeni risk uretir.

Risk:
- Secret echo, pipe veya komut satiri argumani olarak kullanilmamali.
- Komut ciktilarinda secret degeri gorunmemeli.

Rollback:
- Preview env Vercel Dashboard veya CLI ile kaldirilir/duzeltilir.
- Sorunlu preview deployment kullanilmaz.

39 kullanici etkisi:
- Preview scope ile sinirli kalirsa production kullanicilarina etkisi yoktur.

Karar: Onerilebilir, ancak sadece acik onayli P1L-fix-B adiminda ve secret
degeri loglanmadan.

### Secenek C - Preview-only test secret

Aciklama: Production secret'ini kullanmadan, yalniz preview icin guclu random bir
`SESSION_SECRET` kullanilir.

Artlar:
- Production secret'i preview hattina tasinmaz.
- Preview deployment session imzasi icin yeterlidir.
- Production riskini azaltir.

Eksiler:
- Preview ile production session cookie imzasi farkli olur; bu beklenen bir
  ayrimdir, fakat test yorumunda not edilmelidir.
- Secret uretimi ve saklanmasi ayrica dikkat gerektirir.

Risk:
- Zayif veya tekrar kullanilan secret secilirse guvenlik riski vardir.
- Deger rapora, terminal ciktilarina veya git'e yazilmamalidir.

Rollback:
- Preview env kaldirilir veya yeni preview-only secret ile degistirilir.
- Sorunlu preview deployment promote edilmez.

39 kullanici etkisi:
- Preview-only kalirsa production kullanicilarini etkilemez.

Karar: Onerilir. Dashboard secenegiyle birlikte en guvenli pratik yol olabilir.

### Secenek D - Auth endpoint'i preview'da skip etmek

Aciklama: Preview'da auth/session kontrolunu gecici devre disi birakmak veya
`/api/auth/me` smoke'u atlamak.

Artlar:
- Kisa vadede 500 engellenmis gibi gorunebilir.

Eksiler:
- Admin gecis hattinin asil riskini dogrulamaz.
- Session, login, auth redirect ve role kontrollerini bypass eder.
- P1M limited pilot icin guvenilir kanit uretmez.

Risk:
- Yanlis guven hissi olusturur.
- Auth/session regression'i saklayabilir.

Rollback:
- Skip kaldirilir; fakat kaybedilen dogrulama zamani geri kazanilmaz.

39 kullanici etkisi:
- Production'a tasinirsa yuksek risklidir.

Karar: Onerilmez.

## G. Recommended Path

Onerilen yol:

1. Production env'e dokunma.
2. Preview environment icin `SESSION_SECRET` varligi saglansin.
3. Bu islem acik onayli P1L-fix-B adimi olarak yapilsin.
4. Secret degeri rapora, terminal ciktilarina, commit'e, patch'e veya docs'a
   yazilmasin.
5. `SUPABASE_URL` ve `SUPABASE_KEY` preview runtime icin var mi, secret degerleri
   aciga cikarilmadan kontrol edilsin.
6. `/api/auth/me` icin sadece `SESSION_SECRET` degil, Vercel Function startup'in
   tum required envleriyle ayaga kalktigi dogrulansin.
7. Env hazirligi sonrasi ayni izole patch setiyle yeni Vercel preview deployment
   olusturulsun.
8. P1L smoke matrisi yeniden calistirilsin.

Bu adimda env degisikligi yapilmadi. P1L-fix-B icin kullanici onayi gerekir.

## H. P1L Retry Smoke Plan

Preview env readiness tamamlandiktan ve onayli yeni preview deployment
olusturulduktan sonra su route'lar tekrar test edilmeli:

| Route | Beklenen |
| --- | --- |
| `GET /` | 200 HTML; legacy root shell; public arsiv aktif degil |
| `GET /admin` | 200 HTML; `X-Robots-Tag: noindex, nofollow`; strict `Cache-Control` |
| `GET /admin/` | 200 HTML; `X-Robots-Tag: noindex, nofollow`; strict `Cache-Control` |
| `GET /admin/smoke-test` | 200 HTML; `X-Robots-Tag: noindex, nofollow`; strict `Cache-Control` |
| `GET /api/auth/me` | 500 degil; HTML fallback degil; logged-out durumda 200 JSON veya auth politikasina gore 401/403 JSON/non-HTML |
| `GET /manifest.webmanifest` | 200; manifest icerigi korunur |
| `GET /sw.js` | 200; JS icerigi korunur |
| `GET /favicon.ico` | 200; ICO/binary icerik korunur |

`/api/auth/me` icin No-Go belirtileri:

- 500 `FUNCTION_INVOCATION_FAILED`.
- `Content-Type: text/html`.
- `index.html` body.
- Route ordering nedeniyle final catch-all'a dusme.
- Session runtime veya cookie imza hatasi.

## I. Approval Gates

Asagidaki islemler icin acik kullanici onayi gerekir:

- Vercel env ekleme veya degistirme.
- Preview scope disinda herhangi bir env degisikligi.
- Vercel preview yeniden deploy.
- Herhangi bir push.
- Herhangi bir commit.
- Production deploy.
- Production alias verme veya production promote.
- Production env degisikligi.

Bu P1L-fix adiminda bu islemlerin hicbiri yapilmadi.

## J. Go / No-Go Criteria

Go kriterleri:

- `SESSION_SECRET` Preview env'de mevcut.
- Secret value raporlanmadi, terminale basilmedi, git'e girmedi.
- Production env degismedi.
- Preview redeploy acik onayli yapildi.
- `/api/auth/me` 500 degil.
- `/api/auth/me` HTML fallback degil.
- `/admin`, `/admin/`, `/admin/smoke-test` headerlari hala dogru.
- Root `/` hala legacy shell.
- Public root arsiv aktif degil.
- Patch seti izole kaldi; dirty workspace preview'a karismadi.

No-Go kriterleri:

- `SESSION_SECRET` hala eksik.
- Secret value log, rapor, docs veya git icinde gorunurse.
- Production env yanlislikla degisirse.
- `/api/auth/me` 500 verirse.
- `/api/auth/me` HTML fallback verirse.
- Root `/` public arsive donerse.
- `/admin` headerlari kaybolursa.
- Dirty workspace preview'a karisirsa.
- Kullanici soru sistemi veya public root bu hatta sokulursa.

## K. Next Recommended Step

Bir sonraki guvenli adim: P1L-fix-B approved preview env update + redeploy/smoke.

P1L-fix-B icin onerilen kapsam:

1. Kullanici acik onay verir.
2. Production env'e dokunulmaz.
3. Preview scope icin `SESSION_SECRET` varligi saglanir.
4. Gerekirse `SUPABASE_URL` ve `SUPABASE_KEY` preview varligi secret degerleri
   gosterilmeden dogrulanir.
5. Yeni preview deployment olusturulur; `--prod` kullanilmaz.
6. P1L retry smoke matrisi calistirilir.
7. Sonuc Go olursa P1M limited admin pilot planina gecilir.

Alternatif: Kullanici Vercel Dashboard'da Preview `SESSION_SECRET` degerini manuel
ekler ve ardindan P1L retry icin tekrar gorev verir.

P2A deferred scope:

- Kullanici oturum acma, soru gonderme, kendi sorularini ve cevaplarini takip etme,
  ekip/admin cevaplama, public arsive aday yapma ve once benzer arsiv cevaplarini
  gosterme akisi bu P1L-fix icinde uygulanmadi.
- Sistem chatbot gibi gorunmeyecek karari korunur.
- Bu kapsam P2A docs-only mimari adiminda ele alinmali.
