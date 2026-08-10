# AGENTS.md — Arşiv Kontrol AI

Bu dosya projenin kalıcı hafızası ve değişiklik günlüğüdür. Codex her oturumda
bunu okur. Önemli kararlar, mimari ve yapılan değişiklikler buraya kaydedilir.

## Ortak Çalışma Protokolü

- Projede **OpenAI Codex ve Claude Code birlikte çalışır**; ikisi de önce bu dosyayı ve
  `CURRENT_HANDOFF.md` dosyasını okumalıdır.
- `AGENTS.md` mimari kararlar ve kalıcı hafıza için tek yetkili kaynaktır.
- `CURRENT_HANDOFF.md` sadece güncel çalışma ağacı, doğrulama ve sonraki adımı tutar.
- Her ajan işe başlamadan önce `git status -sb` ile diğer ajanın/kullanıcının değişikliklerini
  kontrol eder; tanımadığı değişiklikleri silmez veya geri almaz.
- Kod değişikliğinden sonra zorunlu doğrulama `npm run check` komutudur.
- “Yerelde tamamlandı”, “commit edildi”, “push edildi” ve “deploy edildi” ayrı durumlardır.
  Render deploy ancak push sonrası Render sonucu ve canlı `/health` doğrulanınca tamamlanmıştır.
- Kullanıcı feedback'i sonucunda bir kelime, sure adı, imlâ standardı veya noktalama kararı
  değiştirildiyse yalnız yeni denetim akışı düzeltilmiş sayılmaz. Önce canlı geçmişte etki
  taraması yapılır; `taslak`, `bekliyor`, `onaylandı` ve ileride yayınlanmış içeriklerde aynı
  yanlış ifade varsa doğru kabul edilen standarda kontrollü taşınır. Bu işlem `Geçmiş Düzeltme
  Merkezi` / `content_correction_log` ile geri alınabilir şekilde yapılmadan ilgili feedback
  kapatılmış kabul edilmez.

## Proje Özeti

**Arşiv Kontrol AI** — soru-cevap arşivi metinlerini, tanımlı imlâ/noktalama/yapı
kurallarına göre denetleyen ve düzelten bir kalite kontrol sistemi. OpenAI (gpt-4o)
ile metni analiz eder, hataları kategorilere ayırır, düzeltilmiş metni ve bir kalite
skoru döner.

- **Stack:** Node.js + Express (backend), tek sayfalık `index.html` (frontend), Supabase (PostgreSQL) veri katmanı.
- **Kimlik doğrulama:** `cookie-session` + `bcryptjs`. Roller: `super_admin`, `admin`, `user`.
  Ayrılmış `admin` kullanıcı adı her zaman tek süper admin hesabıdır.
- **AI:** OpenAI Chat Completions, `gpt-4o`, `temperature: 0`, JSON çıktı.
- **Dosya:** `.docx` yükleme `mammoth` ile düz metne çevrilir.

## Dizin / Dosya Yapısı

- `server.js` — tüm backend, API rotaları, Supabase erişimi, OpenAI çağrısı.
- `index.html` — tüm frontend (tek dosya).
- `schema.sql` — Supabase tablo şeması (ilk kurulumda SQL editöründe çalıştırılır).
- `.env` — yerel ortam değişkenleri (git'e **girmez**).
- `package.json` — bağımlılıklar ve scriptler.
- `analysis-core.js` — puanlama ve metin parmak izi gibi test edilebilir saf mantık.
- `test/` — Node yerleşik test runner testleri.
- `CURRENT_HANDOFF.md` — ajanlar arası güncel devir durumu.

## Ortam Değişkenleri

| Değişken          | Açıklama                                            |
|-------------------|-----------------------------------------------------|
| `OPENAI_API_KEY`  | OpenAI API anahtarı (analiz için zorunlu).          |
| `SUPABASE_URL`    | Supabase proje URL'i.                               |
| `SUPABASE_KEY`    | Supabase **service_role / secret** anahtarı (RLS'i bypass eder, yalnızca sunucuda). |
| `SESSION_SECRET`  | Oturum çerezi imzalama sırrı.                        |
| `PORT`            | Sunucu portu (Render otomatik atar, varsayılan 3000).|

## Veri Modeli (Supabase)

- **users** — `id, username, password(bcrypt hash), name, role, active, created_at`
- **history** — `id, user_id, username, name, filename, score, total_errors, cat_counts(jsonb), summary, corrected_text, status, approved_by, approved_at, created_at`
- **alerts** — `id, type, message, user_id, history_id, score, read, created_at`
- **settings** — `key, value` (kurallar `key='rules'` satırında saklanır)

İlk açılışta sunucu: `admin/admin123` kullanıcısını ve varsayılan kuralları (yoksa) seed eder.

## Kurallar (Denetim Mantığı)

Denetim kuralları `settings` tablosunda `rules` anahtarında metin olarak tutulur.
Admin panelinden düzenlenebilir. Varsayılan kural seti `server.js` içindeki
`DEFAULT_RULES` sabitindedir (8 kural başlığı: sözlük, imlâ, peygamber isimleri,
noktalama, zamirler, yapı, sayılar, etiketler).

## Geliştirme

```bash
npm install
npm run dev      # node --watch server.js
```

`.env` dosyasını doldur (yukarıdaki tablo). Supabase tabloları için `schema.sql`'i
bir kez Supabase SQL Editor'de çalıştır.

## Deploy (Vercel — Birincil)

- Vercel projesi: `ugurkarabulutts-projects/arsiv-kontrol`.
- Production alan adı: `arsiv.ibrahimlive.ai`.
- Uygulama `server.js` dosyasını Vercel Function olarak export eder; yerelde doğrudan
  çalıştırıldığında `app.listen` kullanır.
- Oturumlar serverless uyumlu, HttpOnly ve imzalı `cookie-session` çerezidir.
- Toplu analiz frontend tarafından en fazla iki eşzamanlı ayrı `/api/analyze-file`
  isteğine bölünür; tek uzun batch function isteği kullanılmaz.
- Vercel değişkenleri: `OPENAI_API_KEY`, `SUPABASE_URL`, `SUPABASE_KEY`, `SESSION_SECRET`.
- Production deploy tamamlandı sayılmadan önce `/health`, giriş, tek metin analizi ve PDF
  canlı alan adında doğrulanır.

## Eski/Alternatif Deploy (Render)

- **Type:** Web Service, **Build:** `npm install`, **Start:** `npm start`.
- Render ortam değişkenleri: `OPENAI_API_KEY`, `SUPABASE_URL`, `SUPABASE_KEY`, `SESSION_SECRET`.
- Render `PORT`'u otomatik enjekte eder; kod `process.env.PORT` kullanır.
- Veri Supabase'de kalıcıdır; Render instance yeniden başlasa da veri kaybolmaz
  (eski `db.json` dosya tabanlı yaklaşımının aksine).

## Puanlama Mantığı

Skor sunucu tarafında **yetkili** olarak hesaplanır (`finalizeResult`), AI'ın döndürdüğü
skor kullanılmaz. Formül: `100 - Σ(hata sayısı × ağırlık)`, min 0.
Ağırlıklar: sözlük −5, imlâ −4, noktalama −3, etiket −2, yapı −4.
Skor < 60 ise düzeltilmiş metin üretilmez (`correctedText=''`), özet alanına standart
uyarı mesajı yazılır; hatalar yine listelenir.

## Tekrar-Gönderim Kontrolü

Her denetimde normalize edilmiş metnin SHA-256 parmak izi `history.text_hash`'e
yazılır. Aynı kullanıcı aynı metni tekrar gönderirse denetim yapılmadan uyarı döner.
Eski `ilk 100 karakter + uzunluk` parmak izleri geriye dönük olarak tanınır.
`text_hash` kolonu yoksa özellik otomatik devre dışı kalır (`HAS_TEXT_HASH` startup'ta
tespit edilir).

## Değişiklik Günlüğü

### 2026-08-11
- **Arşiv Çalışmaları ilk ekip-uyum UX fazı eklendi:** `/admin` süper admin arşiv çalışma
  alanı ekip liderinin Drive / kişi e-tablosu düzenine daha yakın olacak şekilde sadeleştirildi.
  Görünen ana başlık `Arşiv Çalışmaları` oldu; alt menü adları `Dosyalar`, `Yeni Kaynak`,
  `Kaynak Dosyaları`, `Yayın Linkleri`, `Çalışma Tabloları`, `Hadisler ve Slaytlar`,
  `Dosya Yükle`, `Yayına Hazır Kayıtlar`, `Son Kontrol`, `Yayın Dosyaları`, `Çıktılar`
  ve `Excel Etiketleri` olarak güncellendi. Genel bakış kartları ekip liderinin dokümanındaki
  klasör yapısına göre `Çalışma Tabloları`, `Yayın Linkleri`, `Hadisler`, `Slayt Metinleri`,
  `Standartlar`, `Youtube Dökümanları` ve `Dosya Yükle` başlıklarına çekildi.
  `Çalışma Tabloları` ekranına `Kişi Dosyaları` alanı eklendi: mevcut çalışma satırları ve
  yayın linkleri `assignedTo` alanına göre kişi kartlarında özetlenir; kişi seçilince çalışma
  satırları ve yayın linkleri aynı kişi adına göre süzülür ve seçili kişinin yayın linkleri
  panelde URL, durum, yayın tarihi, platform ve notla görünür. Bu fazda DB/schema migration
  yapılmadı, root `/` public cutover yapılmadı ve public frontend dosyalarına dokunulmadı.
  Değişen dosyalar: `index.html`, `scripts/check-frontend.js`, `server.js`, `AGENTS.md`,
  `CURRENT_HANDOFF.md`. Yerel doğrulama: `node --check server.js`, `node scripts/check-frontend.js`,
  `git diff --check` ve `npm.cmd run check` başarılı; 86/86 test geçti. Ek lokal görsel/viewport
  testinde 1440x1000 PC ve 390x900 mobil ölçekte `Kişi Dosyaları` ve seçili kişi `Yayın Linkleri`
  paneli doğrulandı; yatay taşma veya eski teknik başlık görünmedi. Runtime commit `444e786`
  GitHub'a push edildi ve production'a alındı. Production deploy:
  `https://arsiv-kontrol-q0cms9c9u-ugurkarabulutts-projects.vercel.app`, canlı alias
  `https://arsiv.ibrahimlive.ai`. Canlı smoke: `/health`, root `/`, `/admin`, `/admin/`,
  `/admin/smoke-test`, `/api/auth/me`, manifest, `sw.js` ve favicon başarılı. `/admin`
  header'ları noindex/no-store doğru. Canlı HTML'de `Arşiv Çalışmaları`, `Kişi Dosyaları`,
  `Yayın Linkleri` ve `Çalışma Tabloları` mevcut; eski `Arşiv Operasyon Merkezi`,
  `Yayın Görevleri`, `Çalışma Kayıtları`, `adminRouteProbe` ve public preview marker'ı yok.

### 2026-08-10
- **Admin onay akışı hızlandırıldı ve onaylayan yetkili görünür oldu:** `/admin` onay/red
  işleminde kullanıcı 15 saniye civarı `İşleniyor...` bekleyebiliyordu; kök sebep frontend'in
  onay POST'u bittikten sonra onay panosu, tüm denetim geçmişi ve rozet yenilemeyi sırayla
  beklemesi ve backend'in onay yanıtında büyük metin alanlarını geri seçmesiydi. Onay endpoint'i
  artık yalnız admin UI için gereken hafif alanları döndürür; onay panosu liste sorgusu da
  `original_text` / `corrected_text` gibi büyük alanları çekmez. Frontend POST başarılı olur
  olmaz butonu `Onaylandı` / `Reddedildi` durumuna alır, pano/rozet yenilemeyi arka planda yapar.
  `approved_by` değeri artık `Ad (kullanıcı adı)` formatında saklanır ve yalnız admin/süper admin
  yüzünde onay panosu, denetim geçmişi ve detay modalında gösterilir. Normal kullanıcı
  `/api/history` ve `/api/history/:id/approval-status` yanıtlarında `approvedBy/approvedAt`
  bilgisi almaz; public/root çıktısına onaylayan yetkili bilgisi taşınmaz. Kapsam: `server.js`,
  `index.html`, `scripts/check-frontend.js`, `AGENTS.md`, `CURRENT_HANDOFF.md`.
  Yerel doğrulama: `node --check server.js`, `node scripts/check-frontend.js`,
  `git diff --check` ve `npm.cmd run check` başarılı; 86/86 test geçti.

- **Etiket Aktarımı eşleşmeyen kayıtlar için Excel aday seçimi tamamlandı:** `/admin` süper
  admin Arşiv Operasyon Merkezi içindeki `Etiket Aktarımı` ekranında eşleşmeyen kayıtlar için
  `Excel Adayları` paneli eklendi. Panel, canlı aktarım listesine bağlı Excel satır havuzundan
  en yakın adayları getirir; aday kartında Excel satırı, soru, cevap ön izlemesi, etiketler,
  güven skoru ve eşleşme nedeni görünür. Süper admin `Bu Satırı Seç` dediğinde seçilen Excel
  satırındaki soru ve etiketler ilgili denetim kaydına uygulanır; manuel seçimde soru alanı
  seçilen Excel sorusuyla güncellenebilir, normal toplu uygulama ise daha önce elle yazılmış
  soruları korumaya devam eder. Yeni batch oluşturulurken Excel satır havuzu `settings` altında
  parça parça cache'lenir; eski batch silinirse bu cache kayıtları da temizlenir. Mevcut canlı
  batch `b46a4689-15b5-4db8-a917-cdb33ed6be3c` için `Arşiv Data.xlsx` dosyasından 3.779
  kullanılabilir Excel satırı 69 cache parçası olarak canlı `settings` tablosuna yazıldı.
  Bu adım root `/` public cutover veya public frontend hattına dokunmaz. Kapsam: `server.js`,
  `index.html`, `scripts/check-frontend.js`, `AGENTS.md`, `CURRENT_HANDOFF.md`.
  Yerel doğrulama: `node --check server.js`, `node scripts/check-frontend.js`,
  `git diff --check` ve `npm.cmd run check` başarılı; 86/86 test geçti.

### 2026-08-09
- **Excel soru aktarımı sunucu tarafında gerçekten ilerleyen hale getirildi:** `/admin`
  süper admin Arşiv Operasyon Merkezi içindeki `Etiket Aktarımı > Excel Sorularını Ekle`
  akışı ikinci kez güçlendirildi. Kök sebep, önceki iyileştirmeye rağmen Vercel serverless
  ortamında devam işinin `setTimeout` ile arka planda sürmeye çalışması ve soru yazımlarının
  satır satır ilerlemesiydi; mobilde ekran uyuyunca veya kullanıcı uygulamadan çıkınca sayaç
  ekranda kalabiliyordu. Artık `start` ve `status` istekleri kendi güvenli süreleri içinde işi
  gerçekten ilerletir, eksik `history.question_text` alanları toplu `upsert` ile yazılır, mevcut
  soru alanları korunur ve iş durumu `settings` altında kaldığı yerden devam edecek şekilde
  saklanır. Frontend tamamlanan işi anında kapatır, devam eden işi `Sorular Arka Planda
  Ekleniyor` olarak gösterir ve `boş soru alanı tamamlandı` sayacıyla kullanıcıya sade bilgi
  verir. DB/schema migration gerekmedi; root `/` public cutover ve public frontend hattına
  dokunulmadı. Kapsam: `server.js`, `index.html`, `scripts/check-frontend.js`.
  Doğrulama: `node --check server.js`, `node scripts/check-frontend.js`, `git diff --check`
  ve `npm.cmd run check` başarılı; 86/86 test geçti. Runtime commit `9cd8eb5` GitHub'a push
  edildi ve production'a alındı. Production deploy:
  `https://arsiv-kontrol-7mdutzbz4-ugurkarabulutts-projects.vercel.app`, canlı alias
  `https://arsiv.ibrahimlive.ai`. Canlı smoke: `/health`, root `/`, `/admin`, `/admin/`,
  `/admin/smoke-test`, `/api/auth/me`, manifest, `sw.js` ve favicon başarılı. `/admin`
  header'ları noindex/no-store doğru. Canlı HTML'de `/backfill-questions/start`,
  `/backfill-questions/status`, `Sorular Arka Planda Ekleniyor` ve
  `boş soru alanı tamamlandı` mevcut; eski geçici `adminRouteProbe` yok. Oturumsuz soru
  aktarımı başlangıç endpoint'i `401` döndü. Canlı Excel soru aktarımı ayrıca arka plandan
  tamamlandı: `Arşiv Data.xlsx` listesindeki 2.800 uygulanmış eşleşmenin 2.798'inde soru alanı
  dolu; 389 boş soru alanı dolduruldu, 2 kayıt Excel'de soru hücresi boş geldiği için güvenle
  uydurulmadı.

- **Excel soru aktarımı ekran kapanmasına dayanıklı hale getirildi:** `/admin` süper admin
  Arşiv Operasyon Merkezi içindeki `Etiket Aktarımı > Excel Sorularını Ekle` akışı artık
  telefon ekranı kapanınca, kullanıcı başka uygulamaya geçince veya tarayıcı bağlantısı
  kısa süreli kesilince tek uzun frontend isteğine bağlı kalmaz. Soru aktarımı sunucu tarafında
  `settings` içinde kayıtlı, devam edebilir bir iş olarak başlatılır; frontend yalnız durumu
  izler. Kullanıcı sayfadan ayrılırsa işlem kaydı korunur, kullanıcı geri döndüğünde durum
  otomatik kontrol edilir ve gerekirse iş kaldığı yerden yeniden tetiklenir. Bağlantı kopması
  artık doğrudan kırmızı hata penceresine düşmez; sistem bekleyen aktarımı hatırlar. Yeni
  endpoint'ler: `POST /api/history-tags/import-batches/:id/backfill-questions/start` ve
  `GET /api/history-tags/import-batches/:id/backfill-questions/status`. Eski
  `/backfill-questions` endpoint'i uyumluluk için korunur. DB/schema migration gerekmedi;
  root `/` public cutover ve public frontend hattına dokunulmadı. Kapsam:
  `server.js`, `index.html`, `scripts/check-frontend.js`. Doğrulama:
  `node --check server.js`, `node scripts/check-frontend.js`, `git diff --check` ve
  `npm.cmd run check` başarılı; 86/86 test geçti. Runtime commit `d4b88d1` GitHub'a
  push edildi ve production'a alındı. Production deploy:
  `https://arsiv-kontrol-bkj94n47f-ugurkarabulutts-projects.vercel.app`, canlı alias
  `https://arsiv.ibrahimlive.ai`. Canlı smoke: `/health`, root `/`, `/admin`, `/admin/`,
  `/admin/smoke-test`, `/api/auth/me`, manifest, `sw.js` ve favicon başarılı. `/admin`
  header'ları noindex/no-store doğru. Canlı HTML'de `/backfill-questions/start`,
  `/backfill-questions/status`, `archive-question-backfill-pending` ve
  `Soru Aktarımı Sürüyor` mevcut; public preview marker'ı yok. Oturumsuz soru aktarımı
  başlangıç endpoint'i `401` döndü.

- **Soru-cevap soru alanı ve Excel soru aktarımı eklendi:** `/admin` denetim akışında kullanıcı
  artık denetim sonucunu onaya göndermeden önce cevaba bağlı `Soru` metnini ve virgülle ayrılmış
  `Etiketler` bilgisini elle eklemek zorundadır; soru veya en az bir etiket yoksa kayıt onay
  kuyruğuna gönderilmez. Bu iki alan denetim motoruna sokulmaz; onay ve yayın hazırlığı için
  kayıtla birlikte saklanır. İş Panosu detay penceresinde admin/süper admin bu
  soruyu ve etiketleri görüp onaydan önce düzeltebilir; onay işlemi bu son değerleri kaydeder.
  Excel etiket aktarımında eşleşen kayıtlar için Excel'deki soru metnini `history.question_text`
  alanına taşıyan yeni kontrollü akış eklendi. `Excel Sorularını Ekle` yalnız daha önce uygulanmış
  eşleşmelerde boş kalan soru alanlarını doldurur; kullanıcı/admin tarafından elle yazılmış sorular
  korunur, etiketlere ve cevap metnine dokunmaz. Backend endpoint'i:
  `POST /api/history-tags/import-batches/:id/backfill-questions`. Canlı DB için
  `schema.sql` içindeki `alter table public.history add column if not exists question_text text;`
  satırı uygulanmalıdır. Root `/` public cutover ve public frontend hattına dokunulmadı. Kapsam:
  `server.js`, `index.html`, `schema.sql`, `scripts/check-frontend.js`.

- **Etiket aktarımı toplu uygulama canlı şema uyumsuzluğu düzeltildi:** `/admin` süper admin
  Arşiv Operasyon Merkezi içindeki `Etiket Aktarımı` ekranında `Güvenli Eşleşmeleri Uygula`
  işlemi canlıda önce bazı kayıtları uygulayıp sonra
  `column history_tag_import_matches.updated_at does not exist` hatasına düşebiliyordu. Kök
  sebep, parça parça uygulama sorgusunun `history_tag_import_matches` tablosunda bulunmayan
  `updated_at` kolonuyla sıralama istemesiydi. Sorgu artık canlı şemada kesin bulunan
  `confidence` ve `id` sıralamasıyla çalışır; daha önce uygulanmış kayıtlar korunur ve kalan
  kayıtlar kaldığı yerden uygulanabilir. `scripts/check-frontend.js` bu yanlış sıralamanın geri
  gelmesini engelleyen guard içerir. SQL/DB migration gerekmedi; root `/` public cutover ve
  public frontend hattına dokunulmadı. Yerel doğrulama: `node --check server.js`,
  `node scripts/check-frontend.js`, `git diff --check` ve `npm.cmd run check` başarılı;
  86/86 test geçti. Runtime commit `678e8c2` GitHub'a push edildi ve production'a alındı.
  Production deploy: `https://arsiv-kontrol-d3x39k8ee-ugurkarabulutts-projects.vercel.app`,
  canlı alias `https://arsiv.ibrahimlive.ai`. Canlı smoke: `/health`, root `/`, `/admin`,
  `/admin/`, `/admin/smoke-test`, `/api/auth/me` başarılı; `/admin` header'ları
  noindex/no-store doğru. Oturumsuz toplu uygulama endpoint'i `401` döndü. Canlı HTML'de
  `applyHistoryTagImportMatchesInSteps`, `historyTagImportApplyReadyBtn` ve
  `historyTagImportApplyReviewBtn` mevcut.

- **Etiket aktarımı toplu uygulama zaman aşımı düzeltildi:** `/admin` süper admin Arşiv
  Operasyon Merkezi içindeki `Etiket Aktarımı` ekranında `Güvenli Eşleşmeleri Uygula`
  aksiyonu 2.000+ kaydı tek sunucu isteğinde uygulamaya çalıştığı için canlıda uzun süre
  `uygulanıyor` durumunda kalıp `Sunucu beklenmeyen bir yanıt verdi` uyarısına düşebiliyordu.
  Toplu uygulama artık 60 kayıtlık güvenli adımlarla çalışır; her adım kısa sunucu cevabı
  döner, ekranda kaç kaydın uygulandığı ve kaç kaydın kaldığı görünür. Aynı parça parça
  altyapı `Kontrol Gerekenleri Uygula` aksiyonunda da kullanılır. Tekil `Etiketi Bu Kayda
  Uygula` akışı korunur. SQL/DB migration gerekmedi; root `/` public cutover ve public
  frontend hattına dokunulmadı. Kapsam: `server.js`, `index.html`,
  `scripts/check-frontend.js`, `AGENTS.md`, `CURRENT_HANDOFF.md`. Yerel doğrulama:
  `node --check server.js`, `node scripts/check-frontend.js`, `git diff --check` ve
  `npm.cmd run check` başarılı; 86/86 test geçti. Runtime commit `cdf81c0` GitHub'a push
  edildi ve production'a alındı. Production deploy:
  `https://arsiv-kontrol-3t0plkpzr-ugurkarabulutts-projects.vercel.app`, canlı alias
  `https://arsiv.ibrahimlive.ai`. Canlı smoke: `/health`, root `/`, `/admin`, `/admin/`,
  `/admin/smoke-test`, `/api/auth/me` başarılı; `/admin` header'ları noindex/no-store doğru.
  Canlı HTML'de `applyHistoryTagImportMatchesInSteps`, `historyTagImportApplyReadyBtn`,
  `historyTagImportApplyReviewBtn` ve `limit:60` mevcut.

- **Etiket aktarımı kontrol grubu toplu uygulaması eklendi:** `/admin` süper admin Arşiv
  Operasyon Merkezi içindeki `Etiket Aktarımı` ekranında durum filtresi `Kontrol gerekenler`
  seçildiğinde üst aksiyon alanında `Kontrol Gerekenleri Uygula` butonu görünür. Bu aksiyon
  yalnız seçili aktarım listesindeki `review` eşleşmelerini uygular; hazır, eşleşmeyen, atlanan
  veya uygulanmış kayıtlara dokunmaz. İşlemden önce sistem içi onay penceresi etkilenecek kayıt
  sayısını gösterir. Backend'e süper admin korumalı
  `POST /api/history-tags/import-batches/:id/apply-review` endpoint'i eklendi. SQL/DB migration
  gerekmedi; root `/` public cutover ve public frontend hattına dokunulmadı. Kapsam:
  `server.js`, `index.html`, `scripts/check-frontend.js`, `AGENTS.md`, `CURRENT_HANDOFF.md`.
  Yerel doğrulama: `node --check server.js`, `node scripts/check-frontend.js`,
  `git diff --check` ve `npm.cmd run check` başarılı; 86/86 test geçti. Runtime commit
  `d3fb222` GitHub'a push edildi ve production'a alındı. Production deploy:
  `https://arsiv-kontrol-pmw7r50gz-ugurkarabulutts-projects.vercel.app`, canlı alias
  `https://arsiv.ibrahimlive.ai`. Canlı smoke: `/health`, root `/`, `/admin`, `/admin/`,
  `/admin/smoke-test`, `/api/auth/me`, manifest, `sw.js` ve favicon başarılı. `/admin`
  header'ları noindex/no-store doğru. Canlı HTML'de `Kontrol Gerekenleri Uygula` ve
  `apply-review` mevcut; eski geçici `adminRouteProbe` yok.

- **Etiket aktarımı kullanıcı dili sadeleştirildi:** `/admin` süper admin Arşiv Operasyon
  Merkezi içindeki `Etiket Aktarımı` ekranında teknik `parti` ifadesi görünür kullanıcı
  dilinden çıkarıldı. Ekip için daha anlaşılır olması amacıyla ekranda artık `aktarım listesi`
  veya kısaca `liste` dili kullanılır. `Yüksek Güvenlileri Uygula` butonu
  `Güvenli Eşleşmeleri Uygula`, `Partileri Yenile` butonu `Listeyi Yenile`, `Aktarım
  partileri` başlığı `Aktarım listeleri` olarak değiştirildi. Backend hata mesajları ve
  frontend uyarıları da aynı sade dile çekildi; `scripts/check-frontend.js` eski teknik
  etiketlerin geri sızmasını engelleyen guard içerir. Kapsam: `server.js`, `index.html`,
  `scripts/check-frontend.js`. SQL/DB migration gerekmedi; root `/` public cutover ve public
  frontend hattına dokunulmadı. Yerel doğrulama: `node --check server.js`,
  `node scripts/check-frontend.js`, `git diff --check` ve `npm.cmd run check` başarılı;
  86/86 test geçti. Runtime commit `0956960` GitHub'a push edildi ve proje notlarına işlendi.
  Production deploy: `https://arsiv-kontrol-6889s8jsp-ugurkarabulutts-projects.vercel.app`,
  canlı alias `https://arsiv.ibrahimlive.ai`. Canlı smoke: `/health`, root `/`, `/admin`,
  `/admin/`, `/admin/smoke-test`, `/api/auth/me`, manifest, `sw.js` ve favicon başarılı.
  `/admin` header'ları noindex/no-store doğru. Canlı HTML'de `Güvenli Eşleşmeleri Uygula`,
  `Listeyi Yenile`, `Aktarım listeleri` ve `Seçili Aktarımı Sil` mevcut; eski
  `Yüksek Güvenlileri Uygula`, `Partileri Yenile`, `Aktarım partileri` ve geçici
  `adminRouteProbe` yok.

- **Etiket aktarımı eski dosya/parti temizleme eklendi:** `/admin` süper admin Arşiv Operasyon
  Merkezi içindeki `Etiket Aktarımı` ekranında `Yenile` ve `Partileri Yenile` yalnız listeyi
  tazelediği için kullanıcı eski Excel aktarımını ekrandan kaldıramıyordu. Ekrana `Seçili
  Aktarımı Sil` aksiyonu eklendi; sistem içi onay penceresi bu işlemin denetim kayıtlarını
  silmeyeceğini ve daha önce uygulanmış etiketleri geri almayacağını açıkça söyler. Backend'e
  süper admin korumalı `DELETE /api/history-tags/import-batches/:id` endpoint'i eklendi. Bu
  endpoint yalnız seçili aktarım partisini ve ona ait eşleşme önerilerini siler; `history`
  kayıtlarına ve uygulanmış etiketlere dokunmaz. Aktif parti silinince frontend eski seçimi
  elde tutmaz; varsa listedeki sonraki parti açılır, yoksa ekran boş parti durumuna döner.
  Kapsam: `server.js`, `index.html`, `scripts/check-frontend.js`. SQL/DB migration gerekmedi;
  root `/` public cutover ve public frontend hattına dokunulmadı. Yerel doğrulama:
  `node --check server.js`, `node scripts/check-frontend.js`, `git diff --check` ve
  `npm.cmd run check` başarılı; 86/86 test geçti. Runtime commit `9ab6532` GitHub'a push edildi
  ve production'a alındı. Production deploy:
  `https://arsiv-kontrol-44w0dpfy4-ugurkarabulutts-projects.vercel.app`, canlı alias
  `https://arsiv.ibrahimlive.ai`. Canlı smoke: `/health`, root `/`, `/admin`, `/admin/`,
  `/admin/smoke-test`, `/api/auth/me`, manifest, `sw.js` ve favicon başarılı. `/admin`
  header'ları noindex/no-store doğru; canlı HTML'de `Seçili Aktarımı Sil` ve
  `deleteHistoryTagImportBatch` mevcut; oturumsuz silme endpoint'i `401` döndü.

- **Etiket aktarımı sayaç uyumsuzluğu düzeltildi:** `Arşiv Data.xlsx` importundan sonra
  `2.991 Denetim Kaydı` görünmesine rağmen `Hazır + Kontrol + Eşleşmedi` toplamı yalnız
  `1.000` ediyordu. Kök sebep `refreshHistoryTagImportBatchCounts` fonksiyonunun
  `history_tag_import_matches` satırlarını Supabase varsayılan 1000 satır cevabıyla saymasıydı.
  Sayaç yenileme artık `fetchAllPages` ile tüm eşleşme satırlarını sayar; mevcut bir aktarım
  partisi açıldığında da parti sayaçları yeniden hesaplanıp kayda yazılır. Böylece mevcut
  partiler dosya yeniden yüklenmeden yenilenince doğru dağılımı gösterir. Kapsam: `server.js`,
  `scripts/check-frontend.js`. SQL/DB migration gerekmedi; root `/` public cutover ve public
  frontend hattına dokunulmadı. Yerel doğrulama: `node --check server.js`,
  `node scripts/check-frontend.js`, `git diff --check` ve `npm.cmd run check` başarılı;
  86/86 test geçti. Runtime commit `2fdeb3f` GitHub'a push edildi ve production'a alındı.
  Production deploy: `https://arsiv-kontrol-m1bw5lweh-ugurkarabulutts-projects.vercel.app`,
  canlı alias `https://arsiv.ibrahimlive.ai`. Canlı smoke: `/health`, root `/`, `/admin`,
  `/admin/`, `/admin/smoke-test`, `/api/auth/me`, manifest, `sw.js` ve favicon başarılı;
  oturumsuz import batch endpoint'i `401` döndü.

- **Etiket aktarımı opsiyonel history kolonlarına dayanıklı hale getirildi:** Büyük Excel
  yükleme artık parçalara bölündükten sonra canlı DB'de `history.prompt_version` kolonu
  bulunmadığı için `column history.prompt_version does not exist` hatasına düşüyordu. Etiket
  aktarımı geçmiş kayıtlarını okurken artık `original_text`, `tags`, `prompt_version` ve
  `rules_hash` gibi sonradan eklenmiş kolonları startup'ta tespit edilen canlı şemaya göre
  seçer; olmayan opsiyonel kolonlar sorguya eklenmez. Böylece eski/eksik schema üzerinde de
  etiket eşleştirme devam eder. Kapsam: `server.js`, `scripts/check-frontend.js`. SQL/DB
  migration gerekmedi; root `/` public cutover ve public frontend hattına dokunulmadı. Yerel
  doğrulama: `node --check server.js`, `node scripts/check-frontend.js`, `git diff --check` ve
  `npm.cmd run check` başarılı; 86/86 test geçti. Runtime commit `75d2a55` GitHub'a push edildi
  ve production'a alındı. Production deploy:
  `https://arsiv-kontrol-1et3fa4c5-ugurkarabulutts-projects.vercel.app`, canlı alias
  `https://arsiv.ibrahimlive.ai`. Canlı smoke: `/health`, root `/`, `/admin`, `/admin/`,
  `/admin/smoke-test`, `/api/auth/me`, manifest, `sw.js` ve favicon başarılı; oturumsuz upload
  start endpoint'i `401` döndü ve eski geçici `adminRouteProbe` yok.

- **Etiket aktarımı büyük Excel yükleme sınırı çözüldü:** `/admin` süper admin `Arşiv
  Operasyon Merkezi > Etiket Aktarımı` ekranında `Arşiv Data.xlsx` gibi büyük Excel dosyaları
  tek istekle gönderildiğinde Vercel `413 Request Entity Too Large` /
  `FUNCTION_PAYLOAD_TOO_LARGE` hatası döndürüyordu. Etiket aktarımı artık dosyayı frontend'de
  384 KB'lık güvenli parçalara böler; backend parçaları geçici olarak `settings` içinde
  saklar, tamamlanınca birleştirir ve mevcut eşleştirme ön izlemesini üretir. Yeni süper admin
  korumalı endpoint'ler: `POST /api/history-tags/import/upload/start`,
  `POST /api/history-tags/import/upload/chunk` ve
  `POST /api/history-tags/import/upload/complete`. Doğrudan preview endpoint'i geriye dönük
  korunur, fakat ana UI artık parça parça yükleme kullanır. DB/schema SQL'i gerekmedi; root `/`
  public cutover ve public frontend hattına dokunulmadı. Yerel doğrulama:
  `node --check server.js`, `node scripts/check-frontend.js`, `git diff --check` ve
  `npm.cmd run check` başarılı; 86/86 test geçti. Runtime commit `5384b7b` GitHub'a push
  edildi ve production'a alındı. Production deploy:
  `https://arsiv-kontrol-as23vbkgr-ugurkarabulutts-projects.vercel.app`, canlı alias
  `https://arsiv.ibrahimlive.ai`. Canlı smoke: `/health`, root `/`, `/admin`, `/admin/`,
  `/admin/smoke-test`, `/api/auth/me`, manifest, `sw.js` ve favicon başarılı. `/admin`
  header'ları noindex/no-store doğru. Canlı HTML'de chunk upload marker'ları mevcut; eski
  geçici `adminRouteProbe` yok. Oturumsuz upload start endpoint'i `401` döndü.

- **Etiket aktarımı upload akışı sağlamlaştırıldı:** `/admin` süper admin `Arşiv Operasyon
  Merkezi > Etiket Aktarımı` ekranında Excel yükleme sırasında görülen `Sunucu yanıtı
  okunamadı` hatası için import API'si inceltildi. Upload endpoint'i artık history kayıtlarında
  yalnız gerekli kolonları çeker, uzun metinlerde eşleştirme aday metnini kontrollü sınırlar,
  eşleşmeleri tek büyük insert yerine küçük parçalara bölerek yazar ve ilk cevapta tam denetim
  metinleri yerine kısa ön izleme döndürür. Frontend JSON dışı/eksik cevaplarda kör hata yerine
  HTTP durumunu içeren okunabilir hata mesajı gösterir. Bu adım etiket eşleştirme kararını
  otomatik uygulamaz; yine süper admin ön izleme sonrası tek tek veya yüksek güvenli kayıtları
  toplu uygular. Kapsam: `server.js`, `index.html`, `scripts/check-frontend.js`. DB/schema,
  root `/` public cutover ve public frontend hattına dokunulmadı. Yerel doğrulama:
  `node --check server.js`, `node scripts/check-frontend.js`, `git diff --check` ve
  `npm.cmd run check` başarılı; 86/86 test geçti. Runtime commit `4a5de61` GitHub'a push
  edildi ve production'a alındı. Production deploy:
  `https://arsiv-kontrol-7siqlcblu-ugurkarabulutts-projects.vercel.app`, canlı alias
  `https://arsiv.ibrahimlive.ai`. Canlı smoke: `/health`, root `/`, `/admin`, `/admin/`,
  `/admin/smoke-test`, `/api/auth/me`, manifest, `sw.js` ve favicon başarılı. `/admin`
  header'ları noindex/no-store doğru. Canlı HTML'de `Etiket Aktarımı` ve
  `readHistoryTagImportUploadResponse` mevcut; eski geçici `adminRouteProbe` yok. Oturumsuz
  import preview endpoint'i `401` döndü.

- **Soru-cevap etiketleri ve Excel etiket aktarımı hazırlandı:** Denetim sonucu onaya
  gönderilirken kullanıcı artık virgülle ayrılmış sınırsız etiket girebilir; Türkçe karakterler
  korunur ve etiket alanı denetim motoruna sokulmaz. Admin/süper admin onay modalında bu
  etiketleri görüp düzelterek onaylayabilir; denetim geçmişi, onay listesi ve CSV çıktısı
  etiketleri taşır. Süper admin `Arşiv Operasyon Merkezi > Etiket Aktarımı` ekranında mevcut
  Excel arşiv dosyasını yükleyip `Soru`, `Etiket/Sınıf` ve `Cevap` kolonlarını geçmiş denetim
  kayıtlarıyla kontrollü eşleştirebilir. Sistem her geçmiş denetim kaydı için en yakın Excel
  satırını önerir; mevcut etiketler kırmızı, Excel'den gelecek etiketler yeşil gösterilir.
  Eşleşmeler `Hazır`, `Kontrol gerekli`, `Eşleşmedi`, `Uygulandı` ve `Atlandı` durumlarıyla
  ayrılır. Süper admin tek tek uygulayabilir veya yalnız yüksek güvenli hazır eşleşmeleri
  toplu uygulayabilir; toplu işlem backend tarafında sayfalı çalışır ve 500 kayıtla yarım
  kalmaz. Kapsam: `server.js`, `index.html`, `schema.sql`, `scripts/check-frontend.js`,
  `package.json`, `package-lock.json`. Kalıcı kullanım için gereken `history.tags`,
  `history_tag_import_batches` ve `history_tag_import_matches` SQL blokları kullanıcı
  tarafından canlı Supabase'de başarıyla uygulandı. Yerel doğrulama: `node --check server.js`,
  `node scripts/check-frontend.js`, inline script syntax kontrolü, `git diff --check` ve
  `npm.cmd run check` başarılı; 86/86 test geçti. Runtime commit `39632bd` GitHub'a push
  edildi ve production'a alındı. Production deploy:
  `https://arsiv-kontrol-g20iz8gfg-ugurkarabulutts-projects.vercel.app`, canlı alias
  `https://arsiv.ibrahimlive.ai`. Canlı smoke: `/health`, root `/`, `/admin`, `/admin/`,
  `/admin/smoke-test`, `/api/auth/me`, manifest, `sw.js` ve favicon başarılı. `/admin`
  header'ları noindex/no-store doğru. Canlı HTML'de `Etiket Aktarımı`,
  `/api/history-tags/import/preview` ve `id="submitApprovalTags"` mevcut; eski geçici
  `adminRouteProbe` ve public preview marker'ı yok. Oturumsuz import preview endpoint'i
  `401` döndü. Root `/` public arşive çevrilmedi ve public frontend workstream'ine
  dokunulmadı.

- **Desktop Arşiv Operasyon Merkezi menü görünürlüğü düzeltildi:** `/admin` süper admin
  desktop sol menüsünde `Arşiv Operasyon Merkezi` grubu `Geri Bildirim` bölümünün altında
  kaldığı için küçük ekran yüksekliğinde görünmüyor gibi algılanabiliyordu. Desktop sidebar
  sırası değiştirildi; grup artık `Operasyon` bölümünde `İş Panosu`ndan hemen sonra görünür.
  Mobil menü, `/admin` koşulu ve süper admin yetki sınırı korunur. Frontend guard'a desktop
  sidebar sırasını doğrulayan kontrol eklendi. Kapsam: `index.html`,
  `scripts/check-frontend.js`. DB/schema/root `/` ve public frontend hattına dokunulmadı.
  Yerel doğrulama: `node --check server.js`, `node scripts/check-frontend.js`,
  `git diff --check` ve `npm.cmd run check` başarılı; 86/86 test geçti.

### 2026-08-08
- **Public JSON kalite kapisi eklendi:** `/admin` super admin Arsiv Operasyon Merkezi
  icindeki `Paket Cikti Merkezi`, public on yuz icin JSON uretmeden once artik ikinci bir
  yayin uygunluk kontrolu calistirir. Backend `validateArchivePublicRecords` ile her public
  kayitta baslik, metin, slug, kaynak izi, tekrar slug ve public alanda gorunmemesi gereken ic
  surec ifadelerini (`AI`, `admin`, `prompt`, `model`, `denetim`, `kalite kontrol`,
  `onay kuyrugu`, `test verisi`) kontrol eder. Bloklayici hata varsa `public-json` ciktisi
  bos doner, `blocked:true` ve `publicReadiness` raporu gelir; frontend `Public yayin
  kontrolu` kartinda engel/uyari listesini gosterir ve Public JSON kopyalama/indirme
  aksiyonlarini kapatir. Uyarilar bloklamaz ama super adminin kayit bazinda son kontrol
  yapmasini saglar. Kapsam: `server.js`, `index.html`, `scripts/check-frontend.js`,
  `AGENTS.md`, `CURRENT_HANDOFF.md`. DB/schema/root `/` ve public frontend hattina
  dokunulmadi. Yerel dogrulama: `npm.cmd run check` basarili, 86/86 test gecti. Runtime
  commit `23d101e` GitHub'a push edildi ve production'a alindi. Production deploy:
  `https://arsiv-kontrol-1t5youj5a-ugurkarabulutts-projects.vercel.app`, canli alias
  `https://arsiv.ibrahimlive.ai`. Canli smoke: `/health`, root `/`, `/admin`, `/admin/`,
  `/admin/smoke-test`, `/api/auth/me`, manifest, `sw.js` ve favicon basarili. `/admin`
  header'lari noindex/no-store dogru. Canli HTML'de `Public yayin kontrolu`,
  `archiveOutputPublicReadinessHtml` ve `Public JSON kalite kontrolunden gecmedi` marker'lari
  mevcut; eski gecici `adminRouteProbe` yok. Oturumsuz public-json output endpoint'i `401`
  dondu.

- **Public kayıt JSON sözleşmesi eklendi:** `/admin` süper admin Arşiv Operasyon Merkezi
  içindeki `Paket Çıktı Merkezi` artık kilitli, `Hazır` durumundaki ve paket son kontrolü
  tamamlanmış yayın paketlerinden public ön yüz için temiz kayıt sözleşmesi üretebilir.
  Yeni `public-json` çıktı formatı, paket içindeki kaynak/çalışma/yayın görevi kayıtlarını
  `schemaVersion`, `slug`, `title`, `summary`, `question`, `answer`, `body`, `category`,
  `topics`, `source`, `publication`, `seo`, `reading` ve `updatedAt` alanlarıyla JSON olarak
  verir. Bu çıktı public arşiv ön yüzünün okuyacağı ara katmandır; public root açmaz, kullanıcıya
  AI/admin/denetim/prompt gibi iç süreç ifadeleri taşımaz ve DB/schema migration gerektirmez.
  Frontend'e `Public Kayıt Sözleşmesi` kartı, `Public Kayıtları Hazırla`, `Public JSON Kopyala`
  ve `Public JSON İndir` aksiyonları eklendi. Değişen dosyalar: `server.js`, `index.html`,
  `scripts/check-frontend.js`, `AGENTS.md`, `CURRENT_HANDOFF.md`. Yerel doğrulama:
  `node --check server.js`, `node scripts/check-frontend.js`, `git diff --check` ve
  `npm.cmd run check` başarılı; temiz branch'te 86/86 test geçti. Runtime commit `471d09e`
  GitHub'a push edildi ve production'a alındı. Production deploy:
  `https://arsiv-kontrol-aw1nx17w4-ugurkarabulutts-projects.vercel.app`, canlı alias
  `https://arsiv.ibrahimlive.ai`. Canlı smoke: `/health`, root `/`, `/admin`, `/admin/`,
  `/admin/smoke-test`, `/api/auth/me`, manifest, `sw.js` ve favicon başarılı. `/admin`
  header'ları noindex/no-store doğru. Canlı HTML'de `value="public-json"`,
  `Public Kayıt Sözleşmesi` ve `prepareArchivePublicRecordsOutput` mevcut; eski geçici
  `adminRouteProbe` ve public preview marker'ı yok. Oturumsuz public-json output endpoint'i
  `401` döndü.

- **Paket Çıktı Merkezi yayın takibi eklendi:** `/admin` süper admin Arşiv Operasyon
  Merkezi içindeki `Paket Çıktı Merkezi` artık yalnız JSON/Markdown/CSV çıktı üretmez; çıktı
  sonrası yayın yaşam döngüsünü de aynı paket üzerinde takip eder. Hazır ve kilitli paketler
  için `Yayın Takibi` kartı eklendi: yayın/arşiv linki, kısa not, `Yayına Verildi`,
  `Arşive Aktarıldı` ve `Geri Alındı` durumları tutulur. `Yayına Verildi` ve
  `Arşive Aktarıldı` kararları backend tarafında da yalnız hazır, kilitli ve son kontrolü
  tamamlanmış paketlere uygulanabilir; hazır olmayan paketlerin yayın takibine yanlışlıkla
  alınması engellenir. Yayın durumu paket listesinde, detayda ve çıktı manifestinde görünür;
  Markdown çıktısına yayın takibi/link/not bilgisi eklenir. Bu adım DB/schema/root `/` veya
  public frontend hattına dokunmaz; paket verisi mevcut `settings.archive_ops_release_packages`
  JSON kaydında saklanır. Değişen dosyalar: `server.js`, `index.html`,
  `scripts/check-frontend.js`, `AGENTS.md`, `CURRENT_HANDOFF.md`. Yerel doğrulama:
  `node --check server.js`, `node scripts/check-frontend.js`, `git diff --check` ve
  `npm.cmd run check` başarılı; 258/258 test geçti.

- **Yayın Paketi Çıktı Merkezi eklendi:** `/admin` süper admin Arşiv Operasyon Merkezi içine
  `Paket Çıktı Merkezi` alt ekranı eklendi. Bu ekran yalnız kilitlenmiş, `Hazır` durumundaki
  ve paket son kontrolü tamamlanmış yayın paketlerinden çıktı üretir. Süper admin hazır
  paketleri arayabilir, paket kontrol durumunu görebilir ve seçili paket için JSON, Markdown
  veya CSV çıktısı oluşturup kopyalayabilir ya da indirebilir. Backend'e süper admin korumalı
  `GET /api/archive-ops/release-packages/:id/output` endpoint'i eklendi. Çıktı üretimi yalnız
  paket özetindeki kısa ön izlemeyi değil, kaynak/çalışma/yayın görevi kayıtlarının tam metnini
  kullanır. Hazır olmayan, kilitlenmemiş veya kontrolü eksik paketler için çıktı üretimi
  frontend ve backend tarafında engellenir. Bu adım DB/schema/root `/` veya public frontend
  hattına dokunmaz. Değişen dosyalar: `server.js`, `index.html`, `scripts/check-frontend.js`,
  `AGENTS.md`, `CURRENT_HANDOFF.md`. Yerel doğrulama: `node --check server.js`,
  `node scripts/check-frontend.js`, `git diff --check` ve `npm.cmd run check` başarılı;
  258/258 test geçti. Runtime commit `9778806` GitHub'a push edildi ve production'a alındı.
  Production deploy: `https://arsiv-kontrol-2ea67lvbt-ugurkarabulutts-projects.vercel.app`,
  canlı alias `https://arsiv.ibrahimlive.ai`. Canlı smoke: `/health`, root `/`, `/admin`,
  `/admin/`, `/admin/smoke-test`, `/api/auth/me`, manifest, `sw.js` ve favicon başarılı.
  `/admin` header'ları noindex/no-store doğru. Canlı HTML'de `Paket Çıktı Merkezi`,
  `archiveOutputPackageList`, `generateArchivePackageOutput` ve `/output?format=` mevcut;
  eski geçici `adminRouteProbe` yok. Oturumsuz çıktı endpoint'i `401` döndü.

- **Yayın Paketleri son hazırlık kilidi eklendi:** `/admin` süper admin Arşiv Operasyon
  Merkezi içindeki `Yayın Paketleri` akışı artık paket içindeki her kayıt için ayrı paket son
  kontrol durumu tutar: `Kontrol bekliyor`, `Kontrol edildi`, `Revizyon gerekli`, `Beklet`.
  Paket ancak temel hazırlık kontrolleri eksiksizse ve paketteki tüm kayıtlar `Kontrol edildi`
  ise `Son Hazırlığa Kilitle` ile kilitlenebilir. Kilitli pakette başlık, not, durum, kayıt
  ekleme/çıkarma, kayıt kontrol durumu değiştirme ve paket silme frontend ve backend tarafında
  engellenir; süper admin gerekirse kilidi kaldırınca paket `Son kontrol` durumuna döner.
  Yeni süper admin korumalı API'ler: `POST /api/archive-ops/release-packages/:id/items/:itemId/review`,
  `POST /api/archive-ops/release-packages/:id/lock`, `POST /api/archive-ops/release-packages/:id/unlock`.
  Bu adım DB/schema/root `/` veya public frontend hattına dokunmaz. Değişen dosyalar:
  `server.js`, `index.html`, `scripts/check-frontend.js`, `AGENTS.md`, `CURRENT_HANDOFF.md`.
  Yerel doğrulama: `node --check server.js`, `node scripts/check-frontend.js` ve
  `npm.cmd run check` başarılı; 258/258 test geçti.
  Runtime commit `2a7c868` GitHub'a push edildi ve production'a alındı. Production deploy:
  `https://arsiv-kontrol-la84ec20y-ugurkarabulutts-projects.vercel.app`, canlı alias
  `https://arsiv.ibrahimlive.ai`. Canlı smoke: `/health`, root `/`, `/admin`, `/admin/`,
  `/admin/smoke-test`, `/api/auth/me`, manifest, `sw.js` ve favicon başarılı. `/admin`
  header'ları noindex/no-store doğru. Canlı HTML'de `Son Hazırlığa Kilitle`,
  `Paket son kontrolü`, `lockArchiveReleasePackageUi` ve release package API markerları mevcut;
  eski geçici `adminRouteProbe` yok. Oturumsuz release package ve item review API erişimleri
  `401` döndü.

- **Yayın Paketleri son kontrol katmanı eklendi:** `/admin` süper admin Arşiv Operasyon
  Merkezi içindeki `Yayın Paketleri` detay ekranı artık yayın öncesi paketleri yalnız gruplamaz;
  paket yayına hazır mı değil mi kontrol eder. Paket başlığı, paket içeriği, yayın notu ve
  paket içindeki her aday kayıt için başlık, metin, kategori, kaynak izi, kavramlar ve yayın
  görevi linki kontrolleri görünür. Hazır kontroller yeşil, uyarılar sarı, engelleyici eksikler
  kırmızı gösterilir. Paket içindeki kayıtlar `Kaydı Aç` ile ilgili Kaynak Havuzu, Çalışma
  Kayıtları veya Yayın Görevleri ekranında açılabilir; kayıtlar tek tek paketten çıkarılabilir.
  Eksik başlık, metin, kategori, kaynak izi veya boş paket varsa `Hazır` durumuna alma frontend
  ve backend tarafında engellenir. Bu adım DB/schema/root `/` veya public frontend hattına
  dokunmaz. Değişen dosyalar: `server.js`, `index.html`, `scripts/check-frontend.js`,
  `AGENTS.md`, `CURRENT_HANDOFF.md`. Yerel doğrulama: `node --check server.js`,
  `node scripts/check-frontend.js` ve `npm.cmd run check` başarılı; 258/258 test geçti.
  Runtime commit `7db1d20` GitHub'a push edildi ve production'a alındı. Production deploy:
  `https://arsiv-kontrol-84203zb09-ugurkarabulutts-projects.vercel.app`, deployment
  `dpl_8Dc6uCKDBKQi6V5SFtffGXCy9Upd`, canlı alias `https://arsiv.ibrahimlive.ai`.
  Canlı smoke: `/health`, root `/`, `/admin`, `/admin/`, `/admin/smoke-test`,
  `/api/auth/me`, manifest, `sw.js` ve favicon başarılı. `/admin` header'ları noindex/no-store
  doğru. `/api/archive-ops/release-packages` oturumsuz erişimde `401` döndü. Canlı HTML'de
  `Yayın Paketleri`, `archiveReleasePackageReview`, `archiveReleaseItemChecksHtml`,
  `openArchiveReleaseItemRecord`, `archive-release-review` ve `archive-release-checks` mevcut;
  eski geçici `adminRouteProbe` yok.

- **Yayın Paketleri pilotu eklendi:** `/admin` süper admin Arşiv Operasyon Merkezi içine
  `Yayın Paketleri` alt ekranı eklendi. Bu ekran `yayina_hazir` durumundaki public arşiv
  adaylarını yayın öncesi paketlerde gruplamak için hazırlandı. Süper admin paket başlığı,
  durum ve not tutabilir; paketlerde arama/durum filtresi kullanabilir; yayına hazır kaynak,
  çalışma ve yayın görevi adaylarını seçip pakete ekleyebilir veya paketten tek tek çıkarabilir.
  Paket kayıtları şimdilik ayrı DB migration gerektirmeden `settings.archive_ops_release_packages`
  JSON anahtarında saklanır; aday kayıtlarının durumunu otomatik değiştirmez. Bu adım root `/`
  public cutover yapmaz ve public frontend hattına dokunmaz. Değişen dosyalar: `server.js`,
  `index.html`, `scripts/check-frontend.js`, `AGENTS.md`, `CURRENT_HANDOFF.md`. Yerel doğrulama:
  `node --check server.js`, `node scripts/check-frontend.js` ve `npm.cmd run check` başarılı,
  258/258 test geçti; `git diff --check` whitespace hatası vermedi, yalnız mevcut CRLF uyarıları
  görüldü. Runtime commit `9e3147d` GitHub'a push edildi ve production'a alındı. Production
  deploy: `https://arsiv-kontrol-fy73775lo-ugurkarabulutts-projects.vercel.app`, deployment
  `dpl_7aaPH2LWgQ3EsDPawt1cNmCrqbUC`, canlı alias `https://arsiv.ibrahimlive.ai`. Canlı smoke:
  `/health`, root `/`, `/admin`, `/admin/`, `/admin/smoke-test`, `/api/auth/me`, manifest,
  `sw.js` ve favicon başarılı. `/admin` header'ları noindex/no-store doğru.
  `/api/archive-ops/release-packages` oturumsuz erişimde `401` döndü. Canlı HTML'de
  `Yayın Paketleri`, `archiveReleasePackageTitle`, `loadArchiveReleasePackages` ve
  `/api/archive-ops/release-packages` mevcut; eski geçici `adminRouteProbe` yok.

- **Yayın Hazırlık Kuyruğu eklendi:** `/admin` süper admin Arşiv Operasyon Merkezi içine
  `Yayın Hazırlık Kuyruğu` alt ekranı eklendi. Bu ekran yalnız `yayina_hazir` durumundaki
  public arşiv adaylarını çeker ve adayları normal aday havuzundan ayrı bir son hazırlık
  kuyruğunda gösterir. Süper admin kaynak, çalışma ve yayın görevi türlerine göre filtre
  kullanabilir, kayıt içinde arama yapabilir, yayına hazır/kaynak/çalışma/yayın görevi/eksik
  kontrol sayılarını görebilir, seçilen kaydın kaynak izi, hazırlık checklist'i, metin ön
  izlemesi ve public görünüm ön izlemesini okuyabilir. Seçili kayıt ilgili Kaynak Havuzu,
  Çalışma Kayıtları veya Yayın Görevleri ekranında açılabilir. Uygun olmayan kayıtlar tek tek
  `Son Kontrole Geri Al`, `Revizyon Gerekli`, `Kaynak Eksik` veya `Beklet` kararına taşınır;
  karar yalnız seçili kayda uygulanır. Bu adım backend/DB/schema/root `/` veya public frontend
  hattına dokunmadı. Değişen dosyalar: `index.html`, `scripts/check-frontend.js`,
  `AGENTS.md`, `CURRENT_HANDOFF.md`. Yerel doğrulama: `npm.cmd run check` başarılı,
  258/258 test geçti; `git diff --check` whitespace hatası vermedi, yalnız mevcut CRLF
  uyarıları görüldü. Marker kontrolü `archiveReadySearch`, `archiveReadyList`,
  `archiveReadyDetail`, `loadArchiveReadyQueue`, `setArchiveReadyDecision` ve
  `Yayın Hazırlık Kuyruğu` öğelerini doğruladı. Runtime commit `2773205` GitHub'a push
  edildi ve production'a alındı. Production deploy:
  `https://arsiv-kontrol-4xdicabl9-ugurkarabulutts-projects.vercel.app`, deployment
  `dpl_9bT8Mino37cBvQPVhNjatrHFtLqG`, canlı alias `https://arsiv.ibrahimlive.ai`.
  Canlı smoke: `/health`, root `/`, `/admin`, `/admin/`, `/admin/smoke-test`,
  `/api/auth/me`, manifest, `sw.js` ve favicon başarılı. `/admin` header'ları
  noindex/no-store doğru. `/api/archive-ops/public-candidates?status=yayina_hazir`
  oturumsuz erişimde `401` döndü. Canlı HTML'de `Yayın Hazırlık Kuyruğu`,
  `archiveReadySearch`, `loadArchiveReadyQueue` ve `setArchiveReadyDecision` mevcut;
  eski geçici `adminRouteProbe` yok.

- **Public Arşiv Adayları son kontrol paneli kullanışlı hale getirildi:** `/admin` süper
  admin Arşiv Operasyon Merkezi içindeki `Public Arşiv Adayları` detay ekranına yayın öncesi
  son kontrol katmanı eklendi. Seçilen aday artık yalnız metin ön izlemesi ve karar butonlarıyla
  görünmez; başlık, metin, kategori, kavram ve kaynak izi için okunabilir bir hazırlık kontrolü,
  eksik alanlar özeti, kaynak/çalışma/yayın bağlantı izi ve public arşiv kartında nasıl
  görüneceğini gösteren ön izleme paneli birlikte görünür. Karar önerisi eksik alanlara göre
  otomatik açıklama verir; karar yine yalnız seçili adaya uygulanır. Mobil görünümde uzun başlık,
  kaynak linki ve metin ön izlemesi taşma üretmemesi için aday paneline özel responsive kurallar
  eklendi. Backend/DB/schema/root `/` ve public frontend hattına dokunulmadı. Değişen dosyalar:
  `index.html`, `scripts/check-frontend.js`, `AGENTS.md`, `CURRENT_HANDOFF.md`. Yerel doğrulama:
  `npm.cmd run check` başarılı, 258/258 test geçti; `git diff --check` whitespace hatası
  vermedi, yalnız mevcut CRLF uyarıları görüldü. Runtime commit `f1052d4` GitHub'a push edildi
  ve production'a alındı. Production deploy:
  `https://arsiv-kontrol-nhrwlycof-ugurkarabulutts-projects.vercel.app`, deployment
  `dpl_B8vX5285Fo7g2ecqaseNdxNtzeZn`, canlı alias `https://arsiv.ibrahimlive.ai`. Canlı smoke:
  `/health`, root `/`, `/admin`, `/admin/`, `/admin/smoke-test`, `/api/auth/me`, manifest,
  `sw.js` ve favicon başarılı. `/admin` header'ları noindex/no-store doğru. Canlı HTML'de
  `candidate-review-grid`, `archiveCandidateChecklistHtml`, `Public görünüm ön izlemesi` ve
  `Yayın öncesi durum` mevcut; eski geçici `adminRouteProbe` yok.

- **Public Arşiv Adayları karar akışı eklendi:** `/admin` süper admin Arşiv Operasyon
  Merkezi içindeki `Public Arşiv Adayları` ekranı yalnız adayları listelemekle kalmaz; seçilen
  kaynak, çalışma kaydı veya yayın görevi için public arşiv kararını doğrudan uygulayabilir.
  Süper admin adayları karar durumuna göre filtreleyebilir: `Son kontrol bekliyor`,
  `Yayına hazır`, `Kaynak eksik`, `Revizyon gerekli` ve `Beklet`. Seçilen aday detayında kısa
  karar notu yazılıp ilgili kayıt tek kayda özel güncellenir; karar izi kaydın not alanına en
  son karar en üstte kalacak şekilde eklenir. Backend'e süper admin korumalı
  `POST /api/archive-ops/public-candidates/:kind/:id/decision` endpoint'i eklendi. Karar
  güncellemesi `archive_sources`, `archive_work_items` ve `archive_publish_tasks` kayıtlarıyla
  aynı veri modelini kullanır; yeni DB/schema migration yapılmadı, root `/` public arşive
  çevrilmedi ve public frontend hattına dokunulmadı. Değişen dosyalar: `server.js`,
  `index.html`, `scripts/check-frontend.js`, `AGENTS.md`, `CURRENT_HANDOFF.md`. Doğrulama:
  `npm.cmd run check` başarılı, 258/258 test geçti; `git diff --check` whitespace hatası
  vermedi, yalnız mevcut CRLF uyarıları görüldü. Runtime commit `3f47cd9` GitHub'a push edildi
  ve production'a alındı. Production deploy:
  `https://arsiv-kontrol-iqwk45bnb-ugurkarabulutts-projects.vercel.app`, deployment
  `dpl_HGNLLYiY3L14rsS5FYrJzM6mXMja`, canlı alias `https://arsiv.ibrahimlive.ai`. Canlı smoke:
  `/health`, root `/`, `/admin`, `/admin/`, `/admin/smoke-test`, `/api/auth/me`, manifest,
  `sw.js` ve favicon başarılı. `/admin` header'ları noindex/no-store doğru. Canlı HTML'de
  `archiveCandidateStatusFilter`, `setArchiveCandidateDecision` ve
  `/api/archive-ops/public-candidates` mevcut; eski geçici `adminRouteProbe` yok.

### 2026-08-07
- **Public Arşiv Adayları gerçek aday havuzuna bağlandı:** `/admin` süper admin Arşiv
  Operasyon Merkezi içindeki `Public Arşiv Adayları` ekranı statik açıklama olmaktan çıkarıldı.
  Ekran artık mevcut gerçek veri kaynaklarından `arsiv_adayi` durumundaki kayıtları tek yerde
  toplar: `archive_sources`, `archive_work_items` ve `archive_publish_tasks`. Süper admin aday
  kayıtları arayabilir, kayıt türüne göre filtreleyebilir, toplam/kaynak/çalışma/yayın görevi
  sayılarını görebilir, seçilen adayın kaynak izi ve metin ön izlemesini okuyabilir, aday
  kaydını ilgili Kaynak Havuzu, Çalışma Kayıtları veya Yayın Görevleri ekranında açabilir.
  Backend'e süper admin korumalı `GET /api/archive-ops/public-candidates` endpoint'i eklendi;
  yeni DB/schema migration yapılmadı ve root `/` public arşive çevrilmedi. Değişen dosyalar:
  `server.js`, `index.html`, `scripts/check-frontend.js`, `AGENTS.md`, `CURRENT_HANDOFF.md`.
  Doğrulama: `npm.cmd run check` başarılı, 258/258 test geçti; `git diff --check` whitespace
  hatası vermedi, yalnız mevcut CRLF uyarıları görüldü. Runtime commit `479fcbd` GitHub'a
  push edildi ve production'a alındı. Production deploy:
  `https://arsiv-kontrol-p92k8g1im-ugurkarabulutts-projects.vercel.app`, canlı alias
  `https://arsiv.ibrahimlive.ai`. Canlı smoke: `/health`, root `/`, `/admin`, `/admin/`,
  `/admin/smoke-test`, `/api/auth/me`, manifest, `sw.js` ve favicon başarılı. `/admin`
  header'ları noindex/no-store doğru. Canlı HTML'de `archiveCandidateSearch`,
  `/api/archive-ops/public-candidates`, `Public Arşiv Adayları` ve
  `openArchiveCandidateRecord` mevcut; oturumsuz `/api/archive-ops/public-candidates` `401`
  döndü. Eski geçici `adminRouteProbe` ve public preview marker'ı yok.
- **Hadis ve Slayt Metinleri ekranı gerçek kaynak kayıtlarına bağlandı:** `/admin` süper
  admin Arşiv Operasyon Merkezi içindeki `Hadis ve Slayt Metinleri` artık statik açıklama
  alanı değil, kaynak havuzundaki `hadis` ve `slayt` türlerini ayrı bir çalışma ekranında
  gösteren gerçek metin envanteridir. Süper admin bu ekrandan hadis/slayt metinlerinde
  arama yapabilir, tür ve durum filtresi kullanabilir, toplam/hadis/slayt/arşiv adayı
  sayılarını görebilir, seçtiği kaydın tam metnini okuyabilir, metni kopyalayabilir,
  kaydı Kaynak Havuzu'nda açabilir veya kaynak formuna alıp düzenleyebilir. `Yeni Hadis
  Metni`, `Yeni Slayt Metni` ve `Dosyadan Ekle` aksiyonları kaynak kayıt sistemi ve içe
  aktarım merkeziyle aynı veri modeline bağlıdır. Backend kaynak liste API'si `types`
  parametresiyle çoklu tür filtresini destekler; böylece hadis/slayt ekranı genel ilk
  300 kayıt sınırına takılmadan doğrudan ilgili türleri ister. Bu adım DB/schema/root `/`
  veya public frontend hattına dokunmaz. Değişen dosyalar: `server.js`, `index.html`,
  `scripts/check-frontend.js`, `AGENTS.md`, `CURRENT_HANDOFF.md`. Runtime commit
  `a8cb996` GitHub'a push edildi ve production'a alındı. Production deploy:
  `https://arsiv-kontrol-lkdwvyxrl-ugurkarabulutts-projects.vercel.app`, canlı alias
  `https://arsiv.ibrahimlive.ai`. Doğrulama: `npm.cmd run check` başarılı, 258/258 test
  geçti. Canlı smoke: `/health`, root `/`, `/admin`, `/admin/`, `/admin/smoke-test`,
  `/api/auth/me`, manifest, `sw.js` ve favicon başarılı. `/admin` header'ları
  noindex/no-store doğru. Canlı HTML'de `archiveTextSearch`, `archiveTextList`,
  `loadArchiveTextSources`, `params.set('types','hadis,slayt')` ve `Yeni Hadis Metni`
  mevcut; eski geçici `adminRouteProbe` ve public preview marker'ı yok.
- **Arşiv Operasyon Merkezi Yayın Görevleri gerçek akışa bağlandı:** `/admin` süper admin
  Arşiv Operasyon Merkezi içindeki `Yayın Görevleri` ekranı artık statik açıklama alanı
  değil, gerçek görev takip ekranıdır. Süper admin yayın görevi oluşturabilir; durum,
  öncelik, atanacak kişi, hedef tarih, yayın tarihi, platform/program, yayın linki,
  kategori, kavramlar, bağlı kaynak, bağlı çalışma kaydı, açıklama ve not tutabilir.
  Kaynak Havuzu kayıtları ve Çalışma Kayıtları aranarak yayın görevine bağlanabilir;
  seçilen görev detay panelinde açılır, düzenlenir veya silinir. Backend'e süper admin
  korumalı `/api/archive-ops/publish-tasks` CRUD rotaları eklendi. Canlı DB'de
  `archive_publish_tasks` tablosu varsa gerçek tablo kullanılır; tablo yoksa pilot kullanım
  `settings.archive_ops_publish_tasks` JSON yedeğiyle çalışır. Kalıcı/ölçekli kullanım için
  `schema.sql` içindeki `archive_publish_tasks` bloğu Supabase SQL Editor'de uygulanmalıdır.
  Bu adım root `/` public cutover yapmaz ve public frontend hattına dokunmaz. Değişen
  dosyalar: `server.js`, `index.html`, `schema.sql`, `scripts/check-frontend.js`,
  `AGENTS.md`, `CURRENT_HANDOFF.md`. Runtime commit `5ec6f8c` GitHub'a push edildi ve
  production'a alındı. Production deploy:
  `https://arsiv-kontrol-jumo4q4fr-ugurkarabulutts-projects.vercel.app`, canlı alias
  `https://arsiv.ibrahimlive.ai`. Doğrulama: `npm.cmd run check` başarılı, 258/258 test
  geçti. Canlı smoke: `/health`, root `/`, `/admin`, `/admin/`, `/admin/smoke-test`,
  `/api/auth/me`, manifest, `sw.js` ve favicon başarılı. `/admin` header'ları noindex/no-store
  doğru. Canlı HTML'de `archivePublishTitle`, `/api/archive-ops/publish-tasks` ve
  `Yayın Görevini Sakla` mevcut; public preview/demo marker'ı yok.
  Canlı DB'de `archive_publish_tasks` SQL'i kullanıcı tarafından başarıyla uygulandıktan
  sonra fonksiyonun tabloyu başlangıçta kesin algılaması için temiz HEAD yeniden production'a
  alındı. Redeploy:
  `https://arsiv-kontrol-519ggzg3q-ugurkarabulutts-projects.vercel.app`, canlı alias
  `https://arsiv.ibrahimlive.ai`. Smoke tekrar geçti: `/health`, root `/`, `/admin`,
  `/admin/`, `/admin/smoke-test`, `/api/auth/me`, manifest, `sw.js` ve favicon başarılı;
  `/admin` noindex/no-store doğru, yayın görevi marker'ları canlı HTML'de mevcut ve public
  preview marker'ı yok.
- **Çalışma kayıtları denetim/onay akışına bağlandı:** `/admin` süper admin Arşiv Operasyon
  Merkezi içindeki `Çalışma Kayıtları` artık Metin Denetimi ile bağlantılı çalışır. Süper
  admin bir çalışma kaydının cevap taslağını veya cevap yoksa soru metnini `Denetime Aktar`
  ile Metin Denetimi ekranına taşıyabilir. Denetim ekranında kaydın hangi çalışma kaydından
  geldiğini gösteren bağlam kartı görünür; bu bağlam yerel taslakta korunur ve istenirse
  kaldırılabilir. Bağlı bir denetim sonucu `Onaya Gönder` ile iletilirse ilgili çalışma kaydı
  mevcut `/api/archive-ops/work-items/:id` akışıyla otomatik `onay_bekliyor` durumuna alınır
  ve not alanına denetim kaydı/tarih bilgisi eklenir. Bu adım DB/schema/server/root `/` veya
  public frontend hattına dokunmaz; mevcut çalışma kayıtları API'sini kullanır. Değişen
  dosyalar: `index.html`, `scripts/check-frontend.js`, `AGENTS.md`, `CURRENT_HANDOFF.md`.
  Başarısız public ön yüz demo hattına ait takipli `archive-public.css` ve
  `public-archive-demo.js` dosyaları kaldırıldı; `server.js` üzerindeki public preview/demo
  kirli değişikliği repo sürümüne döndürüldü ve untracked public archive P2D araştırma/brief
  dokümanları silindi. Doğrulama: `npm.cmd run check` başarılı, 258/258 test geçti;
  `git diff --check` whitespace hatası vermedi, yalnız mevcut CRLF uyarıları görüldü.
  Runtime commit `fd34509` GitHub'a push edildi ve production'a alındı. Production deploy:
  `https://arsiv-kontrol-3amq3797h-ugurkarabulutts-projects.vercel.app`, canlı alias
  `https://arsiv.ibrahimlive.ai`. Canlı smoke: `/health`, root `/`, `/admin`, `/admin/`,
  `/admin/smoke-test`, `/api/auth/me`, manifest, `sw.js` ve favicon başarılı. `/admin`
  header'ları noindex/no-store doğru. Canlı HTML'de `archiveWorkAuditContext`,
  `transferArchiveWorkToAudit`, `markArchiveWorkSubmittedAfterApproval` ve `Denetime Aktar`
  mevcut; public preview/demo marker'ı yok.
- **Arşiv Operasyon Merkezi Çalışma Kayıtları gerçek akışa bağlandı:** `/admin` süper admin
  Arşiv Operasyon Merkezi içindeki `Çalışma Kayıtları` ekranı placeholder olmaktan çıkarıldı.
  Süper admin artık soru/cevap çalışması oluşturabilir; durum, öncelik, atanacak kişi,
  hedef tarih, kategori, kavramlar, bağlı kaynak, soru metni, cevap taslağı ve not tutabilir.
  Kaynak Havuzu kayıtları aranarak çalışma kaydına bağlanabilir; bağlı kaynak tek tuşla
  Kaynak Havuzu detayında açılır. Kayıtlar aranabilir ve durum/öncelik filtresiyle
  süzülebilir; seçilen kayıt detayda açılır, düzenlenir veya silinir. Backend'e süper admin
  korumalı `/api/archive-ops/work-items` CRUD rotaları eklendi. Canlı DB'de
  `archive_work_items` tablosu varsa gerçek tablo kullanılır; tablo yoksa pilot kullanım
  `settings.archive_ops_work_items` JSON yedeğiyle çalışır. Kalıcı ve ölçekli kullanım için
  `schema.sql` içindeki `archive_work_items` bloğu Supabase SQL Editor'de uygulanmalıdır.
  Bu adım root `/` public cutover yapmaz ve public frontend dosyalarını kapsamaz. Değişen
  dosyalar: `server.js`, `index.html`, `schema.sql`, `scripts/check-frontend.js`,
  `AGENTS.md`, `CURRENT_HANDOFF.md`. Runtime commit `aa4c291` GitHub'a push edildi ve temiz
  `git archive HEAD` deploy kaynağıyla production'a alındı. Production deploy:
  `https://arsiv-kontrol-frwabikcb-ugurkarabulutts-projects.vercel.app`, deployment
  `dpl_2VDgMUsiq8YxyDhrxJKbsfm1gjb7`, canlı alias `https://arsiv.ibrahimlive.ai`.
  Doğrulama: `npm.cmd run check` başarılı, 86/86 test geçti; temiz deploy klasöründe
  `node --check server.js` ve `node scripts/check-frontend.js` başarılı. Vercel inspect
  deploy durumunu `Ready` gösterdi. Supabase'de `archive_work_items` SQL'i kullanıcı tarafından
  başarıyla uygulandıktan sonra canlı fonksiyonun tabloyu başlangıçta kesin algılaması için
  temiz `HEAD` snapshot'ından yeniden production deploy alındı:
  `https://arsiv-kontrol-8y8nt0bhy-ugurkarabulutts-projects.vercel.app`, deployment
  `dpl_DthUsG8XvnxLfTryMWqT8pEbd7va`, canlı alias `https://arsiv.ibrahimlive.ai`.
  Vercel inspect bu redeploy'u `Ready` gösterdi. Bu ortamdan canlı HTTP smoke istekleri
  bağlantı seviyesinde açılamadı; kullanıcı tarayıcı testiyle ayrıca doğrulanmalıdır.
- **Arşiv Operasyon Merkezi Dosya Merkezi eklendi:** `/admin` süper admin Arşiv Operasyon
  Merkezi içine Drive benzeri ilk `Dosya Merkezi` görünümü eklendi. Bu ekran mevcut kaynak
  kayıtlarını ayrı bir DB/schema gerektirmeden dosya kartları, klasör/kategori grupları,
  tür ve durum filtreleriyle gösterir. Süper admin dosya, kaynak, kategori, kavram veya
  metin önizlemesi içinde arama yapabilir; dosya kartına tıklayınca kayıt mevcut Kaynak
  Havuzu detay ekranında açılır ve mevcut düzenleme/kopyalama akışına bağlanır. Uzun başlık,
  kategori, etiket ve metin önizlemeleri mobilde taşmayacak şekilde kırılır. Bu adım
  backend/DB/schema/root `/` veya public frontend hattına dokunmaz. Değişen dosyalar:
  `index.html`, `scripts/check-frontend.js`, `AGENTS.md`, `CURRENT_HANDOFF.md`.

### 2026-08-06
- **İçe Aktarım Merkezi doğrudan kaynak kaydı akışına geçti:** `/admin` Arşiv Operasyon
  Merkezi `İçe Aktarım Merkezi` ekranında dosya eklendikten sonra kaynak oluşturma adımı
  sadeleştirildi. Dosyalar artık `Kaynak Olarak Kaydet` ile tek tuşla Kaynak Havuzu'na
  alınabilir; detay değiştirmek isteyen süper admin için `Formda Düzenle` ayrı ikincil
  aksiyon olarak kalır. Kaynak kaydı oluşan dosyada `Kaynak Havuzunda Aç` görünür.
  İçe aktarım ekranına dört adımlı kısa akış göstergesi eklendi: dosya seç, metni kontrol et,
  kaynak olarak kaydet, havuzda ara. Benzer kaynak çakışmaları mevcut sistem onayıyla
  korunur; 200.000 karakter kaynak sınırı devam eder. Bu adım DB/schema/root `/` veya public
  frontend hattına dokunmaz. Değişen dosyalar: `index.html`, `scripts/check-frontend.js`,
  `AGENTS.md`, `CURRENT_HANDOFF.md`. Runtime commit `f15e6aa` GitHub'a push edildi ve
  production'a alındı. Final production deploy:
  `https://arsiv-kontrol-i3p8s7uh4-ugurkarabulutts-projects.vercel.app`, canlı alias
  `https://arsiv.ibrahimlive.ai`. Doğrulama: `npm.cmd run check` başarılı, 86/86 test geçti.
  Canlı smoke: `/health`, root `/`, `/admin`, `/admin/`, `/admin/smoke-test`,
  `/api/auth/me`, manifest, `sw.js` ve favicon başarılı. `/admin` header'ları noindex/no-store
  doğru. Canlı HTML'de `ops-import-flow`, `Kaynak Olarak Kaydet`, `Formda Düzenle` ve
  `Kaynak Havuzunda Aç` mevcut; eski geçici `adminRouteProbe` yok.
- **İçe Aktarım Merkezi kuyruk aksiyonları netleştirildi:** `/admin` Arşiv Operasyon Merkezi
  `İçe Aktarım Merkezi` ekranında `Forma Aktar` ve `Atla` etiketleri kullanıcı açısından
  belirsiz bulundu. Akış şu şekilde ayrıştırıldı: `Kaynak Formuna Al` dosya metnini kaynak
  kayıt formuna taşır ama tek başına kayıt oluşturmaz; kalıcı kaynak kaydı için formdaki
  `Kaynak Kaydını Sakla` kullanılır. `İşlem Dışı Bırak` dosyayı silmeden partide pasif duruma
  alır. Yanlış eklenen dosyalar için gerçek `Kuyruktan Sil` işlemi eklendi; bu işlem yalnız
  `archive_import_items` satırını kaldırır, varsa oluşturulmuş kaynak kaydını silmez. Silme
  işlemi sistem temalı onay penceresiyle korunur; henüz DB'ye yazılmamış geçici okuma satırları
  API çağırmadan ekrandan kaldırılır. Backend'e süper admin korumalı
  `DELETE /api/archive-ops/import-items/:id` endpoint'i eklendi. Doğrulama:
  `npm.cmd run check` başarılı, 86/86 test geçti.
- **İçe Aktarım Merkezi mobil taşma düzeltildi:** `/admin` Arşiv Operasyon Merkezi içindeki
  `İçe Aktarım Merkezi` mobil görünümünde uzun DOCX dosya adları, dosya detay başlığı ve
  çıkarılan metin önizlemesi ekran genişliğini taşırarak yatay kaydırma oluşturuyordu.
  Import alanına scoped responsive CSS eklendi: import workspace, liste, kart, detay başlığı,
  öneri paragrafı ve önizleme metni artık `min-width:0`, `max-width:100%`,
  `overflow-wrap:anywhere` ve mobil tek kolon kurallarıyla çalışır. Uzun dosya adları ve uzun
  satırlar kutu dışına çıkmadan kırılır; `Forma Aktar` / `Atla` butonları mobilde düzenli
  iki kolon davranışı alır. Bu adım backend/DB/schema/root `/` veya public frontend dosyalarına
  dokunmadı. `scripts/check-frontend.js` bu mobil taşma korumalarını regresyon olarak kontrol
  eder. Runtime commit `3e0b253` GitHub'a push edildi ve production'a alındı. Production deploy:
  `https://arsiv-kontrol-kkqal7n74-ugurkarabulutts-projects.vercel.app`, canlı alias
  `https://arsiv.ibrahimlive.ai`. Doğrulama: `npm.cmd run check` başarılı, 86/86 test geçti.
  Canlı smoke: `/health`, root `/`, `/admin`, `/admin/`, `/admin/smoke-test`,
  `/api/auth/me`, manifest, `sw.js` ve favicon başarılı. `/admin` header'ları noindex/no-store
  doğru. `/api/archive-ops/import-batches` oturumsuz erişimde `401` döndü. Canlı HTML'de
  mobil taşma koruma marker'ları mevcut; eski geçici `adminRouteProbe` ve public preview flag'i
  yok.
- **İçe Aktarım Merkezi kalıcı parti yapısına hazırlandı:** `/admin` Arşiv Operasyon Merkezi
  içindeki `İçe Aktarım Merkezi` artık yalnız tarayıcı hafızasında duran geçici kuyruk değil,
  Supabase tabanlı `archive_import_batches` ve `archive_import_items` tablolarıyla kalıcı
  içe aktarım partileri olarak çalışacak şekilde geliştirildi. Süper admin parti oluşturabilir,
  DOCX/TXT/MD/CSV/TSV/JSON dosyalarını aktif partiye ekleyebilir, çıkarılan metni ve dosya
  durumunu yenileme sonrası kaybetmeden görebilir. Her dosya `Metin çıkarıldı`, `Kontrol
  bekliyor`, `Kaynak formuna aktarıldı`, `Kaynak kaydı oluşturuldu`, `Atlandı` veya `Hata var`
  durumuyla takip edilir. Dosya kaynak formuna aktarıldığında item `form`, kaynak kaydı
  oluşturulduğunda `source_created` olur. Dosyanın orijinal binary içeriği saklanmaz; çıkarılmış
  metin, dosya adı, tür, boyut, not ve kaynak bağı saklanır. Kalıcı kullanım için canlı
  Supabase'de schema.sql içindeki `archive_import_batches` ve `archive_import_items` blokları
  uygulanmalıdır. Bu adım root `/` public cutover yapmaz ve public frontend hattına dokunmaz.
- **İçe Aktarım Merkezi dosya kuyruğu eklendi:** `/admin` Arşiv Operasyon Merkezi içindeki
  `İçe Aktarım Merkezi` artık yalnız açıklama ekranı değil, süper adminin birden fazla dosyayı
  içe aktarım kuyruğuna alabileceği ilk çalışma alanını içerir. DOCX dosyaları mevcut
  `/api/extract-file-text` endpoint'iyle metne çevrilir; TXT, MD, CSV, TSV ve JSON dosyaları
  tarayıcıda okunur. Dosyalar kalıcı kayda otomatik yazılmaz; önce kuyrukta önizlenir, seçilen
  dosya `Kaynak Kayıtları` formuna aktarılır ve süper admin son kontrol sonrası
  `Kaynak Kaydını Sakla` ile kalıcı kayda alır. Bu adım backend/DB/schema/root `/` veya public
  frontend dosyalarına dokunmadı. Runtime commit `fe2c6a9` GitHub'a push edildi ve production'a
  alındı. Production deploy: `https://arsiv-kontrol-iyokwtgiv-ugurkarabulutts-projects.vercel.app`,
  canlı alias `https://arsiv.ibrahimlive.ai`. Doğrulama: `npm.cmd run check` başarılı,
  86/86 test geçti. Canlı smoke: `/health`, root `/`, `/admin`, `/admin/`, `/admin/smoke-test`,
  `/api/auth/me`, manifest, `sw.js` ve favicon başarılı. `/admin` header'ları noindex/no-store
  doğru. Canlı HTML'de `archiveImportFiles`, `handleArchiveImportFiles`,
  `extractArchiveImportDocx`, `sendArchiveImportToSourceForm` ve `DOCX, TXT, MD, CSV, TSV ve JSON`
  mevcut; eski geçici `adminRouteProbe` yok.
- **Arşiv Operasyon Merkezi açılır başlığı sadeleştirildi:** `/admin` mobil ve masaüstü
  menüsünde `Arşiv Operasyon Merkezi` başlığındaki yazılı `Aç/Kapat` etiketi kaldırıldı.
  Başlık artık diğer menü satırlarıyla aynı renkte görünür ve açılır menü olduğunu sade
  chevron ok işaretiyle anlatır. Alt başlıklar seçildiğinde yalnız alt başlık aktif görünür;
  ana başlık menüde farklı renge dönmez. Bu adımda backend/DB/schema/root `/` değişmedi,
  süper admin rol mimarisi değiştirilmedi ve public frontend dosyalarına dokunulmadı.
  Runtime commit `2196c27` GitHub'a push edildi ve production'a alındı. Production deploy:
  `https://arsiv-kontrol-5oux56oks-ugurkarabulutts-projects.vercel.app`, canlı alias
  `https://arsiv.ibrahimlive.ai`. Doğrulama: `npm.cmd run check` başarılı, 86/86 test geçti.
  Canlı smoke: `/health`, root `/`, `/admin`, `/admin/`, `/admin/smoke-test`, `/api/auth/me`,
  manifest, `sw.js` ve favicon başarılı. Canlı HTML'de chevron CSS'i mevcut, yazılı `Aç`
  span'ı ve eski `Aç/Kapat` text swap kodu yok; eski geçici `adminRouteProbe` yok.
- **Arşiv Operasyon Merkezi menüsü kapalı/açılır hale getirildi:** `/admin` içindeki
  süper admin `Arşiv Operasyon Merkezi` alt başlıkları artık menü açıldığında doğrudan
  uzun liste olarak görünmez. Mobil ve masaüstü menüde önce yalnız ana başlık görünür;
  kullanıcı ana başlığa tıklayınca `Genel Bakış`, `Kaynak Kayıtları`, `Kaynak Havuzu`,
  `Yayın Görevleri`, `Çalışma Kayıtları`, `Hadis ve Slayt Metinleri`, `İçe Aktarım Merkezi`
  ve `Public Arşiv Adayları` alt başlıkları açılır, tekrar tıklanınca kapanır. Bu adımda
  backend/DB/schema/root `/` değişmedi, süper admin rol mimarisi değiştirilmedi ve public
  frontend dosyalarına dokunulmadı. Runtime commit `5583111` GitHub'a push edildi ve
  production'a alındı. Production deploy:
  `https://arsiv-kontrol-qc9fvavzj-ugurkarabulutts-projects.vercel.app`, canlı alias
  `https://arsiv.ibrahimlive.ai`. Doğrulama: `npm.cmd run check` başarılı, 86/86 test
  geçti; statik DOM kontrolü kapalı alt menü işaretlerini doğruladı. Canlı smoke:
  `/health`, root `/`, `/admin`, `/admin/`, `/admin/smoke-test`, `/api/auth/me`,
  manifest, `sw.js` ve favicon başarılı. Canlı HTML'de `toggleArchiveOpsMenu`,
  kapalı mobil/masaüstü alt menü CSS'i ve `archive-ops-menu-group` mevcut; eski geçici
  `adminRouteProbe` yok.
- **Arşiv Operasyon Merkezi alt menü desenine taşındı:** `/admin` içindeki süper admin
  `Arşiv Operasyon Merkezi` artık tek uzun sayfa yerine WordPress benzeri ana menü + alt
  ekran yapısıyla çalışır. Sol menü ve mobil menü altında `Genel Bakış`, `Kaynak Kayıtları`,
  `Kaynak Havuzu`, `Yayın Görevleri`, `Çalışma Kayıtları`, `Hadis ve Slayt Metinleri`,
  `İçe Aktarım Merkezi` ve `Public Arşiv Adayları` başlıkları açılır. Her alt başlık yalnız
  kendi bölümünü gösterir; kaynak araması otomatik `Kaynak Havuzu` ekranına geçirir, seçilen
  kaynak forma alındığında `Kaynak Kayıtları` ekranına taşır. Backend/DB/schema değişmedi,
  root `/` public cutover yapılmadı, public frontend dosyalarına dokunulmadı. Bundan sonra
  dashboard içinde birden çok işi olan diğer ana başlıklar da bu alt menü/odak ekran desenine
  taşınmalıdır. Runtime commit `c0a29d0` GitHub'a push edildi ve production'a alındı.
  Production deploy: `https://arsiv-kontrol-jmn0ywmnf-ugurkarabulutts-projects.vercel.app`,
  canlı alias `https://arsiv.ibrahimlive.ai`. Doğrulama: `npm.cmd run check` başarılı,
  86/86 test geçti; statik DOM kontrolü operasyon alt ekran işaretlerini doğruladı.
  Canlı smoke: `/health`, root `/`, `/admin`, `/admin/`, `/admin/smoke-test`,
  `/api/auth/me`, manifest, `sw.js` ve favicon başarılı. `/admin` header'ları
  `X-Robots-Tag: noindex, nofollow` ve strict no-store. Canlı HTML'de
  `Arşiv Operasyon Merkezi`, `data-ops-view="sources"`, `data-ops-view="library"`,
  `mArchiveOps` ve `openArchiveOps` mevcut; eski geçici `adminRouteProbe` yok.
- **Arşiv kaynak kayıtları tablo destekli hale getirildi:** `/admin` Arşiv Operasyon Merkezi
  kaynak kayıt sistemi pilot `settings.archive_ops_sources` JSON deposuna bağlı kalmadan gerçek
  Supabase tablolarını kullanabilecek şekilde hazırlandı. Yeni `archive_sources`,
  `archive_source_versions` ve `archive_source_events` şeması eklendi. Sunucu başlangıçta bu
  tabloların varlığını algılar; tablolar yoksa mevcut JSON pilot akışı bozulmadan devam eder.
  Tablolar varsa listeleme tam metni yüklemeden `text_preview` / `text_length` ile çalışır,
  detay açılınca tam metin alınır, kayıt oluşturma/güncelleme versiyon ve olay defterine yazılır,
  eski pilot JSON kayıtları tablo boşsa idempotent şekilde taşınır. Canlı DB'de ilgili SQL
  Supabase SQL Editor'de uygulandı; üç tablo REST kontrolünde `200` döndü ve başlangıçta boş
  olduğu doğrulandı. Kaynak importu yapılmadı, root `/` public cutover yapmadı ve kullanıcı
  ekranlarına açmadı. Runtime commit `16ff508` GitHub'a push edildi ve production'a alındı.
  Production deploy: `https://arsiv-kontrol-o1drv6x69-ugurkarabulutts-projects.vercel.app`,
  canlı alias `https://arsiv.ibrahimlive.ai`. Doğrulama: `npm.cmd run check` başarılı,
  86/86 test geçti. Canlı smoke: `/health`, root `/`, `/admin`, `/admin/`,
  `/admin/smoke-test`, `/api/auth/me`, manifest, `sw.js` ve favicon başarılı. `/admin`
  header'ları noindex/no-store doğru; `/api/archive-ops/sources` oturumsuz erişimde `401`
  dönüyor.
- **Kaynak kaydı güncelleme son kontrolü eklendi:** Süper admin bir kaynak kaydını forma alıp
  güncellediğinde sistem artık doğrudan üzerine yazmaz; başlık, tür, durum, kategori, tarih,
  kaynak linki, etiket, not veya metin değiştiyse sistem temalı `Kaynak kaydı güncellensin mi?`
  onay penceresi açar ve değişecek alanları özetler. Bu tam versiyon geçmişi değildir; çünkü
  pilot kaynaklar şimdilik `settings` JSON içinde tutulduğu için 200.000 karakterlik metinlerin
  tam sürüm geçmişini aynı satıra yazmak ölçek açısından doğru değildir. Tam geri alma/versiyon
  geçmişi ayrı kaynak tabloları fazında ele alınmalıdır. Runtime commit `11c0b2e` GitHub'a
  push edildi ve production'a alındı. Production deploy:
  `https://arsiv-kontrol-3d50bqrz2-ugurkarabulutts-projects.vercel.app`, canlı alias
  `https://arsiv.ibrahimlive.ai`. Doğrulama: `npm.cmd run check` başarılı, 86/86 test geçti.
  Canlı smoke ve `/admin` HTML marker kontrolü başarılı; eski geçici `adminRouteProbe` yok.
- **Kaynak kayıtlarında çakışma kontrolü eklendi:** Süper admin `/admin` Arşiv Operasyon
  Merkezi kaynak kayıt sistemi artık aynı metin, aynı kaynak linki veya aynı başlık+tür
  kombinasyonunu kayıt öncesinde yakalar. Çakışma varsa API `409` döner ve frontend sistem
  temalı `Benzer kaynak bulundu` penceresi açar; süper admin kayıtları kontrol edip
  isterse `Yine de Kaydet` ile bilinçli şekilde saklayabilir. Bu karar kayıtta
  `conflictAcceptedAt/conflictAcceptedBy` bilgisiyle tutulur ve listede/detayda görünür.
  Bu adım DB/schema migration yapmaz, root `/` public cutover yapmaz, kaynak verisi içe
  aktarmaz. Runtime commit `f6f7ef1` GitHub'a push edildi ve production'a alındı.
  Production deploy: `https://arsiv-kontrol-docn1eixr-ugurkarabulutts-projects.vercel.app`,
  canlı alias `https://arsiv.ibrahimlive.ai`. Doğrulama: `npm.cmd run check` başarılı,
  86/86 test geçti. Canlı smoke: `/health`, root `/`, `/admin`, `/admin/`,
  `/admin/smoke-test`, `/api/auth/me`, manifest, `sw.js` ve favicon başarılı.
  `/admin` header'ları noindex/no-store doğru. Canlı HTML'de `Benzer kaynak bulundu`,
  `saveArchiveSource(forceSave=false)`, `duplicateWarning` ve API hata detay koruması mevcut;
  eski geçici `adminRouteProbe` yok.
- **Süper admin Kaynak Kayıt Sistemi production'a alındı:** `/admin` içindeki Arşiv
  Operasyon Merkezi artık yalnız plan kabuğu değil, ilk gerçek kaynak kayıt akışını içerir.
  Süper admin transkript, hadis, slayt, doküman, standart ve not türünde kaynak metni
  ekleyebilir; başlık, kategori, tarih, kaynak linki, kavram etiketleri, durum ve karar notu
  tutabilir. Kayıtlar başlık/metin/kategori/link/not/etiket içinde aranır; seçilen kaynak tam
  metniyle açılır, kopyalanır ve forma alınarak düzenlenebilir. Hadis ve slaytlar bağlantı
  olarak değil, metin olarak da sistemde tutulacak yönde hazırlandı. Bu adım DB/schema
  migration yapmaz; ilk pilot veri mevcut `settings` satırında `archive_ops_sources` JSON
  anahtarıyla saklanır. Maksimum kaynak metni 200.000 karakterdir. Root `/` public cutover
  yapılmadı, kullanıcı ekranları değişmedi. Runtime commit `dcfab9e` GitHub'a push edildi.
  Production deploy: `https://arsiv-kontrol-f0yrt2zdx-ugurkarabulutts-projects.vercel.app`,
  deployment `dpl_4ZL1sJy1BBwjc5SAYQCY933fv9Xt`, canlı alias `https://arsiv.ibrahimlive.ai`.
  Doğrulama: `npm.cmd run check` başarılı, 86/86 test geçti. Canlı smoke: `/health`, root `/`,
  `/admin`, `/admin/`, `/admin/smoke-test`, `/api/auth/me`, manifest, `sw.js` ve favicon
  başarılı. `/admin` header'ları `X-Robots-Tag: noindex, nofollow` ve strict no-store.
  `/api/archive-ops/sources` oturumsuz erişimde 401 dönerek süper admin korumasını doğruladı.
- **Süper admin Arşiv Operasyon Merkezi kabuğu production'a alındı:** Manuel Google Drive,
  e-tablo ve doküman akışlarının ileride admin içinde yürütülmesi için ilk süper admin-only
  kabuk eklendi. Yeni alan yalnız `super_admin` rolünde ve `/admin` route'unda görünür; root `/`
  public arşiv cutover için korunur. Kabuk şimdilik veri yazmaz ve DB/schema değiştirmez;
  kaynak havuzu, yayın görevleri, çalışma kayıtları, hadis ve slayt metinleri, içe aktarım ve
  public arşiv adayı aşamalarını tek operasyon merkezi altında gösterir. Commit `1a0fa71`
  GitHub'a push edildi. Production deploy:
  `https://arsiv-kontrol-qzolw1q4e-ugurkarabulutts-projects.vercel.app`, deployment
  `dpl_8qCFG6RadRDZyyQyvctdGAjCwAQq`, canlı alias `https://arsiv.ibrahimlive.ai`.
  Doğrulama: `npm.cmd run check` başarılı, 86/86 test geçti. Canlı smoke: `/health` `ok`,
  root `/` HTTP 200, `/admin`, `/admin/` ve `/admin/smoke-test` HTTP 200, `/api/auth/me`
  HTTP 200 JSON, manifest, `sw.js` ve favicon HTTP 200. `/admin` header'ları
  `X-Robots-Tag: noindex, nofollow` ve `Cache-Control: no-store, no-cache, must-revalidate,
  proxy-revalidate`. Canlı HTML'de `Arşiv Operasyon Merkezi`, `tabContent-archiveOps` ve
  `admin-route-only` mevcut; eski geçici `adminRouteProbe` yok. Untracked public frontend
  brief dosyası deploy kaynağına alınmadı.

### 2026-08-05
- **Rol değişikliği sonrası eski oturum yetkisi düzeltildi:** `/admin` geçişi sonrası
  DB'de `admin` görünen bir kullanıcının kendi ekranında hâlâ ekip üyesi menüsü görmesi
  sorununun kökü session cache olarak tespit edildi. `cookie-session` içindeki eski `role`
  değeri, kullanıcı rolü sonradan değiştirildiğinde otomatik güncellenmiyordu. Auth
  middleware ve `/api/auth/me` artık her oturum kontrolünde `users` tablosundan kullanıcıyı
  tekrar okur, `effectiveRole` ile güncel rolü session'a yazar, pasif/silinmiş kullanıcıyı
  oturumdan düşürür. Böylece admin yapılan kullanıcı sayfayı yenilediğinde veya yeni API
  isteği attığında admin menüsü güncel rolüne göre açılır. Runtime commit `0c51903`
  GitHub'a push edildi ve production'a alındı. Doğrulama: `npm.cmd run check`
  başarılı, 86/86 test geçti.
- **Kelime içi `şer` yanlış pozitif kökü kapatıldı:** Ekip yöneticisinin işaret ettiği
  `Efendimizin sözlüğü` önceliğiyle kısa kökün kelime içindeki harf dizisine uygulanması
  riski backend seviyesinde kapatıldı. `şer -> şerr` standardı yalnız bağımsız `şer`,
  `şerle`, `şerde`, `şerden`, `şerdir` gibi güvenli kök kullanımlarında kabul edilir.
  `ŞERİF`, `HADÎS-İ ŞERİF`, `şeriat`, `ŞERİAT`, `şerh` gibi kelimelerin içine giren
  `ŞERİF -> ŞERRİF`, `şeriat -> şerriat`, `şerh -> şerrh` ve `şerr -> şerrr` önerileri
  skor dışı bırakılır ve düzeltilmiş metne uygulanmaz. Prompt kuralı da aynı yönde
  sıkılaştırıldı. Runtime commit `8c981df` GitHub'a push edildi ve production'a alındı.
  Doğrulama: `npm.cmd run check` başarılı, 86/86 test geçti. Production deploy:
  `https://arsiv-kontrol-qcncicc6u-ugurkarabulutts-projects.vercel.app`, deployment
  `dpl_8emRJVhG58M8t4Mvb3jxkRSQ5hDJ`, canlı alias `https://arsiv.ibrahimlive.ai`.
  Canlı smoke: `/health` `ok`, root `/` HTTP 200, `/admin`, `/admin/` ve
  `/admin/smoke-test` HTTP 200, `/api/auth/me` `{"loggedIn":false}`, manifest, `sw.js`
  ve favicon HTTP 200. `/admin` header'ları `X-Robots-Tag: noindex, nofollow` ve
  `Cache-Control: no-store, no-cache, must-revalidate, proxy-revalidate`. Canlı HTML'de
  geçici `adminRouteProbe` test alanı yok; PWA `/admin` guard'ı mevcut.
- **Son sorunlar production'a alındı:** 200.000 karakter metin denetimi sınırı ve
  `HADÎS-İ ŞERİF` başlık standardı / 100 puanlı sonuçlarda geri bildirim açılması
  düzeltmeleri GitHub'a push edildi ve Vercel production'a deploy edildi. Runtime
  commitleri: `4f7b6c6` ve `b08c80e`. Doğrulama: `npm.cmd run check` başarılı,
  85/85 test geçti. Production deploy:
  `https://arsiv-kontrol-bvbv3hjqo-ugurkarabulutts-projects.vercel.app`, canlı alias
  `https://arsiv.ibrahimlive.ai`. Canlı smoke: `/health` `ok`, root `/` HTTP 200,
  `/admin`, `/admin/` ve `/admin/smoke-test` HTTP 200, `/api/auth/me`
  `{"loggedIn":false}`, manifest, `sw.js` ve favicon HTTP 200. `/admin` header'ları
  `X-Robots-Tag: noindex, nofollow` ve `Cache-Control: no-store, no-cache,
  must-revalidate, proxy-revalidate`. Canlı HTML'de 200.000 karakter frontend sınırı ve
  100 puanlı sonuçta geri bildirim açıklaması doğrulandı; eski `ekibe bildirim kapalı`
  metni yok.

### 2026-08-04
- **Metin denetimi üst sınırı 200.000 karaktere çıkarıldı:** Kullanıcıların uzun konferans
  ve soru-cevap metinlerinde gördüğü eski karakter sınırı engeli kaldırıldı. Frontend
  `MAX_TEXT_CHARS` ve backend `MAX_ANALYSIS_TEXT_CHARS` sınırları `200000` olarak
  hizalandı. 200.000 karaktere kadar metinler mevcut uzun metin parçalara ayırma akışıyla
  denetlenir; 200.000 üstü için kullanıcıya net sınır mesajı gösterilir. Eski `120000`
  sınırı ve `metni bölerek denetleyin` engeli ilgili kontrol akışından kaldırıldı.
  `scripts/check-frontend.js` bu sınırı regresyon olarak doğrular. Doğrulama:
  `npm.cmd run check` başarılı, 84/84 test geçti. Bu adımda production deploy yapılmadı.
- **HADÎS-İ ŞERİF başlık standardı ve 100 puan feedback akışı:** Kullanıcı raporuyla
  `HADÎS-İ şerrİF` gibi bozuk başlıkların 100 puanla kaçabildiği görüldü. Denetim motoruna
  yalnız `hadîs-i şerif` başlığı bağlamında çalışan dar deterministik standart eklendi:
  `HADİS-İ ŞERİF`, `HADÎS-İ ŞERÎF`, `HADÎS-İ şerrİF` ve benzeri varyantlar
  `HADÎS-İ ŞERİF` / `Hadîs-i Şerif` standardına alınır; genel `şerr -> şer` koruması
  bozulmaz. Temiz/100 puanlı sonuçlarda geri bildirim panelinin kapanması kaldırıldı; kullanıcı
  artık sonuç temiz görünse bile `Eksik hata`, `Düzen bozuldu`, `Skor yanlış` veya `Diğer`
  olarak geri bildirim gönderebilir. Doğrulama: doğrudan motor senaryosunda skor `96`, bulgu
  `1`; `npm.cmd run check` başarılı, 85/85 test geçti. Bu adımda production deploy yapılmadı.
- **Geçmiş düzeltme akışı feedback merkezli hale getirildi:** `Geçmiş Düzeltme Kontrolü`
  artık global kelime paketi gibi davranmaz. Etki taramasında `Bildirilen doküman` ve
  `Benzer geçmiş kayıtlar` ayrı gösterilir; her hedef `historyId:field` kimliğiyle tek tek
  seçilebilir. Süper admin bildirilen dokümanı açıp kırmızı/eski ve yeşil/yeni bağlam
  önizlemesini görür, yalnız seçili kayıtları uygulayabilir. Kısmi uygulamalar
  `appliedTargets` ile kayıt altında tutulur; paket tamamen bitmeden de hangi hedeflerin
  işlendiği pasif görünür ve gerekirse `content_correction_log` üzerinden geri alınabilir.
  Doğrulama: `npm.cmd run check` başarılı, 84/84 test geçti. Commit `697cc3f` GitHub'a
  push edildi. Production deploy `dpl_AsqGc9m5YUHj38ziadSV5c6Dnq7Q`, canlı alias
  `https://arsiv.ibrahimlive.ai`. Canlı smoke: `/health` `ok`, root `/` HTTP 200,
  `/admin`, `/admin/` ve `/admin/smoke-test` HTTP 200, `/api/auth/me`
  `{"loggedIn":false}`, manifest, `sw.js` ve favicon HTTP 200. `/admin` header'ları
  `X-Robots-Tag: noindex, nofollow` ve `Cache-Control: no-store, no-cache,
  must-revalidate, proxy-revalidate`. Canlı HTML'de `Bildirilen doküman`,
  `Benzer geçmiş kayıtlar`, `selectedChangeIds`, `Dokümanı Aç`, `Bu Kaydı Uygula`
  mevcut; eski `adminRouteProbe` yok.
- **/admin geçici test alanı kaldırıldı:** Süper admin için eklenen `/admin canlı test`
  doğrulama kartı görevini tamamladıktan sonra `index.html` içinden kaldırıldı.
  PWA/root guard mantığı korunur; `scripts/check-frontend.js` artık guard'ı doğrularken
  geçici test alanının geri eklenmemesini regresyon olarak kontrol eder. Doğrulama:
  `npm.cmd run check` başarılı, 84/84 test geçti. Production deploy
  `dpl_3B2som8JBoAVZKhqHhtBoubcJ7R4`, canlı alias `https://arsiv.ibrahimlive.ai`.
  Canlı smoke: `/health` `ok`, `/admin` HTTP 200 ve noindex/no-store, root `/` HTTP 200,
  manifest `id=/admin`, `start_url=/admin`, canlı HTML'de `adminRouteProbe` ve
  `updateAdminRouteProbeState` yok; `ensureStandaloneAdminRoute` mevcut.

### 2026-08-03
- **Repo/GitHub hijyen kararı:** Proje kaynağı bundan sonra GitHub branch'i üzerinden
  taşınır; yeni cihaza geçiş temiz `git clone` ile yapılır. `.env`, Vercel/Supabase/OpenAI
  secret değerleri ve yerel geçici çıktılar Git'e girmez. `tmp/` ve `demo-public-preview/`
  üretilmiş/geçici çıktı olarak ignore edilir. Public arşiv demo kaynakları
  `PUBLIC_ARCHIVE_DEMO=1` feature flag'i altında tutulur; production admin server'ı bu demo
  modülünü yalnız flag açıkken lazy-load eder. Root `/` public arşive çevrilmedi; `/admin`
  production admin hedefi olarak korunur.
- **PWA root açılışına admin guard eklendi:** iOS ana ekrana ekleme akışında manifest
  `start_url=/admin` olsa bile bazı cihazlarda uygulama root `/` adresinden açılabiliyor.
  Bu nedenle PWA/standalone modunda oturum açmış admin veya süper admin root'ta yakalanırsa
  uygulama kendi içinde `/admin` yoluna taşınır. Manifest `id` değeri de `/admin` yapıldı.
  Bu guard normal tarayıcı root davranışına dokunmaz; root `/` public arşiv cutover için
  şimdilik korunur. Doğrulama: `npm.cmd run check` başarılı, 84/84 test geçti. Production
  deploy `dpl_FGrVj7yYGew5dJgiyyaT2WEjiXhV`, canlı alias `https://arsiv.ibrahimlive.ai`.
  Canlı smoke: `/health` `ok`, `/admin` HTTP 200 ve noindex/no-store, root `/` HTTP 200,
  manifest `id=/admin`, `start_url=/admin`, canlı HTML'de `ensureStandaloneAdminRoute` ve
  `adminRouteProbe` mevcut.
- **PWA ana ekran başlangıcı /admin yapıldı:** Mobilde ana ekrana eklenen uygulamanın root `/`
  yerine admin panelinden başlaması için `manifest.webmanifest` içindeki `start_url` `/admin`
  olarak değiştirildi; `scope` `/` olarak korundu. `scripts/check-frontend.js` bu ayarı
  regresyon olarak doğrular. Doğrulama: `npm.cmd run check` başarılı, 84/84 test geçti.
  Production deploy `dpl_EzA3GHhAgfki2WyET5eCJb9ReuhF`, canlı alias
  `https://arsiv.ibrahimlive.ai`. Canlı smoke: manifest `start_url=/admin`, `/admin` HTTP 200
  ve noindex, root `/` HTTP 200, `/api/auth/me` JSON, `/health` `ok`.
- **/admin süper admin canlı test alanı:** Metin Denetimi ekranına yalnız süper adminin
  `/admin` route'unda görebileceği küçük doğrulama alanı eklendi. Alan `super_admin` rolü ve
  `window.location.pathname` `/admin` kontrolü birlikte sağlanmadan görünmez; root `/` içinde
  markup bulunsa bile gizli kalır. `vercel.json` içinde `/admin` ve `/admin/(.*)` noindex /
  no-store route header'ları yeniden hizalandı. Doğrulama: `npm.cmd run check` başarılı,
  84/84 test geçti; production deploy `dpl_A72UqH1nDRh2mok2Js7VAAwPxaBL`, canlı alias
  `https://arsiv.ibrahimlive.ai`. Canlı smoke: `/admin`, `/admin/`, `/admin/smoke-test`,
  `/`, `/api/auth/me`, `/health`, `manifest.webmanifest`, `sw.js`, `favicon.ico` başarılı.
- **Feedback kaynaklı düzeltmelerde kapsam ayrımı:** Açık feedbacklerden doğan metin
  düzeltmelerinde varsayılan kapsam artık `Bildirilen metin`dir. Böylece kullanıcı belirli
  bir denetimde `Tabi ki -> Tabiatıyla` gibi anlık/bağlamsal bir hatayı bildirdiğinde sistem
  yalnız o feedback'in bağlı olduğu `history_id` üzerinde düzeltme kaydı hazırlar; bütün
  geçmişe kör global replacement yapılmaz. Süper admin isterse formdan ayrıca `Tüm geçmiş`
  kapsamını seçebilir.
- **Geçmiş düzeltme uygulaması feedback kapatır:** `content_correction_packages` içindeki
  bir kayıt süper admin tarafından `Onayla ve Uygula` ile uygulandığında, pakete bağlı
  feedbackler aynı `content-correction-{packageId}` çözüm grubuyla `resolved` durumuna alınır
  ve `resolution_note` doldurulur. Böylece metin düzelip feedback'in açık kalması engellenir.
- **2 Ağustos açık feedback kalite turu:** `ahlaki/ahlakı`, `Allah (cc.)/(A.S)`,
  `hayydırlar/diridirler`, `Sebîlel/Sebîli`, `Tabi ki/Tabiatıyla`, `Cinn/CİN`,
  `ardarda/ard arda`, `dini/dinî`, `sure de/surede`, kaynakta olmayan `Kur'ân'da` ekleme,
  çift virgül, dörtlük satır başı ve benzeri açık feedback kökleri için kod/prompt korumaları
  ve regresyon testleri eklendi. `npm.cmd run check` başarılı; 84/84 test geçti.
- **Canlı düzeltme kayıtları hazırlandı:** Canlıda açık feedback sayısı 34 olarak doğrulandı.
  Haklı ve bağlı metinde karşılığı bulunan 17 yeni metne özel düzeltme kaydı
  `content_correction_packages` içine `ready` durumunda yazıldı. Kayıtlar geçmiş metinleri
  henüz değiştirmedi; süper admin panelinde son kontrol ve uygulama bekler. Toplam paket sayısı
  38 oldu: 37 `ready`, 1 `applied`, 17 kayıt `reported` kapsamlı. Üç konu için bağlı metinde
  eşleşme olmadığı için içerik düzeltme paketi açılmadı; `Al-i İmran -> Âli İmrân` dönüşümü
  mevcut sure standardına uygun görüldüğü için global ters düzeltme yapılmadı.
- **Production deploy:** `https://arsiv-kontrol-3uh7o5s4j-ugurkarabulutts-projects.vercel.app`
  production'a alındı ve `https://arsiv.ibrahimlive.ai` alias'ı güncellendi. Canlı doğrulama:
  `/health` `ok`, ana sayfa HTTP 200, cache `no-store, no-cache, must-revalidate,
  proxy-revalidate`, canlı HTML'de `correctionHistoryScopeFromForm` ve `Bildirilen metin`
  mevcut.

### 2026-08-02
- **Onaya gönderme sonrası yeni denetim state kilidi düzeltildi:** Birgül Nursoy ve Nilgün
  Kabadayı'nın raporladığı `her denetimden sonra Ctrl+Shift+R yapmadan Onaya Gönder aktif
  olmuyor` sorunu incelendi. Kök sebep frontend state yönetimiydi: boş/eksik `status` değeri
  `approvalSubmitted` içinde gönderilmiş kabul edilebiliyor, yeni denetim başlarken eski onay
  modalı/payload state'i temizlenmiyor ve yerel çalışma taslağı gönderilmiş sonucu tekrar
  yükleyebiliyordu. Çözüm: yalnız `bekliyor`, `onaylandi`, `reddedildi` statüleri gönderilmiş
  sayılır; yeni denetim başında eski onay state'i sıfırlanır; gönderilmiş local draft sonucu
  çalışma taslağı gibi geri yüklenmez. `scripts/check-frontend.js` içine bu gerçek kullanıcı
  senaryosuna regresyon kontrolü eklendi. Doğrulama: `npm.cmd run check` başarılı; 83/83 test
  geçti. Production deploy: `https://arsiv-kontrol-l58ww5ptk-ugurkarabulutts-projects.vercel.app`,
  alias `https://arsiv.ibrahimlive.ai`; canlı `/health` `ok`, ana sayfa HTTP 200, cache
  `no-store, no-cache, must-revalidate, proxy-revalidate`, canlı HTML'de
  `SUBMITTED_APPROVAL_STATUSES`, `resetCurrentAnalysisStateForNewRun`,
  `resetSubmitApprovalModalState` ve local draft guard mevcut.
- **Geçmiş Düzeltme Kontrolü UX sadeleştirmesi:** Süper admin tarafındaki geçmiş düzeltme
  ekranı uzun alt alta liste yerine okunabilir kontrol kuyruğuna çevrildi. Sayfa adı
  `Geçmiş Düzeltme Kontrolü` oldu; üstte bekleyen, uygulanan ve geri alınan kayıt sayıları
  özetlenir. Ana listede yalnız `Onay Bekleyen Düzeltmeler` görünür; her kayıt kapalı
  açılır-kapanır kart olarak gelir. `Uygulanan Düzeltmeler` ve `Geri Alınan Düzeltmeler`
  ayrı arşiv bölümlerine taşınır. Etki alanı geniş kayıtlar ayrıca dikkat etiketiyle
  işaretlenir. Bu adımda geçmiş metinlere uygulama yapılmadı, feedback kapatılmadı ve
  kullanıcı bildirimi gönderilmedi. Doğrulama: `npm.cmd run check` başarılı; 83/83 test
  geçti. `git diff --check` yalnız mevcut CRLF uyarılarını verdi. Production deploy canlı
  alias'a alındı; `/health` `ok`, ana sayfa HTTP 200, cache `no-store, no-cache,
  must-revalidate, proxy-revalidate`, canlı HTML'de `Geçmiş Düzeltme Kontrolü`,
  `Onay Bekleyen Düzeltmeler`, `Uygulanan Düzeltmeler`, `Geri Alınan Düzeltmeler` ve
  açılır kart CSS'i mevcut.
- **Geçmiş düzeltmeler için süper admin onay şartı:** Geçmiş metinlere uygulanacak düzeltmeler
  artık doğrudan uygulanamaz. Yeni düzeltme kaydı varsayılan olarak süper admin son kontrolü
  gerektirir; önce etki taraması yapılır, örnekler incelenir, yalnız süper admin
  `Onayla ve Uygula` dediğinde `content_correction_log` ile geri alınabilir biçimde geçmiş
  `history.corrected_text` kayıtlarına taşınır. Apply API'si `lastScan`, `status='ready'`,
  `confirmReview:true` ve `superAdminApproved:true` olmadan geçmişe yazı yapmaz. Production
  deploy: `https://arsiv-kontrol-dmg6ic71w-ugurkarabulutts-projects.vercel.app`, alias
  `https://arsiv.ibrahimlive.ai`; canlı `/health` `ok`, ana sayfa HTTP 200, cache `no-store`.
- **22 açık feedback için geçmiş düzeltme kayıtları hazırlandı:** Canlıda açık feedback sayısı
  `22` olarak doğrulandı; yeni kayıt `aciz -> âciz` yanlış düzeltmesiydi. Bu açık feedbacklerden
  doğan geçmiş taşıma işleri için `settings.content_correction_packages` içine `20` yeni
  süper admin onaylı düzeltme kaydı eklendi; daha önce uygulanmış `Tevbe 69 sure referansı`
  kaydına ilgili `2` feedback bağlantısı eklendi. Toplam paket sayısı `21`: `20` kayıt
  `ready`, `1` kayıt `applied`. Bu adımda `history` geçmiş metinleri değiştirilmedi,
  `alerts` feedbackleri kapatılmadı ve kullanıcı bildirimi gönderilmedi.
- **21 açık feedback kök kalite turu:** Canlıdan çekilen 21 açık feedback için kod ve prompt
  katmanında çözüm uygulandı. Kullanıcıların haklı olduğu yanlış-pozitifler artık skor dışı
  bırakılır ve düzeltilmiş metne uygulanmaz: `faziletler -> fazlalar`, `fazılla -> fazl ile`,
  `yakîn -> yakın`, bağlaç olan `sure de -> surede`, `dini -> dinî`, `Tabiatıyla -> Tabiî ki`,
  `lâzımgelen -> lâzım gelen`, kaynakta olmayan `Kur'ân'da` ekleme, mevcut virgül/noktalama
  üzerine ikinci noktalama ekleme, referans sonundaki iki noktayı silme ve bozuk
  `." diyor."` tırnak yerleşimi.
- **Geçerli düzeltmeler deterministic güvenceye alındı:** `Tevbe 69` sure/âyet referansı
  normal `tövbe` kelimesi gibi dönüştürülmez; kaynakta `Tövbe 69` varsa `Tevbe 69` yapılır.
  `Yunus 7, 8’de` gibi açık sure referansları `Yûnus 7, 8’de` standardına alınır. `Hz. Musa'ya
  Hızır'a var dedi;` dar kalıbı virgüle döner. Dörtlük satır başlarında `nice...` ve
  `bir kâmil...` büyük harfle başlatılır.
- **Yeni sure adı regresyonu:** Sonradan gelen `Mumtehine -> Mumtehıne` feedback'i aynı turda
  eklendi. `Mumtehine` doğru yazım olarak korunur; bozuk noktasız-ı varyantı kaynakta varsa
  `Mumtehine` yapılır.
- **Doğrulama ve deploy:** `npm.cmd run check` başarılı; 83/83 test geçti. `git diff --check`
  yalnız mevcut CRLF uyarılarını verdi. Production deploy:
  `https://arsiv-kontrol-a7ijgc047-ugurkarabulutts-projects.vercel.app`, alias
  `https://arsiv.ibrahimlive.ai`. Canlı doğrulama: `/health` `ok`, ana sayfa HTTP 200,
  cache `no-store, no-cache, must-revalidate, proxy-revalidate`, canlı HTML'de
  `/approval-status` ve `/withdraw` mevcut. Canlı DB salt-okunur son sayımda açık feedback
  hâlâ `21`; bu adımda feedback kapatma veya kullanıcı bildirimi yapılmadı.
- **Yeni kapanış kuralı:** Bundan sonra kelime/standart düzeltmesi içeren feedbacklerde
  kapatma sırası zorunlu olarak `kod/prompt düzeltmesi -> geçmiş etki taraması -> gerekiyorsa
  geçmiş içerik uygulaması -> feedback kapatma -> kişisel bildirim` şeklindedir. Sadece kod
  düzeltmesi veya sadece feedback kapatma yeterli sayılmaz.

### 2026-08-01
- **Onaya gönderim doğrulaması ve geri çekme:** Kullanıcıların `Onaya Gönder` dediğinde
  sonucun bazen ekrandan gönderilmiş gibi görünüp onay kuyruğunda kesinleşmemesi riski
  kapatıldı. Frontend artık gönderim sonrası `/api/history/:id/approval-status` ile kaydın
  gerçekten `bekliyor/onaylandı` statüsüne geçtiğini doğrular; doğrulanmadan başarı ekranına
  geçmez. Aynı kayda ikinci istek gelirse backend bunu idempotent başarı olarak ele alır.
  Kullanıcılar kendi `bekliyor` kayıtlarını admin işleminden önce `Onaydan Geri Çek` ile
  tekrar `taslak` durumuna alabilir; duplicate düzeltilmiş metin kilidi de bu durumda serbest
  bırakılır.
- **Âdem (A.S) zürriyet kalıbı:** `Âdem (A.S)'ın sureti` / `Adem(A.S)'ın sureti` benzeri
  dar bağlam, sistem standardında `Âdem (A.S)'ın zürriyeti` yönünde deterministik olarak
  düzeltilir. Bu kural genel `sureti` kelimesine dokunmaz. Önceki kalite kararı korunmuştur:
  `kin ve nefret` içindeki `nefret` kelimesi `nefs`e çevrilmez.
- **Doğrulama ve deploy:** `npm.cmd run check` başarılı; 81/81 test geçti. `git diff --check`
  yalnız mevcut CRLF uyarılarını verdi. Production deploy:
  `https://arsiv-kontrol-1xhjjg4ar-ugurkarabulutts-projects.vercel.app`, alias
  `https://arsiv.ibrahimlive.ai`. Canlı doğrulama: `/health` `ok`, ana sayfa HTTP 200,
  canlı HTML'de `/approval-status`, `/withdraw`, `verifyApprovalStatus` ve
  `Onaydan Geri Çek` mevcut. Vercel deployment `dpl_93QTaN4Pv9AtFcWE19spudt2gHP2` Ready.
- **Geçmiş düzeltme uygulama durum netliği:** Canlı kontrolde `Tevbe 69 sure referansı
  düzeltmesi` kaydının gerçekten uygulandığı doğrulandı: paket `applied`, 2 geçmiş kayıt
  güncellendi ve `content_correction_log` içinde 2 uygulama kaydı var. Kullanıcı tarafında
  uygulama sonrası ekranın hâlâ `Taslak / Uygula` gibi görünebilmesi kafa karıştırdığı için
  UI güçlendirildi: uygulandı durumunda kartta yeşil başarı bandı çıkar, `Uygula` butonu
  `Uygulandı` olarak pasifleşir, yalnız `Geri Al` aktif kalır. API stale sayfadan tekrar
  uygulama isteği gelirse hata vermek yerine `alreadyApplied` ile güncel paket durumunu döndürür.
  Frontend API çağrıları `cache:'no-store'` ile canlı durumu okur; `npm.cmd run check`
  başarılı; 80/80 test geçti. Production deploy:
  `https://arsiv-kontrol-qlj2go3bq-ugurkarabulutts-projects.vercel.app`, alias
  `https://arsiv.ibrahimlive.ai`. Canlı doğrulama: `/health` `ok`, ana sayfa HTTP 200,
  canlı HTML'de `correctionStateNote`, `alreadyApplied`, `cache:'no-store'` ve
  `Düzeltme zaten uygulanmış` mevcut.
- **Tema uyumlu sistem içi onay pencereleri:** Geçmiş düzeltme uygulama sırasında görünen
  tarayıcıya ait beyaz `confirm/alert/prompt` pencereleri kaldırıldı. Uygulama, geri alma,
  kullanıcı silme, kural sıfırlama, yetki uyarıları ve çözüm notu yazma akışları artık
  açık/koyu tema ile uyumlu, mobilde ortalanan, sistemin premium tasarım diline bağlı özel
  modal üzerinden gösterilir. `scripts/check-frontend.js` içine tarayıcı native
  `confirm(`/`alert(`/`prompt(` kullanımını yakalayan regresyon kontrolü eklendi.
  `npm.cmd run check` başarılı; 80/80 test geçti. Production deploy:
  `https://arsiv-kontrol-opyvthnvq-ugurkarabulutts-projects.vercel.app`, alias
  `https://arsiv.ibrahimlive.ai`. Canlı doğrulama: `/health` `ok`, ana sayfa HTTP 200,
  canlı HTML'de `systemConfirmModal`, `systemConfirmInputWrap` ve `openSystemConfirm` mevcut;
  native `confirm/alert/prompt` çağrısı yok.
- **Geri bildirimden geçmiş içerik düzeltme altyapısı:** Kullanıcıların haklı olduğu
  feedback kararlarının yalnız yeni denetimlere değil, daha önce denetlenmiş metinlere de
  kontrollü taşınabilmesi için `Geçmiş Düzeltmeleri` yönetim alanı eklendi. Admin seçili
  feedbacklerden düzeltme kaydı oluşturabilir; kayıt yanlış ifade, doğru ifade, not, hedef alan
  ve şüpheli durum bayrağı taşır.
- **Önce tara, sonra uygula:** `/api/correction-packages` API akışı paketleri listeler,
  oluşturur, geçmiş `history.corrected_text` / seçilirse `summary` alanlarında etki taraması
  yapar ve kaç kayıt/kaç geçiş etkileneceğini örneklerle gösterir. `chunk_draft` ve
  `submitted_part` gibi teknik parça kayıtları taramaya ve uygulamaya alınmaz.
- **Geri alınabilir uygulama şartı:** Geçmiş metinlere toplu uygulama yalnız süper admin
  yetkisiyle ve canlı DB'de `content_correction_log` tablosu varsa çalışır. Her değişiklikte
  eski değer, yeni değer, alan adı, kayıt id'si ve hash bilgisi kayıt defterine yazılır;
  paket gerektiğinde `Geri Al` ile eski değerlere döndürülebilir. Bu tablo yoksa sistem
  yalnız etki taraması yapar, içerik değiştirmez.
- **Sistem sağlığı düzeltmeleri:** Tekil çözüm bildirimi ve kullanıcıya tekil duyuru
  gönderiminde kopuk değişken kullanımı temizlendi. İş Panosu onay/red sonrası düzeltilmiş
  metin duplicate kilidi doğru yerde güncellenir: onaylanan kayıt kilide alınır, reddedilen
  kayıt yeniden çalışılabilir.
- **Doğrulama:** `npm.cmd run check` başarılı; 80/80 test geçti. `git diff --check` yalnız
  mevcut CRLF uyarılarını verdi. Bu adımda canlı deploy, canlı DB yazımı, paket uygulama,
  feedback kapatma veya kullanıcı bildirimi yapılmadı.
- **Canlı altyapı devreye alındı:** Kullanıcı Supabase SQL Editor'da
  `content_correction_log` tablosu ve indexlerini uyguladı; salt-okunur doğrulamada tablo
  `status=200`, `contentRange=*/0` döndü. Ardından production deploy alındı:
  `https://arsiv-kontrol-2ymt7zpi6-ugurkarabulutts-projects.vercel.app`, alias
  `https://arsiv.ibrahimlive.ai`. Canlı doğrulama: `/health` `ok`, ana sayfa HTTP 200,
  cache `no-store, no-cache, must-revalidate, proxy-revalidate`, canlı HTML'de
  `tabContent-corrections` ve `loadCorrectionPackages` mevcut. Mobil görünümde bu alan
  `Geçmiş Düzeltme Merkezi` başlığına, `Yeni düzeltme kaydı` form diline ve taşmayan özel
  checkbox düzenine alındı. `/api/correction-packages`
  yetkisiz erişimde 401 döndürerek route'un yayında ve korumalı olduğunu doğruladı.
  Bu adımda düzeltme kaydı uygulanmadı, feedback kapatılmadı ve kullanıcı bildirimi
  gönderilmedi.
- **Geçmiş düzeltme ekranı mobil UX düzeltmesi:** Canlı mobil kontrolde eski
  `Düzeltme Paketleri` başlığı ve metin alanı stilinden etkilenen büyük checkboxlar
  karışık göründü. Admin menüsü ve sayfa adı `Geçmiş Düzeltmeleri` /
  `Geçmiş Düzeltme Merkezi` olarak değiştirildi; form dili `Yeni düzeltme kaydı`,
  `Hatalı veya eski ifade`, `Doğru ifade`, `Nerede aransın?` çizgisine çekildi.
  Checkboxlar özel ayar satırlarına alındı ve mobilde taşmayacak şekilde ayrıştırıldı.
  `npm.cmd run check` başarılı; 80/80 test geçti. Production deploy:
  `https://arsiv-kontrol-m2fznzdjd-ugurkarabulutts-projects.vercel.app`, alias
  `https://arsiv.ibrahimlive.ai`. Canlı doğrulama: `/health` `ok`, ana sayfa HTTP 200,
  `Geçmiş Düzeltme Merkezi` ve `Geçmiş Düzeltmeleri` mevcut, eski `Düzeltme Paketleri`
  adı yok, yeni checkbox CSS'i canlıda var.

### 2026-07-31
- **29 açık feedback kök kalite turu yerel çözümü:** Canlıdan çekilen 29 açık feedback'in
  kökleri kod ve prompt katmanına işlendi. `Yunus Emre / Yunus diyor` kişi adı bağlamı artık
  `Yûnus` sure adı gibi düzeltilmez; yalnız açık sure/referans bağlamında `Yûnus` uygulanır.
  Âyet/transliterasyon satırlarında çıplak `İsa`, `sırâtın mustekîm(mustekîmin)` ve `dînekum`
  gibi kaynak ifadeler korunur. `Resûlullah'ın (S.A.V)` yerleşimi `Resûlullah (S.A.V)'in`
  biçimine normalize edilir. `Sebîlel gayy / Sebîlel rüşd` standardı `Sebîli ...` olarak
  deterministik uygulanır ve kaynak apostrof biçimi korunur.
- **Yanlış-pozitif uygulama kökü kapatıldı:** Kabul edilen düzeltmelerin metne uygulanması
  artık ham substring replace ile yapılmaz; kelime sınırı ve esnek apostrof/boşluk eşleşmesi
  birlikte kullanılır. Böylece `şer -> şerr` düzeltmesi `ŞERİAT` içine girmez, `şerr` kelimesini
  `şerrr` yapmaz, `vücud -> vücut` yalnız bağımsız kelimede çalışır ve `vücudun/vücuttur`
  gibi ekli/özel kullanımları bozmaz.
- **Ek korumalar:** `Nefret -> nefs`, `var ya` silme, `şeriat kitabı,` gibi gereksiz virgül,
  `BAKARA – 139: De ki:` gibi kaynakta olmayan iki nokta, `AFETİ -> ÂFETİ`, kaynak/hadis
  bibliyografya satırlarında `Fezailül / Alamet-il` şapka-apostrof müdahalesi ve çıplak
  `İsa -> İsa (A.S)` yanlışları skor dışı bırakılır.
- **Tevbe standardı:** Normal metindeki `tevbe/tevbeyi` geçişleri bütün tekrarlarıyla
  `tövbe/tövbeyi` yapılır; `TEVBE` sure adı veya `TEVBE-...` referansı korunur.
- **Doğrulama:** `test/analysis-core.test.js` içine 29 Temmuz feedback köklerini kapsayan
  regresyon testi eklendi. `npm.cmd run check` başarılı; 80/80 test geçti. Bu adımda canlı
  deploy, DB yazımı, feedback kapatma veya kullanıcı bildirimi yapılmadı.
- **Deploy, canlı kapanış ve bildirim:** Yerel çözüm production'a deploy edildi:
  `https://arsiv-kontrol-hqqgl4qo4-ugurkarabulutts-projects.vercel.app`, alias
  `https://arsiv.ibrahimlive.ai`. Canlı doğrulama: `/health` `ok`, ana sayfa HTTP 200,
  cache başlığı `no-store, no-cache, must-revalidate, proxy-revalidate`. Canlıdaki 29 açık
  feedback `feedback-fix-2026-07-31-root-quality-1785452209555` çözüm grubuyla kapatıldı.
  Tuba Aydın, Birgül Nursoy, Elçin Akay, Nuray Ardagümüşoğlu ve Nazlı Özkaplan'a kendi
  bildirdikleri başlıklara göre 5 kişisel `feedback_resolution` bildirimi gönderildi.
  Bildirim başlıkları UTF-8 olarak doğrulandı; son canlı kontrolde açık feedback `0`.
- **Uzun metin kullanıcı dili sadeleştirmesi:** Uzun metin denetimi ve onaya gönderme
  ekranlarında kullanıcıya görünen `parça`, `tek kayıt`, `birleşik sonuç` ve yoğun
  `yönetici` dili kaldırıldı. Arka plandaki parçalı işleme teknik olarak korunur; kullanıcı
  yalnız `Metin güvenli şekilde denetleniyor`, `Sonuç hazırlandı`, `Onaya Gönder dediğinizde
  sonuç onay kuyruğuna iletilir` ve `Sonuç onay sürecine iletildi` gibi sade süreç metinlerini
  görür. `npm.cmd run check` başarılı; 80/80 test geçti. Production deploy:
  `https://arsiv-kontrol-dq2j1stxh-ugurkarabulutts-projects.vercel.app`, alias
  `https://arsiv.ibrahimlive.ai`. Canlı doğrulama: `/health` `ok`, ana sayfa HTTP 200,
  canlı HTML'de yeni kopyalar mevcut; eski `parça tek kayıt`, `parça halinde tamamlandı`,
  `Birleşik Sonuç` ve `yöneticilerin onay kuyruğu` kopyaları yok.

### 2026-07-30
- **Elçin/Nuray uzun metin onaya gönderim takılması:** Canlı kayıt kontrolünde Elçin Akay ve
  Nuray Ardagümüşoğlu'nun uzun metin denemeleri incelendi; Telegram'da görülen bazı
  `Gönderiliyor...` denemelerinin canlı DB'ye hiç ulaşmadığı, yani sadece ekran yenileme
  problemi olmadığı görüldü. Kök risk, onaya gönderimde aynı düzeltilmiş metni engellemek için
  kullanıcının tüm eski `corrected_text` kayıtlarının taranması ve uzun metin/kayıt yoğunluğunda
  isteğin uzamasıydı. Bu kontrol `settings` tablosunda `submitted_corrected_hash:{userId}:{hash}`
  hızlı kilidine taşındı; eşzamanlı çift gönderim engellenir, 20 dakikadan eski yarım kalmış
  `pending` kilitler temizlenir, onaylanınca kilit kalır, reddedilince kilit kaldırılır.
  Birleşik uzun metin gönderiminde parça gizleme hatası ana onay kaydını başarısız göstermeyecek
  şekilde kritik yoldan çıkarıldı. Frontend onay modalı gönderim sırasında kapanmaz, bekleme
  mesajı gösterir, hata/HTML yanıtlarını kontrollü Türkçe mesaja çevirir. Vercel route header'ları
  `no-store` yapıldı; kullanıcıların yeni JS için Ctrl+Shift+R yapmak zorunda kalma ihtimali
  azaltıldı. Doğrulama: `npm.cmd run check` başarılı; 79/79 test geçti, `git diff --check`
  whitespace hatası vermedi. Production deploy:
  `https://arsiv-kontrol-puoqfpte2-ugurkarabulutts-projects.vercel.app`, alias
  `https://arsiv.ibrahimlive.ai`. Canlı doğrulama: `/health` `ok`, ana sayfa HTTP 200,
  canlı HTML'de `submitApprovalInFlight` ve `Gönderim kontrol ediliyor` mevcut, ana sayfa ve
  `sw.js` cache başlığı `no-store, no-cache, must-revalidate, proxy-revalidate`.
- **Denetim geçmişi 200 kayıt limiti kaldırıldı:** Kullanıcıların kendi denetim geçmişinde
  toplam kayıt sayısı 400+ görünmesine rağmen yalnızca 200 kayda ulaşabilmesinin kök sebebi
  `/api/history` endpoint'indeki sabit `.limit(200)` sınırıydı. Endpoint artık mevcut
  `fetchAllPages` yardımcı fonksiyonuyla tüm ilgili kayıtları sayfalı çeker; kullanıcı kendi
  tüm geçmişini, admin ise yetkisine göre tüm görünür geçmiş kayıtlarını görebilir. UI alt
  başlığı `Tüm denetimleriniz` olarak netleştirildi. `scripts/check-frontend.js` bu endpoint
  tekrar 200 kayda sabitlenirse hata verecek regresyon kontrolü içerir. Doğrulama:
  `npm.cmd run check` başarılı; 79/79 test geçti. Production deploy:
  `https://arsiv-kontrol-hd6t9ay6c-ugurkarabulutts-projects.vercel.app`, alias
  `https://arsiv.ibrahimlive.ai`. Canlı doğrulama: `/health` `ok`, ana sayfa HTTP 200,
  canlı HTML'de `Tüm denetimleriniz` ve `/api/history` mevcut.
- **Uzun metin onaya gönderme akışı tek kayıt ve temiz kapanış:** Uzun metin denetiminde
  parça kayıtlarının kullanıcı geçmişinde ayrı ayrı `Onaya Gönder` butonuyla görünmesi
  ve birleşik onay penceresinin net başarı durumu vermemesi giderildi. `/api/analyze`
  artık uzun metin parçalarını `chunk_draft` teknik statüsüyle saklar; `/api/history`
  ve admin listeleri `chunk_draft` / `submitted_part` kayıtlarını gizler. Parçalar
  denetim sonunda `/api/history/merged-draft` ile tek birleşik `taslak` kayda bağlanır.
  Kullanıcı yalnız bu birleşik taslağı onaya gönderebilir; parça kayıtları tek başına
  onaya gönderilemez.
- **Onay sonrası çalışma alanı kapanışı:** `Onaya Gönder` başarıyla tamamlanınca modal
  kapanır, buton tekrar aktif kalmaz, giriş alanı temizlenir ve kullanıcıya
  `Onay kuyruğuna alındı` başlıklı net bir başarı kartı gösterilir. Kartta yeni denetime
  başlama, düzeltilmiş metni kopyalama ve geçmişte görme aksiyonları bulunur. Böylece
  kullanıcı aynı sonucu tekrar göndermeye çalışmaz ve sayfayı kapatmanın işlemi iptal
  etmeyeceği açıkça anlaşılır.
- **Modal ve duplicate rota temizliği:** Geri bildirim modalı ile onaya gönder modalının
  iç içe görünmesine neden olan HTML kapanış hatası düzeltildi. Eski ikinci
  `/api/history/submit-merged` route'u kaldırıldı; birleşik gönderim artık tek ve
  doğrulamalı backend akışından geçer. `scripts/check-frontend.js` bu korumaları
  regresyon kontrolüne aldı. Doğrulama: `npm.cmd run check` başarılı; 79/79 test geçti.
  Production deploy: `https://arsiv-kontrol-mqnb8trkq-ugurkarabulutts-projects.vercel.app`,
  alias `https://arsiv.ibrahimlive.ai`. Canlı doğrulama: `/health` `ok`, ana sayfa HTTP 200,
  canlı HTML'de `Onay kuyruğuna alındı`, `chunk_draft` ve `/api/history/merged-draft` mevcut;
  `submit-merged` tek kez görünüyor. Push yapılmadı.
- **2000+ bekleyen onay kuyruğu güvenli temizliği:** Canlı onay kuyruğu salt-okunur analiz
  edildi; 12 test kaydı, 180 düzeltilmiş metni olmayan kayıt ve 72 aynı kullanıcıya ait
  birebir mükerrer düzeltilmiş metin kaydı tespit edildi. Kullanıcı onayı sonrası toplam
  264 kayıt silinmeden `reddedildi` statüsüne alındı. `approved_by` alanı sırasıyla
  `Sistem Temizlik 2026-07-30: test kaydi`,
  `Sistem Temizlik 2026-07-30: duzeltilmis metin yok` ve
  `Sistem Temizlik 2026-07-30: mukerrer duzeltilmis metin` olarak işaretlendi.
  İşlem sırasında yeni bir kayıt geldiği için kuyruk 2398'den 2134'e düştü. Son kontrolde
  bekleyen kuyrukta kalan test, boş düzeltilmiş metin veya aynı kullanıcı mükerreri `0`.

### 2026-07-29
- **Onaya gönderimde düzeltilmiş metin duplicate engeli:** `Onaya Gönder` akışında yalnızca
  kaynak metin `text_hash` kontrolü yeterli değildi; kullanıcı kaynakta küçük değişiklik
  yaparsa aynı düzeltilmiş cevap yeniden üretilebilir ve ikinci kez onaya düşebilirdi. Tekil
  `/api/history/:id/submit` ve uzun metin `/api/history/submit-merged` endpointleri artık aynı
  kullanıcı için `bekliyor`, `onaylandi` veya eski boş statüde aynı normalize edilmiş
  `corrected_text` varsa ikinci gönderimi reddeder. `reddedildi` kayıtlar yeniden çalışma
  ihtimali için engel sayılmaz. `scripts/check-frontend.js` bu kuralı regresyon kontrolüne
  aldı. `npm.cmd run check` başarılı; 79/79 test geçti. Production deploy:
  `https://arsiv-kontrol-6neioe0k0-ugurkarabulutts-projects.vercel.app`, alias
  `https://arsiv.ibrahimlive.ai`; canlı `/health` `ok`, ana sayfa HTTP 200. Eski 2000+
  bekleyen kayıt üzerinde otomatik temizlik yapılmadı.
- **İş Panosu onay/red yenileme düzeltmesi:** Admin İş Panosu'nda `Onayla` veya `Reddet`
  tıklandıktan sonra işlem yapılmış olsa bile kartın aynı kolonda kalıyor görünmesi giderildi.
  Kök sebep, eski `approveItem/rejectItem` fonksiyonlarının yalnızca denetim geçmişini ve
  badge'leri yenilemesi, `/api/history/approval-board` ile beslenen İş Panosu listesini
  yeniden çekmemesiydi. Onay/red işlemleri ortak `setApprovalAction` akışına alındı; buton
  işlem sırasında kilitlenir, hata varsa ekranda görünür mesaj verir, başarıda `loadOnay()`,
  `loadHistory()` ve `refreshBadges()` çalışır. `scripts/check-frontend.js` bu davranışı
  regresyon kontrolüne aldı. `npm.cmd run check` başarılı; 79/79 test geçti. Production deploy:
  `https://arsiv-kontrol-h0sjen9om-ugurkarabulutts-projects.vercel.app`, alias
  `https://arsiv.ibrahimlive.ai`; canlı `/health` `ok`, ana sayfa HTTP 200.
- **Düzeltilmiş metin sonuç UX sadeleştirmesi:** Sonuç ekranındaki iki ayrı `Onaya Gönder`
  görünümü kaldırıldı; başlık aksiyon satırı artık onay butonu taşımaz. Kullanıcı yalnızca
  düzeltilmiş metnin altındaki taslak/onay panelinden onaya gönderir. Sonuç alanındaki
  `PDF İndir` butonu kaldırıldı; kopyalama, düzeltilmiş metin kutusunun sağ üst kenarında
  duran tek modern `Kopyala` butonuna taşındı. Mobilde buton metnin üstüne binmemesi için
  metin alanı boşluğu ayarlandı. `scripts/check-frontend.js` eski aksiyon satırı, ikinci
  onay veya sonuç PDF butonu geri gelirse hata verecek şekilde güncellendi. `npm.cmd run check`
  başarılı; 79/79 test geçti. Production deploy:
  `https://arsiv-kontrol-bgweehvog-ugurkarabulutts-projects.vercel.app`, alias
  `https://arsiv.ibrahimlive.ai`; canlı `/health` `ok`, ana sayfa HTTP 200.
- **Konferans tam metni için 50k-100k uzun metin modu:** Soru-cevap dışındaki uzun konferans
  metinlerinde de denetim/düzeltme çıktısı alınabilmesi için parçalı analiz güçlendirildi.
  Uzun metin parça boyutu 16.000 karakterden 8.000 karaktere indirildi ve en fazla iki parça
  eşzamanlı işlenecek şekilde hızlandırıldı. Parçalardan biri düşük skor nedeniyle düzeltilmiş
  metin üretmezse artık tüm birleşik sonuç boşaltılmaz; o bölüm kaynak haliyle korunur, diğer
  parçaların düzeltilmiş halleriyle birlikte tek tam metin olarak gösterilir ve bulgular listede
  yer almaya devam eder. `scripts/check-frontend.js` bu davranışı kontrol eder.
  `npm.cmd run check` başarılı; 79/79 test geçti.
- **Onaya gönderme akışı ayrıldı:** Denetle & Düzelt artık kullanıcı adına doğrudan admin
  onay kuyruğuna kayıt açmaz; sonuç önce `taslak` olarak kullanıcının kendi geçmişinde kalır.
  Kullanıcı sonuç ekranındaki veya kendi geçmişindeki `Onaya Gönder` butonuna bastığında modern
  son teyit penceresi açılır; onay verirse kayıt `bekliyor` durumuna alınır ve admin panosunda
  görünür. Admin listeleri, CSV ve istatistikler `taslak` ve `submitted_part` kayıtlarını
  gizler. Uzun metinlerde parça taslakları admin tarafına düşmez; kullanıcı onaya gönderdiğinde
  parçalar `submitted_part` yapılıp tek birleşik `bekliyor` kaydı oluşturulur.
  Doğrulama: `npm.cmd run check` başarılı; 79/79 test geçti. Production deploy:
  `https://arsiv-kontrol-ncrgetvkj-ugurkarabulutts-projects.vercel.app`, alias
  `https://arsiv.ibrahimlive.ai`; canlı `/health` `ok`, ana sayfa HTTP 200.
- **Mobil onaya gönder görünürlüğü:** Mobilde düzeltilmiş metin başlığındaki aksiyon satırı
  dar ekranda butonu saklamasın diye responsive düzen güçlendirildi. `Onaya Gönder` butonu
  artık taslak/onay paneli içinde de tam genişlikte görünür. Doğrulama: `npm.cmd run check`
  başarılı; 79/79 test geçti. Production deploy:
  `https://arsiv-kontrol-38klecuop-ugurkarabulutts-projects.vercel.app`, alias
  `https://arsiv.ibrahimlive.ai`; canlı `/health` `ok`, ana sayfa HTTP 200.

### 2026-07-28
- **Uzun metin denetimi dayanıklılığı:** Çok uzun metinlerde tek büyük OpenAI/Vercel
  isteğinin süre/context sınırına takılıp kullanıcıya `Denetim tamamlanmadı` hatası
  göstermesi engellendi. Frontend artık 16.000 karakter üstü metinleri paragraf/cümle
  sınırlarını gözeterek parçalara böler, her parçayı ayrı `/api/analyze` isteğiyle
  denetler ve sonucu tek rapor gibi birleştirir. `.docx` yüklemeleri için
  `/api/extract-file-text` endpoint'i eklendi; uzun dosyalar da önce metne çevrilip aynı
  parçalı akıştan geçer. Parçalı sonuçtaki bulgu geri bildirimleri kendi parça geçmiş
  kaydına bağlanır. `npm.cmd run check` başarılı; 79/79 test geçti.
- **Onay sayaçları 1000 satır sınırı düzeltmesi:** Dashboard ve İş Panosu sayaçlarında
  Supabase'in varsayılan 1000 satır dönüşü nedeniyle bekleyen onay sayısı `997` gibi eksik
  görünebiliyordu. `/api/stats` artık `history` ve `alerts` kayıtlarını sayfalı çeker;
  İş Panosu için `/api/history/approval-board` endpoint'i eklendi ve her kolon gerçek
  `exact count` ile sayılır. Kart listesi performans için son 80 örneği gösterir, başlıktaki
  sayı gerçek toplamdır. Canlı salt-okunur sayımda `history_total=2076`,
  `bekliyor=2073`, `onaylandi=2`, `reddedildi=1` görülmüştü.
- **Birgül Nursoy 3 açık feedback kök çözümü:** Canlı kuyrukta görülen 3 açık kayıt iki köke
  ayrıldı ve kalıcı çözüldü. `MULK-8` âyetindeki `herbir grup` yazımı artık birleşik
  korunur; modelin `herbir -> her bir` dönüşümü skor dışı bırakılır ve düzeltilmiş metne
  uygulanmaz. Aynı bağlamda kaynak `her bir grup` içerirse deterministic olarak
  `herbir grup` standardına döner.
- **Sayı alternatifi koruması:** `6 tane, 7 tane âyet-i kerime var.` gibi sayı alternatifi
  içeren cümleler artık sadeleştirilmez ve kaynakta olmayan açıklamayla genişletilmez.
  Modelin `6 tane, 7 tane -> 6 tane âyet-i kerime` gibi ikinci sayıyı düşüren dönüşümleri
  yanlış-pozitif kabul edilir; `6 tane âyet-i kerime âyet-i kerime` benzeri tekrar üretimi
  düzeltilmiş metne alınmaz.
- **Regresyon testi:** İki yeni test eklendi; canlı feedback kökleri birebir simüle edildi.
  `npm.cmd run check` başarılı; 79/79 test geçti.
- **Canlı kapanış ve bildirim:** Production deploy sonrası 3 açık feedback
  `feedback-fix-2026-07-28-herbir-count-alternatives` çözüm grubuyla kapatıldı. Birgül
  Nursoy'a üç geri bildirimi için tek kişisel `feedback_resolution` bildirimi gönderildi.
  Son canlı kontrolde açık feedback `0`; canlı `/health` `ok`.

### 2026-07-27
- **14 açık feedback sözlük/sure kalite turu:** Canlı geri bildirim kuyruğunda Mihrimah
  Bilgili ve Birgül Nursoy tarafından bildirilen 14 kayıt kök sınıflara ayrıldı ve kod +
  prompt katmanına işlendi. Kaynak/kitap adlarında geçen `İhyâ’u Ulûmi’d-dîn` /
  `Ulumi’d-dîn` yazımı artık `din` standardına zorlanmaz; `derecat` ve `afet` kelime
  ailelerine gereksiz şapka eklenmez; `hadîsi` gibi ekli kullanımlar `hadîs` köküne
  kırpılmaz.
- **Sure ve slayt standartları güçlendirildi:** `Âli İmrân` yazımı tireli veya yanlış
  şapkalı biçimlere çevrilmez; `Suresinin/Suresini` kelimeleri apostrofla ayrılmaz.
  `Câsiye`, `Yûnus`, `Hûd`, `Fâtır`, `Hacc`, `A'râf`, `MUSÎBET`, `VELÎ`, `zahid`,
  `Şerr` ve `(S.A.V)` standartları deterministic katmanda güvenceye alındı. Tek başına
  `Hac -> Hacc/HACC` modeli kabul edilmez; yalnız gerçek sure/referans bağlamı düzeltilir.
- **Regresyon testi:** 26 Temmuz açık feedback kökleri için dört yeni test eklendi.
  `npm.cmd run check` başarılı; 77/77 test geçti.
- **Canlı kapanış ve bildirim:** Production deploy sonrası 14 açık feedback
  `feedback-fix-2026-07-27-sure-sozluk` çözüm grubuyla kapatıldı. Mihrimah Bilgili'ye
  13 geri bildirimi için, Birgül Nursoy'a 1 geri bildirimi için kişisel
  `feedback_resolution` bildirimi gönderildi. Son canlı kontrolde açık feedback `0`.
  Kişisel çözüm bildirimi üreticisi de güncellendi; bundan sonra mesaj gövdesi
  `Sevgili [kullanıcı adı],` satırıyla başlar, `Mesaj:` etiketi göstermez.

### 2026-07-25
- **14 açık feedback kök kalite turu:** Canlı geri bildirimlerde kullanıcıların haklı
  olduğu 14 kök sınıf kod ve prompt katmanına işlendi. Sistem artık `ilim -> Kur'ân ilmi`,
  `Mehdi -> Mehdî`, `beka -> bekâ`, `münezzehtir -> Sûbhân'dır`, âyet/alıntı tekrarını
  silme (`lânetle lânetle -> lânetle`), `Allah ile bile olursanız -> Allah ile olursanız`
  ve `gayret üstüne gayret -> gayret üstüne gayret,` gibi gereksiz virgül eklemeleri ile
  kaynak cümleye açıklama ekleyen genişletmeleri skor dışı bırakır ve düzeltilmiş metne uygulamaz.
- **Yeni deterministic standartlar:** Model kaçırsa bile `nefisleriyle -> nefsleriyle`,
  `fedakarlık -> fedakârlık`, `Kur'an/Kur’an -> Kur'ân`, `ŞURA -> ŞÛRÂ`,
  `Şura suresinin -> Şûrâ Suresi'nin`, `Her Resûl -> Her resûl`, eksik kaynak parantezleri,
  `2.Gay yolu -> 2. Gayy yolu`, `gayy yolu/GAYY YOLU`, `âyetTE -> ÂYETTE` ve
  `HADİS-İ ŞERİF -> HADÎS-İ ŞERİF` uygulama katmanında üretilir. Bu kökler için üç yeni
  regresyon testi eklendi; `npm.cmd run check` başarılı, 73/73 test geçti.
- **AI geçici hata dayanıklılığı:** Canlı kullanımda görülen `The server had an error
  processing your request` benzeri ham OpenAI hata mesajlarının kullanıcıya yansıması
  engellendi. `server.js` içine ortak `fetchOpenAIChatCompletion` katmanı eklendi; metin
  denetimi, Denetim Yardımcısı, admin AI insight ve operasyon raporu çağrıları bu katmana
  alındı. 408/429/5xx/timeout gibi geçici hatalarda otomatik yeniden deneme yapılır.
- **Kullanıcı dostu hata dili:** AI çağrısı yine de başarısız kalırsa frontend artık teknik
  İngilizce servis metni göstermez. Kullanıcıya metninin ekranda korunduğu, birkaç dakika
  sonra tekrar `Denetle & Düzelt` yapılabileceği Türkçe olarak bildirilir. Toplu dosya
  denetimi de aynı güvenli hata dilini kullanır.
- **Regresyon kontrolü:** `scripts/check-frontend.js` kullanıcı dostu AI hata mesajı ve
  metnin korunduğunu belirten durum metni için kontrol içerir. `npm.cmd run check` başarılı;
  70/70 test geçti.

### 2026-07-24
- **Masaüstü favicon düzeltmesi:** PWA/Apple ikonları olmasına rağmen masaüstü tarayıcı
  faviconu eksikti; `/favicon.ico` canlıda ana sayfa HTML fallback'i döndürüyordu. Mevcut
  uygulama ikonundan `icons/favicon.ico`, `icons/favicon-32.png` ve `icons/favicon-16.png`
  üretildi. `index.html` içine masaüstü favicon linkleri eklendi; Express ve Vercel routing
  `/favicon.ico` isteğini gerçek ICO dosyasına yönlendirecek şekilde güncellendi.
- **Doğrulama ve deploy:** `scripts/check-frontend.js` favicon dosya ölçülerini, ICO başlığını
  ve HTML favicon linklerini kontrol edecek şekilde genişletildi. `npm.cmd run check`
  başarılı; 70/70 test geçti. Commit `66f1cdf` production'a deploy edildi
  (`https://arsiv-kontrol-jy6wdrgok-ugurkarabulutts-projects.vercel.app`) ve
  `https://arsiv.ibrahimlive.ai/favicon.ico` canlıda `image/vnd.microsoft.icon`, 3481 byte,
  geçerli ICO başlığı `00-00-01-00-02-00` döndürdü. Canlı `/health` `ok`.

### 2026-07-23
- **15 açık feedback kök doğrulama turu:** Canlı feedback kuyruğunda 15 açık kayıt
  doğrulandı: Serap Pamuk 6, Hacer Terzi 6, Nuray Ardagümüşoğlu 2, Aysun Aydöner 1.
  Kullanıcı lehine yanlış-pozitif olan dönüşümler kalite katmanında kalıcı olarak
  reddedildi: `takva -> takvâ`, âyet/transliterasyon içinde `dînâ/dînen -> dinâ/dinen`,
  `taktirde -> o taktirde` ile `o o taktirde` üretimi, `afet -> ni'met`,
  `Allah'ın Zat'ında ifna olur -> Allah'ın Zat'ında fena bulur` ve
  `mürşide/mürşide tâbiiyet -> mürşidin/mürşidin tâbiiyet`.
- **Doğru standart ayrımı:** Kullanıcıların bildirdiği bazı kayıtların düzeltme yönü doğru
  kabul edildi ve sistem davranışı netleştirildi. `s 120` sayfa referansı artık deterministik
  olarak `s.120` biçimine gider; araya boşluklu `s. 120` hedefi reddedilir. `Hac/HAC`
  sure adı eksik harfliyse `Hacc/HACC` yapılır, ancak metin akışındaki `Hac` gereksiz yere
  tamamen büyük harfe çevrilmez.
- **Regresyon testi:** 23 Temmuz açık feedback köklerini kapsayan iki test eklendi:
  yanlış-pozitiflerin skor dışı kalması ve doğru sayfa/Hacc standartlarının uygulanması.
  `npm.cmd run check` başarılı; 70/70 test geçti.
- **Deploy ve canlı kapanış:** Commit `46fd64d` production'a deploy edildi
  (`https://arsiv-kontrol-qcgtmp4gm-ugurkarabulutts-projects.vercel.app`) ve
  `https://arsiv.ibrahimlive.ai/health` canlıda `ok` döndü. 15 açık feedback
  `feedback-fix-2026-07-23-latest-standards-1784822374472` çözüm grubuyla kapatıldı;
  Hacer Terzi, Serap Pamuk, Nuray Ardagümüşoğlu ve Aysun Aydöner için 4 kişisel
  `feedback_resolution` bildirimi gönderildi. Son canlı kontrolde açık feedback `0`.
- **Son aktiflik kalıcı güvenilirlik düzeltmesi:** Canlı DB'de `users.last_seen_at` kolonu
  henüz uygulanmadığında son aktif verisinin eksik veya kırılgan görünmemesi için aktivite
  takibi güçlendirildi. `recordUserActivity` artık tek ortak `settings.user_last_seen` JSON
  satırına bağlı kalmaz; her kullanıcı için ayrı `settings.user_last_seen:{userId}` yedeği
  yazar. Böylece eşzamanlı kullanıcı isteklerinde ortak JSON satırının birbirini ezmesi
  riski azaltıldı.
- **Kullanıcı listesi son aktif hesaplama:** `/api/users` artık son aktif zamanını sırasıyla
  `users.last_seen_at`, tekil settings yedeği, eski toplu settings yedeği ve son denetim
  geçmişinden en güncel güvenilir tarih olarak hesaplar. UI'da tarih hücresine veri kaynağı
  için kısa açıklama eklendi; aktivite sinyali olmayan kullanıcılar bilinçli olarak `—`
  görünür.
- **Canlı migrasyon ve doğrulama:** Eski `settings.user_last_seen` içindeki 26 kayıt canlıda
  tekil `user_last_seen:{userId}` kayıtlarına taşındı. Canlı kontrolde 38 kullanıcıdan 16'sında
  gerçek son aktif sinyali var; kalanlarda güvenilir aktivite sinyali olmadığı için boş
  görünmesi doğru. `npm.cmd run check` başarılı; 68/68 test geçti. Commit `280c3ed`
  production'a deploy edildi (`dpl_EgTozzSEGcZKEgqvD4qng4jmnUsk`), canlı `/health` `ok`.
- **Canlı DB kolon uygulaması:** Kullanıcı tarafından Supabase SQL Editor'da
  `users.last_seen_at` kolonu ve `users_last_seen_at_idx` indeksi uygulandı. Backfill sonucu
  `son_aktif_dolu=16`, `toplam_kullanici=38`. Sonrasında temiz Vercel production deploy
  alındı (`dpl_Eub4NnvaNT92AVBNZhK5Hfhj9eXg`) ve canlı kontrolde kolon service role ile
  okunabilir, `/health` `ok` olarak doğrulandı.

### 2026-07-19
- **Tekrarlanan sure adı standardı kalıcı çözümü:** Serap Pamuk geri bildirimiyle gelen
  `ŞURA-8` düzeltilip aynı metindeki `ŞURA-28` geçişinin düzeltilmemesi kök seviyede
  çözüldü. Kök sebep, deterministic standart ekleme katmanının aynı `original -> fixed`
  çiftini tekil sayıp tekrar eden geçişleri eklememesiydi; uygulama katmanı da her issue'yu
  bir geçişe uyguladığı için yalnız ilk geçiş düzeliyordu. `addDeterministicIssue` artık
  tekrar eden deterministic standart geçişlerini kayda alır; mevcut güvenlik sayacı kaynak
  metindeki gerçek geçiş sayısından fazlasını yine kabul etmez.
- **Regresyon testi:** Tek AI bulgusu `ŞURA -> ŞÛRÂ` olsa bile kaynakta geçen tüm sure adı
  referanslarının (`ŞURA-8`, `ŞURA-28`) `ŞÛRÂ-8`, `ŞÛRÂ-28` olarak uygulandığını doğrulayan
  test eklendi. `npm.cmd run check` başarılı; 68/68 test geçti.
- **Deploy ve canlı kapanış:** Commit `cc86b43` production'a deploy edildi
  (`dpl_BikBzJGB7btZA2Awj7ArTboRPD5i`), `https://arsiv.ibrahimlive.ai/health` canlıda
  `ok` ve ana sayfa HTTP 200 döndü. Feedback
  `feedback-fix-2026-07-19-serap-shura-repeat-1784458769071` çözüm grubuyla kapatıldı,
  Serap Pamuk'a kişisel `feedback_resolution` bildirimi gönderildi. Son canlı kontrolde
  açık feedback `0`.

### 2026-07-18
- **8 açık feedback kök çözüm turu:** Hacer Terzi, Nuray Ardagümüşoğlu ve Aysun Aydöner
  geri bildirimleriyle gelen yeni açık kayıtlar kalite katmanına işlendi. Sistem artık
  `şekli şemalinize -> şekil şemalinize`, `kaadirdir -> kâdirdir`, `halifesi -> halîfesi`,
  `suretiyle -> surette`, `Allah arasındadır -> Allah'a arasındadır` ve metinde zaten
  `(S.A.V)` varken ikinci kez `(S.A.V)` ekleme dönüşümlerini skor dışı bırakır ve
  düzeltilmiş metne uygulamaz.
- **Keyfe mâ yeşâ standardı:** `keyfe meaşadır` veya `keyfe meşadır` kullanımı deterministic
  olarak `keyfe mâ yeşâdır` standardına düzeltilir; modelin `meaşadır -> meşadır` üretimi
  yanlış-pozitif kabul edilip reddedilir.
- **Çift tırnak geniş koruma:** Gereksiz `""...""` ve birden çok iç alıntıda tekrar eden çift
  tırnak varyasyonları temizlenir; sonda kalan boş çift tırnak artığı kaldırılır.
- **Prompt ve test:** Üst öncelikli prompt kuralları `suretiyle`, `keyfe mâ yeşâdır`,
  `Allah arasındadır`, `kaadirdir`, `halifesi` ve mükerrer `(S.A.V)` korumalarıyla
  güncellendi. `npm.cmd run check` başarılı; 63/63 test geçti.
- **Canlı feedback kapatma:** 8 açık feedback
  `feedback-fix-2026-07-18-latest-roots-1784328201245` çözüm grubuyla kapatıldı. Hacer
  Terzi, Nuray Ardagümüşoğlu ve Aysun Aydöner için 3 kişisel `feedback_resolution`
  bildirimi gönderildi. Son kontrolde açık feedback `0`.
- **Yeni mustekîm/Hristiyan/salih feedback turu:** Nuray Ardagümüşoğlu geri bildirimleriyle
  gelen 4 açık kayıt kalite katmanına işlendi. Arapça âyet okunuşu/transliterasyon satırında
  geçen `sırâtekel mustekîm(mustekîme)` ifadeleri Türkçe `Sıratı Mustakîm` standardına
  zorlanmaz; ancak Türkçe anlatıdaki `Sıratı Mustakîm` düzeltmesi korunur. `Hristiyanlar`
  yazımı TDK yazım kuralıyla uyumlu biçimde korunur ve `Hıristiyanlar` yapılmaz. `salih`,
  `salihler`, `salihlerle` yazımları otomatik `sâlih/sâlihler/sâlihlerle` yapılmaz.
  `npm.cmd run check` başarılı; 65/65 test geçti. Production deploy `/health ok` ile
  doğrulandı. 4 feedback `feedback-fix-2026-07-18-translit-hristiyan-salih-1784399770169`
  grubuyla kapatıldı ve Nuray Ardagümüşoğlu için tek kişisel çözüm bildirimi gönderildi.
- **Serap Pamuk nimet listesi feedback turu:** Canlı kuyruğa sonradan düşen 2 açık feedback
  ayrıca incelendi. Numaralı nimet listesinde `3 nimet -> 3. ni'met` birleşik dönüşümü
  reddedilir; eksik nokta varsa yalnız `3 nimet -> 3. nimet` uygulanır ve `nimet` kelimesi
  bu listede `ni'met` yapılmaz. `Bismillâhirrahmânirrahîm` arşiv standardı bitişik yazım
  olarak korunur; bu konuda sistem standardı doğru olduğu için kod değişikliği yapılmadı,
  kullanıcıya açıklamayla bildirildi. `npm.cmd run check` başarılı; 66/66 test geçti.
  Production deploy `/health ok` ile doğrulandı. 2 feedback
  `feedback-fix-2026-07-18-serap-nimet-bismillah-1784400162577` grubuyla kapatıldı ve
  Serap Pamuk için tek kişisel çözüm bildirimi gönderildi. Son canlı kontrolde açık feedback `0`.
- **Hacer Terzi Kur'ân-ı Kerîm feedback turu:** Canlı kuyruğa sonradan düşen 1 açık feedback
  incelendi. `Kur’ân-ı Kerîm bunu böyle mi yazıyor? -> Kur'ân bunu böyle mi yazıyor?`
  dönüşümü kök seviyede engellendi; `Kur'ân-ı Kerîm`, `Kur’ân-ı Kerîm` gibi tamlamalarda
  `-ı Kerîm` kısmı kaynakta varsa silinmez. Prompt'a aynı açık kural eklendi.
  `npm.cmd run check` başarılı; 67/67 test geçti. Production deploy `/health ok` ile
  doğrulandı. Feedback `feedback-fix-2026-07-18-hacer-kuran-kerim-1784400533116` grubuyla
  kapatıldı ve Hacer Terzi için tek kişisel çözüm bildirimi gönderildi. Son canlı kontrolde
  açık feedback `0`.

### 2026-07-17
- **Hacer Terzi 6 açık feedback kök turu:** Canlı feedbacklerde gelen `surette -> sürette`,
  `bir şey -> birşey` ve `şekli şemalinize -> şekil şemalinize` yanlış-pozitif olarak
  korumaya alındı. `surette`, `bir şey` ve `şekli şemalinize` bu bağlamlarda kaynakta
  olduğu gibi korunur.
- **S.A.V parantez standardı revizyonu:** Kullanıcı düzeltmesiyle `(S.A.V:` gibi kapanmamış
  parantezlerin gerçek noktalama hatası olduğu netleştirildi. Sistem bu kullanımı hata
  olarak göstermeli ve `(S.A.V):` biçimine düzeltmelidir; bu sınıf yanlış-pozitif korumasından
  çıkarıldı.
- **Âyet standardı bağlamı:** Bağımsız küçük harf `ayet -> âyet` standardı korunur. Ancak
  `Hidayet/Hidayette/hidayete` içindeki `ayet` parçası kelime gibi yakalanmaz ve yalnızca
  büyük başlık/listede geçen `AYET` kullanımı normal cümle kelimesi gibi skorlanmaz.
- **Prompt ve test:** Üst öncelikli prompt kurallarına `bir şey`, `surette`, `şekli şemal`
  korumaları ve kapanmamış S.A.V parantezini düzeltme standardı eklendi. `npm.cmd run check`
  başarılı; 61/61 test geçti.
- **Canlı feedback kapatma:** Hacer Terzi'ye ait 6 açık feedback
  `feedback-fix-2026-07-17-hacer-roots-1784252599562` çözüm grubuyla kapatıldı. Hacer
  Terzi için tek kişisel `feedback_resolution` bildirimi gönderildi. Son kontrolde açık
  feedback `0`, çözüm sonrası açık takip `0`.

### 2026-07-16
- **Tavsiye/birşey/bağlaç/hidayet ekleri kök koruması:** Nuray Ardagümüşoğlu ve Hacer
  Terzi geri bildirimleriyle gelen 6 açık kayıt 4 kök sınıfa ayrıldı ve kalite katmanında
  genel guard olarak çözüldü. `tavsiye -> tâbî` gibi ilgisiz kelimeyi `tâbî` yapma,
  `birşey -> herşey` gibi anlam değiştirme, `ve elimize -> elimize` gibi baştaki bağlacı
  silme ve `hidayete -> hidayet` gibi ekli `hidayet` kullanımlarını köke kırpma skor dışı
  bırakılır ve düzeltilmiş metne uygulanmaz.
- **Prompt güçlendirme:** Üst öncelikli kurallara `birşey/herşey` anlam ayrımı, `tavsiye`
  kelimesinin korunması, `hidayete/hidayeti/hidayetten` gibi ekli kullanımların eklerinin
  düşürülmemesi ve `ve/veya/ama/fakat/çünkü` bağlaçlarının silinmemesi eklendi.
- **Test:** `npm.cmd run check` başarılı; 59/59 test geçti. Yeni regresyon testi dört kök
  sınıfı birlikte doğrular: toplam hata `0`, skor `100`, düzeltilmiş metin kaynak metinle
  aynı kalır.
- **Canlı feedback kapatma:** 6 açık feedback
  `feedback-fix-2026-07-16-latest-roots-1784217498144` çözüm grubuyla kapatıldı. Nuray
  Ardagümüşoğlu ve Hacer Terzi için 2 kişisel `feedback_resolution` bildirimi gönderildi.
  Son kontrolde açık feedback `0`, çözüm sonrası açık takip `0`.
- **Apostroflu terkip ve mevcut nokta koruması:** Nuray Ardagümüşoğlu geri bildirimleriyle
  gelen `"fazl'ıl" -> "fazl'ul"` ve `"Allah’ın Zat’ı" -> "Allah’ın Zat’ı."` yanlış
  dönüşümleri kök seviyede çözüldü. Apostrof sonrası kısa Arapça/transliterasyon
  parçalarında yalnızca sesli harf değiştirerek yapılan şüpheli dönüşümler genel olarak
  skor dışı bırakılır; normal Türkçe kesme eki düzeltmeleri bu korumadan muaf tutulur.
  Kaynak metinde nokta zaten varsa, tek kelime değil çok kelimeli ifadelerde de "nokta
  eksik" bulgusu reddedilir. Prompt sözlüğüne `fazl’ıl azîm` standardı eklendi.
- **Test:** `npm.cmd run check` başarılı; 58/58 test geçti. Yeni regresyon testi iki canlı
  feedback kökünü birlikte doğrular: toplam hata `0`, skor `100`, düzeltilmiş metin kaynak
  metinle aynı kalır.
- **Canlı feedback kapatma:** Nuray Ardagümüşoğlu'na ait 2 açık feedback
  `feedback-fix-2026-07-16-apostrophe-punctuation-1784179484959` çözüm grubuyla kapatıldı
  ve tek kişisel `feedback_resolution` bildirimi gönderildi. Son kontrolde açık feedback `0`.
- **Şerr kökü ekli kullanım koruması:** Serap Pamuk geri bildirimleriyle gelen
  `"şerrdir" -> "şerdir"` ve `"şerrle" -> "şerle"` yanlış dönüşüm kökü kalıcı olarak
  kapatıldı. `şerr` standardı artık yalnız tek kelime olarak değil, ek almış formlarda da
  korunur; model bu kökü `şer` köküne düşürürse bulgu skor dışı kalır ve düzeltilmiş metne
  uygulanmaz.
- **Test:** `npm.cmd run check` başarılı; 57/57 test geçti. Yeni regresyon testi canlı iki
  örneğin toplam hata sayısını `0`, skoru `100` ve düzeltilmiş metni kaynak metinle aynı
  tuttuğunu doğrular.
- **Canlı feedback kapatma:** Serap Pamuk'a ait 2 açık feedback
  `feedback-fix-2026-07-16-serr-1784153654037` çözüm grubuyla kapatıldı ve tek kişisel
  `feedback_resolution` bildirimi gönderildi. Aysun Aydöner'in eski çift tırnak
  `Çözülmedi` takip yanıtı, çift tırnak regresyonu canlı kodda testle güvence altında olduğu
  için kapatıldı. Son kontrolde açık feedback `0`, çözüm sonrası açık takip `0`.

### 2026-07-14
- **15 Temmuz 18 acik feedback kok koruma turu:** Bihter Oksak, Serap Pamuk ve Nuray
  Ardagumusoglu tarafindan gelen 18 acik feedback kok siniflara ayrildi ve kalite katmanina
  islendi. Cozulen siniflar: dis/cift tirnak temizligi, `Sura -> Şûrâ` eksik sapka yakalama,
  Arapca ayet/transliterasyon parantez ve bosluk korumasi, `cihad` ve `Ebu` sapka zorlamasini
  reddetme, sure apostrof dusurme (`Ra'd -> RAD`), noktalı virgulu iki noktaya zorlama,
  ayri cumleyi virgul ile birlestirme, `Eûzü...` duasini bitisiklestirme, `inşaallah` ters
  standardini reddetme, metinde olmayan `kasiyet -> kasvet`, `lâzımgelen`, ayet icindeki
  `dîni/dîne` ve `Hz. İsa’ya -> Hazreti İsa (A.S)’ya` donusumlerini koruma.
- **Test:** `npm.cmd run check` basarili; 56/56 test gecti. Yeni regresyon testi 14 Temmuz
  acik feedback koklerini birlikte dogrular.
- **Canli feedback kapatma:** 18 acik feedback `feedback-fix-2026-07-15-18-1784128089002`
  cozum grubuyla kapatildi. Bihter Oksak, Serap Pamuk ve Nuray Ardagumusoglu icin 3
  kisisel `feedback_resolution` bildirimi gonderildi. Son kontrolde acik feedback sayisi `0`.
- **Feedback kok kategori ve tekrar uyarisi:** Geri bildirimler artik mesaj iceriginden kok
  kategoriye ayrilir: referans/sure formati, noktalama, sapka/sozluk, tirnak, duzeltilmis
  metne uygulama, duzen/paragraf, kaynakta olmayan icerik ve genel kalite. Acik feedback,
  daha once cozulmus ayni kok kategoriye benziyorsa Geri Bildirim Merkezi kartinda
  "Daha once cozulmus kategoriye benziyor" uyarisi, cozum sayisi ve son cozum tarihi gorunur.
  Cozum kapatilirken kok kategoriler ic kayit olarak `resolution_note` ve
  `issue_resolution_log.summary` alanlarina eklenir; kullaniciya giden mesaj sade kalir.
- **Test:** `npm.cmd run check` basarili; 54/54 test gecti.
- **3 acik feedback kalici koruma turu:** Hacer Terzi geri bildirimleriyle gelen 3 yeni
  yanlis-pozitif vaka cozuldu. Kaynakta nokta zaten varsa `lazim -> lazim.` gibi tek kelime
  nokta ekleme bulgusu skor disi kalir; `kitab -> kitâb` sapkalama zorlamasi reddedilir;
  `3/ALI IMRAN-20 -> 3. ALI IMRAN-20` gibi cok kelimeli sure adi iceren meal/referans
  formatlari degistirilmez.
- **Tekrar sebebi:** Onceki referans korumasi tek kelimeli sure adlarini (`39/ZUMER-17`)
  kapsiyordu; `ALI IMRAN` gibi bosluklu sure adlari regex disinda kaliyordu. Kural artik
  cok kelimeli referans adlarini da kapsar ve regresyon testindedir.
- **Test:** `npm.cmd run check` basarili; 54/54 test gecti.
- **Canli feedback kapatma:** 3 acik feedback `feedback-fix-2026-07-14-hacer-1783977404365`
  cozum grubuyla kapatildi. Hacer Terzi icin tek kisisel `feedback_resolution` bildirimi
  gonderildi. Son kontrolde acik feedback sayisi `0`.

### 2026-07-12
- **13 Temmuz kritik uygulama katmani duzeltmesi:** Aysun Aydoner geri bildiriminde gorulen
  "hatalari buluyor ama duzeltilmis metne uygulamiyor" kok sebebi giderildi. Issue dogrulama
  kaynak metni kanonik olarak bulabiliyor; ancak uygulama katmani apostrof, tirnak ve bosluk
  varyantlarinda daha dar eslesiyordu. `applyAcceptedIssues` artik apostrof/tirnak/ellipsis ve
  bosluk farklarina toleransli uygular. Modelin ekledigi gereksiz `""...""` cift tirnaklari
  `normalizeDoubledQuotes` ile temizlenir.
- **Test:** `npm.cmd run check` basarili; 53/53 test gecti. Yeni testler "issue bulunduysa
  duzeltilmis metne uygulanir" ve "gereksiz cift tirnaklar temizlenir" regresyonlarini kapsar.
- **Canli feedback kapatma:** Aysun Aydoner'in 2 acik feedback kaydi
  `feedback-fix-2026-07-13-apply-1783962347176` grubuyla kapatildi. Kendisine tek kisisel
  cozum bildirimi gonderildi. Son kontrolde acik feedback sayisi `0`.

- **12 Temmuz ek feedback koruma turu:** Canli feedbackteki 6 yeni vaka kullanici lehine
  cozuldu. `Kusluk namazi ... rekat` cumlesinde anlam bozan virgulleme/dagilim degisikligi
  reddedilir; `vaad/vaadde` kok kullanimi `vaat/vaatte` yapilmaz; `afetlerine` sapkali
  bicime zorlanmaz; `...` ile `...`/ellipsis farki hata sayilmaz; `biraraya` sozluk
  standardi olarak korunur ve `bir araya` kaynakta gecerse `biraraya` yapilir. `19 tane
  haslet ruhun` ifadesi yalniz virgulle birakilmaz, deterministic olarak `Ruhta 19 tane
  haslet` bicimine duzeltilir.
- **Test:** `npm.cmd run check` basarili; 51/51 test gecti. Yeni regresyon testi 12 Temmuz
  feedback vakalarini skor ve duzeltilmis metin uzerinde dogrular.
- **Canli feedback kapatma:** Production deploy sonrasi 6 acik feedback kaydi
  `feedback-fix-2026-07-13-1783893985888` cozum grubuyla `resolved` kapatildi. Birgul
  Nursoy, Nuray Ardagumusoglu ve Hacer Terzi icin 3 kisisel `feedback_resolution`
  bildirimi gonderildi. Son kontrolde acik feedback sayisi `0`.
- **Yeni feedback koruma turu:** 11-12 Temmuz canli feedbacklerinde kullanicilarin hakli
  oldugu kabul edilen 17 acik vaka kalite katmanina islendi. `Kadir/Kaadir`, `Kadiri/Kaadiri`,
  `Vel Asr/Vel-Asr`, sure/ayet referans formatini nokta standardina zorlama, `Allah -> Allahu
  Teala` baglam genisletmesi, `dinehum`, `hadisi/hadis-i`, `Allah'da/Allah'ta`, `sagir/sagir`,
  `ukba/ukba`, `rahmete/rahmeti` ve tablo sablonu bosluklari kullanici lehine korunur.
  `Zuruf -> Zumer` yanlis eslesmesi reddedildi; kaynak `Zuruf` ise dogru hedef `Zuhruf`
  olarak deterministic standarda alindi. `Kadir` genel kelime olarak artik otomatik
  `Kaadir` yapilmaz; yalniz `kadirdir -> kaadirdir` standardi korunur.
- **Test:** `npm.cmd run check` basarili; 50/50 test gecti. Yeni regresyon testi 11 Temmuz
  feedback vakalarinin skor ve duzeltilmis metin uzerinde kullanici lehine korundugunu dogrular.
- **Canli feedback kapatma:** Deploy sonrasi canli DB'de acik kalan 18 feedback kaydi
  `feedback-fix-2026-07-12-1783851067872` cozum grubuyla `resolved` kapatildi. Birgul
  Nursoy, Hacer Terzi, Nuray Ardagumusoglu ve Serap Pamuk icin 4 kisisel
  `feedback_resolution` bildirimi gonderildi. Son kontrolde acik feedback sayisi `0`.

### 2026-07-10 Final Feedback Temizlik Turu
- **Final feedback temizlik ve kalite kilidi:** Canli Supabase feedback kuyrugundaki 52 acik kayit kullanici onayli `feedback-cleanup-2026-07-10` cozum grubuyla `resolved` kapatildi. Ayni turda 7 kullaniciya kisisel `feedback_resolution` bildirimi gonderildi; ilk yazimda olusan encoding riski sonrasinda son 7 bildirim kaydi tekrar kontrol edilip okunur metinle guncellendi. Canli kontrolde acik feedback sayisi `0` olarak dogrulandi.
- **Ek regresyon korumalari:** `vucudunu -> vucutunu` gibi ekli kelime bozulmalari engellendi; yalnizca yalniz duran `vucud/vucud/vucut` kokleri `vucut` standardina baglandi. `kadirdir -> kaadirdir`, `5 dakika 10 dakikalik` virgulleme, `Efendimiz (S.A.V)'dir` noktalama ve `Irade eksikligi; irade... -> Irade eksikligi: Irade...` kurallari deterministic test kapsaminda guvenceye alindi.
- **Test ve deploy:** `npm.cmd run check` basarili; 49/49 test gecti. Degisiklikler `95c7621` commit'iyle production'a deploy edildi ve `https://arsiv.ibrahimlive.ai/health` canli ortamda `ok` donusuyle dogrulandi.
### 2026-07-10
- **13 feedback karar standardı:** Kullanıcı onayıyla 13 maddelik geri bildirim kararları
  kod ve prompt katmanına işlendi. `vücud/vücût → vücut`, `Hazreti İsa → Hazreti İsa (A.S)`,
  `HADİS-İ ŞERİF → HADÎS-İ ŞERİF`, `dîn... → din...`, `inşallah → inşaallah` ve âyet/sure
  referans boşluk düzeltmeleri kabul edildi. `herşey` ekli halleri, `tabiî`, `derecât`,
  `hayy/hayydırlar`, `hidayet` kelimesine ek uydurma, `vücut/vücuttan → vücud/vücuddan`,
  `Şerif → Şerîf` ve kaynakta olmayan `Evet/diyor` gibi içerik eklemeleri güvenlik filtresine
  alındı.
- **Kesin standart ve tekrar sayım güvenliği:** `finalizeResult` artık kritik standartları
  yalnızca modele bırakmaz; model kaçırsa bile `dîn...`, `her şey...`, `vücud/vücût`,
  `inşallah`, `Hadis-i Şerif`, `Hazreti İsa` ve sure/âyet referans boşlukları için
  deterministic issue ekler. Ayrıca kaynak metindeki gerçek geçiş sayısından fazla aynı
  `original` issue kabul etmez. Böylece kaynakta bir kez geçen `Kur'ân-ı`, `hidayet` veya
  benzeri ifadeler model tarafından birkaç kez hata sayılırsa fazlalıklar skor ve düzeltilmiş
  metinden düşer.
- **Test:** `npm.cmd run check` başarılı; 45/45 test geçti. Yeni regresyon testi 13 kararın
  kabul edilen ve reddedilen yönlerini birlikte doğrular.

### 2026-07-07
- **Sistem özellik dokümanı ve feedback kapatma:** Kullanıcı onayıyla canlı DB'deki
  29 açık feedback kaydı `approved-close-2026-07-07` çözüm grubuyla `resolved` kapatıldı;
  kullanıcılara yeni bildirim gönderilmedi. Sistem kapsamı, kullanıcı/admin özellikleri,
  feedback, bildirim, standart, rapor ve teknik mimari detayları
  `docs/SISTEM_OZELLIKLERI.md` dosyasında kalıcı kaynak olarak toplandı.
- **Son aktiflik güvenilirliği:** `recordUserActivity` artık yalnızca login/me çağrısında
  değil, yetkili API isteklerinde dakikada en fazla bir kez çalışır. Canlı DB'de
  `users.last_seen_at` kolonu varsa doğrudan oraya yazar; kolon yoksa mevcut
  `settings.user_last_seen` yedeğine düşer. `schema.sql` içine `users.last_seen_at`
  ALTER ve indeks satırları eklendi.
- **Operasyon paneli toparlama turu:** Rapor Geçmişi ekranı ay/tarih filtresi, özet
  sayaçları ve katlanabilir rapor kartlarıyla sadeleştirildi. Geri Bildirim Merkezi
  açık/okunmamış/çözülen/tümü filtreleri ve kullanıcı adı gösterimi aldı. Mesaj Kayıtları
  toplu/kişisel/çözüm/duyuru filtreleri ve özet sayaçlarıyla düzenlendi. Canlı Supabase
  kontrolünde 197 toplam feedback içinde 29 açık kayıt görüldü: Serap Pamuk 7, Bihter
  Oksak 6, Aysun Aydöner 6, Nuray Ardagümüşoğlu 5, Mihrimah Bilgili 3, Hacer Terzi 2.
- **Gerçek görüntüleme takibi:** Kullanıcı bildirimleri ve Standartlarımız kartları artık
  `Okundu/Okudum` butonuna bağlı değildir. Kart ekranda en az 1 saniye görünür kalırsa
  tekil olarak görüntülendi sayılır; admin takip sayaçları bu gerçek görüntüleme kaydından
  beslenir. Sayfa açılışında görünmeyen bildirim veya standartlar topluca okundu yapılmaz.
- **Standart takip UX düzeltmesi:** Standartlarımız ekranındaki admin takip alanında
  `Görmeyenler` listesi kaldırıldı. Her standartta göz butonu ile `görüntüleyen/toplam`
  sayısı gösterilir; tıklanınca yalnızca görüntüleyen kullanıcılar açılır. Mesaj Kayıtları
  ile aynı takip dili kullanılır. `npm.cmd run check` başarılı; 44/44 test geçti.
- **Çözüm tekrarı kontrolü:** Canlı kontrolde Test hesabına görünen eski çözüm mesajının
  farklı bir feedback kaydına ait olduğu, açık görünen Test kaydının ayrı ve rastgele bir
  kayıt olduğu doğrulandı. Bu Test kaydı canlı DB'de `resolved` işaretlendi ve yeni mesaj
  gönderilmedi. Tekil `Çözüm bildir` endpoint'i resolved işaretli feedbacke ikinci kez
  çözüm bildirimi göndermeyi reddeder. Açık kuyruk 29 gerçek feedback / 6 kullanıcı olarak
  doğrulandı. `npm.cmd run check` başarılı; 44/44 test geçti.
- **Mesaj kayıtları UX düzeltmesi:** Çözüm mesajı hitabı artık `Sevgili {kullanıcının sistemdeki adı}`
  satırıyla başlar; virgül eklenmez ve isim/kalp sistemde kayıtlı haliyle korunur. Mesaj Kayıtları
  ekranında aynı toplu mesaj tek kartta gösterilir; alıcılar tek tek basılmaz. Kartta yalnızca göz
  butonu ile `görüntüleyen/toplam` sayısı görünür, tıklanınca sadece görüntüleyen kullanıcılar açılır;
  görüntülemeyenler listesi bu ekranda gösterilmez. `npm.cmd run check` başarılı; 44/44 test geçti.
- **Çözüm bildirimi geri dönüş döngüsü:** Kullanıcıların `feedback_resolution` bildirimleri
  altında artık `Sorun çözüldü` ve `Çözülmedi` seçenekleri vardır. `Çözülmedi` seçilirse
  not alanı açılır ve cevap admin kuyruğuna `Çözüm sonrası sorun devam ediyor` başlıklı yeni
  feedback olarak düşer. Yanıtlar SQL migration gerektirmeden `settings` içindeki
  `resolution_feedback_responses` kaydında tutulur. Süper admin için ayrı `Çözüm Takibi`
  ekranı eklendi; Mesaj Kayıtları ekranında da gönderilen çözüm bildirimlerinin yanıt durumu
  görünür. `npm.cmd run check` başarılı; 44/44 test geçti.
- **Canlı feedback çözüm turu:** Test hesabının rastgele geri bildirimi kalite hatası kabul
  edilmedi. Gerçek kullanıcı feedbacklerinden gelen `vücud`, `şerr`, `arif`, `cahiliye`,
  `dinde`, `ve vechini`, `NEFSİ EMMÂRE`, hadis kaynak numarası, `Mu'min`, `A'raf` ve `Nur`
  bağlamları kod seviyesinde korumaya alındı. Doğru kabul edilen kelime halleri
  `CANONICAL_WORD_STANDARDS` sabitinde kayıtlıdır ve otomatik testlerle izlenir.
- **Düzeltilmiş metin güvenliği güçlendirmesi:** `correctedText` artık kaynak metin üzerine
  yalnızca kabul edilen issue'ların kontrollü uygulanmasıyla üretilir. Modelin serbest
  correctedText çıktısındaki tablo/paragraf bozulması, uygulanmayan bulgu veya ek kelime
  üretimi sonuç metnine taşınmaz.
- **Kullanıcı denetim ekranı sadeleştirme:** Kullanıcı tarafındaki `AI Raporu Oluştur`
  butonu ve Denetim Yardımcısı paneli kaldırıldı. Geri bildirim akışı bulgu bazlı ve
  doğrudan sonuç ekranında kaldı; admin AI rapor altyapısına dokunulmadı.
- **Test:** `npm.cmd run check` başarılı; 44/44 test geçti.

### 2026-07-06
- **Açık feedback çözüm paketi:** Canlı açık geri bildirimler kök sebeplere ayrıldı ve
  backend doğrulama katmanı genişletildi. `nefsi/nefsin`, `taktirde`, `A.S/S.A.V`,
  `Efendimiz (A.S)`, `derecat*`, ek/tamlayan kırpma, kaynakta şapkalı yazılmış kelimeyi
  şapkasızlaştırma, `birr`, `hâdise`, `afv-u` ve hadîs kaynak adı dönüşümleri yanlış-pozitif
  olarak skor dışı bırakılır.
- **Düzeltilmiş metin güvenliği:** `correctedText` artık modelin serbest metni olarak
  kabul edilmez; kaynak metne yalnızca kabul edilen issue'lar kontrollü uygulanır. Böylece
  issue listesinde olmayan gizli değişiklikler, tablo/düzen bozulmaları ve şapkalı kelime
  sadeleşmeleri düzeltilmiş metne sızmaz.
- **Feedback modalı sağlamlığı:** Uzun geri bildirim notlarında gönder butonu görünür kalır,
  modal gövdesi kaydırılabilir ve gönderim sırasında çift tıklama engellenir.
- **Kapsamlı audit düzeltmeleri:** Cron rapor endpoint'i artık `CRON_SECRET` olmadan çalışmaz
  ve spoof edilebilir `x-vercel-cron` header'ına güvenmez. Proje kökü statik servis edilmez;
  sadece `icons`, `manifest.webmanifest` ve `sw.js` açık servis edilir. Feedback not limiti
  frontend/backend uyumlu biçimde 2000 karakterdir.
- **Geri bildirim ve kullanıcı yönetimi sağlamlığı:** Geri Bildirim Merkezi seçim/çözüm sonrası
  bulunduğu ekranı yeniler; kullanıcıyı Sistem Uyarıları sekmesine atmaz. Kullanıcı yönetiminde
  Bildirim/Düzenle/Sil butonları id, ad ve rol değerlerini güvenli JSON argümanıyla taşır;
  apostrof veya tırnak içeren isimler butonları bozmaz.

### 2026-07-03
- **Denetim Yardımcısı AI:** Kullanıcı tarafındaki Metin Denetimi ekranına güvenli "Denetim
  Yardımcısı" eklendi. Yardımcı; metni denetime hazırlama, sonucu sade açıklama, şüpheli
  noktaları ikinci göz olarak yorumlama ve geri bildirim taslağı oluşturma görevlerini yapar.
  Kullanıcı ekranında serbest soru alanı yoktur; yardım chat gibi değil, görev bazlı denetim
  rehberi gibi çalışır. Metni kendi başına düzeltmez, kural değiştirmez, dini/içerik yorumu yapmaz,
  kullanıcı adına onay/red vermez. Backend `POST /api/ai/helper` endpoint'i `gpt-4o-mini` ile
  JSON yanıt üretir; API anahtarı yoksa güvenli fallback önerileri döner.
- **Canlı AI hissi:** Kullanıcı ve admin AI ekranlarında model adı gösterilmez. İşlem sırasında
  "metin okunuyor / bulgular değerlendiriliyor / öneriler çıkarılıyor" gibi süreç adımları,
  canlı nokta animasyonu ve tamamlandı durumları gösterilir. Admin AI rapor ve soru ekranı da
  aynı süreç panelini kullanır; kullanıcıya `4o mini çalışıyor` gibi teknik ifade gösterilmez.
- **Denetim Yardımcısı gelişmiş görevleri:** Yardımcıya `Şüpheli Bulgular` ve `Kopyalama
  Kontrolü` görevleri eklendi. Backend yanıtları artık `checks` ve `nextActions` alanlarını da
  destekler. Frontend canlı süreç adımları sabit metinlerden çıkarıldı; görev tipi, metin
  uzunluğu, düzen izleri, skor ve hata sayısına göre farklı adımlar seçer.
  Böylece kullanıcı/admin tarafında aynı cümlelerin sürekli dönmesi engellenir.
- **Kullanıcı feedback rehberi:** Bulgu bazlı `Metinde yok` veya `Yanlış düzeltme` butonlarına
  basıldığında Denetim Yardımcısı ilgili bulgunun neyi değiştirdiğini, hangi durumda bu geri
  bildirimin doğru kullanılacağını ve kısa notun nasıl yazılacağını gösterir. Tarayıcı `prompt`
  penceresi yerine uygulama içinde modern, geniş ve otomatik yükseklikli bir geri bildirim modalı
  açılır; kullanıcıya düzenleyebileceği bağlamlı bir not taslağı sunulur. Bu, yanlış veya eksik
  feedback kayıtlarını azaltmak için eklendi.
- **Tek AI raporu ve feedback kapısı:** Kullanıcı tarafındaki çoklu yardımcı butonları kaldırıldı;
  tek ana aksiyon `AI Raporu Oluştur` oldu. Bu rapor metni, denetim sonucunu, şüpheli bulguları,
  kopyalama güvenliğini ve ekibe bildirim gerekip gerekmediğini birlikte değerlendirir. Sonuçta
  bulgu varsa genel ve bulgu bazlı feedback butonları doğrudan görünür; temiz/0 bulgulu sonuçlarda
  feedback kapalı kalır. Amaç pozitif/sağlıklı sonuçların admin feedback kuyruğunu şişirmesini
  engellerken, gerçek bulgu içeren sonuçlarda kullanıcının hızlı geri bildirim verebilmesidir.
- **Kullanıcı sonuç ekranı sadeleştirme:** `Prompt` ve `Kural` sürüm chipleri kullanıcı
  sonuç ekranından tamamen kaldırıldı. `Temizle` artık sonuç belleğini önce
  sıfırlar, sonra input/yardımcı alanını resetler; Denetim Yardımcısı tek tıkla `Hazır` durumuna
  döner. Yardımcı durum metni `AI hazır`/`Rapor için hazır` diline çekildi ve canlı AI noktası
  daha belirgin menekşe vurgu rengiyle gösterilir.
- **Premium UX ve okunurluk turu:** Uygulama fontu `Noto Sans` olarak değiştirildi; yaşça büyük
  kullanıcılar için daha okunur ve yüksek kontrastlı metin yapısı hedeflendi. Açık/koyu tema
  paletleri daha premium, daha az parlak ve daha katmanlı hale getirildi. Sol menü beyaz düz
  blok görünümünden çıkarılıp yüzey, gölge, aktif durum ve bölüm alt çizgileriyle belirgin
  bir navigasyon katmanına dönüştürüldü. Butonlara hover/active durumları ve tıklamada kısa
  parlak geçiş efekti eklendi.
- **Kullanıcı ayarları ve taslak koruma:** Yeni `Ayarlar` ekranı eklendi. Kullanıcı küçük,
  orta veya büyük yazı boyutu seçebilir; tercih `localStorage` ile cihazda hatırlanır ve örnek
  metinle anında gösterilir. Metin denetim alanı ve son analiz sonucu otomatik taslak olarak
  cihazda saklanır; kullanıcı ekranı uzun süre açık bırakır veya sayfayı yenilerse metin/sonuç
  geri gelir. `Temizle` bilinçli olarak bu taslağı da temizler. Oturum çerez süresi 30 güne
  çıkarıldı.
- **Panel AI asistan ve rapor altyapısı:** Admin paneline "AI Asistan ve Raporlar" ekranı
  eklendi. `gpt-4o-mini` ile günlük/haftalık/aylık/yıllık operasyon raporu üretilebilir ve
  seçilen dönem verisine soru sorulabilir. Backend ham veriyi modele vermeden önce denetim,
  skor, hata kategorisi, kullanıcı aktivitesi, feedback, çözüm kayıtları ve düşük skor
  uyarılarından sınırlı operasyon özeti çıkarır.
- **AI rapor kayıtları:** `schema.sql` içine `ai_reports` tablosu eklendi. Raporlar dönem,
  dönem başlangıç/bitiş, başlık, AI JSON içeriği, kaynak metrikler, model ve oluşturan kişiyle
  kalıcı saklanır. Tablo canlı DB'de yoksa endpoint kontrollü hata döner.
- **Otomatik günlük rapor:** Vercel cron `/api/cron/daily-report` yolunu her gün UTC 21:00'de
  çağıracak şekilde ayarlandı; bu İstanbul saatiyle 00:00'a denk gelir. Endpoint `CRON_SECRET`
  varsa Bearer/query secret veya Vercel cron header ile korunur.
- **AI rapor takvimi ve tekrar güvenliği:** Cron endpoint'i artık İstanbul 00:00'da biten
  takvim dönemlerine göre rapor üretir. Her gece günlük rapor, pazartesi 00:00'da ek olarak
  haftalık rapor, ayın 1'i 00:00'da ek olarak aylık rapor, 1 Ocak 00:00'da ek olarak yıllık
  rapor hazırlanır. Aynı gece birden fazla sınır denk gelirse ilgili raporlar birlikte
  üretilir ve admin/süper adminlere tek duyuru düşer. `ai_reports_period_range_idx` aynı
  dönem aralığının ikinci kez yazılmasını engeller.
- **Test:** `npm.cmd run check` başarılı; 39/39 test geçti. `vercel.json` JSON parse kontrolü
  başarılı.
- **Operasyon paneli UX dönüşümü:** Masaüstünde üst navigasyon yerine sol menülü panel
  düzenine geçildi. Denetim, Operasyon ve Yönetim başlıkları altında ilgili ekranlar
  gruplanır; mobil hamburger menü korunur. Bu düzen ileride e-tablo, IbrahimLive.com ve
  IbrahimLive.ai entegrasyonları için üst barın taşmasını engeller.
- **Geri Bildirim Merkezi:** Feedback kayıtları Uyarılar ekranından ayrıldı ve ayrı
  "Geri Bildirim Merkezi" ekranına taşındı. Uyarılar ekranı düşük skor/duyuru gibi sistem
  olaylarına daraltıldı. Geri Bildirim Merkezi seçili kayıtları çözüm bildirimiyle kapatır
  ve "Codex Paketi" aksiyonuyla açık feedbacklerden kod çözüm turuna aktarılacak çalışma
  metnini panoya kopyalar.
- **Geri bildirim PDF çözüm paketi:** Eski panoya kopyalanan Codex paketi yerine adminler
  seçili veya açık feedbackleri tek PDF olarak indirebilir. PDF; kullanıcı, tarih, skor,
  durum ve ayrıştırılmış geri bildirim alanlarını içerir. Bu akış, uygulamanın doğrudan kod
  değiştiren ajan çalıştırması yerine ekibin dosyayı kullanıcıya/Codex'e kontrollü iletmesi
  için tasarlandı.
- **Süper admin mesaj kayıtları:** Süper admine özel `GET /api/notification-log` eklendi.
  "Mesaj Kayıtları" ekranı kullanıcılara gönderilen `announcement` ve `feedback_resolution`
  bildirimlerini alıcı adı, kullanıcı adı, tarih ve tam mesaj metniyle gösterir. Normal admin
  bu ekranı göremez.
- **Toplu çözüm endpoint düzeltmesi:** Canlı Supabase ilişki cache'ine bağlı embed sorgusu
  kaldırıldı; `/api/alerts/resolve-bulk` artık kullanıcı adlarını ayrı sorguyla alır. Bu,
  panelden toplu çözüm bildirimi gönderimini canlı DB'de güvenilir hale getirir.
- **Test:** `npm.cmd run check` başarılı; 39/39 test geçti ve frontend parse kontrolü tamamlandı.
- **Sorun/çözüm kayıt defteri:** `issue_resolution_log` tablosu eklendi. Tekil veya toplu
  feedback çözümü yapıldığında çözüm turu kısa başlık, özet, çözülen feedback sayısı,
  etkilenen kullanıcı sayısı, çözen kişi ve tarih ile kayıt altına alınır. Admin dashboard'da
  "Sorun / Çözüm Kayıt Defteri" paneli son çözüm turlarını gösterir. Tablo canlı DB'de yoksa
  uygulama kırılmaz; panel boş gelir ve kayıt yazılmaz.
- **Geri bildirim katkı ve çözüm istatistikleri:** Admin dashboard'a geri bildirim yaşam
  döngüsü metrikleri eklendi: toplam/açık/çözülen feedback, çözüm oranı, katkı veren
  kullanıcı sayısı, en çok geri bildirim verenler ve sistem iyileştirmesine en çok katkı
  sağlayan kullanıcılar. Katkı skoru çözülen feedbackleri daha yüksek ağırlıkla sayar.
- **Toplu kişisel çözüm bildirimi:** Adminler Uyarılar ekranında birden fazla `feedback`
  kaydını seçip tek çözüm notuyla kapatabilir. Sistem seçilen feedbackleri kullanıcıya göre
  gruplar; aynı kullanıcı birden fazla sorun bildirdiyse tek kişisel mesaj gönderilir.
  Aynı hatayı birden çok kullanıcı raporladıysa, çözüm sırasında raporlayan her kullanıcıya
  kendi adıyla ayrı teşekkür bildirimi gider. Bu özellik yalnızca geri bildirim butonuyla
  oluşturulan `feedback` kayıtları için çalışır; genel yenilikler yine `announcement`
  kanalından toplu duyurulur.
- **Alerts çözüm modeli:** `schema.sql` `alerts.feedback_status`, `resolved_at`,
  `resolved_by`, `resolution_group` ve `resolution_note` kolonlarını içerir. Kolonlar canlı
  DB'de yoksa uygulama kırılmaz; tam çözüm durumu ve oran takibi için ALTER satırları canlı
  Supabase SQL Editor'de uygulanmalıdır.
- **Test:** `npm.cmd run check` başarılı; 39/39 test geçti, frontend parse kontrolü de tamamlandı.
- **Canlı feedback yanlış-pozitif turu:** Canlı `alerts` feedback kayıtları incelendi. Toplam
  45 geri bildirim içinde 29 kayıt orijinal metinle doğrulanabildi. Gerçek hata olduğu teyit
  edilen dönüşümler backend güvenlik katmanında yasaklandı: `Tabi/Tabiî → tâbî`,
  `süre → sûre`, `afet → âfet`, `zahid → zâhid`, `zülmanî → zulmanî`,
  tek başına `Efendimiz → Efendimiz (S.A.V)`, `(S.A.V) → (S.A.V.)`,
  `Nebîler → Nebiler`, `nefs → nefis`, `ahiret → âhiret` ve yalnızca `islâm → İslâm`
  büyük/küçük harf dönüşümü. Bu issue'lar skor dışı bırakılır ve düzeltilmiş metinden geri alınır.
- **Sıfır hata metin koruması:** Model hiç geçerli issue üretmediği halde `correctedText`
  içinde metni değiştirmişse, sunucu artık skor 100 sonucunda kaynak metni aynen korur. Bu,
  “hata yok ama karşılaştırmada metin bozulmuş” geri bildirimlerini engeller.
- **Prompt güçlendirme:** Canlı feedbacklerden çıkan bağlam uyarıları sistem prompt'una eklendi:
  `Tabi/Tabiî` konuşma bağlamında `tâbî` yapılmaz, zaman anlamındaki `süre` sure adı sanılmaz,
  yukarıdaki korumalı kelimeler ters yöne bozulmaz ve `(S.A.V)` kısaltmasına fazladan nokta eklenmez.
- **Test:** `npm.cmd run check` başarılı; kalite regresyon havuzuna 8 yeni canlı feedback vakası
  eklendi ve toplam test sayısı 39'a çıktı. `Rum → RÛM` gibi şapka farkı içeren sure adı
  düzeltmeleri hâlâ gerçek imlâ farkı olarak korunur; `her şeyi → herşeyi` mevcut sözlük
  kararına göre doğru düzeltmedir.
- **Sure adlarında büyük/küçük harf kararı:** Sure isimlerinde büyük/küçük harf farkı artık
  tek başına hata sayılmaz. Sistem `Fâtiha → FÂTİHA`, `Mulk → MULK`, `Muzzemmil → MUZZEMMİL`,
  `Zumer → ZUMER` gibi sadece case dönüşümlerini skorlamaz ve düzeltilmiş metinden geri alır.
  Asıl kontrol şapka, apostrof ve harf dizilimi gibi imlâ farklarıdır; `Rum → Rûm` gibi şapka
  gerektiren gerçek imlâ farkları hâlâ skorlanır.
- **Test:** Sure adı case-only regresyonları kalite havuzuna eklendi; `npm.cmd run check`
  başarılı, test sayısı 31'e çıktı.
- **Temizle reset bug düzeltmesi:** Metin denetimi ekranında `Temizle` butonu yalnızca
  textarea değerini boşaltıyor, karakter sayacı ve otomatik büyüyen alan yüksekliği eski
  metinden kalıyordu. `clearAnalyze()` artık `handleTextInput()` çağırır; boş metinde sayaç
  `0 karakter` olur, yardımcı metin ilk hale döner ve textarea yüksekliği 180px başlangıç
  yüksekliğine resetlenir.
- **Test:** `npm.cmd run check` başarılı; 27/27 test geçti ve frontend parse kontrolü tamamlandı.

### 2026-07-01
- **Bildirim imza tekrarı:** Bildirim gövdesinin sonundaki tek başına `Arşiv Kontrol AI`
  imza satırı kaldırıldı; gönderen adı zaten kart footer'ında gösterildiği için tekrar
  yazılmaz. Mevcut toplu duyuru kayıtları canlı DB'de imzasız gövdeyle güncellendi.
- **Bildirim gönderen adı:** Kullanıcı bildirimlerinde gönderen adı her zaman `Arşiv Kontrol AI`
  olarak gösterilir. Yeni duyuru ve feedback çözüm bildirimleri backend'de bu adla üretilir;
  bildirim kartı da eski kayıtlarda farklı gönderen olsa bile kullanıcıya `Arşiv Kontrol AI`
  gösterir. Mevcut toplu duyuru kayıtları canlı DB'de aynı gönderen adıyla güncellendi.
- **Bildirim UX iyileştirmesi:** Kullanıcı "Bildirimler" ekranındaki duyuru kartları ham
  `Başlık / Mesaj / Gönderen` log metni yerine ayrıştırılmış modern kart olarak gösterilir.
  Başlık, paragraf gövdesi, gönderen, tarih ve okundu aksiyonu ayrı alanlara bölündü; mobil
  görünümde kart tek sütuna düşer ve daha okunaklı satır aralığı kullanır.
- **Sure adları standardı:** 114 sure adı kullanıcı tarafından verilen listeye göre üst
  öncelikli imlâ standardı yapıldı. Baştaki sıra numaraları imlâ kontrolünde dikkate alınmaz.
  Sure adları listedeki büyük harf, şapka ve apostrof biçimine göre düzeltilir; sure adının
  içinden parça yakalanıp ayrı sözlük kelimesi gibi değiştirilmez. Örnek: `Muminun/Müminun`
  sure adı olarak geçiyorsa `MU'MİNÛN`, `Zumer/Zümer` sure adı olarak geçiyorsa `ZUMER`
  standardı kullanılır.
- **Sure testi:** `Muminun → MU'MİNÛN`, `MU'MİNÛN → mü'min` yanlış indirgemesinin reddi,
  `Zumer → ZUMER` ve `ZUMER → Zümer` yanlış dönüşümünün reddi kalite regresyon havuzuna eklendi.
  `npm.cmd run check` başarılı; test sayısı 27'ye çıktı.
- **Sözlük kararı — din:** Efendimizin sözlüğünde `dîn` yazımı yerine artık `din` doğru
  kabul edilir. Sistem `din` kelimesini `dîn`e çevirmemeli; metinde `dîn` varsa `din`
  olarak düzeltmelidir. Bu karar prompt'a üst öncelikli kural olarak eklendi ve backend
  güvenlik katmanında `din → dîn` dönüşümü yasaklandı.
- **Sözlük kararı — herşey:** `her şey` yerine artık birleşik `herşey` doğru kabul edilir.
  Sistem `herşey` yazımını ayırmamalı; metinde `her şey` varsa `herşey` olarak düzeltmelidir.
  Bu karar prompt'a üst öncelikli kural olarak eklendi ve backend güvenlik katmanında
  `herşey → her şey` dönüşümü yasaklandı.
- **Test:** `npm.cmd run check` başarılı; kalite regresyon havuzuna bu iki karar için hem
  yanlış yönü engelleyen hem de yeni doğru yönü skorlayan 4 test eklendi. Test sayısı 23'e çıktı.

### 2026-06-30
- **İş panosu:** Onay Bekleyenler sekmesi "İş Panosu"na dönüştürüldü. Denetimler
  Bekleyen / Onaylanan / Reddedilen sütunlarında kartlarla gösterilir; kartlardan metin
  görülebilir, onaylanabilir veya reddedilebilir. Bu, ekip operasyon akışının ilk görünür
  sürümüdür.
- **Analiz izlenebilirliği:** analiz sonuçlarına `promptVersion` ve `rulesHash` meta bilgisi
  eklendi; sonuç ekranında küçük chip olarak gösterilir. `schema.sql` yeni kurulumlar için
  `history.prompt_version` ve `history.rules_hash` kolonlarını içerir. Canlı veritabanında
  kolonlar yoksa uygulama kırılmaz, sadece geçmiş kaydına sürüm yazmaz.
- **Geri bildirim merkezi:** Uyarılar sekmesi "Uyarılar ve Geri Bildirimler" olarak
  genişletildi. Adminler Tümü / Geri Bildirim / Düşük Skor filtreleriyle kayıtları ayırabilir.
- **Yan yana karşılaştırma UX'i:** anlık analiz sonucunda orijinal metin ve düzeltilmiş
  metin iki sütunlu karşılaştırma panelinde gösteriliyor. Kısa/orta metinlerde kelime
  düzeyinde kırmızı/yeşil fark vurgusu yapılır; çok uzun metinlerde performans için renkli
  diff kapatılıp metinler yan yana gösterilir. Dosya analizinde sunucu çıkarılan orijinal
  metni response'a ekler; geçmiş kayıtlar için orijinal metni kalıcı saklama sonraki faza
  bırakıldı.
- **Ekip geri bildirim döngüsü:** sonuç ekranına genel geri bildirim ve bulgu bazlı
  "Metinde yok / Yanlış düzeltme" butonları eklendi. Kullanıcılar artık canlı analiz
  sonucundaki yanlış pozitif, eksik hata, düzen bozulması ve skor sorunlarını doğrudan
  uygulama içinden bildirebilir. Backend bu kayıtları mevcut `alerts` tablosunda
  `type='feedback'` olarak saklar; yeni Supabase migration gerektirmez.
- **Doğruyu yanlış sayma kök düzeltmesi:** varsayılan kural setindeki bağlamsız ve çelişkili
  talimatlar yumuşatıldı. Sözlük dönüşümleri artık yalnızca bağımsız/tam kelime ve doğru
  bağlamda uygulanacak şekilde yazıldı; sure adları, özel isimler, slayt/tablo etiketleri
  ve kelime içi parça eşleşmeleri açıkça korundu. `Allah razı olsun.` kuralındaki önceki
  "son cümleye bağla" çelişkisi kaldırıldı; kaynakta ayrı cümleyse ayrı kalır.
- **Korumalı dönüşüm filtresi:** backend `Mu'minûn/Muminun Suresi`, `Tabiî ki`, `derecat`,
  `dinlenmeye`, `Muhterem Efendimiz`, `Zumer` gibi canlı testlerde yanlış pozitif üreten
  ifadeleri korumalı kabul eder. Yasak dönüşümler hem issue listesinden hem de
  `correctedText` içinden geri alınır; böylece skor temizlense bile düzeltilmiş metinde
  yanlış dönüşüm kalmaz.
- **Test:** `npm.cmd run check` başarılı; test sayısı 13'e çıktı. Yeni testler korumalı
  ifadelerin skordan çıkarılmasını ve düzeltilmiş metinden geri alınmasını doğruluyor.
- **Canlı sonuç hata analizi:** ekip tarafından canlı sitede test edilen 16 `.docx` hata
  raporu incelendi. Ortak sorunlar: metinde olmayan kelimelerin hata listesinde görünmesi,
  aynı görünen `original/fixed` çiftlerinin skorlanması, kelime içinden parça yakalama
  (`Muminun` içinden `Mumin`), apostrof/tırnak tipi farklarının gerçek hata sayılması,
  `Tabiî ki`, `derecat`, `dinlenmeye`, `Muhterem Efendimiz` gibi bağlamların yanlış
  yorumlanması ve slayt/hadîs/tablo düzeninin bozulması.
- **AI sonuç doğrulaması:** `finalizeResult(result, sourceText)` kaynak metinde bulunmayan
  veya kullanıcıya aynı görünen issue'ları skor dışı bırakacak şekilde güçlendirildi.
  OpenAI çıktısı artık kaynak metinle birlikte finalize edilir; modelin metinde olmayan
  bulguları doğrudan skoru düşüremez.
- **Prompt istisnaları:** bağımsız "Allah razı olsun." cümlesinin birleştirilmemesi,
  apostrof tipi farkının hata sayılmaması, tırnakların korunması, sure adlarında kelime
  içi parça yakalanmaması ve slayt/tablo düzeninin korunması sisteme açık kural olarak
  eklendi.
- **Test:** `npm.cmd run check` başarılı; test sayısı 11'e çıktı. Yeni testler metinde
  olmayan/aynı görünen issue filtrelemeyi ve `Muminun` içinden `Mumin` eşleşmemesini
  doğruluyor.

### 2026-06-22
- **Süper admin rolü:** `admin` kullanıcı adı girişte ve seed sırasında zorunlu olarak
  `super_admin` rolüne yükseltiliyor; başka hesaplarda saklanmış `super_admin` değeri
  otomatik olarak `admin` rolüne indiriliyor.
- **Kullanıcı yetkileri:** kullanıcı ekleme ve silme API'leri yalnızca süper admine açıldı.
  Normal yöneticiler kullanıcı listesini görebilir ve süper admin dışındaki hesapları
  düzenleyebilir; kullanıcı ekleyemez, silemez veya süper admin hesabını değiştiremez.
- **Yetki testleri:** rol hiyerarşisi ve yalnızca `admin` kullanıcı adına süper admin
  verilmesi `authorization.js` ve otomatik testlerle güvenceye alındı.
- **Serverless başlangıç güvenliği:** kimlik doğrulama akışı Supabase seed/rol migrasyonunun
  tamamlanmasını bekliyor; böylece Vercel fonksiyonunun erken askıya alınması rol
  yükseltmesini yarım bırakamıyor.
- **Eksiksiz bulgular:** sistem prompt'u her hata geçişini ayrı issue olarak zorunlu kılıyor;
  üç ayrı `ayet → âyet` geçişini gösteren somut JSON örneği ve correctedText/issues
  birebir son kontrol talimatı eklendi.
- **Yetkili puanlama:** saf fonksiyonlar `analysis-core.js` dosyasına taşındı ve issue
  sayısı/ağırlıklar için otomatik testler eklendi.
- **60 altı:** mesaj ürün gereksinimindeki metinle birebir eşitlendi; correctedText boş,
  bulgular korunuyor.
- **Tekrar gönderim:** çakışmaya açık ilk-100 parmak izi SHA-256 ile değiştirildi;
  eski parmak izleriyle geriye uyumluluk korundu.
- **Geçmiş/Gör:** yetkili `GET /api/history/:id` eklendi. Gör butonu tüm kullanıcıların
  kendi kayıtlarında gösteriliyor ve metni API'den yeniden yüklüyor.
- **PDF:** HTML indirme kaldırıldı; sunucu PDFKit ve gömülü Noto Serif fontuyla gerçek
  `application/pdf` üretiyor (`POST /api/pdf`).
- **Render health:** oturumsuz `GET /health` eklendi ve sunucu Supabase seed tamamlanmadan
  dinlemeye başlayacak şekilde açılış sırası düzeltildi. UptimeRobot'ta Render servisinin
  `/health` adresi 14 dakikalık HTTP(S) monitor olarak tanımlanmalı.
- **Vercel hazırlığı:** Express uygulaması serverless export edecek şekilde düzenlendi,
  `express-session` yerine imzalı `cookie-session` kullanıldı, dosya sınırı 4 MB yapıldı
  ve toplu analiz iki eşzamanlı bağımsız dosya isteğine bölündü.
- **Vercel production:** `arsiv-kontrol` projesi deploy edildi ve
  `arsiv.ibrahimlive.ai` production aliası başarıyla bağlandı. `/health` ve auth/me
  endpointleri Vercel üzerinden doğrulandı. SSO protection kapatıldı; domain doğrudan
  uygulama login'ine açılıyor. `OPENAI_API_KEY` eklendi; geçici kullanıcıyla canlı login
  ve GPT analizi başarıyla doğrulandı, test verileri temizlendi. Domain kalıcı proje domaini
  olarak ayarlandı ve yeni production deployment'larını otomatik takip eder.
- **Test:** `npm test` ile puanlama, düşük skor, yeni/eski hash ve Türkçe PDF üretimi test ediliyor.
- **PWA/ana ekran:** Kullanıcının verdiği logo değiştirilmeden 192, 512, maskable 512 ve
  Apple 180 ikonlarına dönüştürüldü. Uygulama adı `Arşiv AI` olarak manifest ve Apple meta
  etiketlerine yazıldı; minimal service worker eklendi. Favicon ayrı tasarlanacak.
- **Link paylaşımı:** WhatsApp, Telegram, Facebook ve X için Open Graph/Twitter Card
  başlık-açıklamaları ve logolu 1200x630 sosyal paylaşım görseli eklendi.
- **Feedback ölçümleri:** Admin dashboard'a toplam geri bildirim, son 7 gün geri bildirim
  ve okunmamış geri bildirim kartları eklendi. Uyarılar sekmesindeki ekip geri bildirimleri
  artık `Durum / Not / Bulgu / Dosya` alanları ayrıştırılarak daha okunur gösteriliyor.
- **Geçmiş filtreleri:** Denetim Geçmişi ekranına dosya/kullanıcı araması, durum filtresi
  ve düşük skor filtresi eklendi. Filtreler mevcut `/api/history` cevabı üzerinde çalışır;
  yeni veri modeli veya migration gerektirmez.
- **Riskli kayıtlar:** Admin dashboard'a skor 60 altı veya hata sayısı yüksek son denetimleri
  gösteren "Riskli Son Denetimler" paneli eklendi. Panelden Denetim Geçmişi düşük skor
  filtresine hızlı geçiş yapılabilir.
- **Rapor paylaşımı:** Analiz sonucu ekranına "Raporu kopyala" aksiyonu eklendi. Skor,
  toplam sorun, kategori sayıları, özet, analiz sürümü ve ilk bulgular tek metin olarak
  panoya kopyalanır.
- **Karanlık mod:** Uygulamaya açık/koyu tema anahtarı eklendi. Tercih `localStorage` içinde
  saklanır, mobil menüde de değiştirilebilir ve koyu tema siyah/beyaz ağırlıklı çalışır.
- **Tema switch düzeltmesi:** Koyu temada üst barın görünmez hale gelmesine neden olan genel
  renk değişkeni kullanımı ayrıldı. Üst bar artık kendi tema renklerini kullanır; yazılı
  `Karanlık/Aydınlık` butonu yerine ikonlu modern switch vardır.
- **Koyu tema kontrast düzeltmesi:** Koyu temada `green/red/gold` gibi semantik renklerin
  beyaza dönmesi skor rozetleri ve Onayla/Reddet butonlarında renk patlaması yapıyordu.
  Semantik renkler koyu tema için düşük parlaklıklı ama ayırt edilebilir tonlara çekildi.
- **Koyu tema yumuşatma:** Saf siyah arka plan yerine daha yumuşak koyu gri palet kullanıldı;
  kart, input ve topbar tonları göz yormayacak ama kontrastı koruyacak şekilde ayrıştırıldı.
- **Ekip özeti:** `docs/EKIP_DEBUG_GELISTIRME_OZETI_2026-06-30.md` dosyası eklendi; canlı
  debug, AI sağlamlığı, feedback döngüsü, UX ve tema geliştirmeleri ekip sunumu için özetlendi.
- **Bildirim/duyuru sistemi:** Mevcut `alerts` tablosu olay günlüğü olarak kullanıldı.
  Kullanıcı feedback notu bırakabilir; admin feedback için çözüm yanıtı gönderince ilgili
  kullanıcıya kişisel `feedback_resolution` bildirimi düşer. Admin ayrıca kullanıcı yönetiminden
  tek kullanıcıya özel `announcement` bildirimi gönderebilir. Ek tablo/migration gerektirmez.
- **Kalite regresyon havuzu:** Ekipten gelen canlı hata örnekleri kalıcı test datasına
  çevrilebilsin diye `test/fixtures/quality-regression-cases.json` ve
  `test/quality-regression-cases.test.js` eklendi. `npm.cmd run check` artık bu örneklerde
  yanlış pozitif, eşdeğer apostrof farkı, kelime içi yakalama ve korumalı ifade regresyonlarını
  yakalar.
- **Feedback çözüm metrikleri:** Dashboard'a çözüm bildirimi ve duyuru sayıları eklendi.
  Uyarılar ekranında `Çözüm` ve `Duyuru` filtreleriyle admin logları ayrıştırılabilir.
- **Orijinal metin saklama:** `history.original_text` opsiyonel kolonu eklendi. Kolon canlı
  DB'de varsa yeni analizlerde kaynak metin geçmişe yazılır; yoksa uygulama kırılmaz. Geçmiş
  detayda orijinal metin varsa düzeltilmiş metinle yan yana gösterilir.
- **Metin denetim sağlamlığı:** Metin girişi normalize edilir, çok kısa/boş/çok uzun metinler
  hem frontend hem API tarafında denetime gönderilmeden durdurulur. Denetim sırasında çift
  tıklama ile ikinci analiz başlatılması engellenir.

### 2026-06-18 (2. tur)
- **Skorlama** sunucu tarafında ağırlıklı formülle yeniden yazıldı (`finalizeResult`),
  sistem prompt'una formül eklendi.
- **60 altı skor**: düzeltilmiş metin üretilmiyor, standart uyarı + bulgular gösteriliyor.
- **Tekrar-gönderim kontrolü** eklendi (`text_hash`, per-user). schema.sql'e ALTER eklendi.
- **Kullanıcı adı güncellemesi**: admin kendi adını değiştirince session + topbar yenileniyor
  (`/api/auth/me`'ye `id`, `refreshMe()`).
- **Varsayılan şifre uyarısı** koşullu hale getirildi (`/api/security/default-admin`).
- **Gör butonu** ve **şifre teyidi** doğrulandı (önceki turda çözülmüştü).

### 2026-06-18
- **AGENTS.md eklendi** — proje hafızası ve değişiklik günlüğü başlatıldı.
- **Supabase entegrasyonu** — veri katmanı dosya tabanlı `data/db.json` ve
  `data/rules.txt`'ten Supabase (PostgreSQL) `@supabase/supabase-js` istemcisine taşındı.
  Tüm rotalar async hale getirildi. `schema.sql` eklendi. Seed mantığı startup'a taşındı.
- **Render deploy** — `.gitignore`, `.env.example` ve deploy talimatları eklendi.
