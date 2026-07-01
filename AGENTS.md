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

### 2026-07-01
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
