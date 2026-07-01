# CURRENT_HANDOFF — Arşiv Kontrol AI

Son güncelleme: 2026-06-22 — Claude Code (Codex çalışması devralındı)

## Durum

- Dal: `codex/vercel-arsiv-production` (origin'e push edildi, upstream takipli).
- Uzak depo: `origin` → `https://github.com/ugurkarabulutt/arsiv-kontrol.git`
- **Commit:** `4f54438` — `feat: deploy archive control to Vercel` (16 dosya).
- **Push:** başarılı (`origin/codex/vercel-arsiv-production`).
- **PR:** [#1](https://github.com/ugurkarabulutt/arsiv-kontrol/pull/1) → `main`, **open** (otomatik merge edilmedi).
- `.env` ve `.vercel` commit'e dahil DEĞİL (ignore doğrulandı).
- Vercel projesi: `ugurkarabulutts-projects/arsiv-kontrol` oluşturuldu ve yerel klasöre bağlandı.
- Production deploy: `https://arsiv-kontrol.vercel.app` hazır.
- Özel alan adı: `https://arsiv.ibrahimlive.ai` production aliasına başarıyla bağlandı.
- Kullanıcı veya diğer ajan değişiklikleri izinsiz geri alınmamalı.
- 2026-06-30 Codex: Ekip tarafından canlı sitede test edilen 16 hata raporu
  (`C:\Users\ugur\Desktop\arsiv-test-sonucu-hatalar`) incelendi. Ana sorunlar:
  metinde olmayan kelimelerin issue olarak gösterilmesi, aynı görünen original/fixed
  çiftlerinin hata sayılması, kelime içi parça eşleşmeleri (`Muminun` içinden `Mumin`),
  apostrof/tırnak tipinin gereksiz hata yapılması, bağlam hataları (`Tabiî ki`, `derecat`,
  `dinlenmeye`, `Muhterem Efendimiz`) ve slayt/tablo düzeninin bozulması.

## Bu çalışma ağacındaki değişiklikler

- 2026-07-01/02 Codex sure standardı turu: Kullanıcının verdiği 114 sure adı listesi
  `SURE_STANDARD_LIST` olarak `server.js` içine eklendi. `buildSystemPrompt` listeyi üst
  öncelikli standart olarak verir; baştaki sıra numaraları imlâ kontrolüne dahil değildir.
  `analysis-core.js` filtreleri daraltıldı: `Muminun → MU'MİNÛN` gibi tam sure adı düzeltmesi
  geçerli kabul edilir, fakat `MU'MİNÛN/Muminun → mü'min` gibi kelime içi/parça indirgemesi
  reddedilir. `ZUMER` standardı korunur, `Zümer` dönüşümü reddedilir. Kalite regresyon
  fixture'ına 4 sure vakası eklendi.
- 2026-07-01 Codex sözlük kararı turu: `dîn` yerine `din`, `her şey` yerine `herşey`
  üst öncelikli standart olarak eklendi. `buildSystemPrompt` bu iki kararı mevcut DB kural
  metni tersini söylese bile öncelikli uygular. `analysis-core.js` eski yöne dönüşleri
  (`din → dîn`, `herşey → her şey`) yasak dönüşüm sayar ve skor/düzeltilmiş metinden geri alır.
  Kalite regresyon fixture'ına 4 vaka eklendi.
- Her hata instance'ını ayrı issue yapan güçlendirilmiş AI promptu.
- Issue sayısına dayalı yetkili puanlama ve 60-altı kesin davranışı.
- SHA-256 tekrar gönderim kontrolü ve eski hash desteği.
- Güvenilir geçmiş detay API'si ve çalışan Gör butonu.
- PDFKit + Noto Serif ile gerçek PDF.
- Seed'i beklemeyen `GET /health` endpoint'i.
- Otomatik testler ve ortak ajan çalışma protokolü.
- Vercel uyumu: serverless export, imzalı cookie oturumu, 4 MB dosya sınırı ve dosya başına
  ayrı çalışan iki eşzamanlı toplu analiz işçisi.
- PWA: uygulama adı `Arşiv AI`; iOS/Android ana ekran ikonları, manifest ve minimal service
  worker eklendi ve production'a deploy edildi. Favicon bilerek ayrı bırakıldı.
- Sosyal paylaşım: WhatsApp/Telegram/Facebook/X için Open Graph ve Twitter Card metalarıyla
  1200x630 logo içeren paylaşım görseli eklendi.
- Yetki modeli: `admin` kullanıcı adı tek `super_admin` hesabıdır. Kullanıcı ekleme/silme
  yalnızca süper admine açıktır; normal adminler kullanıcıları görebilir ve süper admin
  dışındaki hesapları düzenleyebilir.
- AI sonuç güvenlik katmanı: `finalizeResult(result, sourceText)` artık kaynak metinde
  bulunmayan issue'ları, kullanıcıya aynı görünen original/fixed çiftlerini ve kelime içi
  parça eşleşmelerini skor dışı bırakıyor. `server.js` OpenAI sonucunu kaynak metinle
  birlikte finalize ediyor.
- Kök yanlış-pozitif düzeltmesi: varsayılan kural setindeki bağlamsız dönüşümler ve
  `Allah razı olsun.` çelişkisi temizlendi. `Mu'minûn/Muminun Suresi`, `Tabiî ki`,
  `derecat`, `dinlenmeye`, `Muhterem Efendimiz`, `Zumer` gibi korumalı ifadeleri değiştiren
  yasak dönüşümler hem issue listesinden hem de `correctedText` içinden geri alınıyor.
- Ekip geri bildirim döngüsü: analiz sonuç ekranına genel geri bildirim ve bulgu bazlı
  "Metinde yok / Yanlış düzeltme" butonları eklendi. Backend `POST /api/history/:id/feedback`
  ile bu kayıtları mevcut `alerts` tablosunda `type='feedback'` olarak saklıyor; adminler
  Uyarılar sekmesinden görebilir. Yeni Supabase migration gerektirmez.
- Yan yana karşılaştırma UX'i: anlık analiz sonucunda orijinal ve düzeltilmiş metin iki
  sütunda gösteriliyor; kısa/orta metinlerde kelime düzeyi kırmızı/yeşil diff vurgusu var.
  Çok uzun metinlerde performans için renkli diff kapatılıp metinler yan yana gösterilir.
  Dosya analizinde server response'u `originalText` döndürür; geçmiş kayıtlar için orijinal
  metnin kalıcı saklanması sonraki faza bırakıldı.
- Analiz izlenebilirliği: sonuç response'u `analysisMeta.promptVersion` ve `rulesHash`
  döndürür; sonuç ekranında chip olarak gösterilir. `schema.sql` `history.prompt_version`
  ve `history.rules_hash` kolonlarını içerir. Canlı DB'de kolonlar yoksa uygulama kırılmaz,
  sadece geçmişe sürüm meta yazmaz.
- Geri bildirim merkezi: Uyarılar sekmesi "Uyarılar ve Geri Bildirimler" oldu; Tümü /
  Geri Bildirim / Düşük Skor filtreleri eklendi.
- İş panosu: Onay Bekleyenler sekmesi "İş Panosu" oldu. Denetimler Bekleyen / Onaylanan /
  Reddedilen sütunlarında kartlarla gösterilir; kartlardan Gör / Onayla / Reddet işlemleri
  yapılabilir.
- Feedback ölçüm ekranı: admin dashboard toplam geri bildirim, son 7 gün geri bildirim ve
  okunmamış geri bildirim sayılarını gösteriyor. Uyarılar sekmesinde ekip geri bildirimleri
  tek satır metin yerine ayrıştırılmış alanlar halinde okunuyor.
- Geçmiş filtreleme: Denetim Geçmişi ekranında dosya/kullanıcı araması, Bekleyen/Onaylanan/
  Reddedilen/Düşük skor filtresi ve kaç kaydın görüntülendiğini gösteren sayaç var. Sunucu
  veya veritabanı değişikliği yok; mevcut liste üzerinde çalışıyor.
- Riskli kayıt görünümü: admin dashboard skor 60 altı veya hata sayısı 5 ve üzeri son
  denetimleri "Riskli Son Denetimler" panelinde gösteriyor; panelden düşük skor geçmiş
  filtresine hızlı geçiş var.
- Rapor paylaşımı: analiz sonucu ekranındaki "Raporu kopyala" butonu skor, toplam sorun,
  kategori kırılımı, özet, analiz sürümü ve ilk bulguları tek metin halinde panoya alıyor.
- Karanlık mod: topbar ve mobil menüde tema değiştirme düğmesi var. Tercih tarayıcıda
  saklanıyor; koyu tema siyah/beyaz ağırlıklı, yüksek kontrastlı çalışıyor.
- Tema switch düzeltmesi: koyu temada topbar artık beyaza dönmez; üst bar için ayrı
  `--topbar-*` renkleri kullanılıyor. Üstte yazılı `Karanlık/Aydınlık` yerine ikonlu switch,
  mobil menüde ise "Tema" satırı ve mini switch var.
- Koyu tema kontrast düzeltmesi: skor rozetleri, bildirim sayıları ve Onayla/Reddet gibi
  aksiyonlar koyu temada beyaz blok haline gelmesin diye `green/red/gold/orange/blue`
  semantik renkleri koyu tema için ayrıştırıldı.
- Koyu tema yumuşatma: saf siyah arka plan yerine koyu gri palet kullanılıyor; kartlar,
  inputlar ve topbar birbirinden daha okunur ayrılıyor.
- Ekip paylaşım özeti: `docs/EKIP_DEBUG_GELISTIRME_OZETI_2026-06-30.md` canlı debug ve
  geliştirme özetini içerir.
- Bildirim/duyuru sistemi: feedback çözüm yanıtları ve kullanıcıya özel duyurular mevcut
  `alerts` tablosunda `feedback_resolution` ve `announcement` tipleriyle tutuluyor. Kullanıcılar
  "Bildirimler" sekmesinde sadece kendilerine ait duyuru/çözüm yanıtlarını görür. Adminler
  Uyarılar ekranındaki feedback için "Çözüm bildir" kullanabilir ve Kullanıcı Yönetimi'nden
  tek kullanıcıya bildirim gönderebilir.
- Kalite regresyon havuzu: `test/fixtures/quality-regression-cases.json` canlı hata
  örneklerinden türeyen kalıcı test datasını tutuyor. `test/quality-regression-cases.test.js`
  bu fixture'ı okuyup `finalizeResult` güvenlik katmanının yanlış pozitifleri skor dışı
  bırakmasını ve güvenli geri almaları doğruluyor.
- Feedback çözüm görünürlüğü: dashboard çözüm bildirimi ve duyuru sayılarını gösteriyor.
  Uyarılar ekranında `Çözüm` ve `Duyuru` filtreleri var; admin feedback, çözüm ve duyuru
  loglarını ayrı ayrı inceleyebilir.
- Orijinal metin saklama: `schema.sql` `history.original_text` kolonunu içerir. Sunucu startup'ta
  kolonu algılar; varsa yeni analizlerde kaynak metni geçmişe yazar, yoksa özellik pasif kalır.
  Geçmiş detay modalı orijinal metin varsa orijinal/düzeltilmiş karşılaştırmasını gösterir.
- Metin denetim sağlamlığı: manuel metin alanında karakter sayısı ve hazır/uyarı durumu
  gösteriliyor. Boş, çok kısa ve çok uzun metinler frontend'de durduruluyor; aynı kontroller
  `/api/analyze`, `/api/analyze-file` ve batch dosya analizinde sunucu tarafında da uygulanıyor.
- Prompt'a canlı hata raporlarından çıkan istisnalar eklendi: "Allah razı olsun" cümlesi
  birleştirilmez; apostrof tipi tek başına hata değildir; tırnaklar korunur; sure adlarında
  kelime içi parça yakalanmaz; `Tabiî ki`, `derecat`, `dinlenmeye`, `Muhterem Efendimiz`
  bağlamları korunur; slayt/hadîs/tablo düzeni bozulmaz.

## Doğrulama

- `npm.cmd run check`: başarılı (2026-06-30 Codex). 11/11 test geçti; yeni testler
  metinde olmayan/aynı görünen issue'ların skor dışı bırakılmasını ve `Muminun`
  içinden `Mumin` eşleştirilmemesini güvenceye alıyor.
- `npm.cmd run check`: başarılı (2026-06-30 Codex ikinci tur). 13/13 test geçti; yeni
  testler korumalı/yasak dönüşümlerin skordan ve düzeltilmiş metinden geri alınmasını
  doğruluyor.
- `npm.cmd run check`: başarılı (2026-06-30 Codex üçüncü tur). 13/13 test geçti; geri
  bildirim endpoint'i ve sonuç ekranı butonları frontend parse kontrolünden geçti.
- `npm.cmd run check`: başarılı (2026-06-30 Codex dördüncü tur). 13/13 test geçti; yan
  yana karşılaştırma ve diff UI frontend parse kontrolünden geçti.
- `npm.cmd run check`: başarılı (2026-06-30 Codex beşinci tur). 13/13 test geçti; analiz
  sürüm chip'i ve uyarı/geri bildirim filtreleri frontend parse kontrolünden geçti.
- `npm.cmd run check`: başarılı (2026-06-30 Codex altıncı tur). 13/13 test geçti; iş panosu
  frontend parse kontrolünden geçti.
- `npm.cmd run check`: başarılı (2026-06-30 Codex yedinci tur). 13/13 test geçti; dashboard
  feedback metrikleri ve ayrıştırılmış geri bildirim kartları frontend parse kontrolünden geçti.
- `npm.cmd run check`: başarılı (2026-06-30 Codex sekizinci tur). 13/13 test geçti; geçmiş
  arama/durum/düşük skor filtreleri frontend parse kontrolünden geçti.
- `npm.cmd run check`: başarılı (2026-06-30 Codex dokuzuncu tur). 13/13 test geçti; riskli
  denetimler dashboard paneli ve düşük skor geçmiş geçişi frontend parse kontrolünden geçti.
- `npm.cmd run check`: başarılı (2026-06-30 Codex onuncu tur). 13/13 test geçti; analiz
  raporu kopyalama aksiyonu frontend parse kontrolünden geçti.
- `npm.cmd run check`: başarılı (2026-06-30 Codex on birinci tur). 13/13 test geçti; karanlık
  tema, metin sağlık göstergesi ve sunucu tarafı metin uzunluk kontrolleri doğrulandı.
- `npm.cmd run check`: başarılı (2026-06-30 Codex on ikinci tur). 13/13 test geçti; topbar
  tema renk ayrımı ve ikonlu tema switch frontend parse kontrolünden geçti.
- `npm.cmd run check`: başarılı (2026-06-30 Codex on üçüncü tur). 13/13 test geçti; koyu
  tema semantik renkleri, Onayla/Reddet ve skor rozeti kontrast düzeltmeleri doğrulandı.
- `npm.cmd run check`: başarılı (2026-07-01 Codex). 13/13 test geçti; koyu tema siyah
  yoğunluğu azaltıldı ve tema meta rengi güncellendi.
- `npm.cmd run check`: başarılı (2026-07-01 Codex bildirim turu). 13/13 test geçti; kişisel
  bildirimler, feedback çözüm yanıtı ve kullanıcıya özel duyuru akışları frontend parse
  kontrolünden geçti.
- `npm.cmd run check`: başarılı (2026-07-01 Codex regresyon turu). 19/19 test geçti; kalite
  regresyon havuzu fixture'ları otomatik test kapsamına alındı.
- `npm.cmd run check`: başarılı (2026-07-01 Codex feedback metrik turu). 19/19 test geçti;
  dashboard çözüm/duyuru metrikleri ve Uyarılar filtreleri frontend parse kontrolünden geçti.
- `npm.cmd run check`: başarılı (2026-07-01 Codex orijinal metin turu). 19/19 test geçti;
  opsiyonel `history.original_text` saklama ve geçmiş karşılaştırma modalı frontend parse
  kontrolünden geçti.
- `npm.cmd run check`: başarılı (2026-07-01 Codex sözlük kararı turu). 23/23 test geçti;
  `din/dîn` ve `herşey/her şey` yeni standartları hem koruma hem düzeltme yönünde doğrulandı.
- `npm.cmd run check`: başarılı (2026-07-02 Codex sure standardı turu). 27/27 test geçti;
  114 sure adı listesi prompt'a üst öncelikli standart olarak eklendi, `Muminun/MU'MİNÛN`
  ve `Zumer/ZUMER` regresyonları doğrulandı.
- `npm test`: 9/9 başarılı (5 analiz/PDF + 4 rol/yetki testi).
- `node --check server.js`: başarılı.
- Frontend inline JavaScript parse kontrolü: başarılı.
- Yerel `GET /health`: HTTP 200 ve `{"status":"ok"}`.
- Vercel production `GET /health`: `{"status":"ok"}`.
- Vercel production `GET /api/auth/me`: `{"loggedIn":false}`.
- Canlı uçtan uca smoke test: geçici kullanıcıyla login ve GPT analizi başarılı;
  skor 87, 3 issue ve düzeltilmiş metin döndü. Test kullanıcısı/geçmişi silindi.
- Canlı PWA doğrulaması: manifest adı `Arşiv AI`, standalone modu, service worker, Apple touch
  bağlantısı ve 192/512/maskable ikonların HTTP 200 + gerçek ölçüleri doğrulandı.
- Canlı Supabase salt-okunur kontrolü bağlantıda zaman aşımına uğradı; veri değiştirilmedi.
- Canlı süper admin doğrulaması: Supabase'deki `admin` hesabı `super_admin` rolüne yükseltildi.
  Geçici normal admin ile production `POST /api/users` ve `DELETE /api/users/:id` çağrıları
  ayrı ayrı HTTP 403 döndü; geçici kullanıcılar test sonunda temizlendi.

## Sonraki güvenli adım

1. PR [#1](https://github.com/ugurkarabulutt/arsiv-kontrol/pull/1) incelenip kullanıcı onayıyla `main`'e merge edilsin (otomatik merge yok).
2. Geçerli ekip kullanıcısıyla geçmiş Gör ve PDF akışını kullanıcı arayüzünden doğrula.
3. Vercel GitHub bağlantısı tamamlanınca branch-scoped Preview env değişkenleri eklensin.

## Vercel ortam durumu

- `SUPABASE_URL`, `SUPABASE_KEY` ve güçlü rastgele `SESSION_SECRET` Production ortamına eklendi.
- Proje GitHub'a henüz Vercel tarafından bağlanamadığı için branch-scoped Preview değişkenleri
  eklenemedi; CLI production deploy bundan etkilenmez.
- `OPENAI_API_KEY` Production ortamına eklendi ve canlı GPT analiziyle doğrulandı.
- Vercel SSO protection kapatıldı; özel domain doğrudan uygulamanın kendi login ekranına açılıyor.
- Ham internet smoke testi: `/health` 200, `/` 200 ve login endpoint'i uygulama JSON'u döndürüyor.
- Varsayılan `admin/admin123` canlı ortamda reddedildi; varsayılan şifre kullanılmıyor.
- `arsiv.ibrahimlive.ai` kalıcı proje domaini olarak eklendi; gelecekteki production
  deployment'larına otomatik atanacak.
