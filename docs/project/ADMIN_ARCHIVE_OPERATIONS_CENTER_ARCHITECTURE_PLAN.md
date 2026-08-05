# Admin Arşiv Operasyon Merkezi Mimari Planı

Tarih: 2026-08-05
Kapsam: Google Drive, Google E-Tablolar ve Google Dokümanlar üzerinde yürüyen manuel arşiv çalışma sisteminin Arşiv Kontrol AI admin paneline taşınması.
Durum: Planlama dokümanı. Bu doküman kod değişikliği, schema migration, canlı veri yazımı veya deploy içermez.

## 1. Amaç

Mevcut çalışma düzeni Google Drive klasörleri, kullanıcıya özel Google E-Tablolar, Google Dokümanlar ve indirilen YouTube transkript dosyaları üzerinden yürütülüyor.

Yeni hedef, bu manuel sistemi Arşiv Kontrol AI içinde online ve kontrollü bir operasyon sistemine dönüştürmektir.

Ana hedef:

`Kaynak -> Görev -> Çalışma Kaydı -> Denetim -> Onay -> Arşiv Adayı -> Yayın Adayı`

Bu sistem ilk aşamada sadece `super_admin` tarafından görülecek. Normal kullanıcılar ve adminler, sistem test edilip onaylanmadan yeni modülleri görmeyecek.

## 2. Kesin Ürün Kararları

- Aktif admin çalışma adresi `/admin` olacak.
- Root `/` bu iş kapsamında public arşive çevrilmeyecek.
- Public ön yüz çalışması ayrı iş hattı olarak kalacak.
- Mevcut denetim, feedback, onay, geçmiş düzeltme ve bildirim akışları bozulmayacak.
- Yeni arşiv operasyon modülleri başlangıçta sadece `super_admin` rolüne görünür olacak.
- Hadisler ve slayt metinleri kullanıcıya sadece bağlantı olarak değil, sistem içinde gerçek metin olarak gösterilecek.
- Sistem kaynak bağlantısını arka planda tutabilir; fakat kullanıcı kaynak içeriğini metin olarak okuyup seçebilmeli.
- Kullanıcının kaynak, görev, transkript, standart, hadis, slayt veya soru-cevap bulması gereken her yerde arama olacak.
- Tasarım yüksek okunabilirlik, sade kullanım, güçlü kontrast ve mobil uyum üzerine kurulacak.

## 3. Ekip Lideri Dokümanından Anlaşılan Manuel Sistem

Mevcut manuel sistemde şu parçalar var:

1. Arşiv çalışmaları için Google Drive ana klasörü.
2. `Çalışma Tabloları` klasörü altında 36 kullanıcıya özel Google E-Tablo.
3. Her kullanıcı dosyasında iki ana sayfa:
   - kişinin soru-cevap çalışma tablosu
   - kişiye tanımlanmış yayın linkleri
4. Çalışma tablosu sütunları:
   - Soru
   - Etiket/Sınıf
   - Cevap
   - Sorunun İşleme Alınma Tarihi
   - Yayın Linki
   - Program
   - Notlar
5. Yayın linkleri sayfası sütunları:
   - YouTube linki
   - yayın tarihi
   - atanan kişi
   - durum bilgisi, örnek `TAMAM`
6. YouTube transkriptleri harici araçla indirilip kullanıcıya özel dosyalarda saklanıyor.
7. Hadisler ortak kaynak/depo olarak tutuluyor.
8. Slayt metinleri ortak kaynak/depo olarak tutuluyor ve olduğu gibi korunması gerekiyor.
9. Standartlar ayrı dokümanlar halinde tutuluyor.
10. Yetki mantığı:
   - herkes ortak yapıyı görüntüleyebiliyor
   - kullanıcı kendi dosyasını düzenliyor
   - adminler herkesin dosyasını düzenleyebiliyor

## 4. Hedef Sistem Mantığı

Yeni sistem dosya klasörü mantığıyla değil, iş akışı mantığıyla kurulmalı.

Ana nesne `dosya` değil, `çalışma kaydı` olmalı.

Bir çalışma kaydı şu bağlantıları taşımalı:

- hangi kaynaktan geldi
- hangi kullanıcıya atandı
- hangi transkriptle ilişkili
- hangi soru-cevap üretildi
- hangi hadis/slayt metni kullanıldı
- hangi denetimden geçti
- hangi versiyon onaya gönderildi
- admin ne karar verdi
- ileride public arşive aday oldu mu

Bu yapı kurulursa kullanıcı dosya aramak yerine işini takip eder; admin de kimde hangi iş olduğunu doğrudan görür.

## 5. Ana Modüller

### 5.1 Arşiv Operasyon Merkezi

Yeni sistemin süper admin ana ekranı.

Bu ekranda şunlar görünmeli:

- aktif görevler
- işlenmemiş yayın linkleri
- transkript bekleyen işler
- taslak soru-cevaplar
- denetim bekleyen kayıtlar
- onay bekleyen kayıtlar
- geri dönen işler
- tamamlanan işler
- kaynak havuzu durumu
- kullanıcı bazlı iş yükü
- tüm operasyon içinde arama

Bu ekran bir liste yığını değil, çalışma kontrol merkezi olmalı.

### 5.2 Kaynak Havuzu

Tüm kaynak metinlerin merkezi.

Kaynak türleri:

- YouTube yayını
- YouTube transkripti
- Hadis metni
- Slayt metni
- Standart dokümanı
- Program/kategori referansı
- Diğer doküman

Her kaynakta bulunması gereken bilgiler:

- başlık
- kaynak türü
- gerçek metin içeriği
- kısa özet
- harici link varsa link
- yayın tarihi
- ekleyen kullanıcı
- atanan kullanıcı
- durum
- etiketler
- notlar
- oluşturulma/güncellenme tarihleri

Hadis, slayt ve transkriptlerde `metin içeriği` zorunlu olmalı.

### 5.3 Yayın Görevleri

Google E-Tablolardaki `Yayın Linkleri` sayfasının online karşılığı.

Desteklenecek işlemler:

- YouTube linki ekleme
- yayın tarihi girme
- kullanıcıya atama
- transkript ekleme/yükleme
- durum takibi
- bu yayından kaç soru-cevap çıkarıldığını görme
- kullanıcı, durum, tarih, program ve tamamlanma filtresi

Önerilen durumlar:

- Atandı
- Transkript Bekliyor
- Çalışmaya Hazır
- İşleniyor
- Taslak Oluştu
- Denetlendi
- Onaya Gönderildi
- Onaylandı
- Geri Döndü
- Tamamlandı
- İptal Edildi

### 5.4 Kişisel Çalışma Alanı

Google E-Tablolardaki kullanıcıya özel dosyanın sistem içindeki karşılığı.

Her kullanıcı için:

- kendisine atanan yayınlar
- devam eden çalışma kayıtları
- taslak soru-cevaplar
- geri dönen işler
- tamamlanan işler
- kişisel notlar
- kaynak metinlere erişim

İlk aşamada bu ekranı sadece süper admin herkes adına görecek. Daha sonra kullanıcı kendi alanını görecek şekilde açılacak.

### 5.5 Soru-Cevap Çalışma Kaydı

Manuel tablodaki satırın sistemdeki karşılığı.

Alanlar:

- Soru
- Cevap
- Etiket/Sınıf
- Program
- Yayın linki
- Yayın tarihi
- Atanan kullanıcı
- İşleme alınma tarihi
- Notlar
- Bağlı transkript/kaynak
- Kullanılan hadis metinleri
- Kullanılan slayt metinleri
- Denetim sonucu
- Onay durumu
- Versiyon geçmişi

Bu kayıt, mevcut denetim ve onay sistemine bağlanmalı.

### 5.6 Hadis ve Slayt Metni Kullanımı

Bu alan kritik.

Hadis ve slaytlar cevaplara sadece link olarak eklenmemeli. Kullanıcı sistem içinde arama yaparak ilgili hadis/slayt metnini bulmalı, okumalı ve seçebilmelidir.

İdeal akış:

1. Kullanıcı cevap hazırlarken kaynak arama panelini açar.
2. Hadis veya slayt metni içinde arama yapar.
3. Kaynağın gerçek metnini sistem içinde okur.
4. Gerekli bölümü seçer.
5. Seçilen metin çalışma kaydına görünür metin olarak eklenir.
6. Sistem arka planda bu metnin hangi kaynaktan geldiğini kayıt altında tutar.

Kullanıcı açısından metin görünür.
Sistem açısından kaynak ilişkisi korunur.

### 5.7 Standartlar Merkezi

Mevcut Standartlarımız yapısı genişletilmeli.

Standartlar sadece okunacak doküman değil, sistem davranışını etkileyen karar kayıtları olmalı.

Her standartta:

- başlık
- kategori
- standart metni
- karar notu
- oluşturulma tarihi
- güncellenme tarihi
- kim ekledi
- kim okudu
- denetim motorunu etkiliyor mu
- geçmiş düzeltmeyle ilişkili mi
- feedback kararına bağlı mı

Örnek standartlar:

- `din` doğru kabul edilir
- `herşey` birleşik kabul edilir
- sure isimleri mihr.com imlasına göre değerlendirilir
- `şer -> şerr` yalnız bağımsız kullanımda uygulanır

### 5.8 Onay ve İnceleme Merkezi

Mevcut onay akışı yeni çalışma kayıtlarına bağlanmalı.

Onay ekranında görülmesi gerekenler:

- kullanıcı
- kaynak/yayın
- soru
- cevap
- denetim sonucu
- skor
- tespit edilen bulgular
- kullanılan hadis/slayt metinleri
- kaynak transkript özeti
- versiyon farkı
- admin notları

Aksiyonlar:

- Onayla
- Geri Gönder
- Revizyon İste
- Reddet
- Mükerrer İşaretle
- Arşive Hazırla

### 5.9 İçe Aktarım Merkezi

Google Drive/Sheets/Docs verileri sisteme kontrollü taşınmalı.

Desteklenecek import türleri:

- Google E-Tablo CSV export
- Google E-Tablo XLSX export
- DOCX hadis/slayt/standart dosyası
- TXT/transkript dosyası
- manuel metin yapıştırma

Import akışı:

1. Dosya yüklenir veya metin yapıştırılır.
2. Sistem ön izleme gösterir.
3. Süper admin sütun eşleştirmesi yapar.
4. Sistem olası mükerrerleri gösterir.
5. Süper admin onaylar.
6. Sistem import batch kaydı oluşturur.

Import hiçbir zaman sessizce eski veriyi ezmemeli.

## 6. Arama Mimarisi

Arama bu sistemin temel fonksiyonu olmalı.

Arama gereken alanlar:

- tüm kaynak havuzu
- hadisler
- slayt metinleri
- YouTube transkriptleri
- yayın görevleri
- çalışma kayıtları
- standartlar
- onay kuyruğu
- kullanıcılar
- geçmiş düzeltmeler
- feedback kayıtları

Arama özellikleri:

- Türkçe karakter toleransı
- büyük/küçük harf toleransı
- kısmi kelime arama
- ifade/phrase arama
- kullanıcı filtresi
- tarih filtresi
- durum filtresi
- kaynak türü filtresi
- kategori/program filtresi
- etiket filtresi

Örnek aramalar:

- `hidayet`
- `Allah'a ulaşmak`
- `Allaha ulasmak`
- `mürşid`
- `mursid`
- `hadis-i şerif`
- `HADÎS`
- `Aysun`
- `31 Temmuz`
- `tamamlanmadı`
- `Bakara`

İlk fazda normalize edilmiş metin araması yeterli olur. Semantik/akıllı arama daha sonra eklenmeli.

## 7. Veri Modeli Önerisi

Bu bölüm migration değildir. Sadece öneridir.

### 7.1 `archive_sources`

Kaynak metinleri tutar.

Önerilen alanlar:

- `id`
- `source_type`
- `title`
- `body_text`
- `summary`
- `external_url`
- `publication_date`
- `owner_user_id`
- `assigned_user_id`
- `created_by`
- `status`
- `tags`
- `metadata`
- `created_at`
- `updated_at`

### 7.2 `archive_assignments`

Kullanıcıya atanan işleri tutar.

Önerilen alanlar:

- `id`
- `source_id`
- `assigned_user_id`
- `assigned_by`
- `status`
- `priority`
- `due_date`
- `started_at`
- `completed_at`
- `notes`
- `created_at`
- `updated_at`

### 7.3 `archive_work_items`

Soru-cevap çalışma kayıtlarını tutar.

Önerilen alanlar:

- `id`
- `assignment_id`
- `source_id`
- `created_by`
- `assigned_user_id`
- `question`
- `answer`
- `tag_class`
- `program`
- `publication_url`
- `publication_date`
- `processing_started_at`
- `notes`
- `status`
- `current_history_id`
- `approved_history_id`
- `public_candidate_id`
- `created_at`
- `updated_at`

### 7.4 `archive_work_item_source_blocks`

Çalışma kaydına metin olarak eklenen hadis/slayt/kaynak bölümlerini tutar.

Önerilen alanlar:

- `id`
- `work_item_id`
- `source_id`
- `source_type`
- `selected_text`
- `usage_note`
- `sort_order`
- `created_by`
- `created_at`

Bu tablo önemli. Çünkü kullanıcı metni görür; sistem ise hangi metnin hangi kaynaktan geldiğini bilir.

### 7.5 `archive_import_batches`

Google/Drive dosyalarından yapılan içe aktarımları kayıt altında tutar.

Önerilen alanlar:

- `id`
- `import_type`
- `filename`
- `uploaded_by`
- `status`
- `row_count`
- `created_count`
- `duplicate_count`
- `error_count`
- `mapping`
- `result`
- `created_at`

### 7.6 `archive_work_item_versions`

Çalışma kaydı versiyon geçmişini tutar.

Önerilen alanlar:

- `id`
- `work_item_id`
- `version_number`
- `question`
- `answer`
- `notes`
- `change_reason`
- `created_by`
- `created_at`

## 8. Yetki Modeli

İlk faz:

- `super_admin`: tüm yeni modülleri görür ve yönetir
- `admin`: yeni modülleri görmez
- `user`: yeni modülleri görmez

Pilot sonrası:

- `super_admin`: tüm sistem
- `admin`: ekip işleri, atamalar, onaylar
- `user`: sadece kendi görevleri ve kendi çalışma kayıtları

Yetki prensipleri:

- normal kullanıcı başka kullanıcıların çalışma alanını görmemeli
- admin ekip işlerini yönetebilir ama süper admin sistem ayarlarına dokunamaz
- geçmiş düzeltme, import ve standartların denetim motoruna bağlanması süper admin kontrolünde olmalı

## 9. UX Prensipleri

Yeni sistemin tasarımı şu ilkelere uymalı:

- yüksek okunabilirlik
- sade ekranlar
- güçlü kontrast
- mobilde taşmayan yapı
- yaşça büyük kullanıcılar için rahat yazı boyutu
- her yerde net arama
- gereksiz teknik kelime yok
- butonlar ve aksiyonlar açık
- dosya karmaşası yerine iş akışı
- her ekranda kullanıcının sonraki adımı belli

Navigasyon önerisi:

- Arşiv Operasyon Merkezi
- Kaynaklar
- Yayın Görevleri
- Çalışma Kayıtları
- Hadis Arşivi
- Slayt Metinleri
- Standartlar
- İçe Aktarım
- Onay Süreci

## 10. Kullanım Senaryoları

### Senaryo A: Süper admin yayın atar

1. Süper admin Yayın Görevleri ekranını açar.
2. YouTube linkini girer.
3. Yayın tarihini girer.
4. Kullanıcı seçer.
5. Transkript varsa ekler.
6. Görevi kaydeder.

### Senaryo B: Kullanıcı soru-cevap oluşturur

1. Kullanıcı kendisine atanan yayını açar.
2. Transkripti sistem içinde okur.
3. Yeni soru-cevap çalışma kaydı oluşturur.
4. Soru, cevap, etiket, program ve not alanlarını doldurur.
5. Gerekirse hadis/slayt arar.
6. Kaynak metni seçip çalışma kaydına metin olarak ekler.
7. Denetim yapar.
8. Son halini onaya gönderir.

### Senaryo C: Admin onaylar

1. Admin onay kuyruğunu açar.
2. Kaynak, kullanıcı, soru, cevap ve denetim sonucunu görür.
3. Kullanılan hadis/slayt metinlerini okur.
4. Gerekirse versiyon farkına bakar.
5. Onaylar veya geri gönderir.

### Senaryo D: Süper admin eski Google verisini içe aktarır

1. Süper admin İçe Aktarım Merkezi'ni açar.
2. CSV/XLSX/DOCX/TXT dosyası yükler.
3. Alanları eşleştirir.
4. Sistem mükerrer olabilecek kayıtları gösterir.
5. Süper admin onaylar.
6. Sistem import kaydını loglar.

## 11. Mevcut Denetim Sistemiyle Bağlantı

Mevcut `history` tablosu analiz ve onay kayıtları için kullanılmaya devam etmeli.

Yeni `archive_work_items` kayıtları `history` ile bağlanmalı:

- çalışma kaydı analizden önce taslak olabilir
- analiz yapılınca ilgili `history` kaydı bağlanır
- onaya gönderilen son versiyon `history` üzerinden takip edilir
- onaylanan son metin ileride public arşiv adayı olur

Bu yaklaşım mevcut denetim sistemini kopyalamaz, onu operasyon sistemiyle birleştirir.

## 12. Public Arşivle İlişki

Bu çalışma public arşiv değildir.

Fakat gelecekte public arşive aktarılacak içerikler için şimdiden şu alanlar hazırlanmalı:

- temiz soru
- onaylı cevap
- kategori
- konu etiketleri
- kaynak bilgisi
- kısa özet
- slug adayı
- yayın durumu
- son güncelleme tarihi

Public yayınlama bu fazda yapılmayacak.

## 13. Faz Planı

### Faz 0: Plan ve karar

- mimari gözden geçirilir
- veri modeli netleşir
- ilk süper admin ekranları belirlenir
- import yaklaşımı netleşir

### Faz 1: Süper admin-only kabuk

- `/admin` içinde sadece süper adminin göreceği menü eklenir
- Arşiv Operasyon Merkezi boş/kabuk ekran olarak kurulur
- Kaynaklar, Yayın Görevleri, Çalışma Kayıtları ve İçe Aktarım ekranları taslak olarak görünür
- normal kullanıcı/admin görmez

### Faz 2: Kaynak Havuzu MVP

- kaynak oluşturma
- kaynak okuma
- kaynak düzenleme
- hadis/slayt/transkript/standart türleri
- kaynak metni okuma ekranı
- temel arama

### Faz 3: Yayın Görevleri MVP

- YouTube linki ekleme
- kullanıcıya atama
- transkript ekleme
- durum takibi
- filtreleme ve arama

### Faz 4: Çalışma Kaydı MVP

- soru-cevap çalışma kaydı oluşturma
- kaynak ve görev bağlantısı
- hadis/slayt metni ekleme
- taslak durumu
- basit versiyon geçmişi

### Faz 5: Denetim ve onay bağlantısı

- çalışma kaydından denetim başlatma
- denetim sonucunu çalışma kaydına bağlama
- onaya gönderme
- onay ekranında çalışma bağlamını gösterme

### Faz 6: Google verisini içe aktarma

- kullanıcı tabloları
- yayın linkleri
- hadis dokümanları
- slayt dokümanları
- transkript dosyaları
- import ön izleme ve mükerrer kontrolü

### Faz 7: Pilot açılış

- süper admin test eder
- sonra bir admin test eder
- sonra 1-2 kullanıcıya açılır
- sorunlar çözülür
- ekip geneline açılır

## 14. Kullanıcıya Açmadan Önce Kabul Kriterleri

Normal kullanıcıya açmadan önce şunlar çalışmalı:

- süper admin kaynak oluşturabilir
- süper admin kaynaklarda arama yapabilir
- süper admin yayın görevi oluşturabilir
- süper admin çalışma kaydı oluşturabilir
- hadis/slayt metni çalışma kaydında gerçek metin olarak görünür
- arama ana ekranlarda çalışır
- `/admin` route bozulmaz
- root `/` public arşive çevrilmez
- mevcut denetim/onay akışı bozulmaz
- mobil ekranlarda taşma olmaz
- import ön izlemesi yanlış veri yazımını engeller

## 15. Riskler ve Önlemler

### Risk: sistemi dosya yöneticisine çevirmek

Önlem: ana nesne dosya değil, çalışma kaydı olacak.

### Risk: kullanıcı ekranının karmaşık hale gelmesi

Önlem: normal kullanıcıya yalnız kendi işleri, kaynak arama, çalışma kaydı, denetim ve onaya gönderme gösterilecek.

### Risk: Google verisi karışık gelirse yanlış import

Önlem: import ön izleme, sütun eşleştirme, mükerrer kontrol ve import log zorunlu olacak.

### Risk: kaynak metinleri public tarafa sızması

Önlem: tüm yeni kaynak ve çalışma modülleri admin auth altında kalacak.

### Risk: hadis/slayt metinleri sadece linke dönüşürse kullanıcı iş akışı iyileşmez

Önlem: kaynaklar metin olarak aranabilir, okunabilir ve seçilebilir olacak.

## 16. Açık Kararlar

Kodlamadan önce netleşmesi gereken kararlar:

1. Normal kullanıcılar ileride ortak hadis/slayt havuzunun tamamını görecek mi, yoksa sadece görevle ilişkili kaynakları mı görecek?
2. Kullanıcılar diğer kullanıcıların tamamlanan çalışmalarını görecek mi?
3. Google'dan içe aktarılan eski satırlar hangi statüyle başlayacak?
4. Hadis/slayt kaynakları ilk fazda düz metin mi, zengin biçimli metin mi tutulacak?
5. YouTube transkriptleri ilk fazda manuel yükleme/yapıştırma mı olacak?
6. Yayın görevi atama yetkisi pilot sonrası adminlere açılacak mı?
7. Standartlar denetim motoruna otomatik mi bağlanacak, yoksa süper admin onayı şart mı olacak?

## 17. İlk Kodlama Dilimi Önerisi

İlk güvenli kodlama dilimi:

1. `/admin` içinde sadece `super_admin` rolünün göreceği `Arşiv Operasyon Merkezi` menü öğesi eklenir.
2. Boş veri yazmayan bir kabuk ekran hazırlanır.
3. Ekranda modül kartları ve hedef akış görünür.
4. Normal kullanıcı ve admin bu ekranı görmez.
5. Frontend statik regresyon kontrolü eklenir.
6. Mevcut denetim, onay, feedback, kullanıcı yönetimi ve `/admin` route test edilir.

Bu dilim veri yazmadığı için en güvenli başlangıçtır.

## 18. Güncel Öneri

Önce bu plan gözden geçirilmeli. Sonra Faz 1 uygulanmalı:

`Sadece süper adminin göreceği Arşiv Operasyon Merkezi kabuğu`

Tam veri modeli, import ve kullanıcı ekranları daha sonra parça parça eklenmeli.

Bu yöntem hem mevcut çalışan sistemi korur hem de manuel Drive/Sheets/Docs sistemini kontrollü şekilde online sisteme taşır.
