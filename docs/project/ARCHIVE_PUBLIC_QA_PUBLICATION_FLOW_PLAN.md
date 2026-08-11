# Public Soru-Cevap Yayın Akışı Planı

Tarih: 2026-08-11
Durum: Admin tarafı yayın sözleşmesi ve iş akışı planı. Bu belge public ön yüz kodu, root `/`
cutover, DB migration, canlı veri yazımı veya deploy içermez.

## Amaç

Onaylanmış soru-cevapların public arşivde nasıl yayınlanacağını ve public ön yüzün bu kayıtları
hangi temiz sözleşmeyle alacağını netleştirmek.

Temel karar: Public ön yüz `history` tablosunu doğrudan okumaz. Admin tarafı onay, son kontrol ve
çıktı sürecinden geçen temiz public kayıtları üretir; public ön yüz yalnız bu temiz kayıtları alır.

## Kapsam Sınırı

- Bu çalışma admin projesinde kayıt ve sözleşme çalışmasıdır.
- Public ön yüz uygulaması ayrı sohbet/workstream içinde ilerler.
- Root `/` bu iş kapsamında public arşive çevrilmez.
- `/admin` canlı admin hattı olarak korunur.
- Public kayda iç süreç bilgisi taşınmaz: kullanıcı adı, onaylayan yetkili, admin notu, skor,
  prompt, model, analiz bulguları, kaynak düzeltme logu ve ekip içi audit bilgisi public çıktıda
  yer almaz.

## Mevcut Giriş Kaynakları

1. Kullanıcının denetimden sonra onaya gönderdiği kayıt:
   - soru
   - onaylı cevap
   - etiketler
   - varsa kategori/program bilgisi
2. Geçmiş Excel aktarımından tamamlanmış kayıtlar:
   - eşleşen cevap
   - Excel sorusu
   - Excel etiketleri
3. Arşiv Çalışmaları kayıtları:
   - kaynak dosyası
   - çalışma tablosu satırı
   - yayın linki
   - hadis/slayt/standart metni
   - yayın dosyası ve çıktı merkezi

## Admin İç Akış

1. Ekip üyesi cevabı hazırlar.
2. Denetim yapar.
3. Onaya göndermeden önce soru ve etiketleri doldurur.
4. Admin veya süper admin onay ekranında soru, cevap ve etiketleri görür.
5. Yetkili gerekirse soru/etiketi düzeltir.
6. Kayıt onaylanır.
7. Onaylı kayıt Arşiv Çalışmaları tarafında yayına hazır aday olabilir.
8. Süper admin son kontrol yapar.
9. Uygun kayıtlar Yayın Dosyası içinde toplanır.
10. Çıktılar ekranında `public-json` üretimi yapılır.
11. Public ön yüz bu temiz JSON/API sözleşmesinden beslenir.

## Public Kayıt Sözleşmesi

Public ön yüze geçmesi gereken alanlar:

- `schemaVersion`
- `slug`
- `title`
- `summary`
- `question`
- `answer`
- `category`
- `topics`
- `source`
- `publication`
- `seo`
- `reading`
- `updatedAt`

Public ön yüze geçmemesi gereken alanlar:

- `user_id`, `username`, `name`
- `approved_by`, `approved_at` içinde yetkili kimliği
- admin notları
- skor ve hata sayımları
- prompt/model bilgileri
- denetim bulguları
- ham çalışma/audit logları
- iç sistem durum adları

## Public Ön Yüzün Alacağı Veri

İlk güvenli model:

1. Admin tarafı kilitlenmiş Yayın Dosyasından `public-json` üretir.
2. Public ön yüz build/deploy sırasında bu JSON'u veri kaynağı olarak alır.
3. Public ön yüzde yalnız yayınlanmış kayıtlar görünür.
4. JSON kalite kontrolünden geçmeyen kayıt public'e taşınmaz.

Daha sonra büyütülebilecek model:

1. Ayrı `public_qa` katmanı açılır.
2. Admin onaylı ve son kontrolden geçmiş kayıt bu katmana yazılır.
3. Public ön yüz yalnız `published` durumundaki `public_qa` kayıtlarını okur.

Her iki modelde de public ön yüz `history` veya admin operasyon tablolarını doğrudan okumaz.

## Canlı Public Sitede Olması Gerekenler

İlk public sürüm için beklenen ana alanlar:

- Ana sayfa: sakin, Türkçe, arama odaklı soru-cevap arşivi.
- Soru-cevap detay sayfası: soru, cevap, ilgili etiketler, kategori, okunabilir kaynak izi.
- Kategori sayfaları: kategoriye bağlı soru-cevap listesi.
- Etiket/kavram sayfaları: aynı kavrama bağlı soru-cevap listesi.
- Arama: Türkçe karakter toleranslı, sade sonuç listesi.
- SEO: canonical URL, title/description, structured data, sitemap ve robots kararı.
- Mobil: 390px genişlikte yatay taşma, metin kırpılması veya üst üste binme olmamalı.
- Admin ayrımı: public sayfalarda admin, denetim, skor, kullanıcı, onaylayan yetkili veya prompt dili görünmemeli.

## Yetki ve Ekip Kararları

- Arşiv Çalışmaları şimdilik sadece `super_admin` rolüne görünür.
- Ekip üyesi sayısı sabit değildir; kişi listesi mevcut aktif kullanıcılarla dinamik eşleşecektir.
- Yayın linklerini seçili ekip liderleri atayacak.
- `Tamam` işareti otomatik değil, işi yapan kişi tarafından elle işaretlenecek.
- Seçili ekip lideri modeli ileride ayrı yetkiyle tanımlanmalı; tüm adminlere otomatik açılmamalı.

## Kalan İşler

1. Aktif kullanıcı listesini kişi dosyalarıyla doğrulayan kişi eşleştirme ekranı.
2. Seçili ekip liderlerini tanımlayacak sade yetki modeli.
3. Yayın linki atama akışında ekip lideri yetkisi.
4. Atanan kişinin yayın linki satırında `Tamam` durumunu elle işaretlemesi.
5. `Tamam` işaretinin kimin tarafından ve ne zaman verildiğini admin içinde audit olarak saklama.
6. Çalışma Tabloları satırlarında soru, etiket/sınıf, cevap, işleme tarihi, yayın linki, program ve not alanlarının ekip alışkanlığına göre sade görünümü.
7. Hadis ve slayt metinlerinin kaynak olarak aranıp cevap hazırlığında seçilebilmesi.
8. YouTube dökümanlarının kişi bazlı transkript akışına bağlanması.
9. Standartlar klasörünün okunabilir doküman merkezi olarak bu yapıya bağlanması.
10. Public JSON çıktısının zorunlu alan, yasak alan ve 390px mobil kabul testleri.

## Kabul Kriterleri

- Normal admin `Arşiv Çalışmaları` menüsünü ve ekranını görmez.
- `/api/archive-ops/*` rotaları `superAdmin` koruması olmadan çalışmaz.
- Public ön yüz için üretilen kayıtlar onaylı soru, cevap ve etiketleri eksiksiz taşır.
- Public çıktıda onaylayan kişi, kullanıcı bilgisi ve denetim iç süreçleri yoktur.
- Public root cutover ayrı açık onay olmadan yapılmaz.
- PC ve 390px mobil testlerinde çalışma ekranları taşma üretmez.
