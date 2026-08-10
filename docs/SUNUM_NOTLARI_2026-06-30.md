# Arşiv Kontrol AI — Sunum Notları

## Bugün Canlıya Alınanlar

### 1. Yanlış Pozitifleri Azaltan AI Güvenlik Katmanı
- Modelin söylediği her hata artık doğrudan kabul edilmiyor.
- Kaynak metinde olmayan bulgular skor dışı bırakılıyor.
- Kullanıcıya aynı görünen düzeltmeler hata sayılmıyor.
- Korumalı ifadeler yanlış düzeltilirse hem bulgu listesinden hem düzeltilmiş metinden geri alınıyor.

Örnek korumalı alanlar:
- `Muminun/Mu'minûn Suresi`
- `Tabiî ki`
- `derecat`
- `dinlenmeye`
- `Muhterem Efendimiz`
- `Zumer`

### 2. Kural Çelişkileri Temizlendi
- `Allah razı olsun.` ayrı cümleyse artık ayrı kalır.
- Sözlük kuralları bağlamsız şekilde her yerde uygulanmaz.
- Sure adı, özel isim, slayt/tablo etiketi ve kelime içi eşleşmeler korunur.

### 3. Sonuç Ekranından Geri Bildirim
- Kullanıcılar her bulgu için `Metinde yok` veya `Yanlış düzeltme` gönderebilir.
- Genel sonuç için `Eksik hata`, `Düzen bozuldu`, `Skor yanlış`, `Diğer` bildirimi yapılabilir.
- Adminler bu kayıtları Uyarılar ve Geri Bildirimler ekranında görebilir.

### 4. Yan Yana Karşılaştırma
- Orijinal metin ve düzeltilmiş metin iki sütunda gösterilir.
- Kısa/orta metinlerde değişiklikler kırmızı/yeşil vurgulanır.
- Uzun metinlerde performans için renkli fark kapatılır, metinler yan yana kalır.

### 5. Analiz İzlenebilirliği
- Sonuç ekranında prompt sürümü ve kural hash bilgisi gösterilir.
- Böylece hangi sonucun hangi kural/prompt sürümüyle üretildiği takip edilebilir.

### 6. Uyarılar ve Geri Bildirim Merkezi
- Uyarılar sekmesi genişletildi.
- Filtreler eklendi:
  - Tümü
  - Geri Bildirim
  - Düşük Skor

### 7. İş Panosu
- Onay Bekleyenler ekranı İş Panosu oldu.
- Denetimler üç sütunda görünür:
  - Bekleyen
  - Onaylanan
  - Reddedilen
- Kartlardan metin görülebilir, onaylanabilir veya reddedilebilir.

## Sunumda Verilecek Ana Mesaj

Arşiv Kontrol AI artık sadece metin denetleyen bir araç değil; ekipten geri bildirim toplayan,
AI çıktısını doğrulayan, metin değişikliklerini karşılaştıran ve denetimleri iş akışı içinde
yöneten bir kalite kontrol paneline dönüşmeye başladı.

## Ekibe Söylenecek Test Talimatı

1. Normal metin, slayt dökümü ve hadîs dökümüyle test edin.
2. Yanlış bulgu görürseniz Word raporu hazırlamak yerine sonuç ekranındaki geri bildirim
   butonlarını kullanın.
3. Orijinal/düzeltilmiş karşılaştırma panelinden AI'ın neyi değiştirdiğini kontrol edin.
4. Adminler Uyarılar ve Geri Bildirimler sekmesinden gelen bildirimleri izlesin.
5. Onay akışı için İş Panosu kullanılmaya başlansın.

## Sonraki Fazlar

- Orijinal metni geçmiş kayıtlarında kalıcı saklama.
- Gerçek kural/prompt versiyon tablosu.
- Kullanıcıya iş atama ve "Benim İşlerim" görünümü.
- Geri bildirimlerden otomatik iyileştirme raporu.
- Daha kapsamlı deterministik sözlük ve korumalı terim motoru.
