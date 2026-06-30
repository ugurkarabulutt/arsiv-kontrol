# Arşiv AI - Debug ve Geliştirme Özeti

Tarih: 2026-06-30

## Ana Odak

Canlı testlerde görülen yanlış pozitifleri azaltmak, ekip geri bildirimini sisteme almak,
denetim sonuçlarını daha izlenebilir yapmak ve uzun süreli kullanım için arayüzü daha rahat
hale getirmek.

## AI Denetim Sağlamlığı

- Modelin kaynak metinde olmayan hataları skora dahil etmesi engellendi.
- Kullanıcıya aynı görünen `original/fixed` çiftleri hata sayılmayacak şekilde filtrelendi.
- Kelime içi yanlış yakalamalar azaltıldı; örnek: `Muminun` içinden `Mumin` yakalama.
- Korunan ifadeler eklendi: `Tabiî ki`, `derecat`, `dinlenmeye`, `Muhterem Efendimiz`, `Zumer`.
- Yasak dönüşümler düzeltilmiş metinden de geri alınıyor.
- Skor artık AI cevabına bırakılmıyor; sunucu tarafında yetkili formülle hesaplanıyor.
- 60 altı sonuçlarda düzeltilmiş metin verilmemesi kuralı korunuyor.
- Metin alanı ve API tarafında boş, çok kısa ve çok uzun metinler durduruluyor.

## Ekip Geri Bildirim Döngüsü

- Sonuç ekranına geri bildirim butonları eklendi.
- Bulgu bazında `Metinde yok` ve `Yanlış düzeltme` bildirimi yapılabiliyor.
- Adminler geri bildirimleri Uyarılar ekranında görebiliyor.
- Dashboard'a toplam geri bildirim, son 7 gün feedback ve okunmamış feedback kartları eklendi.
- Geri bildirim kartları okunabilir alanlara ayrıldı.
- Adminler gelen geri bildirimlere çözüm yanıtı yazabiliyor.
- Çözüm yanıtı ilgili kullanıcıya kişisel bildirim olarak düşüyor.
- Kullanıcılar kendilerine özel duyuru ve çözüm yanıtlarını `Bildirimler` sekmesinde görüyor.
- Adminler Kullanıcı Yönetimi ekranından tek kullanıcıya özel duyuru gönderebiliyor.

## UX ve Operasyon

- Orijinal ve düzeltilmiş metin yan yana karşılaştırılıyor.
- Kısa/orta metinlerde kelime düzeyi farklar kırmızı/yeşil gösteriliyor.
- Analiz sonucunda prompt sürümü ve kural hash bilgisi gösteriliyor.
- `Raporu kopyala` butonu ile skor, kategori kırılımı, özet ve ilk bulgular tek metin olarak alınabiliyor.
- Denetim Geçmişi ekranına arama, durum filtresi ve düşük skor filtresi eklendi.
- İş Panosu; Bekleyen, Onaylanan ve Reddedilen kolonlarıyla çalışıyor.
- Dashboard'a riskli son denetimler paneli eklendi.

## Tema ve Görsel Debug

- Açık/koyu tema eklendi; tercih tarayıcıda saklanıyor.
- Yazılı `Karanlık/Aydınlık` butonu kaldırılıp modern switch eklendi.
- Koyu temada üst barın görünmez hale gelmesi düzeltildi.
- Koyu temada skor rozetleri, uyarı sayıları, Onayla/Reddet butonları ve kategori renkleri yeniden ayarlandı.
- Renk patlaması yapan beyaz bloklar azaltıldı; aksiyonlar artık koyu temada okunabilir kalıyor.

## Doğrulama

- Zorunlu kontrol: `npm.cmd run check`
- Son durumda 13/13 otomatik test başarılı.
- Frontend/PWA parse kontrolü başarılı.
- Production `/health` kontrolü deploy sonrası doğrulanıyor.

## Sonraki Testte Ekibin Bakması Gerekenler

- Doğru metinlerin yanlış kabul edilip edilmediği.
- Kaynakta olmayan bulguların hâlâ listelenip listelenmediği.
- Onay/Reddet ve skor rozetlerinin açık/koyu temada okunabilirliği.
- Geri bildirimlerin admin ekranına doğru düşmesi.
- Yan yana karşılaştırmada metin düzeninin bozulup bozulmadığı.
