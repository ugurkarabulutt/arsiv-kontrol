# Kategori İndekslenebilirlik Denetimi — 3 Ekim 2026

## Sonuç

Search Console'daki `Keşfedildi - şu anda dizine eklenmiş değil` raporu
21 Eylül 2026 tarihli ve 1.848 URL gösteriyor. Rapordaki örneklerin kategori
URL'leri olduğu doğrulandı. Bu sayı, 3 Ekim URL/sitemap temizliğinden önceki
keşif birikimini gösteriyor; güncel sitemap'in tamamını temsil etmiyor.

Canlı sitemap ölçümü:

- Toplam URL: 3.040
- Soru URL'si: 2.729
- Kategori URL'si: 295
- Diğer public URL'ler: 16

Canlı veritabanının salt okunur denetim anındaki görünümü:

- Yayımlanmış soru: 2.735
- Tanımlı kategori: 3.239
- En az bir soruda kullanılan kategori: 2.766
- İndekslenebilir kategori: 295
- `noindex` olan 1-4 soruluk kategori: 2.471
- Boş kategori: 473
- İndekslenebilir olup açıklaması eksik kategori: 0
- Tanımı eksik kullanılan kategori: 0

Canlı veri yayımlar nedeniyle değişebilir. `npm run seo:categories:audit` komutu
aynı envanteri güncel veriden yeniden üretir.

## Mevcut Politika

- En az 5 benzersiz sorusu bulunan kategori indekslenebilir.
- Dokuz temel konu, soru sayısı geçici olarak eşik altında olsa bile korunur.
- Eşik altındaki kategori kullanıcıya görünmeye devam eder; `noindex,follow`
  alır ve sitemap'e eklenmez.
- İndekslenebilir kategori self-canonical, açıklama ve CollectionPage verisi alır.

Bu politika tek bir modüle (`public-archive-seo.js`) taşındı. Sitemap üretimi,
public kategori sayfası ve denetim aracı aynı kararı kullanır; eşiklerin zamanla
birbirinden kopması engellendi.

## Kalite Bulguları

- Kategori dağılımı: 473 boş, 1.905 tek soruluk, 566 adet 2-4 soruluk,
  167 adet 5-9 soruluk, 84 adet 10-24 soruluk ve 44 adet 25+ soruluk.
- Aynı normalize ada sahip kategori yok.
- Zayıf kategoriler arasında aynı soru kümesini paylaşan çok sayıda etiket var;
  bunlar zaten `noindex` olduğu için Google'a ayrı hedef sayfa olarak sunulmuyor.
- İndekslenebilir kategoriler içinde yalnız `mucahede` ve `riyazet` aynı soru
  kümesini paylaşıyor. Kavramlar anlam bakımından ayrı olabileceğinden otomatik
  birleştirme veya yönlendirme uygulanmadı; editoryal karar gerekir.

## Karar

1. Beş soru eşiği şimdilik korunmalı; canlı veride 295 güçlü kategori bırakıyor.
2. Toplu kategori silme, birleştirme veya yönlendirme yapılmamalı.
3. `mucahede` ve `riyazet` sayfaları editoryal olarak incelenmeli; farklı arama
   niyetleri taşıyorlarsa özgün giriş ve soru kümeleriyle ayrıştırılmalı.
4. Yenilenen sitemap Google tarafından tekrar okunduktan sonra Search Console
   raporu 3-7 gün içinde yeniden kontrol edilmeli.
5. Eski 1.848 URL azalmaya başlamadan `Düzeltmeyi doğrula` başlatılmamalı.
