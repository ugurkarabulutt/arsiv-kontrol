# Public Soru-Cevap Aktarımı ve Kategori Karar Notu

Tarih: 2026-08-11
Durum: İstişare ve geçiş planı. Kod, DB migration, root cutover veya public frontend değişikliği değildir.

## Neden Bu Not Var?

Public ön yüz tasarımı onay aşamasına geldi. Admin tarafında bekleyen soru-cevaplar bugün onaylanmaya başlanacak. Bu yüzden onaylanan kayıtların public ön yüze nasıl taşınacağı, kategorilerin nasıl kurulacağı ve hangi verilerin public'e çıkmayacağı net tutulmalıdır.

## Kayıtlarda Zaten Var Olan Kararlar

- Public ön yüz `history` tablosunu doğrudan okumayacak.
- `history.status = 'onaylandi'` public yayın için yalnız aday sinyalidir; otomatik public yayın değildir.
- Public'e gidecek temiz veri ya kilitli yayın dosyasından üretilen `public-json` ile taşınacak ya da kalıcı `public_qa` katmanına yazılacaktır.
- Public response/render içinde kullanıcı, onaylayan yetkili, admin notu, skor, hata sayısı, prompt, model, denetim bulgusu ve iç audit bilgisi olmayacaktır.
- Public route hedefleri: `/`, `/soru/:slug`, `/kategori/:slug`, `/konu/:slug`, `/arama`.
- `/arama` noindex olacak; `/admin` ve `/admin/*` noindex/no-store kalacak.
- Root public cutover ayrı açık onay gerektirir.

## Canlı Veri Anlık Durumu

2026-08-11 salt-okunur Supabase kontrolü:

- `taslak`: 249
- `bekliyor`: 3008
- `onaylandi`: 11
- `reddedildi`: 271

Bekleyen ve onaylı kayıtlar:

- `bekliyor`: 3008 kayıt
- `bekliyor` içinde soru dolu: 2894
- `bekliyor` içinde etiket dolu: 2895
- `bekliyor` içinde soru eksik: 114
- `bekliyor` içinde etiket eksik: 113
- `onaylandi`: 11 kayıt
- `onaylandi` içinde soru dolu: 11
- `onaylandi` içinde etiket dolu: 11
- benzersiz etiket varyantı: 2750

En yoğun etiketler:

- Zikir: 282
- Mürşid: 185
- Nefs: 133
- Hidayet: 96
- Mutluluk: 83
- Tövbe: 82
- Tebliğ: 62
- Ruh: 59
- Allah'a Ulaşmayı Dilemek: 57
- Hacet Namazı: 56
- Tasavvuf: 56
- Sevgi: 52
- Devrin İmamı: 50
- Teslimiyet: 50
- Allah’a Ulaşmayı Dilemek: 48
- Dua: 48
- Namaz: 46
- Cennet: 45
- Kur’ân: 45
- Nefs Tezkiyesi: 41

Not: Etiketlerde apostrof, şapka ve yazım varyantları var. Örnek: `Allah'a Ulaşmayı Dilemek` ve `Allah’a Ulaşmayı Dilemek`; `Hidayet` ve `Hidâyet`. Public kategori/konu yapısından önce etiket normalizasyonu şarttır.

## En Güvenli Aktarım Modeli

### Bugün İçin Hızlı ve Kontrollü Yol

1. Admin/süper admin bekleyen kayıtları onaylar.
2. Eksik soru/etiketli kayıtlar public aktarım dışında kalır veya manuel tamamlanır.
3. Süper admin public'e gidecek kayıtları `Yayına Hazır Kayıtlar` ve `Yayın Dosyaları` akışıyla paketler.
4. Paket son kontrolü tamamlanır ve kilitlenir.
5. `Çıktılar > Public Kayıtları Hazırla` ile `public-json` üretilir.
6. Public ön yüz bu JSON'u veri kaynağı olarak alır.

Bu yol DB migration yapmadan, public tasarım onayı ve ilk veri besleme için uygundur.

### Kalıcı ve Doğru Yol

1. `public_categories`, `public_topics`, `public_qa`, `public_qa_topics`, `public_redirects`, `public_publish_events` tabloları ayrı migration ile kurulur.
2. Admin tarafına süper admin için `Public Arşiv Yönetimi` eklenir.
3. Onaylı kayıtlar public draft'a aktarılır.
4. Her public draft başlık, slug, soru, cevap, özet, kategori, konular, SEO açıklaması ve kaynak iziyle kontrol edilir.
5. Sadece `public_qa.status = 'published'` olan kayıtlar public'te görünür.

Bu yol gerçek uzun vadeli public arşiv için gereklidir.

## Önerilen Karar

Bugünkü tasarım onayı ve ilk veri geçişi için `public-json` yolu kullanılmalı. Ancak 3000'den fazla kayıt ve 2750 etiket varyantı olduğu için kalıcı yayın sistemi `public_qa` katmanına taşınmalıdır. Yani:

- Kısa vadede: `public-json` ile public ön yüzü besle.
- Kalıcı yayında: `public_qa` ve kategori/konu tablolarına geç.

## Kategori ve Etiket Mantığı

Bu arşiv diğer dini siteler gibi hazır ve dışarıdan verilmiş kategori listesiyle ele alınmayacak.
Bizde `Mürşid`, `Zikir`, `Hidayet`, `Allah'a Ulaşmayı Dilemek`, `Nefs`, `Teslimiyet` gibi temel
kavramlar kategori de olabilir. Kategori listesini masa başında değil, eldeki gerçek etiket
yoğunluğundan çıkaracağız.

Basit mantık:

- Çok geçen, arşivin ana kapısı olacak kavramlar kategori adayıdır.
- Daha dar, açıklayıcı veya aynı kavramın yazım varyasyonu olanlar etiket olarak kalır.
- Bir soru-cevap bir ana kategoriye bağlanır.
- Aynı soru-cevap birden fazla etikete bağlı kalabilir.
- Etiketler hem arama hem de ilgili cevapları birbirine bağlama için kullanılacaktır.

Örnek:

- `Zikir` kategori olabilir.
- `Daimî Zikir`, `Zikir Emri`, `Zikir Sayısı` gibi ifadeler etiket olabilir.
- `Hidayet` veya `Allah'a Ulaşmayı Dilemek` kategori olabilir.
- `Hidâyet`, `Allah’a Ulaşmak`, `Allah’a Ulaşmayı Dilemek` gibi yazım ve yakın anlam varyantları
  tek public görünen ad altında toparlanmalıdır.

Teknik kayıtta bunun karşılığı:

- Ana kategori listesi: yoğun etiketlerden seçilen public kategori adları.
- Etiket/kavram listesi: kategori olmayan veya kategoriye bağlı kalan diğer etiketler.
- Her soru-cevap: bir ana kategori + çoklu etiket.

## İlk Kategori Adayı Çıkarma Şekli

Kategori listesini önce canlı etiket yoğunluğundan çıkaracağız. İlk ham adaylar bu yüzden şunlar
olabilir:

1. Zikir
2. Mürşid
3. Nefs
4. Hidayet
5. Allah'a Ulaşmayı Dilemek
6. Tövbe
7. Tebliğ
8. Ruh
9. Hacet Namazı
10. Tasavvuf
11. Sevgi
12. Devrin İmamı
13. Teslimiyet
14. Dua
15. Namaz
16. Cennet
17. Kur'ân
18. Nefs Tezkiyesi
19. Takva
20. Şeytan

Bu liste nihai kategori listesi değildir. İlk iş bu yoğun etiketleri üçe ayırmaktır:

1. Public ana kategori olacaklar.
2. Ana kategori altında etiket olarak kalacaklar.
3. Aynı kavramın yazım/ifade varyantı olduğu için başka bir adın altına birleşecekler.

Kural: `Genel / Kategori Bekliyor` public'te kalıcı kategori olarak öne çıkarılmamalı; yalnız
geçici editoryal kontrol için kullanılmalıdır.

## Etiket Normalizasyonu

Public'e çıkmadan önce etiketler normalize edilmelidir:

- Apostrof varyantları birleştirilmeli.
- Şapkalı/şapkasız varyantlar için tek public görünen ad seçilmeli.
- Büyük/küçük harf farkları birleştirilmeli.
- Aynı kavramın çok yakın yazımları alias olarak tutulmalı.
- Birbiriyle ilişkili ama aynı olmayan kavramlar birleştirilmemeli. Örnek: `Teslim` ve `Teslimiyet` ayrı konu olabilir ama ilişkili gösterilebilir.

## Public'e Aktarım Kapıları

Bir kayıt public'e çıkmadan önce şunlar zorunlu olmalıdır:

- Soru var.
- Cevap var.
- En az bir konu/etiket var.
- Tek ana kategori var.
- Slug var ve benzersiz.
- Public özet var.
- SEO açıklaması var.
- İç süreç dili yok.
- Kullanıcı, onaylayan yetkili, skor, hata sayımı, prompt/model bilgisi yok.
- Public HTML ve JSON-LD aynı görünür içeriği temsil ediyor.

## Bugünkü Pratik İş Sırası

1. Bekleyen kayıtlar onaylanır.
2. Onay sonrası eksik soru/etiket sayısı tekrar ölçülür.
3. Etiket yoğunluğu listesi çıkarılır.
4. Yoğun etiketlerden kategori adayları seçilir.
5. Kategori olacaklar, etiket kalacaklar ve birleşecek yazım varyantları ayrılır.
6. 50-100 kayıtla public tasarım veri testi yapılır.
7. Sonra tüm uygun onaylı kayıtlar public-json veya public_qa draft olarak taşınır.
8. 390px mobil, desktop, SEO, sitemap, noindex ve public dil guard testleri geçmeden indexing açılmaz.

## Karar Bekleyen Noktalar

1. İlk public yayın tüm onaylı kayıtlarla mı başlayacak, yoksa seçilmiş 50-100 kayıtla mı?
2. Yoğun etiketlerden hangileri public ana kategori olacak, hangileri etiket olarak kalacak?
3. Public detay sayfasında kaynak izi olarak yayın linki mi, arşiv kaynak adı mı, yoksa ikisi de mi gösterilecek?
4. İlk yayında `public-json` yeterli mi, yoksa hemen `public_qa` migration hazırlansın mı?

## Benim Teknik Tavsiyem

Public tasarım bugün onaylanacaksa ilk entegrasyon `public-json` ile yapılmalı. Bu, frontend sohbetinin hızlı ilerlemesini sağlar ve root cutover yapmadan veri şeklini test eder. Fakat gerçek canlı public yayın için `public_qa` katmanını geciktirmemek gerekir; çünkü kategori, konu, slug, sitemap, yayın durumu ve redirect yönetimi JSON dosya akışıyla uzun vadede zorlaşır.
