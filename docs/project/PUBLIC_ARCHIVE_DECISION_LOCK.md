# Public Arşiv Mimari Karar Kilidi

Tarih: 2026-07-30
Durum: Bağlayıcı mimari karar, docs-only

## Operasyon Bağlamı

`arsiv.ibrahimlive.ai` aktif kullanılan production çalışma alanıdır. Yaklaşık 39 ekip kullanıcısı metin denetimi, onaya gönderme, admin/süper admin onayı, geri bildirimler, bildirimler, standartlar, raporlama, dashboard ve kullanıcı yönetimi akışlarını canlı kullanmaktadır.

Bu nedenle public arşiv geçişi sıfır kesinti ve minimum risk prensibiyle yapılmalıdır. Mevcut root admin davranışı ilk implementation adımında kaldırılmayacaktır.

## Kilitli Kararlar

1. İlk MVP aynı repo ve mevcut Express app içinde kurulacak.
2. Public taraf HTML-first/server-rendered olacak.
3. Next.js veya ayrı frontend ilk MVP'de uygulanmayacak; gelecekte opsiyon olarak kalacak.
4. Mevcut admin sistemi big-bang rewrite edilmeyecek.
5. `/admin` önce paralel admin route olarak hazırlanacak.
6. `/` mevcut admin davranışını geçiş doğrulanana kadar koruyacak.
7. `/admin` ve `/admin/*` mevcut admin uygulamasını güvenli şekilde çalıştıracak.
8. `/admin` altında browser refresh ve deep linkler çalışmalı.
9. Static asset path, SPA fallback, auth redirect, upload, API call ve session davranışları özel olarak test edilecek.
10. Public root `/` iç operasyon dili içermeyecek.
11. Public site `history` tablosunu doğrudan okumayacak.
12. `history.status = 'onaylandi'` sadece public draft'a aday kabul edilecek.
13. Public görünürlük için ayrı `public_qa.status = 'published'` gerekecek.
14. Onaylanan kayıtlar otomatik yayınlanmayacak.
15. Yayın akışı: `history` onayı -> public yayına hazırla -> public draft -> preview -> yayınla.
16. `QAPage` ve `FAQPage` ilk MVP'de kullanılmayacak.
17. Soru detay schema: `WebPage` + `Article` + `BreadcrumbList`.
18. Konu/kategori schema: `CollectionPage` + `ItemList` + `BreadcrumbList`.
19. `/arama?q=...` sayfaları `noindex,follow` olacak.
20. `/admin`, preview, private route'lar, API route'ları ve draft/review/archived kayıtlar public sitemap dışında kalacak.
21. `arsiv.ibrahimlive.ai` canonical ana kaynak olacak.
22. `ibrahimlive.com` ilk aşamada tam kopya içerik yayınlamayacak; özet + kaynak linki modeli kullanılacak.
23. Public görünür yasak kelimeler: `AI`, `prompt`, `model`, `admin`, `denetim`, `onay kuyruğu`, `kalite kontrol`, `test verisi`.
24. Public HTML ve public API response check'leri bu kelimeler görünürse fail edecek.

## Feature Flag Seti

| Flag | Anlam |
| --- | --- |
| `ADMIN_PARALLEL_ROUTE_ENABLED` | `/admin` ve `/admin/*` route'larını mevcut admin uygulamasına paralel açar. |
| `ADMIN_ROOT_LEGACY_ENABLED` | Ekip `/admin` adresine geçerken `/` üzerindeki mevcut admin davranışını korur. |
| `PUBLIC_ARCHIVE_ENABLED` | Public arşiv route'larını açar. |
| `PUBLIC_ARCHIVE_INDEXING` | Public arşiv sayfalarını sitemap ve indexlenebilir meta durumuna alır. |
| `PUBLIC_ARCHIVE_USE_PUBLIC_QA` | Public okumanın `public_qa` katmanından yapılmasını zorunlu kılar; `history` fallback'i yasaktır. |

## Zorunlu Flag Durumları

Başlangıç:

| Flag | Değer |
| --- | --- |
| `ADMIN_PARALLEL_ROUTE_ENABLED` | `true` |
| `ADMIN_ROOT_LEGACY_ENABLED` | `true` |
| `PUBLIC_ARCHIVE_ENABLED` | `false` |
| `PUBLIC_ARCHIVE_INDEXING` | `false` |
| `PUBLIC_ARCHIVE_USE_PUBLIC_QA` | `false` until public tables exist; public launch öncesi `true` |

Admin geçişi doğrulandıktan sonra:

| Flag | Değer |
| --- | --- |
| `ADMIN_PARALLEL_ROUTE_ENABLED` | `true` |
| `ADMIN_ROOT_LEGACY_ENABLED` | `true` |
| `PUBLIC_ARCHIVE_ENABLED` | `true` |
| `PUBLIC_ARCHIVE_INDEXING` | `false` |
| `PUBLIC_ARCHIVE_USE_PUBLIC_QA` | `true` |

Public SEO onayından sonra:

| Flag | Değer |
| --- | --- |
| `PUBLIC_ARCHIVE_ENABLED` | `true` |
| `PUBLIC_ARCHIVE_INDEXING` | `true` |
| `PUBLIC_ARCHIVE_USE_PUBLIC_QA` | `true` |

Root public geçişinden sonra:

| Flag | Değer |
| --- | --- |
| `ADMIN_PARALLEL_ROUTE_ENABLED` | `true` |
| `ADMIN_ROOT_LEGACY_ENABLED` | `false` |
| `PUBLIC_ARCHIVE_ENABLED` | `true` |
| `PUBLIC_ARCHIVE_INDEXING` | `true` |
| `PUBLIC_ARCHIVE_USE_PUBLIC_QA` | `true` |

Bu aşamada eski admin root/deep-link pattern'leri yalnız güvenli eşleşme varsa `/admin` altına yönlendirilir.

## Root Cutover Kapısı

`/` public arşive dönüşmeden önce şunlar geçmelidir:

- `/admin` ve `/admin/*` gerçek role flow'larıyla doğrulandı.
- Geçiş penceresi boyunca current root `/` çalışmaya devam etti.
- Login, logout, session refresh, upload, denetim, onaya gönderme, onaylama, reddetme, feedback, bildirimler, standartlar, raporlar, dashboard, history ve kullanıcı yönetimi regresyonları geçti.
- Public archive yalnız `public_qa` okuyor.
- Public banned-language checks HTML, JSON-LD, sitemap ve public API responses için geçiyor.
- `/arama` `noindex,follow`.
- `/admin` ve preview route'lar sitemap dışında ve noindex korumalı.
- Rollback yolu production cutover öncesi test edildi.

## Bu Plan Adımında Yapılmayanlar

- Kod değişikliği yok.
- DB migration yok.
- Production deploy yok.
- Push yok.
- Canlı veri yazma yok.
- Root admin davranışını kaldırma yok.
- Auth/session davranışı değiştirme yok.
- Aktif kullanıcı akışlarına müdahale yok.
