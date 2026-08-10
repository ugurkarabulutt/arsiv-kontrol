# Public Soru Cevap Arşivi Mimari Kararı

Tarih: 2026-07-30
Durum: Önerilen karar, güvenli `/admin` geçiş kilidiyle güncellendi, kodlanmadı

## Kapsam

Bu belge `arsiv.ibrahimlive.ai` alan adının ileride public dini soru-cevap arşivi, mevcut ekip uygulamasının ise `/admin` altında çalışması için mimari kararı kaydeder. Bu turda kod, veritabanı, migration, push veya deploy yapılmadı.

Güncel geçiş kilidi: Mevcut root admin davranışı hemen kaldırılmayacak. İlk uygulama adımı sadece `/admin` paralel admin route'unu eklemek olmalı; `/` mevcut admin davranışını korumalıdır. Public root ancak `/admin` geçişi doğrulandıktan sonra aktif edilebilir.

İncelenen kaynaklar: `AGENTS.md`, `CURRENT_HANDOFF.md`, `package.json`, `server.js`, `index.html`, `schema.sql`, `scripts/check-frontend.js`, mevcut route/API/auth/history/onay akışları ve mevcut worktree'de görünen public archive demo dosyaları.

## Mevcut Sistem Özeti

- Uygulama tek Express uygulaması olarak `server.js` üzerinden çalışıyor.
- Frontend tek dosyalı SPA: `index.html`.
- Oturum yönetimi `cookie-session` ile, roller `user`, `admin`, `super_admin`.
- Ayrılmış `admin` kullanıcı adı her zaman tek süper admin kabul ediliyor.
- Kök `GET *` fallback'i `index.html` döndürüyor; bu nedenle canlı kök `/` fiilen ekip uygulaması/login ekranı.
- API'ler çoğunlukla `/api/*` altında. `auth`, `admin`, `superAdmin` middleware zinciriyle korunuyor.
- `history` tablosu operasyonel çalışma kaydıdır: kullanıcı, skor, hata sayımları, kaynak metin, düzeltilmiş metin, statü, onaylayan ve analiz meta bilgileri aynı tabloda tutulur.
- Onay akışı `taslak -> bekliyor -> onaylandi/reddedildi` mantığına geldi. Uzun metin parça kayıtları `chunk_draft` ve `submitted_part` ile gizleniyor.
- Mevcut worktree'de `PUBLIC_ARCHIVE_DEMO=1` ile açılabilen `public-archive-demo.js` var. Bu demo `data/qa-seed` fixture'ını okuyor, `history` okumuyor; fakat production mimarisi olarak kabul edilmemeli.

## Temel Karar

Public arşiv, mevcut admin/history sisteminin doğrudan dışa açılmış hali olmayacak. Public taraf ayrı bir yayın katmanından okunacak.

Karar:

1. İlk MVP aynı repo ve mevcut Express app içinde kurulacak.
2. Public taraf HTML-first/server-rendered çalışacak; içerik ham HTML içinde okunabilir olacak.
3. Next.js veya ayrı frontend ilk MVP'de uygulanmayacak; gelecekte opsiyon olarak kalacak.
4. Mevcut admin sistemi big-bang rewrite edilmeyecek.
5. `/admin` önce paralel admin route olarak hazırlanacak.
6. `/` mevcut admin davranışını geçiş doğrulanana kadar koruyacak.
7. `/admin` ve `/admin/*` mevcut admin uygulamasını güvenli şekilde çalıştıracak.
8. `/admin` altında browser refresh ve deep linkler çalışmalı.
9. Static asset path, SPA fallback, auth redirect ve session davranışları özel olarak test edilmeli.
10. Geçiş doğrulandıktan sonra `/` public arşiv ana sayfası olacak.
11. Public root admin kelimeleri ve iç operasyon dili içermeyecek.
12. Public kayıtlar `history` tablosundan doğrudan okunmayacak.
13. `history.status = 'onaylandi'` sadece public draft'a aday kabul edilecek.
14. Public görünürlük için ayrı `public_qa.status = 'published'` gerekecek.
15. Onaylanan kayıtlar otomatik yayınlanmayacak.
16. Yayın akışı: `history` onayı -> public yayına hazırla -> public draft -> preview -> yayınla.
17. `ibrahimlive.com` ilk aşamada tam kopya içerik yayınlamayacak; özet + kaynak linki modeli kullanacak.
18. Asıl canonical kaynak `https://arsiv.ibrahimlive.ai` olacak.

## Feature Flag Kararı

Geçiş feature flag kontrollü olmalı:

| Flag | Anlam |
| --- | --- |
| `ADMIN_PARALLEL_ROUTE_ENABLED` | `/admin` ve `/admin/*` paralel admin route'larını açar. |
| `ADMIN_ROOT_LEGACY_ENABLED` | `/` üzerinde mevcut admin davranışını korur. |
| `PUBLIC_ARCHIVE_ENABLED` | Public arşiv route'larını açar. |
| `PUBLIC_ARCHIVE_INDEXING` | Public arşivi sitemap/indexlenebilir duruma alır. |
| `PUBLIC_ARCHIVE_USE_PUBLIC_QA` | Public okumanın `public_qa` katmanından yapılmasını zorunlu kılar. |

Başlangıç güvenli durum:

- `ADMIN_PARALLEL_ROUTE_ENABLED=true`
- `ADMIN_ROOT_LEGACY_ENABLED=true`
- `PUBLIC_ARCHIVE_ENABLED=false`
- `PUBLIC_ARCHIVE_INDEXING=false`

Admin geçişi doğrulandıktan sonra:

- `PUBLIC_ARCHIVE_ENABLED=true`
- `PUBLIC_ARCHIVE_INDEXING=false`

Public SEO onayından sonra:

- `PUBLIC_ARCHIVE_INDEXING=true`

Root public geçişinden sonra:

- `ADMIN_ROOT_LEGACY_ENABLED=false`
- Eski admin deep linkleri güvenli eşleşebiliyorsa `/admin` altına yönlendirilir.

## Neden Ayrı Yayın Katmanı

`history` operasyonel bir tablodur. `status = 'onaylandi'` public yayın için tek başına yeterli kalite ve gizlilik sinyali değildir. Aynı satırda kullanıcı kimliği, dosya adı, kaynak metin, skor, hata kırılımı, iç süreç özeti, onaylayan kişi, analiz sürümü ve teknik hash gibi public'e çıkmaması gereken alanlar bulunur.

Ayrı `public_qa` katmanı şu güvenlikleri sağlar:

- İç operasyon verisini public cevap nesnesinden ayırır.
- Başlık, slug, özet, kategori, konu ve SEO metinlerinin editoryal olarak hazırlanmasını zorunlu kılar.
- Onaylanmış ama public'e uygun olmayan kayıtların otomatik yayınlanmasını engeller.
- Yayından kaldırma, slug değişimi ve redirect işlemlerini `history` akışını bozmadan yönetir.
- Public API/SSR kodunun yanlışlıkla kullanıcı, skor veya ham analiz alanı döndürme riskini azaltır.

## Yayın Akışı

Önerilen akış:

1. Ekip mevcut sistemde metni çalışır ve taslak üretir.
2. Kullanıcı taslağı mevcut onay akışına gönderir.
3. Admin mevcut iş panosunda kaydı onaylar veya reddeder.
4. Onaylanan kayıt `history` içinde operasyon kaydı olarak kalır.
5. Admin ayrıca "public yayına hazırla" aksiyonuyla ayrı bir `public_qa` draft kaydı üretir.
6. Yayın editörü başlık, soru, cevap, özet, kategori, konu, slug ve SEO alanlarını kontrol eder.
7. Public preview yalnız yetkili kullanıcıya gösterilir ve `noindex` olur.
8. Yetkili kullanıcı `public_qa.status = 'published'` yapar.
9. Public site sadece bu yayınlanmış kaydı okur.
10. Slug değişirse eski path `public_redirects` ile kalıcı yönlendirmeye alınır.

## Route Kararı

Nihai hedef route sınırı:

- `/`: public arşiv ana sayfası.
- `/arama`: public arama sayfası, query kombinasyonları `noindex,follow`.
- `/soru/:slug`: public soru-cevap detay sayfası.
- `/konu/:slug`: public konu koleksiyon sayfası.
- `/kategori/:slug`: public kategori koleksiyon sayfası.
- `/sitemap.xml`: sadece published canonical public URL'leri.
- `/robots.txt`: crawler kuralları ve sitemap referansı.
- `/admin`: mevcut ekip uygulaması.
- `/admin/*`: mevcut ekip uygulaması refresh/fallback.
- `/api/public/*`: gerekiyorsa yalnız published public veriyi dönen public JSON API.
- Mevcut `/api/*`: admin/ekip uygulaması API'leri olarak korunur.

Geçiş öncesi route sınırı:

- `/`: mevcut admin/login uygulaması olarak kalır.
- `/admin`: aynı admin uygulamasının paralel güvenli adresi olur.
- `/admin/*`: aynı admin uygulamasının refresh/deep-link fallback'i olur.
- Public root etkin değildir.

## Public Dilde Yasaklı İç Terimler

Public arayüz, public meta, public JSON-LD, public sitemap başlıkları ve public görünen hata mesajlarında şu kelimeler görünmemeli:

- `AI`
- `prompt`
- `model`
- `admin`
- `denetim`
- `onay kuyruğu`
- `kalite kontrol`
- `test verisi`

Bu liste dokümantasyonda ve iç testlerde geçebilir; yasak public çıktılar içindir.

## `ibrahimlive.com` İlişkisi

İlk model "özet + kaynak linki" olmalı:

- `ibrahimlive.com` aynı cevabın tam kopyasını yayınlamaz.
- Kısa özet, konu yönlendirmesi ve "Tam cevabı arşivde okuyun" bağlantısı verir.
- Bağlantı canonical public arşiv URL'sine gider.
- `arsiv.ibrahimlive.ai` self-canonical kalır.

Tam metin kopyası ileride gerekli olursa, duplicate riskini azaltmak için `ibrahimlive.com` sayfası canonical olarak ilgili `arsiv.ibrahimlive.ai/soru/:slug` URL'sini göstermelidir.

## Kabul Edilen Teknik Yaklaşım

İlk MVP için aynı repo ve aynı Express deployment içinde ayrıştırma kararı alınmıştır. Bunun gerekçesi canlı admin sisteminin zaten bu deployment içinde olmasıdır. Risk, yeni framework veya ayrı hosting katmanı eklemek yerine route, veri ve render katmanını kontrollü ayırarak düşürülür.

Public taraf büyüyüp bağımsız ürün haline gelirse daha sonra ayrı frontend veya framework değerlendirilebilir. Bu ilk aşamanın şartı değildir.

## Kararın Sonuçları

- Public veri için migration gerekecek, fakat ayrı faz ve ayrı onayla yapılmalı.
- Mevcut admin route'ları yeniden konumlandırılırken önce paralel `/admin` test edilmeli; root legacy kapatılmadan regression test şarttır.
- `history` hiçbir public route veya public API tarafından okunmamalı.
- Public search, kategori ve konu sayfaları `public_qa` üzerinden kurulmalı.
- Public SEO çıktıları server-side üretilecek; sadece client-side meta/canonical kabul edilmemeli.
- Production deploy öncesinde public HTML leak testi zorunlu olmalı.

Bağlayıcı kısa karar listesi ayrıca `PUBLIC_ARCHIVE_DECISION_LOCK.md` dosyasındadır.

## Açık Risk

Mevcut worktree'de public demo router import'u ve env-gated route kaydı görülüyor. Bu dosyalar production mimarisi değil; ayrıca `server.js` bu untracked dosyaya bağımlı hale gelirse yalnız `server.js` commit edilip demo dosyası atlanırsa runtime kırılabilir. Public MVP başlamadan önce demo yaklaşımı ya tamamen ürünleştirilmeli ya da temizlenip ayrı branch/artefact olarak tutulmalı.
