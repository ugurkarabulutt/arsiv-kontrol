# Public Arşiv MVP Uygulama Planı ve Checklist

Tarih: 2026-07-30
Durum: Plan, güvenli paralel `/admin` geçişiyle güncellendi, kodlanmadı

## Bu Turda Yapılmayanlar

- Kod değişikliği yapılmadı.
- DB migration çalıştırılmadı.
- DB'ye yazma yapılmadı.
- Production deploy yapılmadı.
- Push yapılmadı.
- Mevcut admin/auth/onay/feedback/bildirim akışları değiştirilmedi.

## Faz 0 - Mimari Audit

Amaç: Mevcut sistemi bozmadan public arşiv için karar ve riskleri netleştirmek.

Çıktılar:

- `PUBLIC_ARCHIVE_ARCHITECTURE_DECISION.md`
- `PUBLIC_ARCHIVE_ROUTE_AUDIT.md`
- `PUBLIC_ARCHIVE_DATA_MODEL_PROPOSAL.md`
- `PUBLIC_ARCHIVE_SEO_SCHEMA_PLAN.md`
- `PUBLIC_ARCHIVE_MVP_CHECKLIST.md`
- `PUBLIC_ARCHIVE_DECISION_LOCK.md`
- `PUBLIC_ARCHIVE_ADMIN_TRANSITION_PLAN.md`
- `PUBLIC_ARCHIVE_ADMIN_REGRESSION_CHECKLIST.md`
- `PUBLIC_ARCHIVE_ROLLBACK_PLAN.md`
- `PUBLIC_ARCHIVE_PUBLIC_LANGUAGE_GUARD.md`

Kabul kriterleri:

- Current root/admin davranışı dokümante edildi.
- `/admin` taşıma riskleri listelendi.
- API'ler public/user/admin/super-admin olarak ayrıldı.
- `history` alanlarının public'e çıkmaması gerekenleri listelendi.
- Public veri modeli önerildi.
- SEO/schema planı kaynaklarla yazıldı.

## Faz 1 - Paralel `/admin` Route, Root Legacy Korunur

Amaç: Mevcut root admin davranışını değiştirmeden aynı admin uygulamasını `/admin` ve `/admin/*` altında paralel çalıştırmak.

Önerilen işler:

- `ADMIN_PARALLEL_ROUTE_ENABLED=true` ile `/admin` ve `/admin/*` mevcut `index.html` uygulamasını döndürür.
- `ADMIN_ROOT_LEGACY_ENABLED=true` ile `/` mevcut admin/login davranışını korur.
- `PUBLIC_ARCHIVE_ENABLED=false` kalır.
- `/api/*`, `/health`, static assets ve upload/PDF endpointleri HTML fallback'e düşmez.
- Static asset path, SPA fallback, auth/session, browser refresh ve mobile davranışları özel olarak doğrulanır.
- Admin response için noindex koruması tasarlanır; public cutover öncesi uygulanacak test kapsamına alınır.

Riskli olmayan kabul testleri:

- `GET /admin` 200 ve admin app HTML.
- `GET /admin/gecmis` veya seçilen fallback path 200 ve admin app HTML.
- `GET /` hâlâ mevcut admin app HTML.
- `GET /api/auth/me` JSON döndürür; HTML fallback'e düşmez.
- `GET /health` aynı kalır.
- `GET /favicon.ico`, `/manifest.webmanifest`, `/sw.js`, `/icons/*` aynı kalır veya bilinçli ayrılır.
- Normal kullanıcı, admin ve süper admin akışları `/admin` altında geçer.

## Faz 1.5 - Sınırlı Kullanıcı Doğrulaması

Amaç: 39 aktif kullanıcıya duyurmadan önce `/admin` rotasını küçük grupla doğrulamak.

Kapsam:

- 1 normal kullanıcı.
- 1 admin.
- 1 süper admin.
- Mümkünse 1 mobil yoğun kullanıcı.

Kabul kriterleri:

- Login/logout/session yenileme sorunsuz.
- Metin denetimi, dosya upload, onaya gönderme, onaylama, reddetme, feedback, bildirim, standartlar, dashboard, history ve kullanıcı yönetimi rolüne göre çalışır.
- `/admin` refresh ve deep linkler boş sayfa üretmez.
- Root `/` hâlâ eski davranışı korur.

## Faz 1.6 - Ekip Yönlendirmesi

Amaç: Root kapanmadan ekibi `/admin` kullanımına alıştırmak.

Kabul kriterleri:

- Ekip yeni adresi kullanabilir.
- Root eski davranışı safety net olarak açık kalır.
- Tekrarlayan kullanıcı sorunu görülmez.
- Public root hâlâ kapalıdır.

## Faz 1.7 - Root Public Hazırlık Kapısı

Amaç: Root public geçişini ancak `/admin` stabil olduktan sonra açmak.

Gerekli koşullar:

- `PUBLIC_ARCHIVE_ADMIN_REGRESSION_CHECKLIST.md` geçer.
- Rollback flag planı test edilir.
- Public veri modeli ve public language guard hazırdır.
- Public route'lar `history` okumaz.
- Public indexing kapalı başlar.

## Faz 2 - Public Veri Modeli Migration

Amaç: `history` dışı yayın tablolarını eklemek.

Önerilen işler:

- `public_categories`
- `public_topics`
- `public_qa`
- `public_qa_topics`
- `public_redirects`
- `public_publish_events`

Kabul kriterleri:

- Migration staging/preview DB'de denenir.
- Existing `history`, `users`, `alerts`, `settings`, `issue_resolution_log`, `ai_reports` tabloları değiştirilmez veya sadece ayrı onaylı backward-compatible alan eklenir.
- `public_qa.status` check constraint içerir.
- `public_qa.slug` unique.
- `public_qa.content_hash` duplicate kontrolüne hazır.
- `public_qa.source_history_id` public response'a çıkmayacak şekilde sadece iç referanstır.

Bu fazda yapılmaması gerekenler:

- Tüm `onaylandi` kayıtları otomatik yayınlamak.
- `history` tablosunu public view gibi kullanmak.
- Public tarafı service role key ile browser'dan okutmak.

## Faz 3 - Yayın Hazırlama Akışı

Amaç: Mevcut onay akışını bozmadan public yayın draft'ı üretmek.

Önerilen işler:

- Admin iş panosunda onaylanmış kayıt için "public yayına hazırla" aksiyonu.
- `history` kaydından `public_qa` draft üretimi.
- Başlık, soru, cevap, özet, kategori, konular, slug, SEO description edit ekranı.
- Public preview, `noindex`.
- Published yapma yetkisi admin veya süper admin kararıyla netleştirilmeli.
- Her olay `public_publish_events` içine yazılır.

Kabul kriterleri:

- Existing `taslak -> bekliyor -> onaylandi/reddedildi` akışı değişmez.
- Public draft üretmek `history.status` değiştirmez.
- Aynı `source_history_id` için yanlışlıkla birden çok aktif public draft oluşmaz.
- Published olmadan public route 404 döndürür.

## Faz 4 - Public Okuma ve Arama MVP

Amaç: Kullanıcıya açık soru-cevap arşivini yalnız published kayıtlarla göstermek.

Önerilen route'lar:

- `/`
- `/soru/:slug`
- `/kategori/:slug`
- `/konu/:slug`
- `/arama`

Kabul kriterleri:

- Tüm public sorgular `public_qa.status = 'published'` filtresiyle çalışır.
- Public HTML içinde kullanıcı adı, skor, dosya adı, onaylayan, iç meta veya history ID yoktur.
- `/soru/:slug` non-published kayıtta 404 döndürür.
- `/arama` yalnız published sonuçları döndürür.
- Arama Türkçe apostrof/şapka varyasyonlarına tolerans gösterir.
- Public UI ve public meta denylist kelimelerini içermez.
- `PUBLIC_ARCHIVE_USE_PUBLIC_QA=true` olmadan public route production'da açılmaz.

## Faz 5 - SEO Assetleri

Amaç: Public canonical kaynak yapısını arama motorları için açık hale getirmek.

Önerilen işler:

- `sitemap.xml`
- `robots.txt`
- Public canonical helper
- Public noindex helper
- JSON-LD helper
- Redirect resolver

Kabul kriterleri:

- Sitemap yalnız published canonical public URL'leri içerir.
- `/arama`, `/admin`, `/api/*`, draft/preview URL'leri sitemap'te yoktur.
- `/arama` noindex, follow.
- `/admin` noindex header veya meta alır.
- Soru detay Article + WebPage + BreadcrumbList JSON-LD üretir.
- Kategori/konu CollectionPage + ItemList + BreadcrumbList JSON-LD üretir.
- JSON-LD parse edilebilir ve görünen içerikle eşleşir.

## Faz 6 - İlk İçerik Yayını

Amaç: Sınırlı sayıda kayıtla kontrollü public açılış yapmak.

Önerilen işler:

- İlk 20-50 onaylanmış kayıt manuel seçilir.
- Her kayıt için public başlık, soru, cevap, özet, kategori, konu ve slug kontrol edilir.
- Public preview üzerinde banned term ve veri sızıntısı kontrolü yapılır.
- Published yapılır.
- Sitemap ve public route smoke test çalıştırılır.

Kabul kriterleri:

- Public indexlenebilir sayfa sayısı bilinir.
- Her published kayıt en az bir kategori ve bir konuya bağlıdır.
- Kırık internal link yoktur.
- Redirect zinciri yoktur.
- Public HTML leak testi temizdir.

## Faz 7 - `ibrahimlive.com` Backlink Modeli

Amaç: Ana kaynak arşiv kalırken ana domain üzerinden otorite ve keşif desteği vermek.

Önerilen işler:

- `ibrahimlive.com` üzerinde kısa özet sayfaları.
- Her özet sayfasında canonical arşiv cevabına kaynak linki.
- Tam cevap kopyalanmaz.
- Eğer tam cevap kopyalanırsa canonical `arsiv.ibrahimlive.ai/soru/:slug` olur.

Kabul kriterleri:

- Duplicate full-content sayfa üretilmez.
- Arşiv URL'si canonical kaynak olarak kalır.
- Linkler UTM veya query ile canonical sinyali bölmez.

## Admin Bozulmasın Checklist

Preflight:

- `git status -sb` ile tanınmayan değişiklikler görülür.
- Mevcut dirty worktree korunur; ilgisiz dosyalar revert edilmez.
- Production env'de `PUBLIC_ARCHIVE_DEMO` yanlışlıkla açık değil.
- Migration ayrı onay olmadan çalıştırılmaz.

Auth:

- Varsayılan login akışı `/admin` altında çalışır.
- `POST /api/auth/login` başarılı login sonrası aynı kullanıcı bilgilerini döndürür.
- `GET /api/auth/me` logged out durumda `{ loggedIn:false }` döndürür.
- Logout sonrası admin ekranı kapanır.
- Normal user admin API'lerine 403 alır.
- Auth olmadan protected API'ler 401 alır.

User/admin flows:

- Metin analizi taslak oluşturur.
- Dosya analizi taslak oluşturur.
- Uzun metin parçaları tek başına onaya gönderilemez.
- Birleşik uzun metin tek taslak olarak görünür.
- Kullanıcı taslağı onaya gönderir.
- Admin iş panosu bekleyen kaydı görür.
- Onayla/Reddet sonrası iş panosu yenilenir.
- Kullanıcı geçmişi kendi kayıtlarını görür.
- Admin history taslak/parça kayıtlarını görmez.
- CSV export admin-only kalır.
- PDF üretimi auth-only kalır.
- Feedback gönderme ve çözüm bildirimi çalışır.
- Bildirimler kullanıcı ve admin ayrımlarını korur.
- Standartlar okundu takibi çalışır.

Public leak tests:

- `GET /` HTML içinde denylist iç terimleri yok.
- `GET /soru/:slug` HTML içinde denylist iç terimleri yok.
- `GET /kategori/:slug` HTML içinde denylist iç terimleri yok.
- `GET /konu/:slug` HTML içinde denylist iç terimleri yok.
- Public HTML içinde UUID pattern yok veya yalnız public-safe ID yok.
- Public HTML içinde `history`, `score`, `approved`, `promptVersion`, `rulesHash`, `text_hash`, dosya adı yok.
- Public JSON-LD içinde iç operasyon terimi yok.
- Public search response sadece published kayıtları listeler.

SEO:

- Her indexlenebilir public sayfada self canonical var.
- Sitemap URL'leri canonical ile aynı.
- `/arama` noindex, follow.
- `/admin` noindex.
- `/api/*` sitemap'te yok.
- Draft/review/archived kayıt public 404.
- Redirectler 301/308 ve tek sıçrama.

Regression:

- Kod değişikliği yapılan fazlarda `npm.cmd run check` zorunlu.
- Route split fazında ek olarak HTTP smoke test zorunlu.
- Public renderer eklendiğinde HTML parse ve denylist testi `scripts/check-frontend.js` veya ayrı check script'ine eklenmeli.

Production gate:

- Production deploy sadece kullanıcı onayıyla.
- Deploy sonrası `/health`, `/admin`, login, tek metin analizi, onaya gönderme, iş panosu, public `/`, public `/soru/:slug`, sitemap ve robots canlı doğrulanmadan tamamlandı sayılmaz.
