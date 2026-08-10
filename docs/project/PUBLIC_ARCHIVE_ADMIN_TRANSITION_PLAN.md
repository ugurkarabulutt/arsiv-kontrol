# Public Arşiv Güvenli `/admin` Geçiş Planı

Tarih: 2026-07-30
Durum: Plan, docs-only

## Amaç

Mevcut aktif ekip çalışma alanını güvenli şekilde `/admin` altında paralel çalıştırmak, root `/` davranışını geçiş doğrulanana kadar korumak ve public root'u yalnız doğrulama kapısından sonra açmak.

Varsayım: Production sistem yaklaşık 39 aktif ekip kullanıcısı tarafından kullanılmaktadır.

## Prensipler

- Big-bang rewrite yok.
- Root admin uygulaması hemen kaldırılmaz.
- Paralel route fazında auth/session davranışı değiştirilmez.
- `/admin` kanıtlanmadan public root açılmaz.
- Public archive `history` okumaz.
- Feature flag'ler hızlı rollback sağlayacak şekilde tasarlanır.

## Faz 0 - Mevcut Davranış Baseline

Amaç: `/admin` eklenmeden önce çalışan davranışı net kaydetmek.

Kontroller:

- `git status -sb` kaydedilir.
- `/` mevcut admin/login app'i açıyor.
- `/api/auth/me` logged-out response doğru.
- `/health` doğru.
- Güvenli test ortamında veya onaylı canlı testte normal user, admin ve super admin login doğrulanır.
- Denetim, onaya gönderme, onay, red, feedback, bildirim, standartlar, raporlar ve dashboard akışları çalışır.
- Mobil login ve menü davranışı kontrol edilir.
- Dosya upload ve PDF davranışı desteklenen ortamda kontrol edilir.

Çıkış kapısı:

- Mevcut production davranışı dokümante edildi.
- Root davranışı değiştirilmedi.

## Faz 1 - Paralel `/admin` Route

Amaç: `/admin` ve `/admin/*` adreslerini mevcut uygulama için güvenli paralel giriş yapmak; `/` aynen kalır.

Gerekli flag durumu:

| Flag | Değer |
| --- | --- |
| `ADMIN_PARALLEL_ROUTE_ENABLED` | `true` |
| `ADMIN_ROOT_LEGACY_ENABLED` | `true` |
| `PUBLIC_ARCHIVE_ENABLED` | `false` |
| `PUBLIC_ARCHIVE_INDEXING` | `false` |

Beklenen routing:

- `/` mevcut admin app'i eskisi gibi döndürür.
- `/admin` mevcut admin app'i döndürür.
- `/admin/*` browser refresh ve deep link için mevcut admin app'i döndürür.
- `/api/*` JSON kalır; HTML fallback tarafından yutulmaz.
- `/health`, asset'ler, upload endpointleri, PDF endpointleri ve cron endpoint mevcut davranışı korur.

Özel inceleme:

- Asset URL'leri `/admin` altında kırılmamalı.
- API call'ları `/api/...` absolute path davranışını korumalı.
- Service worker scope incelenmeli; root-scope worker public cutover sonrası yanlış cache davranışı üretmemeli.
- `/admin` explicit hale gelince admin HTML için noindex koruması planlanmalı.

Çıkış kapısı:

- `/admin` tüm roller için çalışıyor.
- `/` hâlâ çalışıyor.
- Kullanıcı akışları değişmedi.

## Faz 2 - Sınırlı Kullanıcı Testi

Amaç: Tüm ekibe duyurmadan önce küçük grupla `/admin` doğrulamak.

Önerilen grup:

- 1 normal kullanıcı.
- 1 admin.
- 1 süper admin.
- Mümkünse 1 mobil yoğun kullanıcı.

Test kapsamı:

- Login/logout.
- Session refresh.
- Metin denetimi.
- Dosya upload.
- Uzun metin chunk akışı.
- Onaya gönderme.
- Onaylama/reddetme.
- Feedback gönderme/okuma/cevaplama.
- Bildirimler.
- Standartlar okundu takibi.
- Dashboard/raporlar.
- History liste/detay.
- Süper admin kullanıcı yönetimi.
- `/admin` refresh.
- Kopyalanmış linkleri açma.

Çıkış kapısı:

- Bloker veya veri kaybı yok.
- Auth loop yok.
- Kullanımı etkileyen asset 404 yok.
- `/` ve `/admin` arasında session uyumsuzluğu yok.

## Faz 3 - Ekip Yönlendirme Penceresi

Amaç: Root safety net olarak açık kalırken ekibi `/admin` adresine alıştırmak.

Önerilen rollout:

1. Ekibe yeni çalışma adresinin `/admin` olduğu duyurulur.
2. `/` geçiş penceresinde değişmeden kalır.
3. Destek mesajları ve feedback izlenir.
4. En az bir normal kullanım döngüsü boyunca iki adres de çalışır.
5. Bu fazda public root açılmaz.

Çıkış kapısı:

- Aktif kullanıcıların anlamlı kısmı `/admin` üzerinden çalışmıştır.
- Tekrarlayan workflow sorunu görünmez.
- Admin ve süper admin işlemleri `/admin` altında kullanılmıştır.

## Faz 4 - Eski Deep Link Redirect Planı

Amaç: Root public olduğunda eski admin linklerinin ne yapacağını önceden belirlemek.

Mevcut SPA tab-based olduğu için eski root linklerinin çoğu sadece `/` olabilir. Hash/query state varsa mapping açıkça yazılmalı.

Kurallar:

- `/admin` ekip çalışma alanının canonical adresi olur.
- Bilinen eski admin deep linkleri sadece root public cutover sonrası `/admin` eşdeğerine yönlendirilir.
- Bilinmeyen public path'ler admin'e kör şekilde redirect edilmez.
- `/api/*` hiçbir zaman HTML route'a redirect edilmez.
- Redirectler testte 302, kalıcı karar sonrası 301/308 olmalı.

Çıkış kapısı:

- Redirect mapping dokümante edildi.
- Redirect loop yok.
- Public root admin/API path'lerini yanlış yakalamıyor.

## Faz 5 - Public Archive Noindex Preview

Amaç: Public archive route'larını indexing kapalı şekilde test etmek.

Gerekli flag durumu:

| Flag | Değer |
| --- | --- |
| `PUBLIC_ARCHIVE_ENABLED` | `true` |
| `PUBLIC_ARCHIVE_INDEXING` | `false` |
| `PUBLIC_ARCHIVE_USE_PUBLIC_QA` | `true` |
| `ADMIN_ROOT_LEGACY_ENABLED` | `true` until final cutover |

Davranış:

- Public archive gated/preview route veya planlanan root davranışı üzerinden test edilir.
- Public sayfalar sadece `public_qa` okur.
- Preview ve indexing kapalı mod `noindex` taşır.
- Sitemap public soru URL'lerini SEO onayına kadar index kaynağı gibi sunmaz.

Çıkış kapısı:

- Public language guard geçer.
- Public route smoke test geçer.
- Public veri `public_qa` üzerinden gelir; `history` okunmaz.

## Faz 6 - Root Public Cutover

Amaç: `/` public arşiv, `/admin` ekip çalışma alanı olur.

Gerekli flag durumu:

| Flag | Değer |
| --- | --- |
| `ADMIN_PARALLEL_ROUTE_ENABLED` | `true` |
| `ADMIN_ROOT_LEGACY_ENABLED` | `false` |
| `PUBLIC_ARCHIVE_ENABLED` | `true` |
| `PUBLIC_ARCHIVE_INDEXING` | `false` first, then `true` after SEO approval |
| `PUBLIC_ARCHIVE_USE_PUBLIC_QA` | `true` |

Cutover adımları:

1. `/admin` tam regression green.
2. Rollback flag prosedürü doğrulandı.
3. Root public davranışa alınır.
4. Indexing ilk anda kapalı kalır.
5. `/`, `/soru/:slug`, `/kategori/:slug`, `/konu/:slug`, `/arama` doğrulanır.
6. `/admin` ve `/admin/*` tekrar doğrulanır.
7. Eski admin linkleri mapping varsa güvenli yönlenir.
8. SEO validation sonrası indexing açılır.

## Rollback

Anlık rollback hedefi:

- `ADMIN_ROOT_LEGACY_ENABLED=true`
- `PUBLIC_ARCHIVE_ENABLED=false`
- `PUBLIC_ARCHIVE_INDEXING=false`

Rollback DB verisi değiştirmeden `/` adresini mevcut admin app davranışına döndürmelidir.

Rollback zorunlu tetikleyicileri:

- `/admin` login başarısız.
- Aktif kullanıcılar gönderim, onay, red veya history inceleme yapamıyor.
- API call'ları HTML fallback'e düşüyor.
- Public sayfalar iç operasyon dili veya `history` verisi gösteriyor.
- Public root cutover sonrası temel route'lar 500/404 veriyor.
- SEO kontrolleri fail ve public sayfalar onaydan önce indexlenebilir.

Detaylı senaryolar: `PUBLIC_ARCHIVE_ROLLBACK_PLAN.md`.
