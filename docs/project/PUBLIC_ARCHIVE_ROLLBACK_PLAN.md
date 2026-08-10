# Public Arşiv Rollback Planı

Tarih: 2026-07-30
Durum: Plan, docs-only

## Amaç

Bu plan `/admin` geçişi veya public route ayrımı aktif production çalışma alanını etkilerse nasıl geri dönüleceğini tanımlar. Tercih edilen rollback feature flag tabanlıdır ve DB değişikliği gerektirmez.

## Feature Flag Tablosu

| Flag | Güvenli rollback değeri | Gerekçe |
| --- | --- | --- |
| `ADMIN_PARALLEL_ROUTE_ENABLED` | `true` veya son bilinen sağlam değer | `/admin` çalışıyorsa kullanılabilir kalsın; route conflict üretiyorsa kapatılır. |
| `ADMIN_ROOT_LEGACY_ENABLED` | `true` | Root `/` adresini mevcut admin davranışına döndürür. |
| `PUBLIC_ARCHIVE_ENABLED` | `false` | Public route handling'i root/catch-all path'ten çıkarır. |
| `PUBLIC_ARCHIVE_INDEXING` | `false` | İnceleme sırasında yanlış indexlenmeyi engeller. |
| `PUBLIC_ARCHIVE_USE_PUBLIC_QA` | Public açıkken `true`, public kapalıyken etkisiz | Public açıkken `history` fallback'ini engeller. |

## Bilinen Sağlam Durumlar

### State A - Mevcut Production Davranışı

| Flag | Değer |
| --- | --- |
| `ADMIN_PARALLEL_ROUTE_ENABLED` | `false` veya yok |
| `ADMIN_ROOT_LEGACY_ENABLED` | `true` |
| `PUBLIC_ARCHIVE_ENABLED` | `false` |
| `PUBLIC_ARCHIVE_INDEXING` | `false` |

Beklenen:

- `/` mevcut admin/login app'i servis eder.
- `/api/*` bugünkü gibi çalışır.
- Public archive aktif değildir.

### State B - Paralel Admin Güvenli Durum

| Flag | Değer |
| --- | --- |
| `ADMIN_PARALLEL_ROUTE_ENABLED` | `true` |
| `ADMIN_ROOT_LEGACY_ENABLED` | `true` |
| `PUBLIC_ARCHIVE_ENABLED` | `false` |
| `PUBLIC_ARCHIVE_INDEXING` | `false` |

Beklenen:

- `/` mevcut admin/login app'i servis eder.
- `/admin` da mevcut admin/login app'i servis eder.
- Public root yoktur.

### State C - Public Preview Güvenli Durum

| Flag | Değer |
| --- | --- |
| `ADMIN_PARALLEL_ROUTE_ENABLED` | `true` |
| `ADMIN_ROOT_LEGACY_ENABLED` | `true` |
| `PUBLIC_ARCHIVE_ENABLED` | `true` |
| `PUBLIC_ARCHIVE_INDEXING` | `false` |
| `PUBLIC_ARCHIVE_USE_PUBLIC_QA` | `true` |

Beklenen:

- Root admin çalışır.
- `/admin` çalışır.
- Public preview noindex test edilebilir.

## Rollback Senaryoları

### Senaryo 1 - `/admin` 404 veya blank page

Anlık aksiyon:

- `ADMIN_ROOT_LEGACY_ENABLED=true` kalsın.
- `/admin` route conflict üretiyorsa `ADMIN_PARALLEL_ROUTE_ENABLED=false`.
- `PUBLIC_ARCHIVE_ENABLED=false`.

Doğrulama:

- `/` mevcut admin app'i açar.
- Login çalışır.
- `/api/auth/me` JSON döndürür.
- `/health` ok döndürür.

### Senaryo 2 - API Call'ları HTML veya 404 Döndürüyor

Olası kök: catch-all route ordering.

Anlık aksiyon:

- `PUBLIC_ARCHIVE_ENABLED=false`.
- `ADMIN_ROOT_LEGACY_ENABLED=true`.
- Indexing kapalı kalır.

Doğrulama:

- `/api/auth/me`, `/api/history`, `/api/stats` JSON veya beklenen auth error döndürür.
- Hiçbir API route HTML fallback tarafından yutulmaz.

### Senaryo 3 - `/admin` Login/Session Loop

Anlık aksiyon:

- Kullanıcılara `/` kullanmaya devam etmeleri söylenir.
- `ADMIN_ROOT_LEGACY_ENABLED=true` kalır.
- `/admin` root'u etkiliyorsa paralel route kapatılır.

Doğrulama:

- Root login çalışır.
- Mevcut session'lar geçerli kalır.
- Logout/login döngüsü çalışır.

### Senaryo 4 - `/admin` Altında Asset Kırılıyor

Anlık aksiyon:

- Root legacy açık kalır.
- Ekip migration fazına geçilmez.
- Kırık asset root'u da etkiliyorsa paralel route kapatılır.

Doğrulama:

- CSS, JS, icons, manifest, service worker davranışı.
- Relative URL `/admin/...` altında yanlış çözülmüyor.

### Senaryo 5 - Public Root Erken Açıldı

Anlık aksiyon:

- `PUBLIC_ARCHIVE_ENABLED=false`.
- `PUBLIC_ARCHIVE_INDEXING=false`.
- `ADMIN_ROOT_LEGACY_ENABLED=true`.

Doğrulama:

- `/` tekrar mevcut admin app'i döndürür.
- `/admin` stabilse açık kalır.
- `/sitemap.xml` public draft URL göstermez.
- Public sayfalar noindex veya unavailable durumdadır.

### Senaryo 6 - Public Sayfa İç Operasyon Dili veya Veri Gösteriyor

Anlık aksiyon:

- `PUBLIC_ARCHIVE_ENABLED=false`.
- `PUBLIC_ARCHIVE_INDEXING=false`.
- Admin route'lar stabil bırakılır.

Doğrulama:

- Public route offending output servis etmez.
- Sitemap offending page'e işaret etmez.
- Public language guard güncellenmeden tekrar açılmaz.

### Senaryo 7 - Public Sayfalar `history` Okuyor

Anlık aksiyon:

- `PUBLIC_ARCHIVE_ENABLED=false`.
- `PUBLIC_ARCHIVE_INDEXING` açılmaz.
- Privacy/blocking issue kabul edilir.

Doğrulama:

- Public code path yalnız `public_qa` okur.
- `PUBLIC_ARCHIVE_USE_PUBLIC_QA=true` yeniden test öncesi enforce edilir.

### Senaryo 8 - SEO Indexing Erken Açıldı

Anlık aksiyon:

- `PUBLIC_ARCHIVE_INDEXING=false`.
- Public preview/search/admin/private route'larda noindex doğrulanır.
- Draft/private URL'ler sitemap'ten çıkarılır.

Doğrulama:

- `/robots.txt` yalnız intended sitemap'e işaret eder.
- `/sitemap.xml` private/admin/preview URL içermez.
- `/arama` `noindex,follow` kalır.

## Rollback Sonrası Doğrulama

Her rollback sonrası:

- `/` davranışı bilinen ve kasıtlı durumda.
- `/admin` davranışı bilinen ve kasıtlı durumda.
- `/api/auth/me` JSON döndürür.
- `/api/history` protected.
- `/api/users` admin-protected.
- `/health` çalışır.
- Aktif kullanıcılar çalışmalarına devam edebilir.
- Rollback için DB write veya migration gerekmez.
- Public indexing tekrar onaylanana kadar kapalıdır.

## İletişim

Rollback kullanıcıları etkilerse:

- Ekibe hangi URL'nin kullanılacağı net söylenir.
- Teknik flag dili yerine "mevcut adresi kullanmaya devam edin" gibi sade ifade tercih edilir.
- Session testi zorunlu kılmadıkça kullanıcılardan cookie temizlemesi istenmez.
- Kısa incident notu tutulur: saat, flag durumu, gözlenen sorun, rollback aksiyonu, doğrulama.

## Kural

Production cutover sırasında şüphe varsa önce root legacy geri açılır. Public archive launch, aktif ekip çalışma alanının kullanılabilirliğinden daha düşük önceliklidir.
