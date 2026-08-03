# Public Arşiv Admin Regresyon Checklist

Tarih: 2026-07-30
Durum: Checklist, docs-only

## Amaç

Bu checklist `/admin` paralel route'u eklenirken ve daha sonra root `/` public arşive dönerken aktif ekip çalışma alanını korur.

Paralel route fazında kritik akışlar iki adreste de geçmelidir:

- Legacy root `/`
- Paralel `/admin`

Root public cutover sonrası aynı admin akışları `/admin` altında geçmelidir.

## Preflight

- `git status -sb` kaydedildi.
- İlgisiz dirty dosyalar belirlendi ve revert edilmedi.
- Route PR'ına DB migration dahil edilmedi.
- Explicit onay olmadan production deploy yok.
- `ADMIN_PARALLEL_ROUTE_ENABLED=true`.
- `ADMIN_ROOT_LEGACY_ENABLED=true`.
- `PUBLIC_ARCHIVE_ENABLED=false`.
- `PUBLIC_ARCHIVE_INDEXING=false`.
- `PUBLIC_ARCHIVE_USE_PUBLIC_QA=false` until public tables exist.

## Routing

- `/` paralel fazda mevcut admin/login app'i döndürür.
- `/admin` mevcut admin/login app'i döndürür.
- `/admin/` mevcut admin/login app'i döndürür.
- `/admin/gecmis` veya seçilen deep-link test path admin app'i döndürür.
- `/admin/onay` veya seçilen admin deep-link test path admin app'i döndürür.
- Bilinmeyen admin deep link blank page üretmez.
- `/api/auth/me` HTML değil JSON döndürür.
- `/api/history` HTML değil JSON/401 döndürür.
- `/health` health JSON döndürür.
- `/favicon.ico`, `/manifest.webmanifest`, `/sw.js`, `/icons/*` beklenmedik 404 vermez.

## Auth ve Session

- Logged-out `/` paralel fazda mevcut login'i gösterir.
- Logged-out `/admin` aynı login davranışını gösterir.
- Normal kullanıcı login olur.
- Admin login olur.
- Süper admin login olur.
- Yanlış şifre hata verir ve session oluşturmaz.
- Logout session'ı temizler.
- Browser refresh valid session'ı korur.
- Kullanıcı `/` üzerinden login olup `/admin` açınca session beklenen şekilde görünür.
- Kullanıcı `/admin` üzerinden login olup `/` açınca paralel fazda session beklenen şekilde görünür.
- `GET /api/auth/me` iki adresten aynı kullanıcı kimliğini döndürür.
- Default-admin uyarısı admin-only kalır.

## Yetki Kontrolü

- Normal user admin API response'larına erişemez.
- Normal user admin-only bölümleri görmez.
- Admin dashboard, iş panosu, feedback center, alerts, users, rules gibi yetkili bölümleri görür.
- Süper admin super-admin-only aksiyonları görür.
- Normal admin super-admin-only create/delete yetkilerini kullanamaz.
- Süper admin hesabı silinemez veya düşürülemez.

## Normal Kullanıcı Paneli

- Metin denetimi ekranı yüklenir.
- Dosya upload ekranı yüklenir.
- Batch upload ekranı varsa yüklenir.
- History ekranı kullanıcıya görünür kayıtları listeler.
- Bildirimler ekranı kullanıcı bildirimlerini listeler.
- Standartlar ekranı görünür standartları listeler.
- Profil ekranı açılır ve şifre değiştirme çalışır.
- Ayarlar ekranı açılır.
- Mobil menü doğru normal-user entry'lerini gösterir.

## Admin Paneli

- Dashboard yüklenir.
- İş panosu bekleyen/onaylanan/reddedilen kolonlarını yükler.
- Feedback center yüklenir.
- Sistem uyarıları yüklenir.
- Kullanıcı listesi yüklenir.
- Kurallar editorü yüklenir.
- Raporlar/asistan ekranı varsa yüklenir.
- Admin mobil menü admin entry'lerini gösterir.

## Süper Admin Paneli

- Yeni kullanıcı modalı açılır.
- Yeni kullanıcı validation çalışır.
- Kullanıcı düzenleme modalı açılır.
- Kullanıcı bildirim modalı izinli ortamda çalışır.
- Kullanıcı silme korumaları çalışır.
- Mesaj kayıtları yüklenir.
- Çözüm yanıtları yüklenir.
- Super-admin-only kontroller normal adminden gizlenir.

## Metin Denetimi

- Boş/çok kısa metin validation çalışır.
- Normal metin denetimi draft oluşturur.
- Düzeltilmiş metin render olur.
- Kopyalama çalışır.
- PDF üretimi akışta kalıyorsa çalışır.
- Geçici hata mesajı kullanıcı metnini korur.
- Duplicate text handling çalışır.
- Work draft restore/clear davranışı korunur.

## Upload

- `.docx` upload metni çıkarır.
- Uzun dosya extraction `/api/extract-file-text` çağırır.
- File size limit kullanıcı dostu hata verir.
- Batch upload mevcut concurrency davranışını korur.
- Upload endpointleri `/admin` path'inden etkilenmez.

## Uzun Metin

- Uzun metin chunk'lara bölünür.
- Chunk kayıtları bağımsız onaya gönder adayı görünmez.
- Merged draft oluşur.
- Merged draft tek kez gönderilebilir.
- Duplicate corrected text engeli çalışır.

## Onay Akışı

- Kullanıcı kendi history'sinde draft görür.
- Kullanıcı eligible draft'ı onaya gönderir.
- Kullanıcı chunk-only kaydı gönderemez.
- Submitted record admin iş panosunda görünür.
- Admin onaylayabilir.
- Admin reddedebilir.
- İş panosu onay/red sonrası yenilenir.
- History status doğru güncellenir.
- Hidden status kayıtları mevcut kurallara göre gizli kalır.

## Feedback

- Kullanıcı sonuç feedback'i gönderir.
- Kullanıcı issue-level feedback gönderir.
- Feedback modal nested veya bozuk görünmez.
- Admin feedback okur.
- Admin alert read yapar.
- Admin feedback'e çözüm bildirir.
- Bulk resolve onaylı non-production veya kontrollü testte çalışır.
- Kullanıcı feedback resolution bildirimi alır.
- Kullanıcı resolution notification'a yanıt verebilir.

## Bildirimler

- Kullanıcı bildirim listesi yüklenir.
- Tek bildirim okundu yapılır.
- Tüm bildirimler okundu yapılır.
- Notification badge yenilenir.
- Admin alert badge yenilenir.
- Feedback badge yenilenir.
- Mesaj kayıtları super-admin-only kalır.

## Standartlar

- Standartlar listesi yüklenir.
- Okundu takibi çalışır.
- Görünür standartları okundu yapma çalışır.
- Admin izinli yerde standart ekler.
- Standards unread badge yenilenir.

## Raporlar ve Dashboard

- `/api/stats` admin-only kalır.
- Dashboard totals yüklenir.
- İş panosu count'ları API response shape'iyle uyumludur.
- Rapor listesi yüklenir.
- Rapor üretme admin-only ve explicit kalır.
- Insight endpoint admin-only kalır.
- Cron endpoint public navigation içinde görünmez.

## History

- Normal user yalnız kendi kayıtlarını görür.
- Admin allowed visible kayıtları görür.
- Admin current rules'a göre draft/chunk teknik satırlarını görmez.
- History detail modal açılır.
- Orijinal/düzeltilmiş karşılaştırma korunur.
- CSV export admin-only kalır.
- History all-pages davranışı korunur.

## Browser ve Mobil

- Desktop Chrome/Edge `/admin` refresh çalışır.
- Mobile Safari/Chrome `/admin` login çalışır.
- Mobile menü açılır/kapanır.
- Kritik admin ekranlarında text overlap yok.
- Back/forward navigation kullanıcıyı tuzağa düşürmez.
- `/admin` yeni tab'de açılınca session beklenen şekilde korunur.

## Asset Path ve Cache

- `/admin` altında relative asset path kırılmaz.
- Inline script çalışır.
- Manifest davranışı bilinçli olarak değerlendirilir.
- Service worker public cutover sonrası yanlış root cache etmez.
- Icon'lar yüklenir.
- Social/OG asset'leri admin akışını bozmaz.

## API Calls

Browser/network layer'da şu çağrıların absolute `/api/...` davranışını koruduğu doğrulanır:

- `/api/auth/login`
- `/api/auth/logout`
- `/api/auth/me`
- `/api/analyze`
- `/api/extract-file-text`
- `/api/analyze-file`
- `/api/history`
- `/api/history/:id`
- `/api/history/:id/submit`
- `/api/history/merged-draft`
- `/api/history/submit-merged`
- `/api/history/approval-board`
- `/api/history/:id/approve`
- `/api/history/:id/reject`
- `/api/history/:id/feedback`
- `/api/alerts`
- `/api/my-notifications`
- `/api/standards`
- `/api/stats`
- `/api/users`
- `/api/rules`

## Public Cutover Öncesi

`ADMIN_ROOT_LEGACY_ENABLED=false` yapılmadan önce:

- `/admin` bu checklist'i geçer.
- Legacy root kullanımı ekibe duyurularak `/admin` adresine taşındı.
- Eski admin deep link redirect mapping hazır.
- Rollback flag planı dokümante ve test edildi.
- Public root leak checks geçer.

## Public Cutover Sonrası

`ADMIN_ROOT_LEGACY_ENABLED=false` sonrası:

- `/` public.
- `/admin` admin.
- Eşleşen eski admin linkleri `/admin` altına redirect olur.
- `/api/*` değişmeden kalır.
- `/admin` sitemap içinde yoktur.
- `/admin` noindex koruması taşır.
