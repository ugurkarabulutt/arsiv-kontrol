# Admin ve Ekip Üyesi Çalışma Alanları

## Durum

6 Eylül 2026. Çalışma dalı: `codex/admin-workspaces-v2`, başlangıç commit'i
`750e7de352bed707d9f8415cd5306d69703a47d0`. Ana çalışma ağacındaki başka değişikliklere dokunulmadı.

Kullanıcı ayrıca canlı Supabase güncellemesini ve production yayını açıkça onayladı.
Migration aynı yetkili araçla başarıyla uygulandı; Supabase kayıt sürümü
`20260906153905`, adı `admin_review_workspaces`. Yerel SQL dosyası aşağıdaki ilk
oluşturulma zamanını taşır. Runtime commit `bd499e8`, production deployment
`dpl_Eko5dMhRAkVuYUEViHJMdtAGTRFu` canlı `https://arsiv.ibrahimlive.ai` adresindedir.
Production ayarlarıyla ayrı build önce --skip-domain olarak kontrol edildi, ardından
promote edildi. Salt okunur preview production'a taşınmadı. GitHub push yapılmadı.

Migration öncesi/sonrası 5.176 history kaydının soru, cevap, etiket, kaynak, sahip ve
durum özeti `1c5430e10f3a79416bb7c9fcc4644a80`; 3.147 public_qa satırının tam içerik
özeti `11a76d47d7723c11ee6ef854cbb67c2f` ile birebir aynı. Yayında 1.987, geri dönen
394; yeni sürüm, atama ve yönlendirme sayısı sıfır. İçerik güncellemesi yapılmadı.
Yeni iki tablo RLS korumalı; yeni beş fonksiyon SECURITY INVOKER ve yalnız service_role
erişimlidir. Anon/authenticated doğrudan okuma/çağrı yetkileri yoktur.

Alan adı geçişi sonrasında public veri özeti ve 1.987 yayın/394 geri dönüş korundu.
Geçiş öncesi eski sürümde bir ekip üyesinin normal taslak düzenleme/gönderimi iki sürüm
kaydı oluşturdu. Bu fark eski admin_action_log ile doğrulandı; ajan içerik değiştirmedi.

Advisor yeni nesnelerde güvenlik uyarısı üretmedi. Önceden mevcut
`increment_public_question_read` fonksiyonunun anon/authenticated SECURITY DEFINER
çağrılabilirliği uyarıları sürüyor; bu değişiklik kapsamında değiştirilmedi.
İnceleme bağlantısı: https://supabase.com/docs/guides/database/database-linter?lint=0028_anon_security_definer_function_executable

## Davranış

- Admin ve süper admin: Ekip Üyesi / Yönetim seçimi; gerçek rol sunucuda doğrulanır.
- Ekip Üyesi: kendi veya kendisine atanmış kayıtları görür. Başkasına atanmış eski kendi
  kaydı kaynak geçmişi olarak okunabilir; artık düzenlenemez.
- Yönetim: ekip kuyruğu, duruma göre filtre, arama, 25 kayıtlık sayfalama. Favori listeleri
  aynı tek kayıt inceleme ekranına açılır; eski çoklu işlem butonları gösterilmez.
- Soru, etiket, düzeltilmiş cevap ve kontrol notu tek ekran ve tek sürümde saklanır.
- Geri dönen kayıt yeniden denetlenirse yeni kopya oluşturulmaz. Özgün denetim metni
  değiştirilmez; yeniden denetime verilen metin ayrıca kayda alınır. AI çağrısı yalnız
  açık `Yeniden Denetle` işlemiyle yapılır. Mevcut cevaplar topluca işlenmez.
- Eşzamanlı düzenleme sürüm çakışmasıyla engellenir; ekrandaki yazı kaybolmaz.
- Kendi kaydını onaylama engellenir. Soru, etiket veya cevap yoksa gönderim/onay engellenir.
  Cevabın kısa olması engel değildir. Mükerrer kontrolü yalnız soru VE cevabın birlikte
  aynı olmasıdır; sadece boşluk/satır farkları normalize edilir, anlam benzerliği kullanılmaz.
- Sahiplik itirazı düzenlemeyi durdurur. Yönetici gerekçeli olarak düzeltme sorumlusu
  atayabilir. `history.user_id` ilk denetleyenin değişmez kaydıdır.
- Çöpe taşıma gerekçelidir; kalıcı silme değildir. History, public görünürlük, sürüm,
  işlem logu ve bildirim aynı SQL transaction'ında sonuçlanır veya birlikte geri alınır.
  Geri alma otomatik yayınlamaz. İsteğe bağlı 301 hedefi sadece yayındaki birebir Q+A
  kopyası olabilir; yönlendirme zincirleri düzleştirilir.
- Onay ile toplu public senkronizasyon birbirinden ayrı kalır. Bu geliştirme eski içerikleri
  yeniden yayımlamaz, Excel eşleştirmelerini düzeltmez veya topluca yeniden atamaz.

## Onay Sonrası Sıra

1. `supabase/migrations/20260906142527_admin_review_workspaces.sql` dosyası için açık
   production DB onayı alın. DDL: dört history alanı, iki özel tablo, iki trigger ve
   yetkili RPC'ler. Tablolar RLS korumalı; `anon` ve `authenticated` erişimi yoktur.
2. Güncel yedek/snapshot ve kullanıcı işlemleri göz önünde tutularak migration uygulanır.
   Önce/sonra içerik ve sahiplik sayıları kontrol edilir. Eski soru/cevap/etiket alanlarına
   UPDATE yapılmaz. Migration idempotenttir; kullanıcı veri düzeltmesi değildir.
3. Yeni production build: `ADMIN_REVIEW_WORKSPACES_ENABLED=1`,
   `ADMIN_PREVIEW_CONTENT_READ_ONLY=0`. Mevcut public root, indexing, OAuth, session ve
   Supabase production ayarlarını koruyun.
4. **Salt okunur preview'ı promote ETMEYİN.** Preview'da public root ve indexing 0,
   yazma koruması 1'dir. Production için kendi production ayarlarıyla yeni deploy gerekir.
5. Oturumsuz API 401, admin no-store/noindex, yeni varlıkların hash'leri; ardından gerçek
   ekip üyesi, admin ve süper admin oturumlarıyla rol/okuma sınırları doğrulanır. Gerçek
   içerikte test kararı vermek için ayrıca açık seçili kayıt onayı gerekir.
6. Ekip lideriyle ilk normal çalışma izlenir. Geçmişte yanlış soruyla eşleşmiş kayıtlar
   kaynak incelemesi gerektirir; yeni ekran bunları kendiliğinden doğruya dönüştürmez.

## Geri Dönüş

Yeni atama/çöp kutusu işlemleri kullanılmaya başlandıktan sonra eski backend'e körlemesine
dönmeyin. Acil durumda yeni backend korunarak yazma koruması geçici açılabilir;
bu bütün API yazmalarını (giriş/çıkış hariç) durdurur. Public API yazmaları da etkilenir.
DDL'yi veya sürüm kayıtlarını silmeyin; düzeltme ileri yönlü migration ile yapılır.

## Doğrulama

- 130/130 yerel otomatik test; temiz sunucuda 6/6 masaüstü/mobil tarayıcı testi geçti.
- Hem yeni production deployment hem canlı alan adında 13 smoke kontrolü geçti.
  Admin HTML/JS/CSS dosyaları yerel kaynaklarla SHA-256 birebir. Yetkisiz review API
  okuma/yazma 401; public root ve temel sayfalar, robots ve sitemap 200; index/follow
  ve canonical korundu. Yeni deployment error log taramasında kayıt yok (son 20dk).
- Gerçek kullanıcı oturumu bağlı değildi. Canlıda gerçek içerik üzerinde onay/silme/
  düzenleme, AI denetimi veya PDF denemesi yapılmadı. Ekip liderinin paneli yenileyip ilk
  olağan çalışmayı doğrulaması gerekir; yerel rol testleri bununla karıştırılmamalı.

- `npm.cmd run check`: mevcut kontroller, Node testleri, tüm inline/external JS syntax'ı.
- `node --test test/review-workflow-db.test.js test/review-workflow-http.test.js`:
  gerçek PostgreSQL/PGlite RPC, rol, sahiplik, boş alan, birebir kopya, sürüm çakışması,
  eski endpoint, transaction geri alma, özel tablo yetkileri ve kaynak/paragraf korunumu.
- `npx.cmd playwright test --config playwright.review.config.js`: masaüstü/mobil gerçek
  tarayıcı, üç rol, modal, düzenleme/gönderim/geri çekme, çöp, arama ve önizleme koruması.
- `test-support/review-fixture.js` sadece 127.0.0.1 ve örnek veriler içindir; canlı DB,
  OpenAI veya gerçek kullanıcı kimliği kullanmaz. Deploy dışında bırakılmıştır.
