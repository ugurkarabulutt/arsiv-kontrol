# CURRENT_HANDOFF — Arşiv Kontrol AI

## 2026-08-06 Codex Güncel Durum

- `/admin` Arşiv Operasyon Merkezi açılır başlığı sadeleştirildi. Yazılı `Aç/Kapat` etiketi
  kaldırıldı; başlık diğer menü satırlarıyla aynı renkte kalır ve açılır menü olduğunu chevron
  ok işaretiyle gösterir. Alt başlık seçildiğinde yalnız alt başlık aktif görünür.

- `/admin` Arşiv Operasyon Merkezi menüsü kapalı/açılır hale getirildi. Mobil ve masaüstü
  menüde önce yalnız ana başlık görünür; ana başlığa tıklanınca alt başlıklar açılır, tekrar
  tıklanınca kapanır. Bu adımda `index.html`, `scripts/check-frontend.js`, `AGENTS.md` ve
  `CURRENT_HANDOFF.md` değişti; backend/DB/schema/root `/` ve public frontend dosyalarına
  dokunulmadı. Süper admin rol mimarisi aynı kaldı.
- Doğrulama: `npm.cmd run check` başarılı, 86/86 test geçti. Ek statik DOM kontrolü kapalı
  alt menü işaretlerini doğruladı.
- Runtime commit `5583111` GitHub'a push edildi ve production'a alındı. Production deploy:
  `https://arsiv-kontrol-qc9fvavzj-ugurkarabulutts-projects.vercel.app`, canlı alias
  `https://arsiv.ibrahimlive.ai`. Canlı smoke: `/health`, root `/`, `/admin`, `/admin/`,
  `/admin/smoke-test`, `/api/auth/me`, manifest, `sw.js` ve favicon başarılı. Canlı HTML'de
  kapalı alt menü işaretleri mevcut; eski geçici `adminRouteProbe` yok.

- `/admin` Arşiv Operasyon Merkezi tek uzun sayfa yerine alt menülü odak ekran yapısına
  taşındı. Süper admin menüsünde `Genel Bakış`, `Kaynak Kayıtları`, `Kaynak Havuzu`,
  `Yayın Görevleri`, `Çalışma Kayıtları`, `Hadis ve Slayt Metinleri`, `İçe Aktarım Merkezi`
  ve `Public Arşiv Adayları` ayrı alt başlıklar olarak açılır. Her başlık yalnız kendi
  bölümünü gösterir; kaynak araması `Kaynak Havuzu` ekranına, kaydı forma alma işlemi
  `Kaynak Kayıtları` ekranına yönlendirir.
- Kapsam dar tutuldu: `index.html`, `scripts/check-frontend.js`, `AGENTS.md` ve
  `CURRENT_HANDOFF.md` değişti. `server.js`, public preview dosyaları, DB/schema ve root `/`
  public cutover'a dokunulmadı. Süper admin rol mimarisi değiştirilmedi; `admin` kullanıcı adı
  tek gerçek süper admin hesabı olarak korunur.
- Doğrulama: `npm.cmd run check` başarılı, 86/86 test geçti. Ek statik DOM kontrolü alt ekran
  işaretleri ve davranış fonksiyonlarının varlığını doğruladı. `git diff --check` yalnız mevcut
  CRLF uyarılarını verdi.
- Runtime commit `c0a29d0` GitHub'a push edildi ve production'a alındı. Production deploy:
  `https://arsiv-kontrol-jmn0ywmnf-ugurkarabulutts-projects.vercel.app`, canlı alias
  `https://arsiv.ibrahimlive.ai`. Canlı smoke: `/health`, root `/`, `/admin`, `/admin/`,
  `/admin/smoke-test`, `/api/auth/me`, manifest, `sw.js` ve favicon başarılı. `/admin`
  header'ları noindex/no-store doğru. Canlı HTML'de Arşiv Operasyon Merkezi alt menü
  işaretleri mevcut; eski geçici `adminRouteProbe` yok.
- Not: Kullanıcının isteğiyle ileride dashboard içinde birden çok işi olan diğer ana başlıklar
  da aynı alt menü / odak ekran desenine taşınmalıdır.

- `/admin` Arşiv Operasyon Merkezi kaynak kayıtları için tablo destekli repository katmanı
  eklendi. Sistem artık canlı DB'de `archive_sources`, `archive_source_versions` ve
  `archive_source_events` tabloları varsa kaynakları bu tablolardan yönetebilir; tablolar henüz
  yoksa mevcut `settings.archive_ops_sources` JSON pilot akışı bozulmadan devam eder.
- Yeni tablo modeli `schema.sql` içine eklendi. Sunucu tablo varlığını startup'ta algılar; tablo
  boşsa eski pilot JSON kayıtlarını idempotent şekilde tabloya taşır. Listeleme tam metni
  çekmeden `text_preview` ve `text_length` ile çalışır; detay açılınca tam metin alınır. Yeni
  kayıt ve güncelleme işlemleri versiyon ve olay kaydı oluşturacak şekilde hazırlandı.
- Değişen dosyalar: `server.js`, `schema.sql`, `scripts/check-frontend.js`, `AGENTS.md`,
  `CURRENT_HANDOFF.md`. Public frontend untracked dokümanlarına dokunulmadı.
- Canlı DB'de `archive_sources`, `archive_source_versions` ve `archive_source_events` SQL
  blokları Supabase SQL Editor'de uygulandı. REST HEAD kontrolünde üç tablo da `200` döndü ve
  başlangıçta boş olduğu doğrulandı.
- Runtime commit `16ff508` GitHub'a push edildi ve production'a alındı. Production deploy:
  `https://arsiv-kontrol-o1drv6x69-ugurkarabulutts-projects.vercel.app`, canlı alias
  `https://arsiv.ibrahimlive.ai`.
- Doğrulama: `npm.cmd run check` başarılı, 86/86 test geçti. Canlı smoke geçti:
  `/health`, root `/`, `/admin`, `/admin/`, `/admin/smoke-test`, `/api/auth/me`,
  `manifest.webmanifest`, `sw.js`, `favicon.ico`. `/admin` noindex/no-store header'ları doğru.
  `/api/archive-ops/sources` oturumsuz erişimde `401` dönüyor.
- Bu adımda kaynak importu yapılmadı, root `/` public cutover yapılmadı, kullanıcı ekranlarına
  yeni özellik açılmadı. Sonraki güvenli adım: süper adminle `/admin` kaynak kayıt akışında
  bir pilot kayıt oluşturup DB repository + versiyon/event kayıtlarını canlıda doğrulamak.

- `/admin` Arşiv Operasyon Merkezi kaynak kayıtlarında güncelleme son kontrolü eklendi. Bir
  kaynak forma alınıp değiştirildiğinde sistem artık değişen alanları özetleyen
  `Kaynak kaydı güncellensin mi?` onay penceresi açar; onay verilmeden mevcut kayıt üzerine
  yazılmaz. Tam metin versiyon geçmişi bu pilot JSON depolama aşamasında bilerek eklenmedi;
  büyük metinlerde ölçekli versiyon/geri alma ayrı kaynak tabloları fazında yapılmalı.
- Runtime commit `11c0b2e` GitHub'a push edildi ve production'a alındı. Production deploy:
  `https://arsiv-kontrol-3d50bqrz2-ugurkarabulutts-projects.vercel.app`, canlı alias
  `https://arsiv.ibrahimlive.ai`. Doğrulama: `npm.cmd run check` başarılı, 86/86 test geçti.
  Canlı smoke ve `/admin` HTML marker kontrolü başarılı.

- `/admin` Arşiv Operasyon Merkezi kaynak kayıtlarına çakışma kontrolü eklendi. Sistem artık
  aynı normalize kaynak metni, aynı kaynak linki veya aynı başlık+tür kombinasyonunu kayıt
  öncesinde yakalar. Uyarı alan süper admin kayıtları kontrol edip isterse `Yine de Kaydet`
  ile bilinçli şekilde saklayabilir; bu karar kaydın üstünde görünür.
- Kapsam dar tutuldu: `server.js`, `index.html`, `scripts/check-frontend.js`, `AGENTS.md` ve
  `CURRENT_HANDOFF.md` değişti. DB/schema migration yok, kaynak içe aktarımı yok, root `/`
  public cutover yok. Public frontend untracked dokümanlarına dokunulmadı.
- Runtime commit `f6f7ef1` GitHub'a push edildi ve production'a alındı. Production deploy:
  `https://arsiv-kontrol-docn1eixr-ugurkarabulutts-projects.vercel.app`, canlı alias
  `https://arsiv.ibrahimlive.ai`.
- Doğrulama: `npm.cmd run check` başarılı, 86/86 test geçti. Canlı smoke geçti:
  `/health`, root `/`, `/admin`, `/admin/`, `/admin/smoke-test`, `/api/auth/me`,
  `manifest.webmanifest`, `sw.js`, `favicon.ico`. `/admin` noindex/no-store header'ları
  doğru. Canlı HTML'de `Benzer kaynak bulundu`, `saveArchiveSource(forceSave=false)`,
  `duplicateWarning` ve API hata detay koruması mevcut; eski geçici `adminRouteProbe` yok.

- `/admin` içindeki Arşiv Operasyon Merkezi için ilk gerçek kaynak kayıt akışı production'a
  alındı. Bu alan hâlâ yalnız süper admin ve yalnız `/admin` hedefli pilot alandır; root `/`
  public arşiv için korunur ve public cutover yapılmadı.
- Yeni akış: süper admin transkript, hadis, slayt, doküman, standart ve not türünde kaynak
  metni ekleyebilir; başlık, kategori, kaynak tarihi, kaynak linki, etiket/kavram, durum ve
  karar notu tutabilir. Hadis ve slaytlar yalnız link değil, metin olarak da sistemde
  saklanacak şekilde hazırlandı.
- Kaynak havuzunda arama başlık, tam metin, kategori, link, not ve etiketlerde çalışır.
  Seçilen kaynak tam metniyle açılır, kopyalanır ve forma alınarak düzenlenebilir.
- Bu adım DB/schema migration yapmadı. İlk pilot veri mevcut `settings` tablosunda
  `archive_ops_sources` JSON anahtarıyla saklanır. Kaynak metni sınırı 200.000 karakterdir.
  Daha büyük kalıcı ölçek için sonraki fazda ayrı kaynak tabloları/import hattı planlanmalı.
- Runtime commit: `dcfab9e feat: add super admin archive source records`. GitHub'a push edildi.
- Production deploy: `https://arsiv-kontrol-f0yrt2zdx-ugurkarabulutts-projects.vercel.app`,
  deployment `dpl_4ZL1sJy1BBwjc5SAYQCY933fv9Xt`, canlı alias `https://arsiv.ibrahimlive.ai`.
- Doğrulama: `npm.cmd run check` başarılı, 86/86 test geçti. Canlı smoke geçti:
  `/health`, `/`, `/admin`, `/admin/`, `/admin/smoke-test`, `/api/auth/me`,
  `manifest.webmanifest`, `sw.js`, `favicon.ico`. `/admin` noindex/no-store header'ları
  doğru. `/api/archive-ops/sources` oturumsuz erişimde 401 dönüyor; route canlı ve korumalı.
- Workspace'teki untracked public frontend dokümanları bu deploy'a dahil edilmedi.

- Süper admin için `/admin` route'una `Arşiv Operasyon Merkezi` ilk kabuğu eklendi ve
  production'a alındı. Bu alan yalnız `super_admin` rolünde ve `/admin` adresinde görünür;
  root `/` şimdilik legacy admin/public cutover öncesi korunur.
- Kapsam: kaynak havuzu, yayın görevleri, çalışma kayıtları, hadis ve slayt metinleri,
  içe aktarım merkezi ve public arşiv adayı aşamalarını tek süper admin operasyon kabuğunda
  göstermek. Bu ilk kabuk veri yazmaz, DB/schema değiştirmez, gerçek Drive/e-tablo entegrasyonu
  başlatmaz.
- Kod commit'i: `1a0fa71 feat: add super admin archive operations shell`. GitHub'a push edildi.
- Production deploy: `https://arsiv-kontrol-qzolw1q4e-ugurkarabulutts-projects.vercel.app`,
  deployment `dpl_8qCFG6RadRDZyyQyvctdGAjCwAQq`, canlı alias `https://arsiv.ibrahimlive.ai`.
- Doğrulama: `npm.cmd run check` başarılı, 86/86 test geçti. Canlı smoke geçti:
  `/health`, `/`, `/admin`, `/admin/`, `/admin/smoke-test`, `/api/auth/me`,
  `manifest.webmanifest`, `sw.js`, `favicon.ico` başarılı. `/admin` noindex/no-store
  header'ları doğru.
- Canlı HTML'de `Arşiv Operasyon Merkezi`, `tabContent-archiveOps` ve `admin-route-only`
  mevcut; eski geçici `adminRouteProbe` yok.
- Deploy temiz `git archive HEAD` kaynağından alındı. Workspace'teki untracked
  `docs/project/PUBLIC_ARCHIVE_P2D_C_REFERENCE_LED_PREMIUM_REDESIGN_BRIEF.md` deploy'a
  dahil edilmedi.

## 2026-08-05 Codex Güncel Durum

- `/admin` geçişinden sonra DB'de `admin` görünen kullanıcının kendi ekranında admin menüsü
  görememesi sorunu incelendi. Kök sebep session cache: `cookie-session` içinde eski `role`
  kalıyor, `/api/auth/me` DB'deki güncel kullanıcı rolünü yeniden okumuyordu. Auth middleware
  ve `/api/auth/me` artık `users` tablosundan kullanıcıyı yeniden okur, `effectiveRole` ile
  session'ı günceller, pasif/silinmiş kullanıcıyı oturumdan düşürür. Runtime commit
  `0c51903` GitHub'a push edildi ve production'a alındı. Doğrulama:
  `npm.cmd run check` başarılı, 86/86 test geçti.
- Ekip yöneticisinin `Efendimizin sözlüğü` önceliğiyle kelime içi yanlış uygulama olabileceği
  tespiti üzerine `şer` kökü backend seviyesinde sıkılaştırıldı. `şer -> şerr` yalnız bağımsız
  kelime/kök kullanımlarında kabul edilir; `ŞERİF`, `HADÎS-İ ŞERİF`, `şeriat`, `ŞERİAT`,
  `şerh` gibi kelimelerin içine giren `ŞERRİF/şerriat/şerrh` önerileri artık skor dışı kalır
  ve düzeltilmiş metne uygulanmaz. `şerr -> şerrr` üçleme hatası da korumaya alındı.
- Prompt tarafındaki kural metni aynı yönde netleştirildi. Runtime commit `8c981df`
  GitHub'a push edildi ve production'a alındı. Doğrulama: `npm.cmd run check`
  başarılı, 86/86 test geçti. Production deploy:
  `https://arsiv-kontrol-qcncicc6u-ugurkarabulutts-projects.vercel.app`, deployment
  `dpl_8emRJVhG58M8t4Mvb3jxkRSQ5hDJ`, canlı alias `https://arsiv.ibrahimlive.ai`.
- Canlı smoke: `/health` `ok`, root `/` HTTP 200, `/admin`, `/admin/` ve
  `/admin/smoke-test` HTTP 200, `/api/auth/me` `{"loggedIn":false}`, manifest,
  `sw.js` ve favicon HTTP 200. `/admin` header'ları noindex/no-store doğru. Canlı HTML'de
  geçici `adminRouteProbe` test alanı yok; `ensureStandaloneAdminRoute` mevcut.
- Son iki runtime düzeltmesi GitHub'a push edildi ve production'a alındı:
  `4f7b6c6 feat: allow 200k character analysis` ve
  `b08c80e fix: catch hadis serif heading feedback`.
- Kullanıcılar artık 200.000 karaktere kadar metin denetleyebilir. Frontend ve backend
  sınırları canlıda `200000` ile hizalıdır; eski 50.000/120.000 kaynaklı engel canlıda yok.
- `HADÎS-İ ŞERİF` başlığının bozuk varyantları artık 100 puanla sessiz geçmez. Hedef motor
  testi `HADÎS-İ şerrİF` varyantını 1 bulgu ve `score=96` ile yakaladı.
- Temiz/100 puanlı sonuçlarda geri bildirim alanı açık kalır; kullanıcı kaçan bir nokta
  gördüğünde yine ekibe bildirim gönderebilir.
- Doğrulama: `npm.cmd run check` başarılı, 85/85 test geçti.
- Production deploy: `https://arsiv-kontrol-bvbv3hjqo-ugurkarabulutts-projects.vercel.app`,
  canlı alias `https://arsiv.ibrahimlive.ai`.
- Canlı smoke: `/health` `ok`, root `/` HTTP 200, `/admin`, `/admin/` ve
  `/admin/smoke-test` HTTP 200, `/api/auth/me` `{"loggedIn":false}`, manifest,
  `sw.js` ve favicon HTTP 200. `/admin` header'ları noindex/no-store doğru. Canlı HTML'de
  200.000 karakter sınırı ve 100 puanlı feedback açıklaması mevcut; eski
  `ekibe bildirim kapalı` metni yok.

## 2026-08-04 Codex Güncel Durum

- Metin denetimi üst sınırı 200.000 karaktere çıkarıldı. Frontend `MAX_TEXT_CHARS` ve
  backend `MAX_ANALYSIS_TEXT_CHARS` artık `200000`; 200.000 karaktere kadar metinler
  mevcut uzun metin parçalı denetim akışıyla kabul edilir. 200.000 üstü için net sınır
  mesajı verilir. Eski `120000` sınırı ve `metni bölerek denetleyin` engeli ilgili
  kontrol akışından kaldırıldı. `scripts/check-frontend.js` bu sınırı regresyon olarak
  doğrular. Doğrulama: `npm.cmd run check` başarılı, 84/84 test geçti. Bu adımda
  production deploy yapılmadı.
- Kullanıcı raporuyla `HADÎS-İ ŞERİF` başlığında sessiz kaçak tespit edildi: `HADÎS-İ şerrİF`
  gibi bozuk varyantlar 100 puanla geçebiliyordu. `analysis-core.js` içine yalnız bu başlık
  bağlamında çalışan dar deterministik standart eklendi; bozuk varyantlar `HADÎS-İ ŞERİF`
  / `Hadîs-i Şerif` standardına alınır, genel `şerr` koruması korunur. Ayrıca 100 puanlı veya
  temiz görünen sonuçlarda geri bildirim panelinin kapanması kaldırıldı; kullanıcı sonuç temiz
  görünse bile eksik/hatalı/kaçan noktayı ekibe bildirebilir. Doğrulama: hedef motor senaryosu
  `score=96`, `totalErrors=1`, `correctedText=HADÎS-İ ŞERİF`; `npm.cmd run check` başarılı,
  85/85 test geçti. Bu adımda production deploy yapılmadı.
- Geçmiş düzeltme akışı feedback merkezli hale getirildi. Süper admin artık düzeltme kaydında
  önce `Bildirilen doküman` bölümünü görür; bu bölüm geri bildirimin bağlı olduğu asıl
  denetim kaydını gösterir. `Benzer geçmiş kayıtlar` ayrı bölümde listelenir. Her hedef
  `historyId:field` kimliğiyle seçilebilir; kırmızı/eski ve yeşil/yeni bağlam önizlemesi
  gösterilir; `Dokümanı Aç`, `Bu Kaydı Uygula` ve `Seçilenleri Uygula` aksiyonları vardır.
  Backend `/api/correction-packages/:id/apply` artık `selectedChangeIds` kabul eder; seçili
  hedef gelirse yalnız o kayıtlar güncellenir. Kısmi uygulamalar `appliedTargets` ile
  saklanır ve geri alma defteri `content_correction_log` korunur. Doğrulama:
  `npm.cmd run check` başarılı, 84/84 test geçti. Commit `697cc3f` GitHub'a push edildi.
  Production deploy `dpl_AsqGc9m5YUHj38ziadSV5c6Dnq7Q`, canlı alias
  `https://arsiv.ibrahimlive.ai`. Canlı smoke: `/health` `ok`, root `/` HTTP 200,
  `/admin`, `/admin/` ve `/admin/smoke-test` HTTP 200, `/api/auth/me`
  `{"loggedIn":false}`, manifest, `sw.js` ve favicon HTTP 200. `/admin` header'ları
  `X-Robots-Tag: noindex, nofollow` ve `Cache-Control: no-store, no-cache,
  must-revalidate, proxy-revalidate`. Canlı HTML'de `Bildirilen doküman`,
  `Benzer geçmiş kayıtlar`, `selectedChangeIds`, `Dokümanı Aç`, `Bu Kaydı Uygula`
  mevcut; eski `adminRouteProbe` yok.
- Kullanıcı `/admin` süper admin doğrulama alanını canlıda gördü ve sorunsuz çalıştığını
  teyit etti. Bu nedenle geçici test kartı kaldırıldı. PWA/root `/admin` guard mantığı
  korunacak; yalnız doğrulama kartı ve `adminRouteProbe` state kodu artık bulunmayacak.
- Doğrulama: `npm.cmd run check` başarılı, 84/84 test geçti. `git diff --check`
  yalnız mevcut CRLF uyarılarını verdi. Production deploy
  `dpl_3B2som8JBoAVZKhqHhtBoubcJ7R4`, canlı alias `https://arsiv.ibrahimlive.ai`.
  Canlı smoke: `/health` `ok`, `/admin` HTTP 200 ve noindex/no-store, root `/` HTTP 200,
  manifest `id=/admin`, `start_url=/admin`, canlı HTML'de `adminRouteProbe` ve
  `updateAdminRouteProbeState` yok; `ensureStandaloneAdminRoute` mevcut.

## 2026-08-03 Codex Güncel Durum

- Repo/GitHub hijyen çalışması başlatıldı. Amaç dirty workspace'i temiz commitlere ayırıp
  GitHub'ı kaynak gerçekliği yapmak ve yeni cihaz geçişini temiz `git clone` üzerinden
  yürütmektir. Snapshot `tmp/repo-cleanup-snapshot-*` altında alındı; `tmp/` ve
  `demo-public-preview/` Git dışı geçici çıktı olarak ignore edildi.
- Public arşiv demo dosyaları production admin akışından ayrıldı: `server.js` artık
  `public-archive-demo` modülünü yalnız `PUBLIC_ARCHIVE_DEMO=1` açıkken lazy-load eder.
  Böylece temiz klonda demo dosyası veya seed datası kaynak olarak eksikse bile normal
  admin production startup'ı etkilenmez. `scripts/check-frontend.js` bu lazy-load guard'ını
  regresyon olarak kontrol eder.
- Root `/` için public arşiv cutover yapılmadı. Admin geliştirmeleri `/admin` hedefiyle
  yürür; root kısa süre daha legacy admin olarak korunur.
- PWA ana ekran uygulaması için ikinci koruma eklendi. Manifest `start_url=/admin` tek başına
  bazı iOS ana ekran senaryolarında yeterli olmadığı için, standalone/PWA modunda oturum açmış
  admin veya süper admin root `/` adresinden açılırsa frontend `history.replaceState` ile
  rotayı `/admin`e taşır. Manifest `id` değeri `/admin` yapıldı. Normal tarayıcı root davranışı
  ve ilerideki public root cutover korunur. Doğrulama: `npm.cmd run check` başarılı; 84/84 test
  geçti. Production deploy `dpl_FGrVj7yYGew5dJgiyyaT2WEjiXhV`; canlı alias
  `https://arsiv.ibrahimlive.ai`. Canlı smoke: `/health` `ok`, `/admin` HTTP 200 ve noindex/
  no-store, root `/` HTTP 200, manifest `id=/admin`, `start_url=/admin`, canlı HTML'de
  `ensureStandaloneAdminRoute` ve `adminRouteProbe` mevcut.
- Kullanıcının yeni kapanış yöntemi kabul edildi: feedbackte bildirilen bir kelime/düzeltme
  önce o feedback'in bağlı olduğu denetim metninde ele alınır; bağlamsal/anlık bir model hatası
  kör biçimde tüm geçmişe uygulanmaz. Süper admin gerekli görürse `Tüm geçmiş` kapsamını ayrıca
  seçebilir.
- Kod değişiklikleri: `analysis-core.js`, `server.js`, `index.html`,
  `scripts/check-frontend.js`, `test/analysis-core.test.js`. Yeni korumalar:
  `ahlaki -> ahlakı`, `Allah (cc.) -> Allah (A.S)`, `hayydırlar -> diridirler`,
  `Sebîlel -> Sebîli`, `Tabi ki -> Tabiatıyla`, `Cinn -> CİN`, `ardarda -> ard arda`,
  `aciz -> âciz`, `dini -> dinî`, `sure de -> surede`, çift virgül, kaynakta olmayan
  `Kur'ân'da` ekleme, `Allah’a ulaşmayı dilemek ve zikir yok. -> yoksa.`, dörtlük satır
  başı büyük harfleri.
- Geçmiş Düzeltme Kontrolü formuna kapsam seçimi eklendi: `Bildirilen metin` varsayılan,
  `Tüm geçmiş` manuel seçimdir. Paketler `historyScope` ve `reportedHistoryIds` taşır;
  reported kapsamda teknik uzun metin parça kayıtları da sadece bağlı feedback için taranabilir.
- Uygulama sonrası kapanış eklendi: süper admin bir düzeltme kaydını `Onayla ve Uygula` ile
  uygularsa pakete bağlı feedbackler `content-correction-{packageId}` çözüm grubuyla
  `resolved` yapılır ve `resolution_note` doldurulur.
- Canlı açık feedback sayısı işlem öncesi/sonrası `34`. Bu sayı bilinçli olarak değişmedi;
  çünkü metin düzeltmeleri henüz uygulanmadı. Canlı `settings.content_correction_packages`
  içine 17 yeni `reported` kapsamlı, `ready` durumunda düzeltme kaydı yazıldı. Son doğrulama:
  toplam paket `38`, `ready=37`, `applied=1`, `reported=17`.
- Kuru taramada 3 konuya içerik düzeltme paketi açılmadı: bozuk alıntı ve `Tabiatıyla` vakasında
  bağlı corrected_text içinde aranacak yanlış ifade kalmamıştı; `Âl-i İmrân -> Âli İmrân`
  paketi de mevcut bağlı metinde eşleşmedi. `Al-i İmran -> Âli İmrân` feedback'i sure standardına
  göre kullanıcı kararı gerektirir; kör ters düzeltme yapılmadı.
- Doğrulama: `npm.cmd run check` başarılı; 84/84 test geçti. `git diff --check` yalnız mevcut
  CRLF uyarılarını verdi.
- Production deploy alındı: `https://arsiv-kontrol-3uh7o5s4j-ugurkarabulutts-projects.vercel.app`,
  alias `https://arsiv.ibrahimlive.ai`. Canlı doğrulama: `/health` `ok`, ana sayfa HTTP 200,
  cache `no-store, no-cache, must-revalidate, proxy-revalidate`, HTML'de
  `correctionHistoryScopeFromForm` ve `Bildirilen metin` mevcut.
- Sıradaki doğru işlem: süper admin `Geçmiş Düzeltme Kontrolü` ekranında `ready` kayıtları
  örnekleriyle kontrol edip uygun olanları `Onayla ve Uygula` ile uygular. Uygulanan paketlere
  bağlı feedbackler otomatik kapanır; sonrasında kullanıcılara kişisel çözüm bildirimi
  hazırlanmalıdır.

## 2026-08-02 Codex Güncel Durum

- Birgül Nursoy ve Nilgün Kabadayı'nın bildirdiği `her denetimden sonra Ctrl+Shift+R yapmadan
  Onaya Gönder aktif olmuyor` akışı düzeltildi ve canlıya alındı. Kök sebep backend onay
  kuyruğu değil, frontend state temizliğiydi: boş/eksik `status` gönderilmiş kabul edilebiliyor,
  yeni denetim başlangıcında eski onay modalı/payload state'i temizlenmiyor ve gönderilmiş yerel
  taslak tekrar yüklenebiliyordu.
- Uygulanan çözüm: yalnız `bekliyor`, `onaylandi`, `reddedildi` statüleri gönderilmiş sayılır;
  yeni denetim başlarken eski onay state'i `resetCurrentAnalysisStateForNewRun` ile temizlenir;
  onay modalı `resetSubmitApprovalModalState` ile sıfırlanır; localStorage içindeki gönderilmiş
  sonuç çalışma taslağı gibi geri yüklenmez. `scripts/check-frontend.js` bu gerçek kullanıcı
  senaryosunu regresyon olarak kontrol ediyor.
- Doğrulama: `npm.cmd run check` başarılı; 83/83 test geçti. `git diff --check` yalnız mevcut
  CRLF uyarılarını verdi. Production deploy:
  `https://arsiv-kontrol-l58ww5ptk-ugurkarabulutts-projects.vercel.app`, alias
  `https://arsiv.ibrahimlive.ai`. Canlı doğrulama: `/health` `ok`, ana sayfa HTTP 200, cache
  `no-store, no-cache, must-revalidate, proxy-revalidate`; canlı HTML'de
  `SUBMITTED_APPROVAL_STATUSES`, `resetCurrentAnalysisStateForNewRun`,
  `resetSubmitApprovalModalState` ve gönderilmiş local draft guard mevcut.
- Süper admin `Geçmiş Düzeltme Kontrolü` ekranı sadeleştirildi ve canlıya alındı. Uzun alt alta
  liste yerine üstte sayaçlar, ana bölümde yalnız `Onay Bekleyen Düzeltmeler`, kapalı
  açılır-kapanır kayıt kartları ve ayrı `Uygulanan Düzeltmeler` / `Geri Alınan Düzeltmeler`
  arşivleri var. Uygulanan kayıtlar ana bekleyen listeden ayrışır; geri alınanlar da ayrı
  bölümde görünür. Geniş etki üreten kayıtlar dikkat etiketiyle işaretlenir.
- Bu UX değişikliğinde geçmiş `history` içeriklerine uygulama yapılmadı, `alerts` feedbackleri
  kapatılmadı ve kullanıcı bildirimi gönderilmedi. Doğrulama: `npm.cmd run check` başarılı;
  83/83 test geçti. `git diff --check` yalnız mevcut CRLF uyarılarını verdi. Canlı doğrulama:
  `https://arsiv.ibrahimlive.ai/health` `ok`, ana sayfa HTTP 200, cache `no-store, no-cache,
  must-revalidate, proxy-revalidate`; canlı HTML'de `Geçmiş Düzeltme Kontrolü`,
  `Onay Bekleyen Düzeltmeler`, `Uygulanan Düzeltmeler`, `Geri Alınan Düzeltmeler`,
  `correctionMetricsHtml` ve açılır kart CSS'i mevcut.
- Geçmiş düzeltmeler için süper admin son kontrol şartı canlıya alındı. Yeni akışta geçmiş
  metne uygulama yapılmadan önce etki taraması zorunlu; apply API'si `lastScan`, `status='ready'`,
  `confirmReview:true` ve `superAdminApproved:true` olmadan `history` güncellemez. Arayüzde
  uygulama aksiyonu `Onayla ve Uygula` olarak görünür. Doğrulama: `npm.cmd run check` başarılı;
  83/83 test geçti. Production deploy:
  `https://arsiv-kontrol-dmg6ic71w-ugurkarabulutts-projects.vercel.app`, alias
  `https://arsiv.ibrahimlive.ai`; canlı `/health` `ok`, ana sayfa HTTP 200, cache `no-store`.
- Canlı açık feedback sayısı yeniden okundu: `22`. Yeni gelen kayıt `aciz -> âciz` yanlış
  düzeltmesiydi. Açık feedbacklerden geçmişe taşınması gereken kararlar için
  `settings.content_correction_packages` içine `20` yeni düzeltme kaydı eklendi ve hepsi
  süper admin son kontrolü için `ready` durumunda bırakıldı. Daha önce uygulanmış
  `Tevbe 69 sure referansı düzeltmesi` kaydına ilgili `2` feedback id'si bağlandı. Canlı
  doğrulama: toplam paket `21`, `ready=20`, `applied=1`, açık feedback hâlâ `22`.
- Bu adımda geçmiş `history` içeriklerine uygulama yapılmadı, `alerts` feedbackleri
  kapatılmadı, kullanıcı bildirimi gönderilmedi. Sıradaki doğru adım: süper admin
  `Geçmiş Düzeltmeleri` ekranında her kaydın örneklerini kontrol edip uygun olanları
  `Onayla ve Uygula` ile uygulamalı; sonra etkilenen feedbackler kapatılıp kişisel
  çözüm bildirimleri hazırlanmalı.
- Canlı açık feedbackler tekrar kontrol edildi; toplam açık kayıt `21`. İlk 20 kayıt önceki
  kalite turunda ele alınan köklerle aynıydı, yeni gelen kayıt `Mumtehine -> Mumtehıne`
  sure adı bozulmasıydı.
- `analysis-core.js`, `server.js` ve `test/analysis-core.test.js` güncellendi. Kapatılan
  kalite kökleri: `faziletler -> fazlalar`, `fazılla -> fazl ile`, `yakîn -> yakın`,
  `sure de -> surede`, `dini -> dinî`, `Tabiatıyla -> Tabiî ki`, `lâzımgelen -> lâzım gelen`,
  kaynakta olmayan `Kur'ân'da` ekleme, mevcut noktalama üzerine ikinci noktalama ekleme,
  referans sonundaki iki noktayı silme, bozuk `." diyor."` tırnak yerleşimi, `Tevbe 69`
  referansının `Tövbe 69` yapılması, `Yunus 7, 8’de` gevşek sure referansı ve dörtlük satır
  başı büyük harfleri.
- `Mumtehine` doğru sure adı olarak korumaya alındı; bozuk `Mumtehıne` varyantı kaynakta
  görülürse `Mumtehine` yapılır, doğru `Mumtehine` ise noktasız-ı varyantına çevrilmez.
- Doğrulama: `npm.cmd run check` başarılı; 83/83 test geçti. `git diff --check` yalnız mevcut
  CRLF uyarılarını verdi. Production deploy:
  `https://arsiv-kontrol-a7ijgc047-ugurkarabulutts-projects.vercel.app`, alias
  `https://arsiv.ibrahimlive.ai`. Canlı doğrulama: `/health` `ok`, ana sayfa HTTP 200,
  cache `no-store, no-cache, must-revalidate, proxy-revalidate`, canlı HTML'de
  `/approval-status` ve `/withdraw` mevcut.
- Bu adımda canlı DB'de feedback kapatma veya kullanıcı bildirimi gönderme yapılmadı. Sonraki
  adım: kullanıcı onayıyla açık feedbackleri çözüm grubuyla kapatmak ve her kullanıcıya kendi
  bildirdiği konuları özetleyen kişisel çözüm bildirimi göndermek.
- 2026-08-02 itibarıyla yeni kalıcı kapanış kuralı: Bir feedback kelime, sure adı, imlâ
  standardı veya noktalama kararını değiştiriyorsa sadece kod/prompt düzeltmesi ve feedback
  kapatma yeterli değildir. Önce canlı geçmişte etki taraması yapılmalı; `taslak`, `bekliyor`,
  `onaylandı` ve ileride yayınlanmış içeriklerde aynı yanlış ifade varsa `Geçmiş Düzeltme
  Merkezi` üzerinden loglu/geri alınabilir biçimde düzeltilmelidir. Ancak bundan sonra
  feedback kapatılıp kullanıcıya çözüm bildirimi gönderilir.
- Bu nedenle mevcut 21 açık feedback için sıradaki doğru adım: çözüm köklerini geçmiş taramasına
  çevirmek, kaç kayıt etkilendiğini çıkarmak, kullanıcı onayıyla geçmiş uygulamasını yapmak,
  sonra feedbackleri kapatıp kişisel bildirimleri göndermek.

## 2026-08-01 Codex Güncel Durum

- Kullanıcı raporuyla gelen iki kritik akış düzeltildi ve canlıya alındı: `Onaya Gönder`
  sonrası kayıt gerçekten onay kuyruğuna girdi mi diye artık `/api/history/:id/approval-status`
  ile doğrulanıyor; doğrulama olmadan başarı ekranına geçilmiyor. Kullanıcı kendi `bekliyor`
  kayıtlarını admin işleminden önce `Onaydan Geri Çek` ile tekrar `taslak` durumuna alabiliyor.
  Backend route'ları: `/api/history/:id/approval-status`, `/api/history/:id/withdraw`.
  Frontend kontrolleri: `verifyApprovalStatus`, `withdrawApprovalFromHistory`,
  `withdrawCurrentSubmittedApproval`.
- `Âdem (A.S)'ın sureti` / `Adem(A.S)'ın sureti` dar bağlamı deterministik standartla
  `Âdem (A.S)'ın zürriyeti` yönünde düzeltiliyor. Genel `sureti` kelimesine dokunulmaz.
  `nefret -> nefs` dönüşümü hâlâ yasak/korumalıdır; `kin ve nefret` korunur.
- Doğrulama: `npm.cmd run check` başarılı; 81/81 test geçti. `git diff --check` yalnız mevcut
  CRLF uyarılarını verdi. Production deploy:
  `https://arsiv-kontrol-1xhjjg4ar-ugurkarabulutts-projects.vercel.app`, alias
  `https://arsiv.ibrahimlive.ai`. Canlı doğrulama: `/health` `ok`, ana sayfa HTTP 200,
  canlı HTML'de `/approval-status`, `/withdraw`, `verifyApprovalStatus` ve `Onaydan Geri Çek`
  mevcut. Vercel inspect: `dpl_93QTaN4Pv9AtFcWE19spudt2gHP2` Ready.
- Canlı kayıt kontrolünde `Tevbe 69 sure referansı düzeltmesi` gerçekten uygulanmış görünüyor:
  paket `applied`, 2 kayıt güncellenmiş, `content_correction_log` içinde 2 uygulama logu var.
  Ekranın işlem sonrası hâlâ `Taslak / Uygula` gibi kalması kafa karıştırdığı için UI düzeltildi:
  uygulandı durumunda kart yeşil başarı bandı gösterir, `Uygula` butonu `Uygulandı` olarak
  pasifleşir, `Geri Al` tek aktif ana aksiyon kalır. Stale sayfadan yeniden uygulama isteği
  gelirse API `alreadyApplied` ile ekranı güncel duruma çeker. API çağrılarına `cache:'no-store'`
  eklendi. Doğrulama: `npm.cmd run check` başarılı; 80/80 test geçti. Production deploy:
  `https://arsiv-kontrol-qlj2go3bq-ugurkarabulutts-projects.vercel.app`, alias
  `https://arsiv.ibrahimlive.ai`. Canlı doğrulama: `/health` `ok`, ana sayfa HTTP 200,
  `correctionStateNote`, `alreadyApplied`, `cache:'no-store'` ve `Düzeltme zaten uygulanmış`
  canlı HTML'de mevcut.
- Geçmiş düzeltme uygulama sırasında çıkan tarayıcıya ait beyaz onay penceresi kaldırıldı.
  Kritik onay/uyarı akışları artık uygulamanın açık/koyu tema yapısına uygun özel sistem içi
  modal ile gösterilir. Kapsanan akışlar: geçmiş düzeltme uygula, geri al, kullanıcı sil,
  kural sıfırla, yetki uyarıları ve çözüm notu yazma. `scripts/check-frontend.js` içine eski
  `confirm(`/`alert(`/`prompt(` kullanımını yakalayan kontrol eklendi.
- Doğrulama: `npm.cmd run check` başarılı; 80/80 test geçti. `git diff --check` yalnız mevcut
  CRLF uyarılarını verdi. Production deploy:
  `https://arsiv-kontrol-opyvthnvq-ugurkarabulutts-projects.vercel.app`, alias
  `https://arsiv.ibrahimlive.ai`. Canlı doğrulama: `/health` `ok`, ana sayfa HTTP 200,
  `systemConfirmModal`, `systemConfirmInputWrap` ve `openSystemConfirm` mevcut; native
  `confirm/alert/prompt` çağrısı yok.
- Geri bildirimlerden doğan kabul edilmiş standart/düzeltme kararlarını geçmiş denetim
  kayıtlarına kontrollü uygulamak için ilk altyapı kuruldu. Yeni admin alanı:
  `Geçmiş Düzeltmeleri` / `Geçmiş Düzeltme Merkezi`.
- Akış: yanlış ifade + doğru ifade + karar notu girilir, seçili feedback id'leri
  düzeltme kaydına bağlanabilir, önce etki taraması yapılır. Tarama `history.corrected_text`
  alanını varsayılan hedef alır; istenirse `summary` de seçilebilir. Teknik uzun metin
  parça kayıtları (`chunk_draft`, `submitted_part`) hariç tutulur.
- Geçmiş kayıtlara uygulama yalnız süper admin ile çalışır ve canlı DB'de
  `content_correction_log` tablosu bulunmazsa kapalı kalır. `schema.sql` içine bu tablo
  eklendi. Tablo uygulanmadan sistem sadece paket oluşturur ve etki taraması yapar.
- Uygulamada eski/yeni metin, alan adı, kayıt id'si ve hash bilgisi `content_correction_log`
  içine yazılır; paket uygulanmışsa `Geri Al` aksiyonu aynı kayıt defterinden eski değerlere
  döner.
- Yan sağlık düzeltmeleri: tekil çözüm bildirimi route'undaki eksik `internalResolutionNote`
  tanımı düzeltildi; tekil kullanıcı duyurusu route'unda hatalı kopuk satır kaldırıldı;
  onay/red sonrası düzeltilmiş metin duplicate kilidi doğru `setApproval` akışına taşındı.
- Doğrulama: `npm.cmd run check` başarılı; 80/80 test geçti. `git diff --check` yalnız
  mevcut CRLF uyarılarını verdi. Canlı deploy, canlı DB yazımı, paket uygulama, feedback
  kapatma veya kullanıcı bildirimi yapılmadı.
- Kullanıcı Supabase SQL Editor'da `content_correction_log` tablosu ve indexlerini uyguladı.
  Salt-okunur Supabase kontrolünde tablo `status=200`, `contentRange=*/0` döndü.
- Production deploy alındı:
  `https://arsiv-kontrol-2ymt7zpi6-ugurkarabulutts-projects.vercel.app`, alias
  `https://arsiv.ibrahimlive.ai`. Canlı doğrulama: `/health` `ok`, ana sayfa HTTP 200,
  cache `no-store, no-cache, must-revalidate, proxy-revalidate`, canlı HTML'de
  `tabContent-corrections` ve `loadCorrectionPackages` mevcut. `/api/correction-packages`
  yetkisiz erişimde 401 döndü; route yayında ve korumalı.
- Mobil ekranda eski `Düzeltme Paketleri` adı adminin anlayacağı şekilde
  `Geçmiş Düzeltme Merkezi` olarak değiştirildi. Form başlığı `Yeni düzeltme kaydı` oldu;
  checkboxlar metin alanı stilinden ayrıldı ve mobilde taşmayacak özel ayar satırlarına
  çevrildi.
- Bu mobil UX düzeltmesi production'a deploy edildi:
  `https://arsiv-kontrol-m2fznzdjd-ugurkarabulutts-projects.vercel.app`, alias
  `https://arsiv.ibrahimlive.ai`. Canlı doğrulama: `/health` `ok`, ana sayfa HTTP 200,
  `Geçmiş Düzeltme Merkezi` ve `Geçmiş Düzeltmeleri` mevcut, eski `Düzeltme Paketleri`
  adı yok, yeni checkbox CSS'i canlıda var. `npm.cmd run check` başarılı; 80/80 test geçti.
- Bu adımda düzeltme kaydı uygulanmadı, feedback kapatılmadı ve kullanıcı bildirimi
  gönderilmedi. Sonraki güvenli adım: açık feedbackler paket sistemiyle taranıp, etki
  önizlemesi kullanıcıya gösterildikten sonra uygulanmalı.

## 2026-07-31 Codex Güncel Durum

- Canlıdan daha önce çekilen 29 açık feedback kökü için yerel kod + prompt çözüm turu yapıldı.
  Çözülen ana sınıflar: `Yunus` kişi adı ile `Yûnus` sure adı ayrımı, âyet/transliterasyon
  satırlarında çıplak `İsa`, `mustekîm` ve `dîn/dînekum` koruması, `Resûlullah'ın (S.A.V)`
  yanlış yerleşimi, `Sebîlel gayy/rüşd -> Sebîli gayy/rüşd`, `şer/şerr/şeriat` kelime sınırı,
  `AFETİ` şapkasız koruması, `vücud/vücut` bağımsız kelime ayrımı, `Nefret -> nefs` reddi,
  gereksiz virgül/iki nokta ve `var ya` silme korumaları.
- Kabul edilen bulguların metne uygulanması artık ham substring replace kullanmıyor; kelime
  sınırı ve esnek apostrof/boşluk eşleşmesiyle yapılıyor. Bu değişiklik `şer` gibi kısa köklerin
  `ŞERİAT` içine girmesini ve `vücud` kökünün ekli kelimeleri bozmasını engeller.
- `tevbe` normal metinde bütün tekrarlarıyla `tövbe` yapılır; `TEVBE` sure adı/referansı korunur.
  `Yunus Emre`, `Yunus diyor`, `Yunus ne diyor` korunur; `10/Yunus-7` gibi referanslar
  `10/Yûnus-7` olur.
- `server.js` sistem prompt'una aynı kararlar eklendi; model baştan daha muhafazakâr davranmalı.
  `test/analysis-core.test.js` içine 29 Temmuz feedback kök regresyonu eklendi.
- Doğrulama: `npm.cmd run check` başarılı; 80/80 test geçti. Bu adımda canlı deploy, DB yazımı,
  feedback kapatma veya kullanıcı bildirimi yapılmadı.
- Sonrasında yerel çözüm production'a deploy edildi:
  `https://arsiv-kontrol-hqqgl4qo4-ugurkarabulutts-projects.vercel.app`, alias
  `https://arsiv.ibrahimlive.ai`. Canlı doğrulama: `/health` `ok`, ana sayfa HTTP 200,
  cache başlığı `no-store, no-cache, must-revalidate, proxy-revalidate`.
- Canlıdaki 29 açık feedback `feedback-fix-2026-07-31-root-quality-1785452209555` çözüm
  grubuyla kapatıldı. Tuba Aydın, Birgül Nursoy, Elçin Akay, Nuray Ardagümüşoğlu ve Nazlı
  Özkaplan'a kendi bildirdikleri başlıklara göre 5 kişisel `feedback_resolution` bildirimi
  gönderildi. Bildirim başlıkları UTF-8 olarak doğrulandı; son canlı kontrolde açık feedback `0`.
- Uzun metin denetimi ve onaya gönderme ekranındaki kullanıcı metinleri sadeleştirildi.
  Kullanıcıya artık `parça`, `tek kayıt`, `birleşik sonuç` veya yoğun `yönetici` dili
  gösterilmez. Teknik parçalı işleme arka planda korunur; görünen dil `Metin güvenli şekilde
  denetleniyor`, `Sonuç hazırlandı`, `Onaya Gönder dediğinizde sonuç onay kuyruğuna iletilir`
  ve `Sonuç onay sürecine iletildi` çizgisine çekildi. `npm.cmd run check` başarılı; 80/80
  test geçti. Production deploy:
  `https://arsiv-kontrol-dq2j1stxh-ugurkarabulutts-projects.vercel.app`, alias
  `https://arsiv.ibrahimlive.ai`. Canlı doğrulama: `/health` `ok`, ana sayfa HTTP 200,
  canlı HTML'de yeni kopyalar mevcut; eski `parça tek kayıt`, `parça halinde tamamlandı`,
  `Birleşik Sonuç` ve `yöneticilerin onay kuyruğu` kopyaları yok.

## 2026-07-30 Codex Güncel Durum

- Elçin Akay ve Nuray Ardagümüşoğlu'nun uzun metin onaya gönderim denemeleri canlı kayıtlardan
  incelendi. Telegram'da görülen `Gönderiliyor...` takılmasının en az bazı denemelerde DB'ye
  hiç düşmediği doğrulandı. Kök risk, onaya gönderirken aynı düzeltilmiş metni engelleyen eski
  kontrolün kullanıcının tüm eski `corrected_text` kayıtlarını taramasıydı; uzun metin ve yoğun
  kayıtlı kullanıcılarda bu istek uzayabiliyordu.
- Çözüm: düzeltilmiş metin duplicate kontrolü `settings` tablosunda
  `submitted_corrected_hash:{userId}:{hash}` hızlı kilidine taşındı. Eşzamanlı çift gönderim
  engellenir; 20 dakikadan eski yarım kalmış `pending` kilitler temizlenir; onaylanınca kilit
  kalır, reddedilince kilit kaldırılır. Birleşik uzun metin gönderiminde parça gizleme hatası
  ana onay kaydını başarısız göstermeyecek şekilde kritik yoldan çıkarıldı.
- Frontend onay modalı gönderim sırasında kapanmaz, kullanıcıya `Gönderim kontrol ediliyor`
  bekleme mesajı verir ve ağ/HTML hata yanıtlarını kontrollü Türkçe mesaja çevirir. Vercel
  route header'ları `no-store` yapıldı; eski JS/HTML için Ctrl+Shift+R ihtiyacı azaltıldı.
- Doğrulama: `npm.cmd run check` başarılı; 79/79 test geçti. `git diff --check` yalnız mevcut
  CRLF uyarılarını verdi. Production deploy:
  `https://arsiv-kontrol-puoqfpte2-ugurkarabulutts-projects.vercel.app`, alias
  `https://arsiv.ibrahimlive.ai`. Canlı doğrulama: `/health` `ok`, ana sayfa HTTP 200,
  canlı HTML'de `submitApprovalInFlight` ve `Gönderim kontrol ediliyor` mevcut; ana sayfa ve
  `sw.js` cache başlığı `no-store, no-cache, must-revalidate, proxy-revalidate`.
- Denetim Geçmişi'nde 200 kayıt sınırı kaldırıldı. Kök sebep `/api/history` endpoint'inin
  `.limit(200)` kullanmasıydı; toplamı 400+ olan kullanıcılar yalnız ilk 200 kaydı görüyordu.
  Endpoint artık `fetchAllPages` ile tüm ilgili kayıtları sayfalı çekiyor. UI alt başlığı
  `Tüm denetimleriniz` oldu. `scripts/check-frontend.js` aynı limit geri gelirse test fail
  edecek. Doğrulama: `npm.cmd run check` başarılı; 79/79 test geçti. Production deploy:
  `https://arsiv-kontrol-hd6t9ay6c-ugurkarabulutts-projects.vercel.app`, alias
  `https://arsiv.ibrahimlive.ai`. Canlı doğrulama: `/health` `ok`, ana sayfa HTTP 200,
  canlı HTML'de `Tüm denetimleriniz` ve `/api/history` mevcut.
- Uzun metinlerde parça kayıtlarının kullanıcı geçmişinde ayrı ayrı onaya gönderilebilir
  görünmesi kapatıldı. `/api/analyze` uzun metin parçalarını artık `chunk_draft` teknik
  statüsüyle saklar; `/api/history`, admin onay listeleri, istatistik/rapor akışları
  `chunk_draft` ve `submitted_part` kayıtlarını gizler.
- Uzun metin denetimi bittiğinde frontend `/api/history/merged-draft` ile tek birleşik
  `taslak` kaydı oluşturur. Parça kayıtları `submitted_part` yapılır. Kullanıcı geçmişinde
  ve sonuç ekranında yalnız birleşik taslak onaya gönderilebilir. Parçalar tek başına
  `/api/history/:id/submit` ile gönderilmeye çalışılırsa backend bunu açık hata mesajıyla
  reddeder.
- `Onaya Gönder` başarıyla tamamlanınca modal kapanır, işlem butonu yeniden aktif kalmaz,
  giriş alanı temizlenir ve sonuç alanında `Onay kuyruğuna alındı` başarı kartı gösterilir.
  Kartta `Yeni Denetime Başla`, `Düzeltilmiş Metni Kopyala` ve `Geçmişte Gör` aksiyonları
  vardır. Sayfayı kapatmanın onay işlemini iptal etmeyeceği metinle belirtilir.
- Geri bildirim modalı ile onaya gönder modalının iç içe görünmesine neden olan HTML kapanış
  hatası düzeltildi. Eski ikinci `/api/history/submit-merged` route'u kaldırıldı; birleşik
  onay artık tek doğrulamalı backend rotasından geçer.
- Doğrulama: `npm.cmd run check` başarılı; 79/79 test geçti. `git diff --check` yalnız
  Windows CRLF uyarıları verdi, whitespace hatası yok. Production deploy:
  `https://arsiv-kontrol-mqnb8trkq-ugurkarabulutts-projects.vercel.app`, alias
  `https://arsiv.ibrahimlive.ai`. Canlı doğrulama: `/health` `ok`, ana sayfa HTTP 200,
  canlı HTML'de `Onay kuyruğuna alındı`, `chunk_draft`, `/api/history/merged-draft` var ve
  `submit-merged` tek kez görünüyor. Push yapılmadı.
- Canlı 2000+ bekleyen onay kuyruğu analiz edilip kullanıcı onayıyla güvenli temizlendi.
  Silme yapılmadı; 12 test kaydı, 180 düzeltilmiş metni olmayan kayıt ve 72 aynı kullanıcıya
  ait mükerrer düzeltilmiş metin kaydı `reddedildi` statüsüne alındı. `approved_by` alanları
  ASCII sebep notlarıyla işaretlendi. İşlem sırasında bir yeni kayıt geldiği için kuyruk
  2398'den 2134'e indi. Son kontrolde bekleyen kuyrukta kalan test, boş düzeltilmiş metin
  veya aynı kullanıcı mükerreri `0`.

## 2026-07-29 Codex Güncel Durum

- Onaya gönderimde ikinci güvenlik katmanı eklendi. Önceki `Onaya Gönder` akışı aynı kaynak
  metnin ikinci kez onaya düşmesini `text_hash` ile engelliyordu; ancak kaynak metin küçük
  değişmiş olsa bile aynı düzeltilmiş metin üretilebilirdi. Artık tekil ve uzun/birleşik
  onaya gönderme endpointleri, aynı kullanıcı için `bekliyor`, `onaylandi` veya eski boş
  statüde aynı normalize edilmiş `corrected_text` varsa ikinci gönderimi reddeder. `reddedildi`
  kayıtlar yeniden çalışma ihtimaline karşı engel sayılmaz. `scripts/check-frontend.js` bu
  kuralı regresyon kontrolüne aldı. Doğrulama: `npm.cmd run check` başarılı; 79/79 test geçti.
  Production deploy: `https://arsiv-kontrol-6neioe0k0-ugurkarabulutts-projects.vercel.app`,
  alias `https://arsiv.ibrahimlive.ai`. Canlı `/health` `ok`, ana sayfa HTTP 200. Eski 2000+
  bekleyen kayıt üzerinde temizlik/silme yapılmadı; bu ayrıca raporlu ve onaylı yapılmalı.
- İş Panosu onay/red etkileşimi düzeltildi. Önceki akışta `Onayla` veya `Reddet`
  tıklandıktan sonra API kaydı güncelleyebiliyor, ancak İş Panosu kendi listesini yeniden
  yüklemediği için kart bekleyen kolonda kalmış gibi görünüyordu. `approveItem/rejectItem`
  ortak `setApprovalAction` akışına alındı; buton işlem sırasında kilitlenir, hata varsa
  görünür mesaj verir, başarıda `loadOnay()`, `loadHistory()` ve badge yenilemesi çalışır.
  `scripts/check-frontend.js` bu yenileme davranışını regresyon kontrolüne aldı.
  Doğrulama: `npm.cmd run check` başarılı; 79/79 test geçti. Production deploy:
  `https://arsiv-kontrol-h0sjen9om-ugurkarabulutts-projects.vercel.app`, alias
  `https://arsiv.ibrahimlive.ai`. Canlı `/health` `ok`, ana sayfa HTTP 200; canlı HTML'de
  `setApprovalAction`, `await loadOnay();` ve `İşleniyor...` akışı mevcut. Push yapılmadı.
- Düzeltilmiş metin sonuç UX'i sadeleştirildi. Başlık satırındaki ikinci `Onaya Gönder`
  kaldırıldı; sonuç PDF indirme butonu kaldırıldı. Kopyalama artık düzeltilmiş metin
  kutusunun sağ üst kenarındaki modern tek `Kopyala` butonuyla yapılır. `Onaya Gönder`
  yalnızca metnin altındaki taslak/onay panelinde kalır. `scripts/check-frontend.js` eski
  aksiyon satırı, ikinci onay ve sonuç PDF butonu geri gelirse hata verecek şekilde
  güncellendi. Doğrulama: `npm.cmd run check` başarılı; 79/79 test geçti. Production deploy:
  `https://arsiv-kontrol-bgweehvog-ugurkarabulutts-projects.vercel.app`, alias
  `https://arsiv.ibrahimlive.ai`. Canlı `/health` `ok`; canlı HTML'de `corrected-copy-btn`
  ve alt panel onayı var, `corrected-btns` ve `downloadPDF()` aksiyonu yok. Push yapılmadı.
- Konferans tam metinleri için 50.000-100.000 karakter uzun metin modu güçlendirildi.
  Parça boyutu 16.000'den 8.000 karaktere indirildi, en fazla iki parça eşzamanlı
  denetlenecek şekilde hızlandırıldı. Bir parça düşük skor nedeniyle düzeltilmiş metin
  üretmezse artık tüm birleşik çıktı boşaltılmıyor; o parça kaynak haliyle korunup diğer
  düzeltilmiş parçalarla tek tam metin olarak gösteriliyor. `scripts/check-frontend.js`
  bu davranış için kontrol içeriyor. Doğrulama: `npm.cmd run check` başarılı; 79/79 test
  geçti. Deploy/push yapılmadı.
- Onaya gönderme akışı ayrıldı. Yeni denetimler önce `taslak` olarak kullanıcının kendi
  geçmişinde kalır; admin onay kuyruğu, istatistikler ve CSV taslakları görmez. Kullanıcı
  sonuç ekranındaki veya kendi geçmişindeki `Onaya Gönder` butonuna bastığında son teyit
  penceresi açılır; onaydan sonra kayıt `bekliyor` olur. Uzun metinlerde parça taslakları
  admin tarafında görünmez; onaydan sonra tek birleşik kayıt oluşturulur ve parça kayıtları
  `submitted_part` olarak gizlenir. Vercel production deploy tamamlandı:
  `https://arsiv-kontrol-ncrgetvkj-ugurkarabulutts-projects.vercel.app`, alias
  `https://arsiv.ibrahimlive.ai`. Canlı doğrulama: `/health` `ok`, ana sayfa HTTP 200,
  canlı HTML içinde `Onaya Gönder` ve `Taslak olarak kaydedildi` akışı mevcut. Push yapılmadı.
- Mobil görünürlük düzeltmesi: `Onaya Gönder` butonu sadece düzeltilmiş metin üst aksiyon
  satırında değil, taslak/onay panelinin içinde de gösteriliyor. Mobilde aksiyon satırı iki
  kolonlu düzene geçti; `Onaya Gönder` tam genişlikte görünür. Doğrulama: `npm.cmd run check`
  başarılı; 79/79 test geçti. Production deploy:
  `https://arsiv-kontrol-38klecuop-ugurkarabulutts-projects.vercel.app`, alias
  `https://arsiv.ibrahimlive.ai`. Canlı `/health` `ok`, ana sayfa HTTP 200; canlı HTML’de panel
  butonu ve mobil grid düzeni mevcut. Push yapılmadı.

## 2026-07-28 Codex Güncel Durum

- Uzun metinlerde görülen `Denetim tamamlanmadı` hatası için dayanıklı analiz akışı eklendi.
  16.000 karakter üstü metinler frontend'de güvenli parçalara ayrılır, parçalar ayrı
  `/api/analyze` istekleriyle denetlenir ve sonuç tek raporda birleştirilir. `.docx`
  yüklemeleri için `/api/extract-file-text` endpoint'i eklendi; uzun dosyalar da parçalı
  akıştan geçer. Parçalı sonuç geri bildirimleri doğru parça geçmiş kaydına bağlanır.
  Doğrulama: `npm.cmd run check` başarılı; 79/79 test geçti. Deploy/push yapılmadı.
- Onay sayaçları düzeltildi. Canlı salt-okunur sayımda gerçek durum `history_total=2076`,
  `bekliyor=2073`, `onaylandi=2`, `reddedildi=1` iken uygulama benzeri sınırsız olmayan
  sorguda yalnız 1000 satır dönüyor ve bunun içinde `bekliyor=997` göründüğü doğrulandı.
  Kök sebep Supabase varsayılan 1000 satır dönüşünün `/api/stats` hesaplarını eksik
  beslemesi ve İş Panosu'nun `/api/history` son 200 kayıtla kolon saymasıydı.
- `/api/stats` artık `history` ve `alerts` kayıtlarını sayfalı çeker. İş Panosu için
  `/api/history/approval-board` endpoint'i eklendi; bekleyen/onaylanan/reddedilen kolonları
  gerçek `exact count` ile sayılır, performans için yalnız son 80 kart gösterilir.
- Canlı kuyrukta Birgül Nursoy'a ait 3 açık feedback görüldü. Kökler: `MULK-8`
  bağlamında `herbir -> her bir` yanlış ayrımı ve `6 tane, 7 tane âyet-i kerime var.`
  cümlesinin `6 tane âyet-i kerime` diye ikinci sayıyı düşürerek/genişleterek bozulması.
- Kod ve prompt katmanına kalıcı koruma eklendi. `herbir` kayıtlı standartlara alındı;
  `herbir -> her bir` yasak dönüşüm oldu. `MULK-8` bağlamında kaynak `her bir grup`
  içerirse deterministic olarak `herbir grup` yapılır.
- `6 tane, 7 tane` gibi sayı alternatifi içeren ifadeler artık kaynakta olduğu gibi
  korunur; modelin bu yapıyı sadeleştiren veya açıklama ekleyerek değiştiren bulguları
  skor dışı kalır ve düzeltilmiş metne uygulanmaz.
- Doğrulama: `npm.cmd run check` başarılı; 79/79 test geçti. Production deploy alındı;
  canlı `https://arsiv.ibrahimlive.ai/health` `ok`, ana sayfa HTTP 200.
- Canlı kapanış: 3 açık feedback `feedback-fix-2026-07-28-herbir-count-alternatives`
  çözüm grubuyla kapatıldı. Birgül Nursoy'a üç geri bildirimi için tek kişisel çözüm
  bildirimi gönderildi. Son canlı kontrolde açık feedback `0`.

## 2026-07-27 Codex Güncel Durum

- Canlı geri bildirim kuyruğunda görülen 14 açık kayıt kod ve prompt katmanında kök
  seviyede çözüldü. Kökler: `İhyâ’u Ulûmi’d-dîn / Ulumi’d-dîn` kaynak başlığı koruması,
  `derecat` ve `afet` ailelerinde gereksiz şapka engeli, `hadîsi` gibi ekli `hadîs`
  kullanımlarının kırpılmaması, `Suresinin/Suresini` apostrof koruması, doğru `Âli İmrân`
  biçimi, `Câsiye`, `Yûnus`, `Hûd`, `Fâtır`, `Hacc`, `A'râf`, `MUSÎBET`, `VELÎ`, `zahid`,
  `Şerr` ve `(S.A.V)` standartları.
- `Hac` için güvenlik ayrımı netleştirildi: tek başına `Hac -> Hacc/HACC` AI bulgusu kabul
  edilmez; sistem yalnız `22/Hac 37`, `4. Hac - 35`, `Hac Suresi` gibi gerçek sure/referans
  bağlamlarını düzeltir.
- Doğrulama: `npm.cmd run check` başarılı; 77/77 test geçti. `git diff --check` yalnızca
  Git'in Windows satır sonu uyarılarını verdi, boşluk hatası yok. Production deploy alındı;
  canlı `https://arsiv.ibrahimlive.ai/health` `ok`, ana sayfa HTTP 200.
- Canlı kapanış: 14 açık feedback `feedback-fix-2026-07-27-sure-sozluk` çözüm grubuyla
  kapatıldı. Mihrimah Bilgili'ye 13, Birgül Nursoy'a 1 geri bildirimi için kişisel çözüm
  bildirimi gönderildi. Son canlı kontrolde açık feedback `0`.
- Mesaj formatı: kişisel çözüm bildirimleri bundan sonra `Sevgili [kullanıcı adı],`
  satırıyla başlar; kullanıcıya görünen gövdede `Mesaj:` etiketi kullanılmaz.

## 2026-07-25 Codex Güncel Durum

- 14 açık feedback kökü kod ve prompt katmanına işlendi. Yanlış-pozitif korumalar:
  `ilim -> Kur'ân ilmi`, `Mehdi -> Mehdî`, `beka -> bekâ`, `münezzehtir -> Sûbhân'dır`,
  `lânetle lânetle -> lânetle`, `Allah ile bile olursanız -> Allah ile olursanız` ve
  `gayret üstüne gayret -> gayret üstüne gayret,` gibi gereksiz virgül eklemeleri ile
  kaynak cümleye açıklama ekleyen dönüşümler skor dışı kalır ve düzeltilmiş metne uygulanmaz.
- Eksik standartlar deterministic katmana alındı: `nefisleriyle -> nefsleriyle`,
  `fedakarlık -> fedakârlık`, `Kur'an/Kur’an -> Kur'ân`, `ŞURA -> ŞÛRÂ`,
  `Şura suresinin -> Şûrâ Suresi'nin`, `Her Resûl -> Her resûl`, eksik kaynak
  parantezleri, `2.Gay yolu -> 2. Gayy yolu`, `gayy yolu/GAYY YOLU`, `âyetTE -> ÂYETTE`
  ve `HADİS-İ ŞERİF -> HADÎS-İ ŞERİF`.
- `CANONICAL_WORD_STANDARDS` içine `beka`, `Mehdi`, `fedakârlık`, `Kur'ân` ve `gayy yolu`
  standartları eklendi. `npm.cmd run check` başarılı; 73/73 test geçti.
- Canlı kullanımda görülen `The server had an error processing your request` benzeri ham
  OpenAI hata mesajlarının kullanıcı ekranına yansıması kök seviyede giderildi. Sorun,
  `server.js` içindeki OpenAI hatasının doğrudan `throw new Error(...)` edilmesi ve
  `index.html` tarafında aynen basılmasıydı.
- `server.js` içine ortak `fetchOpenAIChatCompletion` katmanı eklendi. Metin denetimi,
  Denetim Yardımcısı, admin AI insight ve operasyon raporu çağrıları artık bu katmanı kullanır.
  408/429/5xx/timeout gibi geçici hatalarda kısa aralıklarla yeniden deneme yapılır; başarısız
  kalırsa kullanıcıya sade Türkçe mesaj döner.
- `index.html` içine `friendlyAnalyzeError` eklendi. Denetim başarısız olduğunda kullanıcıya
  teknik İngilizce servis mesajı gösterilmez; metnin ekranda korunduğu ve tekrar denenebileceği
  net yazılır. Toplu dosya denetimi de aynı hata dilini kullanır.
- `scripts/check-frontend.js` bu davranışı regresyon kalkanına ekledi. `npm.cmd run check`
  başarılı; 70/70 test geçti.

## 2026-07-24 Codex Güncel Durum

- Masaüstü favicon eksikliği giderildi. Önceki durumda PWA/Apple ikonları vardı ancak
  `favicon.ico` yoktu; canlı `/favicon.ico` ana sayfa HTML'i döndürüyordu. Mevcut uygulama
  ikonundan `icons/favicon.ico`, `icons/favicon-32.png` ve `icons/favicon-16.png` üretildi.
- `index.html` içine favicon linkleri eklendi; Express ve Vercel routing `/favicon.ico`
  isteğini gerçek ikon dosyasına döndürecek şekilde güncellendi.
- `scripts/check-frontend.js` artık favicon PNG ölçülerini, ICO başlığını ve HTML linklerini
  doğrular. `npm.cmd run check` başarılı; 70/70 test geçti.
- Commit `66f1cdf fix: add desktop favicon` production'a deploy edildi
  (`https://arsiv-kontrol-jy6wdrgok-ugurkarabulutts-projects.vercel.app`), özel alan adı
  `https://arsiv.ibrahimlive.ai` aliaslandı. Canlı doğrulama: `/favicon.ico`
  `image/vnd.microsoft.icon`, 3481 byte, ICO başlığı `00-00-01-00-02-00`; PNG favicon
  `image/png`; `/health` `ok`.

## 2026-07-23 Codex Güncel Durum

- Açık feedback kalite turu: Canlıda 15 açık feedback doğrulandı (Serap Pamuk 6, Hacer
  Terzi 6, Nuray Ardagümüşoğlu 2, Aysun Aydöner 1). Yanlış-pozitif kökler kod ve prompt
  katmanında korumaya alındı: `takva -> takvâ`, âyet/transliterasyon içindeki
  `dînâ/dînen -> dinâ/dinen`, `taktirde -> o taktirde`, `afet -> ni'met`,
  `ifna olur -> fena bulur`, `mürşide/mürşide tâbiiyet -> mürşidin/mürşidin tâbiiyet`.
  Doğru standart ayrımı olarak `s 120 -> s.120` deterministik yapıldı; `Hac` metin akışında
  `Hacc`, başlık/listede `HAC` ise `HACC` olacak şekilde case korunuyor.
- Doğrulama ve kapanış: `npm.cmd run check` başarılı; 70/70 test geçti. Commit `46fd64d`
  production'a deploy edildi (`https://arsiv-kontrol-qcgtmp4gm-ugurkarabulutts-projects.vercel.app`),
  `https://arsiv.ibrahimlive.ai/health` canlıda `ok`. 15 açık feedback
  `feedback-fix-2026-07-23-latest-standards-1784822374472` çözüm grubuyla kapatıldı;
  Hacer Terzi, Serap Pamuk, Nuray Ardagümüşoğlu ve Aysun Aydöner'e toplam 4 kişisel
  çözüm bildirimi gönderildi. Son canlı kontrolde açık feedback `0`.
- Son production commit: `46fd64d fix: harden latest feedback standards`.
- Son aktiflik kalıcı düzeltildi: `recordUserActivity` artık tek ortak
  `settings.user_last_seen` JSON satırına bağlı kalmıyor; her kullanıcı için ayrı
  `settings.user_last_seen:{userId}` kaydı yazıyor. Bu, eşzamanlı kullanıcı isteklerinde
  son aktif verisinin birbirini ezmesi riskini azaltır.
- `/api/users` son aktif zamanını en güncel güvenilir kaynaktan hesaplar: `users.last_seen_at`
  varsa onu, tekil settings yedeğini, eski toplu settings yedeğini ve son denetim geçmişini
  birlikte değerlendirir. Hiç aktivite sinyali olmayan kullanıcılar bilinçli olarak `—`
  görünür.
- Canlı veri migrasyonu: eski `settings.user_last_seen` içindeki 26 kayıt tekil
  `user_last_seen:{userId}` kayıtlarına taşındı. Canlı kontrolde 38 kullanıcıdan 16'sında
  gerçek son aktif sinyali var; kalanlarda güvenilir aktivite sinyali yok.
- Doğrulama: `npm.cmd run check` başarılı, 68/68 test geçti. Vercel production deployment
  `dpl_EgTozzSEGcZKEgqvD4qng4jmnUsk`; canlı `/health` `ok`.
- 2026-07-23 canlı DB güncellemesi: `users.last_seen_at` kolonu ve
  `users_last_seen_at_idx` indeksi Supabase SQL Editor'da uygulandı. Backfill sonucu
  `son_aktif_dolu=16`, `toplam_kullanici=38`. Temiz Vercel production deploy
  `dpl_Eub4NnvaNT92AVBNZhK5Hfhj9eXg`; canlı `/health` `ok`. Son doğrulamada kolon
  service role ile okunuyor ve 16/38 kullanıcıda dolu.

## 2026-07-19 Codex Güncel Durum

- Son production commit: `cc86b43 fix: apply repeated deterministic standards`.
- Kalıcı çözüm: Aynı metinde birden fazla geçen deterministic standart düzeltmeleri artık
  tekil kayda indirilmiyor. Bu özellikle Serap Pamuk geri bildirimiyle görülen `ŞURA-8`
  düzelirken aynı metindeki `ŞURA-28` geçişinin kalması sorununu çözdü. Bundan sonra tek
  AI bulgusu `ŞURA -> ŞÛRÂ` olsa bile kaynakta geçen tüm gerçek geçişler uygulanır; kaynakta
  olmayan fazla tekrarlar mevcut güvenlik sayacıyla yine reddedilir.
- Doğrulama: `npm.cmd run check` başarılı, 68/68 test geçti. Yeni regresyon testi tekrar
  eden sure adı referanslarının tamamının `ŞÛRÂ` standardına uygulandığını doğrular.
- Deploy: Vercel production deployment `dpl_BikBzJGB7btZA2Awj7ArTboRPD5i`; özel alan adı
  `https://arsiv.ibrahimlive.ai` aliaslandı. Canlı `/health` `ok`, ana sayfa HTTP 200.
- Canlı feedback kapanışı: Serap Pamuk kaydı
  `feedback-fix-2026-07-19-serap-shura-repeat-1784458769071` çözüm grubuyla kapatıldı ve
  kendisine kişisel çözüm bildirimi gönderildi. Son canlı kontrolde açık feedback sayısı `0`.

## 2026-07-18 Codex Güncel Durum

- Son production commitleri: `0542e3d fix: protect latest feedback standards` ve
  `6ac4dc8 fix: preserve numbered nimet list items`, ardından
  `16d19b4 fix: preserve Kuran-i Kerim phrase`.
- Canlı doğrulama: `npm.cmd run check` son çalışmada başarılı, 67/67 test geçti.
  `https://arsiv.ibrahimlive.ai/health` canlıda `ok`, ana sayfa HTTP 200.
- Kapatılan canlı feedback grupları:
  - `feedback-fix-2026-07-18-translit-hristiyan-salih-1784399770169`: Nuray
    Ardagümüşoğlu geri bildirimleri; mustekîm/mustekîme transliterasyon koruması,
    Hristiyan yazımı ve salih/salihler/salihlerle koruması.
  - `feedback-fix-2026-07-18-serap-nimet-bismillah-1784400162577`: Serap Pamuk
    geri bildirimleri; numaralı nimet listesinde yalnız `3 nimet -> 3. nimet`
    uygulanır, `ni'met` yapılmaz. Bismillâhirrahmânirrahîm bitişik arşiv standardı
    olarak korundu ve kullanıcıya açıklama gönderildi.
  - `feedback-fix-2026-07-18-hacer-kuran-kerim-1784400533116`: Hacer Terzi geri
    bildirimi; `Kur’ân-ı Kerîm` tamlaması `Kur'ân` diye kısaltılmaz, `-ı Kerîm`
    kısmı kaynakta varsa korunur.
- Son canlı kontrolde açık feedback sayısı `0`.

Son güncelleme: 2026-06-22 — Claude Code (Codex çalışması devralındı)

## Durum

- Dal: `codex/vercel-arsiv-production` (origin'e push edildi, upstream takipli).
- Uzak depo: `origin` → `https://github.com/ugurkarabulutt/arsiv-kontrol.git`
- **Commit:** `4f54438` — `feat: deploy archive control to Vercel` (16 dosya).
- **Push:** başarılı (`origin/codex/vercel-arsiv-production`).
- **PR:** [#1](https://github.com/ugurkarabulutt/arsiv-kontrol/pull/1) → `main`, **open** (otomatik merge edilmedi).
- `.env` ve `.vercel` commit'e dahil DEĞİL (ignore doğrulandı).
- Vercel projesi: `ugurkarabulutts-projects/arsiv-kontrol` oluşturuldu ve yerel klasöre bağlandı.
- Production deploy: `https://arsiv-kontrol.vercel.app` hazır.
- Özel alan adı: `https://arsiv.ibrahimlive.ai` production aliasına başarıyla bağlandı.
- Kullanıcı veya diğer ajan değişiklikleri izinsiz geri alınmamalı.
- 2026-06-30 Codex: Ekip tarafından canlı sitede test edilen 16 hata raporu
  (`C:\Users\ugur\Desktop\arsiv-test-sonucu-hatalar`) incelendi. Ana sorunlar:
  metinde olmayan kelimelerin issue olarak gösterilmesi, aynı görünen original/fixed
  çiftlerinin hata sayılması, kelime içi parça eşleşmeleri (`Muminun` içinden `Mumin`),
  apostrof/tırnak tipinin gereksiz hata yapılması, bağlam hataları (`Tabiî ki`, `derecat`,
  `dinlenmeye`, `Muhterem Efendimiz`) ve slayt/tablo düzeninin bozulması.

## Bu çalışma ağacındaki değişiklikler

- 2026-07-10 Codex 13 feedback karar turu: Kullanıcının verdiği 13 karar kod/prompt/test
  katmanına işlendi. `vücud/vücût` artık `vücut` standardına çevrilir; `Hazreti İsa`
  her zaman `Hazreti İsa (A.S)` olur; `HADİS-İ ŞERİF` doğru standardı `HADÎS-İ ŞERİF`
  olarak yazılır ve `Şerif` kelimesine şapka eklenmez. `dîn...` ekli halleri `din...`
  yönünde düzeltilir; `herşey` ekli halleri ayrılmaz; `tabiî`, `derecât`, `hayy/hayydırlar`,
  `hidayet` kelimesine kaynakta olmayan ek uydurma ve kaynakta olmayan `Evet/diyor` gibi
  içerik eklemeleri güvenlik filtresine alındı. Kritik standartlar modele bırakılmadı:
  `finalizeResult` model kaçırsa bile `dîn...`, `her şey...`, `vücud/vücût`, `inşallah`,
  `Hadis-i Şerif`, `Hazreti İsa` ve sure/âyet referans boşlukları için deterministic issue
  üretir. Aynı `original` bulguyu kaynakta geçtiği sayıdan fazla kabul etmez.
  `npm.cmd run check` başarılı; 45/45 test geçti.
- 2026-07-07 Codex sistem özellik dokümanı ve feedback kapatma: Kullanıcı onayıyla canlı
  DB'deki 29 açık feedback kaydı `approved-close-2026-07-07` çözüm grubuyla `resolved`
  kapatıldı; kullanıcılara yeni bildirim gönderilmedi. Sistem kapsamı, kullanıcı/admin
  özellikleri, feedback, bildirim, standart, rapor ve teknik mimari detayları
  `docs/SISTEM_OZELLIKLERI.md` dosyasında kalıcı kaynak olarak toplandı.
- 2026-07-07 Codex son aktiflik güvenilirliği: `recordUserActivity` artık yalnızca login/me
  çağrısında değil, yetkili API isteklerinde dakikada en fazla bir kez çalışır. Canlı DB'de
  `users.last_seen_at` kolonu varsa doğrudan oraya yazar; kolon yoksa mevcut
  `settings.user_last_seen` yedeğine düşer. `schema.sql` içine `users.last_seen_at`
  ALTER ve indeks satırları eklendi.
- 2026-07-07 Codex operasyon paneli toparlama turu: Rapor Geçmişi ekranı ay/tarih
  filtresi, özet sayaçları ve katlanabilir rapor kartlarıyla sadeleştirildi. Geri Bildirim
  Merkezi açık/okunmamış/çözülen/tümü filtreleri ve kullanıcı adı gösterimi aldı. Mesaj
  Kayıtları toplu/kişisel/çözüm/duyuru filtreleri ve özet sayaçlarıyla düzenlendi.
  Canlı Supabase kuyruğu kontrolünde 197 toplam feedback içinde 29 açık kayıt olduğu
  görüldü: Serap Pamuk 7, Bihter Oksak 6, Aysun Aydöner 6, Nuray Ardagümüşoğlu 5,
  Mihrimah Bilgili 3, Hacer Terzi 2.
- 2026-07-07 Codex gerçek görüntüleme takibi: Kullanıcı bildirimleri ve Standartlarımız
  kartları artık `Okundu/Okudum` butonuna bağlı çalışmaz. Kart ekranda en az 1 saniye
  görünür kalırsa tekil API çağrısıyla görüntülendi sayılır; admin takip sayaçları bu
  gerçek görüntüleme kaydından beslenir. Sayfa açılışında görünmeyen kayıtlar topluca
  okundu yapılmaz.
- 2026-07-07 Codex standart takip UX düzeltmesi: Standartlarımız ekranındaki admin takip
  alanında `Görmeyenler` listesi kaldırıldı. Göz butonu `görüntüleyen/toplam` sayısını
  gösterir; tıklanınca yalnızca görüntüleyen kullanıcılar açılır. Mesaj Kayıtları ile aynı
  takip dili kullanılır. `npm.cmd run check` başarılı; 44/44 test geçti.
- 2026-07-07 Codex çözüm tekrarı kontrolü: Canlı veride Test hesabına görünen eski çözüm
  mesajının farklı bir feedback kaydına ait olduğu doğrulandı; açık kalan Test kaydı ayrı,
  rastgele bir kayıttı. Bu kayıt canlı DB'de yeni mesaj gönderilmeden `resolved` işaretlendi.
  Tekil `Çözüm bildir` endpoint'i artık `feedback_status='resolved'` olan kayda ikinci
  çözüm bildirimi göndermeyi reddeder. Açık kuyruk 29 gerçek feedback / 6 kullanıcı olarak
  doğrulandı. `npm.cmd run check` başarılı; 44/44 test geçti.
- 2026-07-07 Codex mesaj kayıtları UX düzeltmesi: Çözüm bildirimi hitabı artık
  `Sevgili {kullanıcının sistemdeki adı}` satırıyla başlar; virgül yoktur ve isim/kalp
  sistemdeki haliyle korunur. Mesaj Kayıtları aynı toplu mesajı tek kartta gösterir;
  alıcılar tek tek listelenmez. Göz butonunda `görüntüleyen/toplam` sayısı görünür,
  tıklanınca yalnızca görüntüleyenler açılır; görüntülemeyenler bu ekranda gösterilmez.
  `npm.cmd run check` başarılı; 44/44 test geçti.
- 2026-07-07 Codex çözüm bildirimi geri dönüş döngüsü: Kullanıcı `feedback_resolution`
  bildirimlerinde artık `Sorun çözüldü` veya `Çözülmedi` yanıtı verebilir. `Çözülmedi`
  seçilirse not alanı açılır ve sistem aynı kullanıcı adına yeni `feedback` kaydı üretir.
  Yanıtlar SQL migration gerektirmeden `settings.resolution_feedback_responses` içinde
  tutulur. Süper admin tarafına `Çözüm Takibi` ekranı eklendi; Mesaj Kayıtları da yanıt
  durumunu gösterir. `npm.cmd run check` başarılı; 44/44 test geçti. Çözüm bildirimleri
  henüz gönderilmedi; kullanıcı onayı sonrası kişiye özel mesajlarla kapatılmalıdır.
- 2026-07-07 Codex canlı feedback çözüm turu: Test hesabının rastgele feedback kaydı kalite
  hatası kabul edilmedi. Gerçek kullanıcı kayıtlarından gelen sözlük/şapka, sure/âyet bağlamı,
  noktalama ve düzeltilmiş metin uygulama sorunları için `analysis-core.js` korumaları
  genişletildi. Doğru kelime halleri `CANONICAL_WORD_STANDARDS` sabitinde tutuluyor.
  `finalizeResult` artık modelin serbest `correctedText` çıktısını esas almak yerine kaynak
  metne yalnızca kabul edilen issue'ları kontrollü uygular; bu tablo/paragraf bozulması ve
  “hata bulundu ama düzeltilmiş metne uygulanmadı” sınıfını azaltır. Kullanıcı denetim
  ekranındaki `AI Raporu Oluştur` butonu ve Denetim Yardımcısı paneli kaldırıldı. `npm.cmd run check`
  başarılı; 44/44 test geçti. Geri bildirim kapatma/bildirim gönderimi henüz yapılmadı;
  kullanıcı onayı sonrası canlı feedbackler kapatılmalıdır.
- 2026-07-06 Codex açık feedback çözüm paketi: Canlı açık geri bildirimler kök sebeplere
  göre gruplandı. Backend güvenlik filtresi `nefsi/nefsin`, `taktirde`, `A.S/S.A.V`,
  `Efendimiz (A.S)`, `derecat*`, ek/tamlayan kırpma, kaynakta şapkalı doğru yazılmış
  kelimelerin şapkasızlaştırılması, `birr`, `hâdise`, `afv-u`, hadîs kaynak adları gibi
  canlı yanlış dönüşümleri skor dışı bırakacak şekilde genişletildi. En kritik mimari
  düzeltme: `correctedText` artık modelin serbest çıktısı olarak kabul edilmiyor; kaynak
  metne yalnızca kabul edilen issue'lar kontrollü uygulanıyor. Bu, gizli metin bozma,
  tablo/düzen kaybı ve "hata listesinde yok ama düzeltilmiş metin bozuldu" sınıfını kapatır.
  Feedback modalı uzun notlarda gönder butonunu görünür tutacak ve çift gönderimi önleyecek
  şekilde güncellendi. Kullanıcılara çözüm bildirimi henüz gönderilmedi; onay sonrası
  açık feedbackler kullanıcı bazında tek mesajla kapatılmalıdır.
- 2026-07-06 Codex kapsamlı audit düzeltme turu: `/api/cron/daily-report` artık
  mutlaka `CRON_SECRET` ister ve spoof edilebilir cron header'ına güvenmez. Proje kökü
  statik servis edilmez; sadece `icons`, `manifest.webmanifest` ve `sw.js` açık servis edilir.
  Kullanıcı feedback not uzunluğu frontend ile uyumlu olarak 2000 karaktere çıkarıldı.
  Geri Bildirim Merkezi'nde seçim/çözüm sonrası ekran kendi bağlamında yenilenir; kullanıcıyı
  Sistem Uyarıları sekmesine geri atmaz. Kullanıcı yönetimi butonları isim/id/rol değerlerini
  güvenli JSON argümanıyla geçirir; apostrof ve tırnak gibi özel karakterler butonları bozmaz.
- 2026-07-03 Codex Denetim Yardımcısı AI turu: Metin Denetimi ekranına kullanıcı tarafında
  güvenli Denetim Yardımcısı eklendi. `POST /api/ai/helper` metni hazırlama, sonucu açıklama,
  geri bildirim taslağı üretme görevlerini yapar; kullanıcı tarafında serbest soru alanı yoktur
  ve yardım chat yerine görev bazlı denetim rehberi olarak konumlanır. Kural/kod/onay
  yetkisi yoktur. Kullanıcı ve admin AI ekranlarında model adı gösterilmez; işlem sırasında
  canlı süreç adımları, pulse noktası ve "yanıt hazırlanıyor" akışı gösterilir. Admin rapor ve
  soru ekranı da aynı canlı süreç hissini kullanır.
- 2026-07-03 Codex Denetim Yardımcısı geliştirme turu: Yardımcıya `Şüpheli Bulgular` ve
  `Kopyalama Kontrolü` görevleri eklendi. `POST /api/ai/helper` artık `checks` ve `nextActions`
  dönebilir. Frontend canlı süreç adımları artık sabit değil; metin uzunluğu, düzen riski,
  skor, hata sayısı, görev tipi ve admin/kullanıcı bağlamına göre farklılaşır. Metin yazıldıkça
  yardımcı paneli proaktif kısa yönlendirme gösterir. Bulgu bazlı geri bildirim butonlarında
  kullanıcıya önce bulgunun neyi değiştirdiği ve hangi durumda geri bildirim verilmesi gerektiği
  açıklanır; tarayıcı prompt'u yerine modern, geniş ve otomatik yükseklikli geri bildirim modalı
  bağlamlı taslakla açılır.
- 2026-07-03 Codex tek AI raporu/feedback kapısı turu: Kullanıcı tarafındaki çoklu Denetim
  Yardımcısı butonları kaldırıldı ve tek `AI Raporu Oluştur` aksiyonuna indirildi. Rapor sonucunda
  temiz/0 bulgulu sonuçlarda ekibe bildirim kapalı kalır; sonuçta bulgu varsa genel feedback alanı
  ve bulgu bazlı feedback butonları doğrudan görünür. Böylece kullanıcı neye basacağını düşünmez,
  admin tarafına pozitif sonuçlardan gereksiz geri bildirim düşmez ama hatalı bulgular hızlıca
  raporlanabilir.
- 2026-07-03 Codex kullanıcı sonuç ekranı sadeleştirme turu: Normal kullanıcı ekranında teknik
  `Prompt`/`Kural` chipleri sonuç ekranından tamamen kaldırıldı. `Temizle` sırası
  düzeltildi; sonuç belleği önce sıfırlanır ve yardımcı tek tıkla `Hazır` durumuna döner.
  Yardımcı metinleri `AI hazır`/`Rapor için hazır` diline çekildi, canlı durum noktası daha
  belirgin menekşe AI vurgu rengine alındı.
- 2026-07-03 Codex mobil menü sadeleştirme turu: Tema değiştirme zaten topbar switchinde olduğu
  için mobil menü içindeki ikinci `Tema` satırı kaldırıldı. Ayarlar sayfasındaki tema kontrolü
  korunur; menü tekrarı kaldırılmıştır.
- 2026-07-03 Codex premium UX/ayarlar turu: Genel font `Noto Sans` oldu; açık/koyu tema,
  buton hover/active durumları, tıklamada parlak geçiş efekti, sol menü katman hissi ve bölüm
  ayraçları iyileştirildi. `Ayarlar` ekranı eklendi; kullanıcı küçük/orta/büyük yazı boyutu
  seçebilir ve tercih cihazda saklanır. Metin denetimi girişi ve son analiz sonucu otomatik
  taslak olarak `localStorage` içinde tutulur; sayfa uzun süre açık kalır veya yenilenirse
  çalışma geri yüklenir. `Temizle` taslağı da siler. Oturum çerez süresi 30 güne çıkarıldı.
- 2026-07-03 Codex rapor takvimi/PDF feedback paketi turu: `/api/cron/daily-report` artık
  İstanbul 00:00 takvim sınırlarına göre çalışır; her gece günlük, pazartesi haftalık, ayın
  1'i aylık ve 1 Ocak yıllık raporu birlikte üretir. Aynı dönem aralığı daha önce üretildiyse
  tekrar yazılmaz; `schema.sql` `ai_reports_period_range_idx` benzersiz indeksini içerir.
  Yeni rapor üretilirse admin/süper adminlere tek duyuru düşer. Geri Bildirim Merkezi'ndeki
  "Sorunları Çöz" akışı doğrudan ajan çalıştırmak yerine seçili/açık feedbackleri PDF çalışma
  paketine dönüştürür; PDF içinde kullanıcı, tarih, skor, durum ve mesaj alanları yer alır.
- 2026-07-03 Codex panel AI asistan/rapor turu: Admin paneline "AI Asistan ve Raporlar"
  ekranı eklendi. `gpt-4o-mini` ile günlük/haftalık/aylık/yıllık operasyon raporu üretilebilir
  ve seçilen dönem verisine soru sorulabilir. Backend önce denetim, skor, kategori, kullanıcı,
  feedback, çözüm kayıtları ve düşük skor verilerinden sınırlı snapshot çıkarır; modele bu
  özet verilir. `schema.sql` `ai_reports` tablosunu içerir. Vercel cron
  `/api/cron/daily-report` yolunu UTC 21:00'de çalıştıracak şekilde ayarlandı; İstanbul 00:00.
  `npm.cmd run check` başarılı; 39/39 test geçti. `vercel.json` parse kontrolü başarılı.
- 2026-07-03 Codex operasyon paneli UX turu: Masaüstünde üst navigasyon yerine sol menülü
  panel düzenine geçildi; Denetim / Operasyon / Yönetim başlıkları altında ekranlar
  gruplanıyor, mobil hamburger korunuyor. Feedback kayıtları Uyarılar ekranından ayrılıp
  ayrı `feedback` tabına taşındı; Uyarılar artık düşük skor/duyuru gibi sistem olaylarına
  daraltıldı. Geri Bildirim Merkezi seçili kayıtları çözüm bildirimiyle kapatır ve açık
  feedbacklerden "Codex çözüm paketi" metnini panoya kopyalar. Süper admin-only
  `GET /api/notification-log` ve "Mesaj Kayıtları" ekranı eklendi; normal admin göremez.
  `/api/alerts/resolve-bulk` canlı Supabase embed ilişki sorununa takılmaması için kullanıcıları
  ayrı sorguyla alacak şekilde düzeltildi. `npm.cmd run check` başarılı; 39/39 test geçti.
- 2026-07-03 Codex sorun/çözüm kayıt defteri turu: `schema.sql` içine
  `issue_resolution_log` tablosu eklendi. Tekil ve toplu feedback çözüm akışları çözüm
  turunu kısa başlık, özet, feedback sayısı, kullanıcı sayısı, çözen kişi ve tarih ile bu
  tabloya yazar. Admin dashboard'da "Sorun / Çözüm Kayıt Defteri" paneli son çözüm turlarını
  gösterir. Tablo canlı DB'de yoksa uygulama kırılmaz ama kayıt defteri pasif kalır.
  `npm.cmd run check` başarılı; 39/39 test geçti.
- 2026-07-03 Codex geri bildirim katkı/çözüm istatistik turu: Admin dashboard'a toplam/açık/
  çözülen feedback, çözüm oranı, katkı veren kullanıcı sayısı, en çok geri bildirim verenler
  ve sistem iyileştirmesine en çok katkı sağlayanlar eklendi. Uyarılar ekranında feedback
  kayıtları seçilebilir hale geldi; `POST /api/alerts/resolve-bulk` seçilen kayıtları kullanıcı
  bazında gruplayıp her kullanıcıya tek kişisel `feedback_resolution` teşekkür bildirimi gönderir.
  Aynı hatayı birden çok kullanıcı raporladıysa her raporlayan kullanıcı ayrı kişisel bildirim
  alır. `schema.sql` alerts çözüm kolonlarını içerir; canlı DB'de kolonlar yoksa uygulama
  kırılmaz ama tam açık/çözüldü takibi için ALTER satırları Supabase SQL Editor'de uygulanmalıdır.
  `npm.cmd run check` başarılı; 39/39 test geçti.
- 2026-07-03 Codex canlı feedback yanlış-pozitif turu: Canlı feedback kayıtlarından doğrulanan
  hatalı dönüşümler `analysis-core.js` güvenlik filtresine eklendi. `Tabi/Tabiî → tâbî`,
  `süre → sûre`, `afet → âfet`, `zahid → zâhid`, `zülmanî → zulmanî`, tek başına
  `Efendimiz → Efendimiz (S.A.V)`, `(S.A.V) → (S.A.V.)`, `Nebîler → Nebiler`,
  `nefs → nefis`, `ahiret → âhiret` ve yalnızca `islâm → İslâm` case dönüşümü skor dışı
  bırakılır ve düzeltilmiş metinden geri alınır. Model geçerli issue üretmeden metni
  değiştirdiyse, `totalErrors=0` sonucunda `correctedText` kaynak metne resetlenir.
  Sistem prompt'una aynı bağlam uyarıları eklendi. `npm.cmd run check` başarılı; test sayısı
  39'a çıktı.
- 2026-07-03 Codex sure case turu: Sure adlarında büyük/küçük harf farkı tek başına hata
  sayılmayacak şekilde prompt ve backend filtreleri güncellendi. `analysis-core.js`
  `SURA_NAMES`/`isSuraCaseOnlyChange` ile `Fâtiha → FÂTİHA`, `Mulk → MULK`,
  `Muzzemmil → MUZZEMMİL`, `Zumer → ZUMER` gibi case-only dönüşümleri skor dışı bırakır
  ve correctedText'ten geri alır. Şapka/apostrof/harf dizilimi farkları hâlâ gerçek imlâ
  farkıdır; örn. `Rum → Rûm` skorlanır.
- 2026-07-03 Codex temizle reset bug turu: Metin denetimi ekranında `Temizle` butonu artık
  `handleTextInput()` çağırır. Bu sayede metin boşalınca karakter sayacı `0 karakter` olur,
  yardımcı metin ilk hale döner ve otomatik büyüyen textarea yüksekliği 180px başlangıç
  yüksekliğine resetlenir.
- 2026-07-02 Codex bildirim imza turu: Bildirim gövdesinin sonunda tek başına duran
  `Arşiv Kontrol AI` imza satırı artık render edilmeden temizlenir; gönderen adı zaten footer'da
  gösterilir. Canlı DB'deki 36 toplu duyuru kaydı imzasız gövdeyle güncellendi ve
  `Gönderen: Arşiv Kontrol AI` alanı korundu.
- 2026-07-02 Codex bildirim gönderen adı turu: Kullanıcıya görünen bildirim gönderen adı
  her zaman `Arşiv Kontrol AI` olacak şekilde sabitlendi. `/api/users/:id/notify` ve
  `/api/alerts/:id/respond` yeni kayıtları bu sistem adıyla üretir; `renderNotice` eski
  kayıtlarda farklı gönderen metni olsa bile footer'da `Gönderen: Arşiv Kontrol AI` gösterir.
  Canlı DB'deki son toplu duyurunun 36 kaydı da aynı gönderen adıyla güncellendi.
- 2026-07-02 Codex bildirim UX turu: Kullanıcı "Bildirimler" ekranındaki `announcement` ve
  `feedback_resolution` mesajları artık ham `Başlık / Mesaj / Gönderen` satırları yerine
  parse edilmiş `.notice-card` bileşeniyle gösterilir. Duyuru tipi, başlık, paragraf gövdesi,
  gönderen, tarih ve okundu aksiyonu ayrıldı; mobil kırılımda kart tek sütuna düşer.
- 2026-07-01/02 Codex sure standardı turu: Kullanıcının verdiği 114 sure adı listesi
  `SURE_STANDARD_LIST` olarak `server.js` içine eklendi. `buildSystemPrompt` listeyi üst
  öncelikli standart olarak verir; baştaki sıra numaraları imlâ kontrolüne dahil değildir.
  `analysis-core.js` filtreleri daraltıldı: `Muminun → MU'MİNÛN` gibi tam sure adı düzeltmesi
  geçerli kabul edilir, fakat `MU'MİNÛN/Muminun → mü'min` gibi kelime içi/parça indirgemesi
  reddedilir. `ZUMER` standardı korunur, `Zümer` dönüşümü reddedilir. Kalite regresyon
  fixture'ına 4 sure vakası eklendi.
- 2026-07-01 Codex sözlük kararı turu: `dîn` yerine `din`, `her şey` yerine `herşey`
  üst öncelikli standart olarak eklendi. `buildSystemPrompt` bu iki kararı mevcut DB kural
  metni tersini söylese bile öncelikli uygular. `analysis-core.js` eski yöne dönüşleri
  (`din → dîn`, `herşey → her şey`) yasak dönüşüm sayar ve skor/düzeltilmiş metinden geri alır.
  Kalite regresyon fixture'ına 4 vaka eklendi.
- Her hata instance'ını ayrı issue yapan güçlendirilmiş AI promptu.
- Issue sayısına dayalı yetkili puanlama ve 60-altı kesin davranışı.
- SHA-256 tekrar gönderim kontrolü ve eski hash desteği.
- Güvenilir geçmiş detay API'si ve çalışan Gör butonu.
- PDFKit + Noto Serif ile gerçek PDF.
- Seed'i beklemeyen `GET /health` endpoint'i.
- Otomatik testler ve ortak ajan çalışma protokolü.
- Vercel uyumu: serverless export, imzalı cookie oturumu, 4 MB dosya sınırı ve dosya başına
  ayrı çalışan iki eşzamanlı toplu analiz işçisi.
- PWA: uygulama adı `Arşiv AI`; iOS/Android ana ekran ikonları, manifest ve minimal service
  worker eklendi ve production'a deploy edildi. Favicon bilerek ayrı bırakıldı.
- Sosyal paylaşım: WhatsApp/Telegram/Facebook/X için Open Graph ve Twitter Card metalarıyla
  1200x630 logo içeren paylaşım görseli eklendi.
- Yetki modeli: `admin` kullanıcı adı tek `super_admin` hesabıdır. Kullanıcı ekleme/silme
  yalnızca süper admine açıktır; normal adminler kullanıcıları görebilir ve süper admin
  dışındaki hesapları düzenleyebilir.
- AI sonuç güvenlik katmanı: `finalizeResult(result, sourceText)` artık kaynak metinde
  bulunmayan issue'ları, kullanıcıya aynı görünen original/fixed çiftlerini ve kelime içi
  parça eşleşmelerini skor dışı bırakıyor. `server.js` OpenAI sonucunu kaynak metinle
  birlikte finalize ediyor.
- Kök yanlış-pozitif düzeltmesi: varsayılan kural setindeki bağlamsız dönüşümler ve
  `Allah razı olsun.` çelişkisi temizlendi. `Mu'minûn/Muminun Suresi`, `Tabiî ki`,
  `derecat`, `dinlenmeye`, `Muhterem Efendimiz`, `Zumer` gibi korumalı ifadeleri değiştiren
  yasak dönüşümler hem issue listesinden hem de `correctedText` içinden geri alınıyor.
- Ekip geri bildirim döngüsü: analiz sonuç ekranına genel geri bildirim ve bulgu bazlı
  "Metinde yok / Yanlış düzeltme" butonları eklendi. Backend `POST /api/history/:id/feedback`
  ile bu kayıtları mevcut `alerts` tablosunda `type='feedback'` olarak saklıyor; adminler
  Uyarılar sekmesinden görebilir. Yeni Supabase migration gerektirmez.
- Yan yana karşılaştırma UX'i: anlık analiz sonucunda orijinal ve düzeltilmiş metin iki
  sütunda gösteriliyor; kısa/orta metinlerde kelime düzeyi kırmızı/yeşil diff vurgusu var.
  Çok uzun metinlerde performans için renkli diff kapatılıp metinler yan yana gösterilir.
  Dosya analizinde server response'u `originalText` döndürür; geçmiş kayıtlar için orijinal
  metnin kalıcı saklanması sonraki faza bırakıldı.
- Analiz izlenebilirliği: sonuç response'u `analysisMeta.promptVersion` ve `rulesHash`
  döndürür; sonuç ekranında chip olarak gösterilir. `schema.sql` `history.prompt_version`
  ve `history.rules_hash` kolonlarını içerir. Canlı DB'de kolonlar yoksa uygulama kırılmaz,
  sadece geçmişe sürüm meta yazmaz.
- Geri bildirim merkezi: Uyarılar sekmesi "Uyarılar ve Geri Bildirimler" oldu; Tümü /
  Geri Bildirim / Düşük Skor filtreleri eklendi.
- İş panosu: Onay Bekleyenler sekmesi "İş Panosu" oldu. Denetimler Bekleyen / Onaylanan /
  Reddedilen sütunlarında kartlarla gösterilir; kartlardan Gör / Onayla / Reddet işlemleri
  yapılabilir.
- Feedback ölçüm ekranı: admin dashboard toplam geri bildirim, son 7 gün geri bildirim ve
  okunmamış geri bildirim sayılarını gösteriyor. Uyarılar sekmesinde ekip geri bildirimleri
  tek satır metin yerine ayrıştırılmış alanlar halinde okunuyor.
- Geçmiş filtreleme: Denetim Geçmişi ekranında dosya/kullanıcı araması, Bekleyen/Onaylanan/
  Reddedilen/Düşük skor filtresi ve kaç kaydın görüntülendiğini gösteren sayaç var. Sunucu
  veya veritabanı değişikliği yok; mevcut liste üzerinde çalışıyor.
- Riskli kayıt görünümü: admin dashboard skor 60 altı veya hata sayısı 5 ve üzeri son
  denetimleri "Riskli Son Denetimler" panelinde gösteriyor; panelden düşük skor geçmiş
  filtresine hızlı geçiş var.
- Rapor paylaşımı: analiz sonucu ekranındaki "Raporu kopyala" butonu skor, toplam sorun,
  kategori kırılımı, özet, analiz sürümü ve ilk bulguları tek metin halinde panoya alıyor.
- Karanlık mod: topbar ve mobil menüde tema değiştirme düğmesi var. Tercih tarayıcıda
  saklanıyor; koyu tema siyah/beyaz ağırlıklı, yüksek kontrastlı çalışıyor.
- Tema switch düzeltmesi: koyu temada topbar artık beyaza dönmez; üst bar için ayrı
  `--topbar-*` renkleri kullanılıyor. Üstte yazılı `Karanlık/Aydınlık` yerine ikonlu switch,
  mobil menüde ise "Tema" satırı ve mini switch var.
- Koyu tema kontrast düzeltmesi: skor rozetleri, bildirim sayıları ve Onayla/Reddet gibi
  aksiyonlar koyu temada beyaz blok haline gelmesin diye `green/red/gold/orange/blue`
  semantik renkleri koyu tema için ayrıştırıldı.
- Koyu tema yumuşatma: saf siyah arka plan yerine koyu gri palet kullanılıyor; kartlar,
  inputlar ve topbar birbirinden daha okunur ayrılıyor.
- Ekip paylaşım özeti: `docs/EKIP_DEBUG_GELISTIRME_OZETI_2026-06-30.md` canlı debug ve
  geliştirme özetini içerir.
- Bildirim/duyuru sistemi: feedback çözüm yanıtları ve kullanıcıya özel duyurular mevcut
  `alerts` tablosunda `feedback_resolution` ve `announcement` tipleriyle tutuluyor. Kullanıcılar
  "Bildirimler" sekmesinde sadece kendilerine ait duyuru/çözüm yanıtlarını görür. Adminler
  Uyarılar ekranındaki feedback için "Çözüm bildir" kullanabilir ve Kullanıcı Yönetimi'nden
  tek kullanıcıya bildirim gönderebilir.
- Kalite regresyon havuzu: `test/fixtures/quality-regression-cases.json` canlı hata
  örneklerinden türeyen kalıcı test datasını tutuyor. `test/quality-regression-cases.test.js`
  bu fixture'ı okuyup `finalizeResult` güvenlik katmanının yanlış pozitifleri skor dışı
  bırakmasını ve güvenli geri almaları doğruluyor.
- Feedback çözüm görünürlüğü: dashboard çözüm bildirimi ve duyuru sayılarını gösteriyor.
  Uyarılar ekranında `Çözüm` ve `Duyuru` filtreleri var; admin feedback, çözüm ve duyuru
  loglarını ayrı ayrı inceleyebilir.
- Orijinal metin saklama: `schema.sql` `history.original_text` kolonunu içerir. Sunucu startup'ta
  kolonu algılar; varsa yeni analizlerde kaynak metni geçmişe yazar, yoksa özellik pasif kalır.
  Geçmiş detay modalı orijinal metin varsa orijinal/düzeltilmiş karşılaştırmasını gösterir.
- Metin denetim sağlamlığı: manuel metin alanında karakter sayısı ve hazır/uyarı durumu
  gösteriliyor. Boş, çok kısa ve çok uzun metinler frontend'de durduruluyor; aynı kontroller
  `/api/analyze`, `/api/analyze-file` ve batch dosya analizinde sunucu tarafında da uygulanıyor.
- Prompt'a canlı hata raporlarından çıkan istisnalar eklendi: "Allah razı olsun" cümlesi
  birleştirilmez; apostrof tipi tek başına hata değildir; tırnaklar korunur; sure adlarında
  kelime içi parça yakalanmaz; `Tabiî ki`, `derecat`, `dinlenmeye`, `Muhterem Efendimiz`
  bağlamları korunur; slayt/hadîs/tablo düzeni bozulmaz.

## Doğrulama

- `npm.cmd run check`: başarılı (2026-06-30 Codex). 11/11 test geçti; yeni testler
  metinde olmayan/aynı görünen issue'ların skor dışı bırakılmasını ve `Muminun`
  içinden `Mumin` eşleştirilmemesini güvenceye alıyor.
- `npm.cmd run check`: başarılı (2026-06-30 Codex ikinci tur). 13/13 test geçti; yeni
  testler korumalı/yasak dönüşümlerin skordan ve düzeltilmiş metinden geri alınmasını
  doğruluyor.
- `npm.cmd run check`: başarılı (2026-06-30 Codex üçüncü tur). 13/13 test geçti; geri
  bildirim endpoint'i ve sonuç ekranı butonları frontend parse kontrolünden geçti.
- `npm.cmd run check`: başarılı (2026-06-30 Codex dördüncü tur). 13/13 test geçti; yan
  yana karşılaştırma ve diff UI frontend parse kontrolünden geçti.
- `npm.cmd run check`: başarılı (2026-06-30 Codex beşinci tur). 13/13 test geçti; analiz
  sürüm chip'i ve uyarı/geri bildirim filtreleri frontend parse kontrolünden geçti.
- `npm.cmd run check`: başarılı (2026-06-30 Codex altıncı tur). 13/13 test geçti; iş panosu
  frontend parse kontrolünden geçti.
- `npm.cmd run check`: başarılı (2026-06-30 Codex yedinci tur). 13/13 test geçti; dashboard
  feedback metrikleri ve ayrıştırılmış geri bildirim kartları frontend parse kontrolünden geçti.
- `npm.cmd run check`: başarılı (2026-06-30 Codex sekizinci tur). 13/13 test geçti; geçmiş
  arama/durum/düşük skor filtreleri frontend parse kontrolünden geçti.
- `npm.cmd run check`: başarılı (2026-06-30 Codex dokuzuncu tur). 13/13 test geçti; riskli
  denetimler dashboard paneli ve düşük skor geçmiş geçişi frontend parse kontrolünden geçti.
- `npm.cmd run check`: başarılı (2026-06-30 Codex onuncu tur). 13/13 test geçti; analiz
  raporu kopyalama aksiyonu frontend parse kontrolünden geçti.
- `npm.cmd run check`: başarılı (2026-06-30 Codex on birinci tur). 13/13 test geçti; karanlık
  tema, metin sağlık göstergesi ve sunucu tarafı metin uzunluk kontrolleri doğrulandı.
- `npm.cmd run check`: başarılı (2026-06-30 Codex on ikinci tur). 13/13 test geçti; topbar
  tema renk ayrımı ve ikonlu tema switch frontend parse kontrolünden geçti.
- `npm.cmd run check`: başarılı (2026-06-30 Codex on üçüncü tur). 13/13 test geçti; koyu
  tema semantik renkleri, Onayla/Reddet ve skor rozeti kontrast düzeltmeleri doğrulandı.
- `npm.cmd run check`: başarılı (2026-07-01 Codex). 13/13 test geçti; koyu tema siyah
  yoğunluğu azaltıldı ve tema meta rengi güncellendi.
- `npm.cmd run check`: başarılı (2026-07-01 Codex bildirim turu). 13/13 test geçti; kişisel
  bildirimler, feedback çözüm yanıtı ve kullanıcıya özel duyuru akışları frontend parse
  kontrolünden geçti.
- `npm.cmd run check`: başarılı (2026-07-01 Codex regresyon turu). 19/19 test geçti; kalite
  regresyon havuzu fixture'ları otomatik test kapsamına alındı.
- `npm.cmd run check`: başarılı (2026-07-01 Codex feedback metrik turu). 19/19 test geçti;
  dashboard çözüm/duyuru metrikleri ve Uyarılar filtreleri frontend parse kontrolünden geçti.
- `npm.cmd run check`: başarılı (2026-07-01 Codex orijinal metin turu). 19/19 test geçti;
  opsiyonel `history.original_text` saklama ve geçmiş karşılaştırma modalı frontend parse
  kontrolünden geçti.
- `npm.cmd run check`: başarılı (2026-07-01 Codex sözlük kararı turu). 23/23 test geçti;
  `din/dîn` ve `herşey/her şey` yeni standartları hem koruma hem düzeltme yönünde doğrulandı.
- `npm.cmd run check`: başarılı (2026-07-02 Codex sure standardı turu). 27/27 test geçti;
  114 sure adı listesi prompt'a üst öncelikli standart olarak eklendi, `Muminun/MU'MİNÛN`
  ve `Zumer/ZUMER` regresyonları doğrulandı.
- `npm.cmd run check`: başarılı (2026-07-02 Codex bildirim UX turu). 27/27 test geçti;
  bildirim kartı parse/render değişikliği frontend parse kontrolünden geçti.
- `npm.cmd run check`: başarılı (2026-07-02 Codex bildirim gönderen adı turu). 27/27 test geçti;
  canlı DB'de 36 toplu duyuru kaydı `Gönderen: Arşiv Kontrol AI` olarak doğrulandı.
- `npm.cmd run check`: başarılı (2026-07-02 Codex bildirim imza turu). 27/27 test geçti;
  canlı DB'de 36 toplu duyuru kaydının mesaj gövdesinde son imza satırı olmadığı doğrulandı.
- `npm.cmd run check`: başarılı (2026-07-03 Codex temizle reset bug turu). 27/27 test geçti;
  `clearAnalyze()` sayaç ve textarea yüksekliğini resetleyecek şekilde güncellendi.
- `npm.cmd run check`: başarılı (2026-07-03 Codex sure case turu). 31/31 test geçti;
  sure adlarında sadece büyük/küçük harf dönüşümleri skor dışı bırakılıyor.
- `npm.cmd run check`: başarılı (2026-07-03 Codex canlı feedback yanlış-pozitif turu). 39/39
  test geçti; yeni canlı feedback regresyonları ve sıfır-hata metin koruması doğrulandı.
- `npm test`: 9/9 başarılı (5 analiz/PDF + 4 rol/yetki testi).
- `node --check server.js`: başarılı.
- Frontend inline JavaScript parse kontrolü: başarılı.
- Yerel `GET /health`: HTTP 200 ve `{"status":"ok"}`.
- Vercel production `GET /health`: `{"status":"ok"}`.
- Vercel production `GET /api/auth/me`: `{"loggedIn":false}`.
- Canlı uçtan uca smoke test: geçici kullanıcıyla login ve GPT analizi başarılı;
  skor 87, 3 issue ve düzeltilmiş metin döndü. Test kullanıcısı/geçmişi silindi.
- Canlı PWA doğrulaması: manifest adı `Arşiv AI`, standalone modu, service worker, Apple touch
  bağlantısı ve 192/512/maskable ikonların HTTP 200 + gerçek ölçüleri doğrulandı.
- Canlı Supabase salt-okunur kontrolü bağlantıda zaman aşımına uğradı; veri değiştirilmedi.
- Canlı süper admin doğrulaması: Supabase'deki `admin` hesabı `super_admin` rolüne yükseltildi.
  Geçici normal admin ile production `POST /api/users` ve `DELETE /api/users/:id` çağrıları
  ayrı ayrı HTTP 403 döndü; geçici kullanıcılar test sonunda temizlendi.

## Sonraki güvenli adım

1. PR [#1](https://github.com/ugurkarabulutt/arsiv-kontrol/pull/1) incelenip kullanıcı onayıyla `main`'e merge edilsin (otomatik merge yok).
2. Geçerli ekip kullanıcısıyla geçmiş Gör ve PDF akışını kullanıcı arayüzünden doğrula.
3. Vercel GitHub bağlantısı tamamlanınca branch-scoped Preview env değişkenleri eklensin.

## Vercel ortam durumu

- `SUPABASE_URL`, `SUPABASE_KEY` ve güçlü rastgele `SESSION_SECRET` Production ortamına eklendi.
- Proje GitHub'a henüz Vercel tarafından bağlanamadığı için branch-scoped Preview değişkenleri
  eklenemedi; CLI production deploy bundan etkilenmez.
- `OPENAI_API_KEY` Production ortamına eklendi ve canlı GPT analiziyle doğrulandı.
- Vercel SSO protection kapatıldı; özel domain doğrudan uygulamanın kendi login ekranına açılıyor.
- Ham internet smoke testi: `/health` 200, `/` 200 ve login endpoint'i uygulama JSON'u döndürüyor.
- Varsayılan `admin/admin123` canlı ortamda reddedildi; varsayılan şifre kullanılmıyor.
- `arsiv.ibrahimlive.ai` kalıcı proje domaini olarak eklendi; gelecekteki production
  deployment'larına otomatik atanacak.

- 2026-07-10 Codex ek feedback kalite turu: Yeni acik feedbacklerden gelen net yanlis-pozitif donusumler backend korumasina alindi; model ozetleri gercek kabul edilen kategori sayimindan uretilmeye baslandi; `...lazim` bitisik yazimlari ve cumle sonu bosluk eksikleri deterministic olarak uygulanir hale getirildi. `S.A.V` gibi kisaltmalar bosluk kuralindan muaf tutuldu. Super admin geri bildirim ekranina olumlu/tesekkur filtresi eklendi ve sol panelde geri bildirim ekranlari ayri `Geri Bildirim` basligi altinda toplandi. `npm.cmd run check` basarili; 47/47 test gecti.

## 2026-07-10 Final Feedback Temizlik Turu

- Commit: `95c7621 fix: resolve remaining feedback standards` production'a push/deploy edildi.
- Canli dogrulama: `https://arsiv.ibrahimlive.ai/health` `ok` dondu.
- Test: `npm.cmd run check` basarili; 49/49 test gecti.
- Canli feedback durumu: 52 acik feedback `feedback-cleanup-2026-07-10` cozum grubuyla `resolved` kapatildi; son canli kontrolde acik feedback sayisi `0`.
- Kullanici bildirimi: Hacer Terzi, Sumeyye Ozkul, Elcin Akay, Aysun Aydoner, Nuray Ardagumusoglu, Ebru Kalayci ve Serap Pamuk icin 7 kisisel `feedback_resolution` bildirimi gonderildi. Ilk insert sonrasi encoding riski goruldu; son 7 bildirim kaydi tekrar guncellenip okunur baslik/isim/metinle dogrulandi.
- Kalite kilidi: `vucudunu` gibi ekli kelime bozulmalari, `kadirdir`, `5 dakika 10 dakikalik`, `Efendimiz (S.A.V)'dir` ve `Irade eksikligi; irade...` vakalari regresyon testlerine alindi.

## 2026-07-12 Yeni Feedback Koruma Turu

- Canli kontrolde 17 yeni acik feedback goruldu: Birgul Nursoy 2, Hacer Terzi 9, Serap Pamuk 2, Nuray Ardagumusoglu 4.
- Kullanici bildirimleri hakli kabul edildi ve kalite katmanina islendi.
- Korunan yeni vakalar: `Kadir -> Kaadir`, `Kadiri -> Kaadiri`, `Vel Asr -> Vel-Asr`, `39/ZUMER-17 -> 39. ZUMER-17`, tablo sablonunda `6 . CASIYE-19 -> 6. CASIYE-19`, `Allah -> Allahu Teala` baglam genisletmesi, `dinehum`, `hadisi -> hadis-i`, `Allah'da -> Allah'ta`, `sagir -> sagir`, `ukba -> ukba`, `rahmete -> rahmeti`.
- `Zuruf -> Zumer` yanlis eslesmesi reddedildi; `Zuruf` dogru hedef olarak `Zuhruf` standardina baglandi.
- Test: `npm.cmd run check` basarili; 50/50 test gecti.
- Production: `c04f6e3 fix: protect latest feedback cases` Vercel production'a deploy edildi; `/health ok`, ana sayfa 200.
- Canli kapatma: kapatma aninda 18 acik feedback vardi; hepsi `feedback-fix-2026-07-12-1783851067872` grubuyla `resolved` kapatildi. Birgul Nursoy 3, Hacer Terzi 9, Nuray Ardagumusoglu 4, Serap Pamuk 2 feedback icin 4 kisisel cozum bildirimi gonderildi. Son canli kontrolde acik feedback sayisi `0`.

## 2026-07-13 Ek Feedback Koruma Turu

- Canli kontrolde 6 yeni acik feedback goruldu: Hacer Terzi 2, Nuray Ardagumusoglu 2, Birgul Nursoy 2.
- Kodda cozuldu: namaz rekat dagilimini bozan virgulleme reddedilir; `vaadde -> vaatte`, `afetlerine -> afetlerine` sapkalama, `...`/ellipsis farki ve `biraraya -> bir araya` yanlis pozitifleri korunur.
- Deterministik duzeltme: `19 tane haslet ruhun -> Ruhta 19 tane haslet`; `bir araya -> biraraya`.
- Test: `npm.cmd run check` basarili; 51/51 test gecti.
- Production: `c3647f5 fix: protect latest dictionary feedback` Vercel production'a deploy edildi; `/health ok`, ana sayfa 200.
- Canli kapatma: 6 acik feedback `feedback-fix-2026-07-13-1783893985888` grubuyla kapatildi. Birgul Nursoy 2, Nuray Ardagumusoglu 2, Hacer Terzi 2 feedback icin 3 kisisel cozum bildirimi gonderildi. Son kontrolde acik feedback `0`.

## 2026-07-13 Kritik Uygulama Katmani Duzeltmesi

- Canli kontrolde Aysun Aydoner tarafindan 2 acik feedback goruldu: "hatalari buluyor ama duzeltilmis metne uygulamiyor" ve "hala cift tirnak ekliyor".
- Kok sebep: kaynak dogrulama canonical/toleransli, fakat `applyAcceptedIssues` daha dar eslesmeyle uyguluyordu. Apostrof/tirnak/bosluk farkinda issue skorlanabiliyor ama metne uygulanmayabiliyordu.
- Cozum: `applyAcceptedIssues` flexible pattern ile apostrof, tirnak, ellipsis ve bosluk farklarini tolere eder. `normalizeDoubledQuotes` modelin ekledigi gereksiz cift tirnaklari temizler.
- Test: `npm.cmd run check` basarili; 53/53 test gecti.
- Production: `f588a97 fix: apply accepted issues robustly` Vercel production'a deploy edildi; `/health ok`, ana sayfa 200.
- Canli kapatma: Aysun Aydoner'in 2 acik feedback kaydi `feedback-fix-2026-07-13-apply-1783962347176` grubuyla kapatildi ve tek kisisel cozum bildirimi gonderildi. Son kontrolde acik feedback `0`.

## 2026-07-14 Uc Acik Feedback Koruma Turu

- Canli kontrolde Hacer Terzi tarafindan 3 acik feedback goruldu.
- Cozulen kokler: kaynakta zaten bulunan noktanin `lazim -> lazim.` gibi tekrar hata sayilmasi,
  `kitab -> kitâb` sapkalama zorlamasi ve `3/ALI IMRAN-20 -> 3. ALI IMRAN-20` gibi cok
  kelimeli sure adi iceren meal/referans formatinin degistirilmesi.
- Tekrar sebebi: Onceki referans korumasi tek kelimeli sure adlarini kapsiyordu; `ALI IMRAN`
  bosluklu oldugu icin ayni kok sorun tekrar acik feedbacke dustu. Kural genellendi ve
  regresyon testine alindi.
- Test: `npm.cmd run check` basarili; 54/54 test gecti.
- Production: `5afe883 fix: protect latest feedback cases` Vercel production'a deploy edildi;
  `/health ok`, ana sayfa 200.
- Canli kapatma: 3 acik feedback `feedback-fix-2026-07-14-hacer-1783977404365` grubuyla
  kapatildi. Hacer Terzi icin tek kisisel cozum bildirimi gonderildi. Son kontrolde acik
  feedback sayisi `0`.

## 2026-07-14 Feedback Kok Kategori ve Tekrar Uyarisi

- Feedback mesajlari kok kategoriye ayrilir: referans/sure formati, noktalama, sapka/sozluk,
  tirnak, duzeltilmis metne uygulama, duzen/paragraf, kaynakta olmayan icerik ve genel kalite.
- Geri Bildirim Merkezi acik kayitlarda ayni kok kategoride daha once cozulmus feedback varsa
  kartta "Daha once cozulmus kategoriye benziyor" uyarisi, cozum sayisi ve son cozum tarihini
  gosterir.
- Tekil ve toplu cozum kapatmalarinda kok kategoriler kullanici mesajina eklenmez; ic kayit
  olarak `resolution_note` ve `issue_resolution_log.summary` alanlarina yazilir.
- Test: `npm.cmd run check` basarili; 54/54 test gecti.

## 2026-07-15 18 Acik Feedback Kok Koruma Turu

- Canli kontrolde 18 acik feedback goruldu: Bihter Oksak 12, Serap Pamuk 2,
  Nuray Ardagumusoglu 4.
- Kodda cozuldu: dis/cift tirnak temizligi genisletildi; `Sura -> Şûrâ` deterministik
  eksik sapka duzeltmesi eklendi; Arapca ayet/transliterasyon icinde parantez boslugu,
  `Eûzü...` bitisiklestirme, `dîni/dîne -> dini/dine`, `gayz(gayzi) -> gayz (gayzi)` gibi
  baglam bozucu donusumler reddedildi.
- Korunan standartlar: `cihad` ve `Ebu` sapka zorlamasi, `Ra'd` apostrof dusurme,
  `diyor ki; -> diyor ki:`, `Allah Resûl'ü (S.A.V); -> :`, ayri cumleyi virgul ile
  birlestirme, `inşaallah -> inşallah`, `kasiyet -> kasvet`, `lâzımgelen -> lâzım gelen`,
  `Hz. İsa’ya -> Hazreti İsa (A.S)’ya`.
- Test: `npm.cmd run check` basarili; 56/56 test gecti.
- Production: `3eb3d57 fix: protect latest feedback roots` Vercel production'a deploy edildi;
  `/health ok`, ana sayfa 200.
- Canli kapatma: 18 acik feedback `feedback-fix-2026-07-15-18-1784128089002` grubuyla
  kapatildi. Bihter Oksak, Serap Pamuk ve Nuray Ardagumusoglu icin 3 kisisel cozum bildirimi
  gonderildi. Son kontrolde acik feedback sayisi `0`.
