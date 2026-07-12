# CURRENT_HANDOFF — Arşiv Kontrol AI

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
