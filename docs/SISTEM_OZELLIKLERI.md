# Arşiv Kontrol AI - Sistem Özellikleri

Son güncelleme: 2026-07-07

Bu dosya, Arşiv Kontrol AI sisteminin mevcut kapsamını, kullanıcı/admin özelliklerini,
operasyon mantığını ve önemli teknik kararlarını tek yerde tutmak için hazırlanmıştır.
İleride "bu sistem nedir, neler yapıyor?" sorusuna kapsamlı cevap verirken ana kaynak
olarak kullanılmalıdır.

## 1. Sistem Amacı

Arşiv Kontrol AI; soru-cevap arşivi, sohbet metni, slayt/metin dökümü ve benzeri içerikleri
belirlenmiş arşiv standartlarına göre denetleyen kalite kontrol sistemidir.

Temel amaçlar:
- Metindeki imlâ, noktalama, sözlük, sure adı, yapı ve etiket hatalarını tespit etmek.
- Uygun durumlarda düzeltilmiş metni üretmek.
- Hataları kategori bazlı göstermek.
- Kullanıcıların yanlış bulduğu sonuçları sistem içinden geri bildirim olarak iletmesini sağlamak.
- Adminlerin feedbackleri takip edip çözüm sürecini yönetmesini sağlamak.
- Ekip kalite operasyonunu ölçülebilir hale getirmek.

## 2. Kullanıcı Rolleri

### Kullanıcı
- Metin denetimi yapar.
- `.docx` dosyası yükleyebilir.
- Toplu dosya yükleyebilir.
- Denetim geçmişini görebilir.
- Kendisine gelen bildirimleri ve çözüm yanıtlarını görebilir.
- Standartlarımız bölümündeki güncel standartları görebilir.
- Sonuçlarda hatalı bulduğu noktalara bulgu bazlı veya genel geri bildirim gönderebilir.

### Admin
- Kullanıcıların denetimlerini, geri bildirimlerini ve operasyon panosunu takip eder.
- İş Panosu üzerinden bekleyen/onaylanan/reddedilen denetimleri yönetir.
- Geri Bildirim Merkezi üzerinden açık feedbackleri inceler.
- Seçili feedbacklerden PDF çözüm paketi indirebilir.
- Feedbackleri çözüm notuyla kapatabilir.
- Kullanıcılara çözüm bildirimi gönderebilir.
- AI Asistan ve Raporlar ekranından günlük/haftalık/aylık/yıllık raporları inceleyebilir.

### Süper Admin
- Tüm admin yetkilerine sahiptir.
- Kullanıcı ekleyebilir/silebilir.
- Mesaj Kayıtları ekranında gönderilen duyuru ve çözüm bildirimlerini takip eder.
- Çözüm Takibi ekranında kullanıcıların "Sorun çözüldü / Çözülmedi" yanıtlarını görür.
- Toplu mesajların kaç kişi tarafından görüntülendiğini takip eder.

## 3. Metin Denetimi

Sistem şu kategorilerde denetim yapar:
- Sözlük
- İmlâ
- Noktalama
- Etiket
- Yapı

Denetim sonucu:
- Genel skor
- Kategori bazlı hata sayıları
- Bulgu listesi
- Orijinal / düzeltilmiş karşılaştırma
- Düzeltilmiş metin
- Özet açıklama

Skor sunucu tarafında hesaplanır. AI'ın verdiği skor doğrudan kullanılmaz.

## 4. Düzeltilmiş Metin Güvenliği

Düzeltilmiş metin, modelin serbest çıktısı olarak kabul edilmez.

Sistem kaynak metne yalnızca kabul edilen bulguları kontrollü uygular. Bu yaklaşım:
- Tablo/paragraf düzeninin bozulmasını azaltır.
- Modelin gizli metin değiştirmesini engeller.
- Bulgu listesinde olmayan değişikliklerin düzeltilmiş metne sızmasını engeller.
- Skor 100 ise kaynak metni aynen korur.

60 altı skorda düzeltilmiş metin verilmez; sistem kullanıcıya standart uyarı gösterir.

## 5. Arşiv Standartları

Sistemde özel arşiv kararları kod ve kural katmanında korunur.

Önemli kararlar:
- `dîn` yerine `din` doğru kabul edilir.
- `her şey` yerine `herşey` doğru kabul edilir.
- `vücud` ve `vücût` yerine `vücut` doğru kabul edilir.
- `Hazreti İsa` ifadesine her zaman `(A.S)` eklenir.
- `Hadîs-i Şerif` standardında `Hadîs` şapkalı, `Şerif` şapkasızdır.
- Sure isimleri mihr.com imlâ standardına göre değerlendirilir.
- Sure isimlerinde yalnızca büyük/küçük harf farkı tek başına hata sayılmaz.
- Asıl kontrol şapka, apostrof ve harf dizilimidir.

Korumaya alınmış örnekler:
- `vücut`
- `herşey`, `herşeye`, `herşeydir`
- `hayy`, `hayydırlar`
- `tabiî`
- `derecât`
- `hidayet`
- `şerr`
- `arif`
- `cahiliye`
- `dinde`
- `ve vechini`
- `NEFSİ EMMÂRE`
- hadis kaynak numarası bağlamları
- `Mu'min`
- `A'raf`
- `Nur`

## 6. Karşılaştırma Ekranı

Orijinal metin ve düzeltilmiş metin yan yana gösterilir.

Özellikler:
- Kırmızı: çıkarılan/değiştirilen bölüm.
- Yeşil: eklenen/düzeltilen bölüm.
- Uzun metinlerde de renkli fark gösterimi korunur.
- Scroll Lock varsayılan olarak açıktır.
- Scroll Lock açıkken orijinal ve düzeltilmiş metin birlikte kayar.
- Scroll Lock kapalıyken iki alan bağımsız kayar.

## 7. Geri Bildirim Sistemi

Kullanıcılar denetim sonucunda:
- Eksik hata
- Düzen bozuldu
- Skor yanlış
- Diğer
- Bu bulgu hatalı
- Bu düzeltme yanlış

gibi geri bildirimler gönderebilir.

Geri bildirim modalı:
- Kullanıcıya hazır bağlamlı metin sunar.
- Uzun metinde alan otomatik büyür/kaydırılır.
- Not limiti 2000 karakterdir.
- Gereksiz pozitif sonuç feedbacki oluşturmayı azaltmak için sadece bulgulu/riskli sonuçlarda açılır.

## 8. Geri Bildirim Merkezi

Adminler için ayrı merkezdir.

Özellikler:
- Açık Kuyruk
- Okunmamış
- Çözülen
- Tümü
- Kullanıcı adı gösterimi
- Toplu seçim
- PDF çözüm paketi indirme
- Seçili feedbackleri çözüm notuyla kapatma

Feedback kapatılırken kullanıcıya bildirim gönderilebilir veya sadece operasyonel olarak
resolved işaretlenebilir.

## 9. Çözüm Bildirimleri

Bir kullanıcının bildirdiği sorun çözüldüğünde, kullanıcıya kişisel çözüm bildirimi gönderilebilir.

Mesaj mantığı:
- "Sevgili {kullanıcının sistemdeki adı}" hitabı kullanılır.
- Kullanıcı adı sistemdeki haliyle, kalp dahil korunur.
- Aynı kullanıcı birden fazla sorun bildirdiyse tek mesajda toplu anlatılabilir.
- Aynı sorunu birden fazla kişi bildirdiyse her kullanıcıya ayrı teşekkür bildirimi gönderilebilir.

Kullanıcı çözüm bildiriminin altında:
- Sorun çözüldü
- Çözülmedi

seçeneklerini görebilir. Çözülmedi seçilirse not alanı açılır ve admin kuyruğuna yeni feedback düşer.

## 10. Bildirim ve Duyuru Sistemi

Sistem iki tür bildirim üretir:
- Genel duyuru
- Kişisel çözüm bildirimi

Toplu duyurular kullanıcıların Bildirimler ekranına düşer.

Görüntüleme takibi:
- Bildirim veya standart kartı ekranda en az 1 saniye görünürse görüntülendi sayılır.
- Okundu butonuna basmaya bağlı değildir.
- Admin Mesaj Kayıtları ekranında kaç kişinin gördüğü takip edilir.
- Toplu mesajlar tek kayıt olarak gösterilir, alıcılar tek tek kartlara basılmaz.
- Göz butonuyla yalnızca görüntüleyenler listelenir.

## 11. Standartlarımız Bölümü

Standartlarımız ekranı, güncel arşiv standartlarını kullanıcıya gösterir.

Özellikler:
- Admin yeni standart ekleyebilir.
- Kullanıcı standart kartını gördüğünde görüntülendi sayılır.
- Admin kaç kişinin standardı gördüğünü takip eder.
- Görmeyenler listesi kullanıcı ekranını şişirmemek için gösterilmez; görüntüleyenler göz butonuyla açılır.

## 12. Kullanıcı Yönetimi

Admin/süper admin kullanıcıları yönetebilir.

Özellikler:
- Kullanıcı listesi
- Rol gösterimi
- Aktif/pasif durum
- Son aktif zamanı
- Kullanıcıya özel bildirim gönderme
- Süper admin için kullanıcı ekleme/silme

Son aktiflik:
- Login sırasında güncellenir.
- Kullanıcı sistemde yetkili API işlemi yaptıkça dakikada en fazla bir kez güncellenir.
- `users.last_seen_at` kolonu varsa oradan okunur.
- Kolon yoksa `settings.user_last_seen` yedeği kullanılır.

## 13. İş Panosu

İş Panosu denetimleri üç sütunda gösterir:
- Bekleyen
- Onaylanan
- Reddedilen

Kartlarda:
- Kullanıcı adı
- Dosya/metin adı
- Skor
- Hata sayısı
- Gör / Onayla / Reddet aksiyonları

yer alır.

## 14. AI Asistan ve Raporlar

Admin panelinde operasyon verisini yorumlayan AI rapor ekranı vardır.

Rapor türleri:
- Günlük
- Haftalık
- Aylık
- Yıllık

Raporlar:
- Denetim sayısı
- Ortalama skor
- Hata sayıları
- Feedback durumu
- Çözüm oranı
- Kullanıcı aktivitesi
- Riskler
- Öneriler
- Sonraki aksiyonlar

üzerinden oluşturulur.

Rapor geçmişi:
- Rapor tipi filtresi
- Gün filtresi
- Ay filtresi
- Bugün kısayolu
- Katlanabilir modern rapor kartları
- Özet sayaçları

ile gösterilir.

## 15. Otomatik Raporlama

Vercel Cron ile İstanbul saatine göre rapor üretimi planlanmıştır.

Mantık:
- Her gün 00:00'da günlük rapor
- Pazartesi 00:00'da ek haftalık rapor
- Ayın 1'i 00:00'da ek aylık rapor
- 1 Ocak 00:00'da ek yıllık rapor

Aynı gece birden fazla dönem denk gelirse ilgili raporlar birlikte üretilir.

## 16. Mesaj Kayıtları

Süper admin ekranıdır.

Özellikler:
- Toplu mesajlar tek kartta gösterilir.
- Kişisel mesajlar ayrı görülebilir.
- Çözüm / Duyuru filtreleri vardır.
- Kaç kişi görüntüledi bilgisi gösterilir.
- Göz butonuyla görüntüleyenler açılır.
- Görüntülemeyenler uzun liste halinde basılmaz.

## 17. Çözüm Takibi

Süper admin ekranıdır.

Kullanıcıların çözüm bildirimlerine verdiği yanıtları gösterir:
- Sorun çözüldü
- Çözülmedi
- Not
- İlgili çözüm mesajı
- Yanıt zamanı

## 18. Dashboard ve İstatistikler

Dashboard şu verileri gösterir:
- Toplam denetim
- Son 30 gün denetim
- Kullanıcı sayısı
- Ortalama skor
- Onay bekleyenler
- Uyarılar
- Toplam feedback
- 7 gün feedback
- Okunmamış feedback
- Açık feedback
- Çözülen feedback
- Çözüm oranı
- Katkı veren kullanıcılar
- Çözüm bildirimi sayısı
- Duyuru sayısı

Ayrıca en çok geri bildirim verenler ve katkı sağlayanlar listelenir.

## 19. Tema ve Kullanıcı Deneyimi

UX tarafında:
- Açık/koyu tema
- Premium koyu mod
- Sol menülü masaüstü panel
- Mobil hamburger menü
- Okunabilir Noto Sans font
- Küçük/orta/büyük yazı boyutu tercihi
- Tercihin cihazda hatırlanması
- Modern buton hover/active efektleri
- Taslak koruma
- Metin ve son analiz sonucunu localStorage ile koruma

bulunur.

## 20. Teknik Mimari

Stack:
- Node.js
- Express
- Tek dosya frontend: `index.html`
- Supabase PostgreSQL
- OpenAI Chat Completions
- Vercel production deployment

Önemli dosyalar:
- `server.js`: backend, API, Supabase, OpenAI çağrıları
- `index.html`: frontend
- `analysis-core.js`: test edilebilir denetim/puanlama mantığı
- `schema.sql`: Supabase şeması
- `test/`: otomatik testler
- `AGENTS.md`: kalıcı karar günlüğü
- `CURRENT_HANDOFF.md`: güncel çalışma devri

## 21. Güvenlik ve Sağlamlık

Önemli kararlar:
- Supabase service key yalnızca backend tarafında kullanılır.
- Session cookie imzalı ve HttpOnly yapıdadır.
- Cron endpoint'i `CRON_SECRET` ile korunur.
- Proje kökü statik servis edilmez.
- Feedback notları backend/frontend aynı limitte sınırlandırılır.
- Kullanıcı yetkilerinde `admin` kullanıcı adı tek süper admin hesabıdır.
- Resolved feedbacke ikinci kez çözüm bildirimi gönderilmesi engellenir.

## 22. Mevcut Durum Notları

2026-07-07 itibarıyla:
- Önceki açık 29 feedback kaydı kullanıcı onayıyla resolved kapatıldı.
- Kullanıcılara bu kapatma için yeni bildirim gönderilmedi.
- Son aktiflik takibi güçlendirildi.
- Sistem özellikleri bu dosyada kalıcı olarak kayıt altına alındı.

## 23. 2026-07-10 Ek Feedback Kalite Turu

- Yeni acik feedbacklerden gelen net yanlis-pozitif donusumler backend korumasina alindi:
  `var ama -> var, ama`, cift tirnak cogaltma, `dilemeyenler -> dileyemeyenler`,
  `aheze -> ahize`, `zekat` sapkalama, `oluyken -> olu iken`, `amenustecibu`
  bosluk ekleme, `heryeri -> herseyi`, `peygamber -> nebi`, `7 safha 4 teslimi`
  virgulleme, `helalinden/maddi/ahirette` sapkalama, `Allah -> Allahu Teala`
  genisletme, `sergilerse -> sergilesin`, `artisi -> artisini`,
  `Tirmizi -> Tirmizi,`, `Es Safi -> Es-Safi`, kaynakta olmayan kelime ekleme,
  uzun cizgi donusumu ve `Nebi -> nebi` case kaybi.
- Model ozetleri artik kabul edilen gercek kategori sayimindan uretilir; altta sorun
  olmayan kategori ozet metninde hata varmis gibi yazilmaz.
- `...lazim` bitisik yazimlari ve cumle sonu bosluk eksikleri deterministic olarak
  uygulanir; `S.A.V` gibi kisaltmalar bu bosluk kuralina takilmaz.
- Super admin geri bildirim ekraninda olumlu/tesekkur icerikleri ayri filtreye alindi.
- Sol panelde geri bildirimle ilgili ekranlar `Geri Bildirim` basligi altinda toplandi.
- Dogrulama: `npm.cmd run check` basarili; 47/47 test gecti.

## 24. 2026-07-10 Final Feedback Temizlik Turu

- Canli feedback kuyrugundaki 52 acik kayit kullanici onayiyla `feedback-cleanup-2026-07-10` cozum grubunda kapatildi.
- Son canli kontrolde acik feedback sayisi `0` olarak dogrulandi.
- 7 kullaniciya kisisel cozum bildirimi gonderildi: Hacer Terzi, Sumeyye Ozkul, Elcin Akay, Aysun Aydoner, Nuray Ardagumusoglu, Ebru Kalayci ve Serap Pamuk.
- Bildirimlerin son hali okunur baslik, kullanici adi ve mesaj metniyle tekrar kontrol edildi.
- Yeni kalite korumalari test kapsaminda: ekli `vucud` kelimeleri, `kadirdir`, sure/standart kaynakli yanlis-pozitifler, surecler arasi virgulleme/noktalama ve `Irade eksikligi` bicimi.
- Dogrulama: `npm.cmd run check` basarili; 49/49 test gecti.
- Production dogrulama: `95c7621` commit'i deploy edildi; `/health` canli ortamda `ok` dondu.

## 25. 2026-07-12 Yeni Feedback Koruma Turu

- 11-12 Temmuz canli feedbacklerinde gelen 17 yeni vaka kullanici lehine degerlendirildi.
- Sistem artik su baglamlari yanlis pozitif olarak skorlamaz ve duzeltilmis metne uygulamaz:
  `Kadir -> Kaadir`, `Kadiri -> Kaadiri`, `Vel Asr -> Vel-Asr`, sure/ayet referans formatini
  nokta standardina zorlama, tablo sablonundaki referans bosluklarini degistirme,
  `Allah -> Allahu Teala` baglam genisletmesi, Arapca ayet kelimesi `dinehum`, `hadisi -> hadis-i`,
  `Allah'da -> Allah'ta`, `sagir -> sagir`, `ukba -> ukba`, `rahmete -> rahmeti`.
- `Zuruf -> Zumer` yanlis eslesmesi engellendi; `Zuruf` gorulurse dogru standart `Zuhruf` olarak uygulanir.
- `Kadir` genel kelime/kaynak ismi olarak otomatik `Kaadir` yapilmaz; yalniz `kadirdir -> kaadirdir`
  standardi korunur.
- Dogrulama: `npm.cmd run check` basarili; 50/50 test gecti.
- Canli operasyon: production deploy sonrasi 18 acik feedback kaydi `feedback-fix-2026-07-12-1783851067872`
  cozum grubuyla kapatildi. 4 kullaniciya kisisel cozum bildirimi gonderildi ve son canli kontrolde
  acik feedback sayisi `0` olarak dogrulandi.

## 26. 2026-07-13 Ek Feedback Koruma Turu

- 6 yeni canli feedback kullanici lehine cozuldu.
- Namaz rekat dagilimini anlam olarak bozan otomatik virgulleme reddedilir.
- `vaad/vaadde` kok kullanimi korunur; `vaatte` yapilmaz.
- `afetlerine` kelimesi sapkali bicime zorlanmaz.
- `...` ve ellipsis farki tek basina hata sayilmaz.
- `biraraya` sozluk standardi olarak korunur; kaynakta `bir araya` gecerse `biraraya` yapilir.
- `19 tane haslet ruhun` ifadesi `Ruhta 19 tane haslet` olarak deterministic duzeltilir.
- Dogrulama: `npm.cmd run check` basarili; 51/51 test gecti.
- Canli operasyon: production deploy sonrasi 6 acik feedback kaydi
  `feedback-fix-2026-07-13-1783893985888` cozum grubuyla kapatildi. 3 kullaniciya kisisel
  cozum bildirimi gonderildi ve son kontrolde acik feedback sayisi `0`.

## 27. 2026-07-13 Kritik Uygulama Katmani Duzeltmesi

- Sorun: Sistem bazi durumlarda hatayi bulup listeliyor, fakat duzeltilmis metne uygulamadan
  sonucu veriyordu. Bu ozellikle apostrof, tirnak ve bosluk karakteri kaynak/model arasinda
  farkli oldugunda ortaya cikabiliyordu.
- Cozum: `applyAcceptedIssues` artik kaynakta canonical olarak dogrulanan issue'lari duzeltilmis
  metne de toleransli regex ile uygular.
- Cift tirnak korumasi: Modelin ekledigi gereksiz `""...""` bicimleri temizlenir; metin icindeki
  normal alinti tirnaklari korunur.
- Dogrulama: `npm.cmd run check` basarili; 53/53 test gecti.
- Canli operasyon: Aysun Aydoner'in 2 acik feedback kaydi
  `feedback-fix-2026-07-13-apply-1783962347176` cozum grubuyla kapatildi. Kisisel cozum
  bildirimi gonderildi ve son kontrolde acik feedback sayisi `0`.

## 28. 2026-07-14 Uc Acik Feedback Koruma Turu

- Hacer Terzi tarafindan bildirilen 3 yeni canli feedback kullanici lehine cozuldu.
- Kaynak metinde nokta zaten varsa `lazim -> lazim.` gibi tek kelimelik nokta bulgusu
  tekrar hata sayilmaz.
- `kitab -> kitâb` sapkalama zorlamasi reddedilir; ayet/meâl baglaminda kelime keyfi
  bicimde sapkalandirilmaz.
- `3/ALI IMRAN-20` gibi bosluklu/cok kelimeli sure adi iceren meal referanslari nokta
  standardina zorlanmaz.
- Tekrar sebebi kayda alindi: onceki referans korumasi tek kelimeli sure adlarini kapsiyor,
  `ALI IMRAN` gibi bosluklu referanslari kaciriyordu. Kural genellendi.
- Dogrulama: `npm.cmd run check` basarili; 54/54 test gecti.
- Canli operasyon: 3 acik feedback `feedback-fix-2026-07-14-hacer-1783977404365` cozum
  grubuyla kapatildi. Hacer Terzi icin tek kisisel cozum bildirimi gonderildi ve son
  kontrolde acik feedback sayisi `0`.

## 29. Feedback Kok Kategori ve Tekrar Uyarisi

- Sistem feedback mesajlarini kok kategoriye ayirir: referans/sure formati, noktalama,
  sapka/sozluk, tirnak, duzeltilmis metne uygulama, duzen/paragraf, kaynakta olmayan icerik
  ve genel kalite.
- Acik feedback daha once cozulmus ayni kok kategoriye benziyorsa Geri Bildirim Merkezi
  kartinda admin icin uyarilir. Kartta kategori adi, daha once kac kez cozuldugu ve son
  cozum tarihi gorunur.
- Cozum kapatilirken kok kategori bilgisi kullaniciya giden mesaji sisirmez; yalniz
  admin ic kayitlarinda `resolution_note` ve `issue_resolution_log.summary` icinde saklanir.
- Bu sistem tekrar eden kok sorunlari manuel olarak yeniden kesfetmeyi azaltmak icin eklendi.
- Dogrulama: `npm.cmd run check` basarili; 54/54 test gecti.

## 30. 2026-07-15 18 Acik Feedback Kok Koruma Turu

- 18 acik feedback tek kok koruma turunda ele alindi.
- Kalite katmani artik su tekrar eden hatalari skorlamaz ve duzeltilmis metne uygulamaz:
  cift/dis tirnak uretimi, Arapca ayet/transliterasyon parantez ve bosluk bozma,
  `cihad/Ebu` sapka zorlamasi, sure apostrof dusurme, noktalı virgulu iki noktaya zorlama,
  ayri cumleyi virgul ile birlestirme, `Eûzü...` duasini bitisiklestirme,
  `inşaallah -> inşallah`, metinde olmayan `kasiyet -> kasvet`, `lâzımgelen -> lâzım gelen`,
  ayet icinde `dîni/dîne -> dini/dine` ve `Hz. İsa’ya -> Hazreti İsa (A.S)’ya`.
- Sistem `Şura` yazimini deterministik olarak `Şûrâ` bicimine duzeltir; sadece buyuk/kucuk
  harf farkini hata saymaz.
- Dogrulama: `npm.cmd run check` basarili; 56/56 test gecti.
