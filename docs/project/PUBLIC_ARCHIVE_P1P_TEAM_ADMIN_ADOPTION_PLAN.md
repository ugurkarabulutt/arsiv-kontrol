# Public Archive P1P Team Admin Adoption Plan

Tarih: 2026-08-03
Durum: Docs-only communication and monitoring plan

## A. Current Production State

P1O production parallel `/admin` rollout tamamlandi.

Canli durum:

| Route | Durum |
| --- | --- |
| `https://arsiv.ibrahimlive.ai/` | Legacy ekip/admin paneli olarak calisiyor. |
| `https://arsiv.ibrahimlive.ai/admin` | Yeni paralel ekip/admin calisma adresi olarak calisiyor. |
| Public root archive | Aktif degil. |
| Root public cutover | Yapilmadi. |

Bu P1P adimi:

- Production deploy degildir.
- Kod gelistirme degildir.
- Feedback fix degildir.
- Public frontend veya public archive acilisi degildir.
- Kullanici soru sistemi degildir.

P1Q hygiene karari korunur:

- Ana workspace production deploy kaynagi olarak kullanilmaz.
- Admin gelistirmeleri tek ortak admin app'e yapilir.
- Her admin degisikligi hem `/` hem `/admin` uzerinde test edilir.
- Feedback/denetim motoru, public frontend ve kullanici soru sistemi ayri is
  hatlaridir.

## B. Team Communication Message

Ekibe gonderilecek kisa duyuru taslagi:

```text
Merhaba,

Arsiv Kontrol icin yeni calisma adresimizi kullanima actik:

https://arsiv.ibrahimlive.ai/admin

Eski adresimiz su an kapanmadi. Bir sure iki adres de birlikte calismaya devam
edecek. Bu gecis doneminde mumkun oldukca yeni /admin adresini kullanmanizi
rica ediyoruz.

Bu asamada public soru-cevap arsivi acilmadi; sadece ekip calisma adresimiz
paralel olarak hazirlandi.

Giris, denetim, onaya gonderme, onay/red, bildirimler, standartlar veya mobil
kullanimda herhangi bir sorun gorurseniz lutfen ekran goruntusuyle birlikte
bize bildirin.

Tesekkurler.
```

Alternatif daha kisa mesaj:

```text
Yeni calisma adresimiz:
https://arsiv.ibrahimlive.ai/admin

Eski adres su an kapanmadi; bir sure iki adres birlikte calisacak. Mumkun
oldukca yeni adresi kullanmanizi rica ediyoruz. Sorun gorurseniz ekran
goruntusuyle bildirmeniz yeterli.
```

## C. Monitoring Window

Izleme penceresi:

```text
Ilk 24-48 saat
```

Izleme hedefi:

- Ekip yeni `/admin` adresini kullanirken login/session ve temel is akislarinda
  sorun olup olmadigini anlamak.
- Root `/` legacy panelin yedek olarak calismaya devam ettigini dogrulamak.
- Public root archive'in yanlislikla aktif olmadigini takip etmek.
- Genis 39-user transition icin Go/No-Go karari verecek kanit toplamak.

Izlenecek sinyaller:

- Kullanici bildirimi.
- Ekran goruntusu.
- Saat ve rol bilgisi.
- Tarayici/cihaz bilgisi.
- Teknik ekip smoke kontrolu.
- Kritik durumda `/api/auth/me` response tipinin JSON/non-HTML kalmasi.

Bu izleme sirasinda:

- Eski root kapatilmaz.
- Root public archive'e cevrilmez.
- DB migration yapilmaz.
- Feedback kapatma veya data fix bu hatta alinmaz.

## D. Monitoring Checklist

24-48 saatlik izleme checklist'i:

| Area | Check | Expected | Result |
| --- | --- | --- | --- |
| Login | `/admin` uzerinden giris | Basarili login | `PENDING` |
| Logout | Cikis yapma | Session kapanir, login ekrani gelir | `PENDING` |
| Session | Sayfa yenileme | Aktif session korunur | `PENDING` |
| Session | Yeni sekmede `/admin` acma | Ayni session calisir | `PENDING` |
| Route | `/admin` acilisi | 200 HTML admin shell | `PENDING` |
| Route | `/admin/` acilisi | 200 HTML admin shell | `PENDING` |
| Route | `/admin/smoke-test` deep link | 200 HTML admin shell | `PENDING` |
| Root | `/` legacy panel | Eski calisma adresi calismaya devam eder | `PENDING` |
| API | `/api/auth/me` | JSON/non-HTML; 500 yok | `PENDING` |
| Asset | `manifest.webmanifest` | 200 | `PENDING` |
| Asset | `sw.js` | 200 | `PENDING` |
| Asset | `favicon.ico` | 200 | `PENDING` |
| User workflow | Normal kullanici ekrani | Rolune uygun ekran | `PENDING` |
| Admin workflow | Admin ekrani | Admin paneli ve is listeleri | `PENDING` |
| Super admin workflow | Super admin ekrani | Super admin alanlari dogru | `PENDING` |
| Analysis | Metin denetimi | Denetim baslar ve sonuc doner | `PENDING` |
| Submission | Onaya gonderme | Guvenli test kaydi onaya gider | `PENDING` |
| Approval | Onay/red | Guvenli test kaydinda calisir | `PENDING` |
| Notifications | Bildirimler | Liste yuklenir, HTML fallback yok | `PENDING` |
| Standards | Standartlar | Ekran yuklenir | `PENDING` |
| Reports | Rapor/dashboard | Ekran yuklenir | `PENDING` |
| Mobile | Mobil giris | Login ve menu kullanilabilir | `PENDING` |
| Mobile | Mobil denetim | Text input ve ana aksiyonlar kullanilabilir | `PENDING` |
| Mobile | Mobil refresh | Session ve layout korunur | `PENDING` |

Monitoring result values:

- `PASS`
- `FAIL`
- `NOT TESTED`
- `BLOCKED`

## E. Issue Report Template

Ekip sorun bildirirken su formu doldurabilir:

```text
Ad:
Rol: Ekip Uyesi / Admin / Super Admin
Cihaz: Telefon / Bilgisayar / Tablet
Tarayici: Chrome / Safari / Edge / Diger
Kullanilan adres: / veya /admin
Islem: Ne yapmaya calisiyordunuz?
Hata aciklamasi: Ekranda ne oldu?
Saat:
Tekrar ediyor mu? Evet / Hayir / Bazen
Ekran goruntusu var mi? Evet / Hayir
Not:
```

Teknik ekip icin ek alanlar:

```text
Issue ID:
Severity:
Route:
HTTP status:
Content-Type:
Console error:
Network error:
Owner:
Status:
```

Kayit kurallari:

- Sifre, cookie, token veya secret yazilmaz.
- Gercek kullanici verisi gerekiyorsa herkese acik dokumana yazilmaz.
- Onay/red testleri yalniz acikca isaretlenmis guvenli test kaydi ile yapilir.
- Gercek kayit yanlislikla degistirilirse en az `Critical` kabul edilir.

## F. Severity Classification

| Severity | Tanim | Ornek |
| --- | --- | --- |
| `Blocker` | Gecis durur; ekip calisamaz veya guvenlik riski vardir. | Giriş yapılamıyor; session sürekli düşüyor; root bozuluyor; `/api` HTML fallback oluyor. |
| `Critical` | Temel is akisi veya yetki guvenligi bozulur. | Normal kullanici admin alani goruyor; admin/super admin paneli acilmiyor; onay/red calismiyor. |
| `Major` | Gecis devam edebilir ama 39-user adoption oncesi fix gerekir. | Mobilde ana aksiyon kullanilamiyor; bildirim/standartlar sik hata veriyor. |
| `Minor` | Dusuk riskli, workaround'i olan kullanim/gorsel sorun. | Kucuk layout tasmasi, bir buton metni net degil. |
| `Observation` | Hata degil; not veya iyilestirme onerisi. | Kullanim aliskanligi, menu sirasi onerisi. |

Blocker ornekleri:

- `/admin` login calismiyor.
- Session surekli dusuyor.
- Normal kullanici admin alanlarini goruyor.
- Admin paneli veya super admin paneli acilmiyor.
- `/api/auth/me` HTML fallback oluyor.
- `/` legacy panel bozuluyor.
- Public root archive yanlislikla gorunuyor.

Critical ornekleri:

- Admin onay/red isleyemiyor.
- Kullanici kendi ekraninda baska role ait veri/aksiyon goruyor.
- Denetim sonucu kayboluyor veya yanlis kayda gidiyor.
- Mobilde login var ama temel is akisi yapilamiyor.

## G. Gradual Adoption Plan

### Gun 1-2

- Ekibe yeni adres duyurulur:
  `https://arsiv.ibrahimlive.ai/admin`
- Eski root `/` yedek olarak acik kalir.
- Kullanicilardan mumkun oldukca yeni adresi kullanmalari rica edilir.
- Blocker/Critical sorunlar aninda kayda alinir.
- Teknik ekip route/API/asset smoke kontrollerini tekrar edebilir.

### Gun 3-7

- Ekipten cogunlugun `/admin` kullanmaya baslamasi hedeflenir.
- Eski root hala kapanmaz.
- Tekrarlayan login/session/mobil/yetki sorunlari aranir.
- Admin ve super admin akislarinda onay/red ve dashboard kullanimi izlenir.
- Normal kullanici denetim/onaya gonderme akisi izlenir.

### Monitoring tamamlanmadan

- Eski root kapatilmaz.
- Root public archive'e cevrilmez.
- 39-user transition duyurusu "zorunlu yeni adres" tonuna alinmaz.
- Public frontend veya user question scope baslatilsa bile root cutover yapilmaz.

### Monitoring temizse

- Yeni `/admin` adresi ekip icin birincil calisma adresi olarak kabul edilir.
- Eski root bir sure daha yedek olarak kalabilir.
- Root public cutover ayri faz ve ayri onay konusu olur.

## H. Go / No-Go Criteria

### Go for wider `/admin` adoption

39-user `/admin` adoption icin Go ancak su kosullarla verilir:

- Ilk 24-48 saatte Blocker veya Critical sorun yok.
- Login stabil.
- Logout calisiyor.
- Session refresh stabil.
- `/admin` ve `/admin/*` aciliyor.
- `/api/auth/me` JSON/non-HTML donuyor.
- Normal kullanici ekrani dogru.
- Admin ekrani dogru.
- Super admin ekrani dogru.
- Rol sinirlari dogru.
- Metin denetimi calisiyor.
- Onaya gonderme calisiyor.
- Admin onay/red calisiyor.
- Bildirimler, standartlar ve dashboard temel olarak calisiyor.
- Mobil temel kullanim calisiyor.
- Root `/` legacy panel olarak korunuyor.
- Public archive aktif degil.

### Conditional Go

Conditional Go yalniz su durumda dusunulur:

- Blocker/Critical yok.
- Yalniz Minor veya dusuk riskli Major issue var.
- Issue icin net workaround veya kisa fix plani var.
- Eski root yedek olarak acik kalmaya devam eder.

### No-Go

Asagidaki durumlardan biri varsa 39-user adoption genisletilmez:

- Login/session problemi.
- Yetki ihlali.
- `/api/*` HTML fallback.
- Root `/` etkilenmesi.
- Public archive'in yanlislikla acilmasi.
- Admin temel akislarinin calismamasi.
- Normal kullanici denetim/onaya gonderme akisinin bozulmasi.
- Mobil temel kullanimda Blocker/Critical sorun.
- Static asset yukleme sorunu ana kullanimi bozuyorsa.

## I. Next Recommended Step

Onerilen siradaki guvenli adim:

```text
P1P monitoring execution: 24-48 saatlik ekip kullanimi ve issue log takibi.
```

Monitoring temizse:

1. `/admin` ekip icin birincil adres ilan edilir.
2. Eski root bir sure daha yedek kalir.
3. P1R dirty admin/feedback workstream isolation audit baslatilir.
4. P2B public frontend UX/design plan ayri hatta ilerler.
5. P2A user question intake architecture ayri hatta ilerler.
6. Root public cutover en son, ayri onayla ele alinir.

Monitoring No-Go ise:

1. Sorun severity ile kayda alinir.
2. Eski root yedek olarak kullanilmaya devam eder.
3. Dar kapsamli fix plan hazirlanir.
4. Production'a yeni deploy yalniz temiz patch/branch ile ve ayri onayla yapilir.
