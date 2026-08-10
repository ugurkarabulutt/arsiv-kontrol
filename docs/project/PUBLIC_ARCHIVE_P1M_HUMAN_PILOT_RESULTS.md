# Public Archive P1M Human Pilot Test Form and Results

Tarih: 2026-08-02
Son guncelleme: 2026-08-03
Durum: P1O production parallel `/admin` rollout icin Super Admin, Admin, Standard User ve Super Admin Mobile pilotlari PASS; 39-user transition ayri asamadir

## A. Scope

Bu dokuman P1M insan pilotu icin uygulanacak test formunu ve sonuc kayit
sablonunu tanimlar. Pilot yalniz mevcut Vercel Preview URL uzerinde
calistirilacaktir:

```text
https://arsiv-kontrol-bxxlhrueb-ugurkarabulutts-projects.vercel.app/admin
```

Bu adimda production deploy, production alias, live root cutover, 39 kullanici
duyurusu, public archive aktivasyonu, kod degisikligi, commit, push, DB
migration, feedback islemi veya kullanici soru sistemi calismasi yoktur.

Pilot sonuc kayitlari kullanicilar tarafindan aktarildikca bu dokuman
gercek PASS/FAIL/NOT TESTED/BLOCKED sonuclariyla guncellenmelidir. Bu
guncellemede kullanicinin net bildirdigi Super Admin PC, Super Admin Mobile,
Admin ve Standard User/Ekip Uyesi sonuclari PASS olarak islenmistir. Bu PASS
karari yalniz production parallel `/admin` rollout gate'i icindir; 39-user
transition duyurusu ve genis ekip yonlendirmesi ayri asamada yapilacaktir.

## B. Result Status Legend

Her test maddesi yalniz su durumlardan biriyle kaydedilecektir:

| Status | Anlam |
| --- | --- |
| `PASS` | Test beklenen sonucu verdi. |
| `FAIL` | Test calisti ama beklenen sonucu vermedi. |
| `NOT TESTED` | Test henuz calistirilmadi. |
| `BLOCKED` | Test, onceki bir hata/eksik bilgi/ortam sorunu nedeniyle calistirilamadi. |

## C. Issue Severity Legend

Bulunan her sorun su severity siniflarindan biriyle kaydedilecektir:

| Severity | Anlam |
| --- | --- |
| `Blocker` | Pilot veya 39-user transition durur. Login calismamasi, session kaybi, yanlis role erisim, API HTML fallback, root degisimi, production etkisi. |
| `Critical` | Temel is akisini veya yetki guvenligini bozar. Onay/red bozulmasi, admin/user siniri ihlali, veri kaybi riski. |
| `Major` | Pilot ilerleyebilir ama 39-user transition oncesi fix gerekir. Onemli UI/API hata veya sik tekrar eden kullanim sorunu. |
| `Minor` | Dusuk riskli gorsel/kullanim sorunu. Gecisi tek basina durdurmaz. |
| `Observation` | Not veya iyilestirme onerisi. Hata sayilmayabilir. |

## D. Production and Data Safety Rules

Pilot sirasinda su kurallar zorunludur:

- Production domain kullanilmayacak:
  `https://arsiv.ibrahimlive.ai`
- 39 kullaniciya duyuru yapilmayacak.
- Kullanici grubu `/admin` adresine topluca yonlendirilmeyecek.
- Yalniz acikca isaretlenmis guvenli test kaydi kullanilacak.
- Gercek onay kuyruğu kayitlari yanlislikla onaylanmayacak veya
  reddedilmeyecek.
- Gercek kullanici silinmeyecek.
- Kalici rol degisikligi yapilmayacak.
- Hassas veri, cookie, token veya secret rapora yazilmayacak.
- Manuel SQL veya dogrudan DB yazimi yapilmayacak.
- Feedback konusu bu hatta test edilmeyecek veya islenmeyecek.
- Public archive acilmayacak.

Guvenli test kaydi etiketi:

```text
P1M ADMIN PILOT TEST - SAFE TEST RECORD - DO NOT USE REAL QUEUE ITEMS
```

## E. Pilot Roster Form

Pilot kullanici isimleri bu dokumana yazilmayabilir. Operasyon ekibi isterse
isimleri ayri, guvenli ve dahili listede tutabilir.

| Pilot | Role | Device | Browser | Test time | Tester confirmation | Screenshot/log required | Overall result |
| --- | --- | --- | --- | --- | --- | --- | --- |
| Super Admin Pilot | `super_admin` | PC | Browser not recorded | 2026-08-03 user-reported | User reported no issue as super admin | User report | `PASS` |
| Admin Pilot | `admin` | Browser not recorded | Browser not recorded | 2026-08-03 user-reported | User reported admin-side tests were completed and issues resolved | User report | `PASS` |
| Standard User Pilot | `user` | Browser not recorded | Browser not recorded | 2026-08-03 user-reported | User reported team-member tests were completed and issues resolved | User report | `PASS` |
| Mobile Pilot | `super_admin` | Mobile phone | Mobile browser not recorded | 2026-08-03 user-reported | User reported no issue as super admin on mobile | User report | `PASS` |

## F. Common Test Form

Bu ortak maddeler dort pilot rol icin de calistirilir.

| ID | Test | Expected result | Super Admin | Admin | Standard User | Mobile | Notes |
| --- | --- | --- | --- | --- | --- | --- | --- |
| C-01 | Open `/admin` | Login/app shell loads; no blank page | `PASS` | `PASS` | `PASS` | `PASS` | User-reported pilot completion |
| C-02 | Login | Correct role logs in successfully | `PASS` | `PASS` | `PASS` | `PASS` | User-reported pilot completion |
| C-03 | Logout | Session clears; protected UI no longer accessible | `PASS` | `PASS` | `PASS` | `PASS` | User-reported pilot completion |
| C-04 | Session refresh | Browser refresh keeps valid session | `PASS` | `PASS` | `PASS` | `PASS` | User-reported pilot completion |
| C-05 | New tab `/admin` | Same valid session appears in new tab | `PASS` | `PASS` | `PASS` | `PASS` | User-reported pilot completion |
| C-06 | Deep link `/admin/smoke-test` | Admin shell loads; no 404 or blank page | `PASS` | `PASS` | `PASS` | `PASS` | User-reported pilot completion |
| C-07 | Back/forward | Browser navigation does not trap or logout unexpectedly | `PASS` | `PASS` | `PASS` | `PASS` | User-reported pilot completion |
| C-08 | Asset loading | Icons, manifest, service worker, CSS/JS work | `PASS` | `PASS` | `PASS` | `PASS` | User-reported pilot completion |
| C-09 | API calls | `/api/...` responses are JSON or expected non-HTML; no index fallback | `PASS` | `PASS` | `PASS` | `PASS` | User-reported pilot completion plus P1L/P1O smoke |
| C-10 | Root preservation check | `/` still legacy shell; public archive not active | `PASS` | `PASS` | `PASS` | `PASS` | P1L/P1O smoke verified |

## G. Super Admin Pilot Form

Super Admin Pilot yalniz guvenli/read-only veya geri alinabilir islemler yapar.
Kullanici silme, kalici rol degistirme veya production etkili islem yoktur.

| ID | Test | Expected result | Result | Evidence | Issue ID |
| --- | --- | --- | --- | --- | --- |
| SA-01 | `/admin` login | Super admin dashboard/panel opens | `PASS` | User-reported PC/mobile |  |
| SA-02 | Logout | Session clears | `PASS` | User-reported PC/mobile |  |
| SA-03 | Session refresh | Refresh after login preserves session | `PASS` | User-reported PC/mobile |  |
| SA-04 | New tab | `/admin` opens with same session | `PASS` | User-reported PC/mobile |  |
| SA-05 | Deep link | `/admin/smoke-test` returns app shell while logged in | `PASS` | User-reported PC/mobile |  |
| SA-06 | Role boundary: super admin access | Super-admin-only areas visible as expected | `PASS` | User-reported PC/mobile |  |
| SA-07 | User management view | User list/management screen opens without deleting/changing users | `PASS` | User-reported; no destructive action recorded |  |
| SA-08 | Role/permission screens | Screens visible; no permanent role change performed | `PASS` | User-reported; no permanent role change recorded |  |
| SA-09 | Admin functions | Admin dashboard, standards, reports load | `PASS` | User-reported PC/mobile |  |
| SA-10 | Unauthorized boundary check | Normal/admin-only boundaries documented using safe visual checks | `PASS` | User-reported PC/mobile |  |
| SA-11 | API/asset errors | No HTML fallback or broken asset observed | `PASS` | User-reported PC/mobile |  |
| SA-12 | Issue summary | Any issue recorded with severity | `PASS` | No issue reported by user |  |

## H. Admin Pilot Form

Admin Pilot yalniz acikca isaretlenmis test kaydi uzerinde onay/red akisini
denemelidir. Gercek queue kayitlari kullanilmaz.

| ID | Test | Expected result | Result | Evidence | Issue ID |
| --- | --- | --- | --- | --- | --- |
| AD-01 | `/admin` login | Admin panel opens | `PASS` | User-reported admin pilot complete |  |
| AD-02 | Logout | Session clears | `PASS` | User-reported admin pilot complete |  |
| AD-03 | Session refresh | Refresh preserves session | `PASS` | User-reported admin pilot complete |  |
| AD-04 | New tab | `/admin` opens with same session | `PASS` | User-reported admin pilot complete |  |
| AD-05 | Deep link | `/admin/smoke-test` returns app shell while logged in | `PASS` | User-reported admin pilot complete |  |
| AD-06 | Role boundary: no super admin powers | Super-admin-only destructive controls unavailable | `PASS` | User-reported admin pilot complete |  |
| AD-07 | Approval board | Queue/list opens | `PASS` | User-reported admin pilot complete |  |
| AD-08 | Open safe test record | Clearly marked P1M test record opens | `PASS` | User-reported admin pilot complete |  |
| AD-09 | Approve safe test record | Only safe test record approved; real records untouched | `PASS` | User-reported admin pilot complete; Codex did not touch DB |  |
| AD-10 | Reject safe test record | Only safe test record rejected if using separate safe record | `PASS` | User-reported admin pilot complete; Codex did not touch DB |  |
| AD-11 | Notifications | Admin notifications load | `PASS` | User-reported admin pilot complete |  |
| AD-12 | Standards | Standards screen loads | `PASS` | User-reported admin pilot complete |  |
| AD-13 | Reports/dashboard | Dashboard/reporting loads | `PASS` | User-reported admin pilot complete |  |
| AD-14 | API/asset errors | No HTML fallback or broken asset observed | `PASS` | User-reported admin pilot complete plus P1O smoke |  |
| AD-15 | Issue summary | Any issue recorded with severity | `PASS` | Issues reported earlier were resolved before P1O approval |  |

## I. Standard User Pilot Form

Standard User Pilot yeni ve guvenli test metniyle calisir. Sonuc onaya
gonderilecekse kayit acikca P1M test kaydi olarak isaretli olmalidir.

| ID | Test | Expected result | Result | Evidence | Issue ID |
| --- | --- | --- | --- | --- | --- |
| SU-01 | `/admin` login | Standard user panel opens | `PASS` | User-reported team-member pilot complete |  |
| SU-02 | Logout | Session clears | `PASS` | User-reported team-member pilot complete |  |
| SU-03 | Session refresh | Refresh preserves session | `PASS` | User-reported team-member pilot complete |  |
| SU-04 | New tab | `/admin` opens with same session | `PASS` | User-reported team-member pilot complete |  |
| SU-05 | Deep link | `/admin/smoke-test` returns app shell while logged in | `PASS` | User-reported team-member pilot complete |  |
| SU-06 | Role boundary: no admin screens | Admin-only screens/actions unavailable | `PASS` | User-reported team-member pilot complete |  |
| SU-07 | Text input/upload | Safe test text/file can be entered | `PASS` | User-reported team-member pilot complete |  |
| SU-08 | Start analysis | Analysis starts without route/session error | `PASS` | User-reported team-member pilot complete |  |
| SU-09 | View result | Result renders correctly | `PASS` | User-reported team-member pilot complete |  |
| SU-10 | Submit approval | Clearly marked safe test record submitted | `PASS` | User-reported team-member pilot complete; Codex did not touch DB |  |
| SU-11 | Own history | User sees own records only | `PASS` | User-reported team-member pilot complete |  |
| SU-12 | Notifications | User notifications load | `PASS` | User-reported team-member pilot complete |  |
| SU-13 | API/asset errors | No HTML fallback or broken asset observed | `PASS` | User-reported team-member pilot complete plus P1O smoke |  |
| SU-14 | Issue summary | Any issue recorded with severity | `PASS` | Issues reported earlier were resolved before P1O approval |  |

## J. Mobile Pilot Form

Mobile Pilot gercek mobil cihazda calistirilir. Mobil kullanici standard user,
admin veya super admin olabilir; hangi role ile test edildigi kaydedilmelidir.

| ID | Test | Expected result | Result | Evidence | Issue ID |
| --- | --- | --- | --- | --- | --- |
| MO-01 | Mobile `/admin` login | Login works on mobile browser | `PASS` | User-reported super admin mobile |  |
| MO-02 | Mobile logout | Session clears | `PASS` | User-reported super admin mobile |  |
| MO-03 | Mobile session refresh | Refresh preserves session | `PASS` | User-reported super admin mobile |  |
| MO-04 | Mobile new tab | `/admin` opens with expected session | `PASS` | User-reported super admin mobile |  |
| MO-05 | Mobile deep link | `/admin/smoke-test` loads app shell | `PASS` | User-reported super admin mobile |  |
| MO-06 | Responsive layout | No blocking overlap; menu usable | `PASS` | User-reported super admin mobile |  |
| MO-07 | Text input | Text input usable on mobile | `PASS` | User-reported super admin mobile |  |
| MO-08 | Analysis | Safe test analysis starts/completes | `PASS` | User-reported super admin mobile |  |
| MO-09 | Submit approval | Safe test record can be submitted if role supports it | `PASS` | User-reported super admin mobile; Codex did not touch DB |  |
| MO-10 | Notifications/panel | Mobile panel and notifications usable | `PASS` | User-reported super admin mobile |  |
| MO-11 | Back/forward | Mobile back/forward works without trapping user | `PASS` | User-reported super admin mobile |  |
| MO-12 | API/asset errors | No HTML fallback or broken asset observed | `PASS` | User-reported super admin mobile plus P1O smoke |  |
| MO-13 | Issue summary | Any issue recorded with severity | `PASS` | No open pilot blocker/critical issue reported |  |

## K. API and Asset Quick Checks

Pilot sirasinda browser network panelinde veya teknik operatorde su kontroller
kaydedilmelidir:

| Check | Expected | Result | Notes |
| --- | --- | --- | --- |
| `/api/auth/me` after login | JSON with correct logged-in state/role | `PASS` | User-reported pilot plus non-auth smoke |
| `/api/auth/me` after logout | JSON logged-out or expected auth response | `PASS` | P1O smoke returned `{"loggedIn":false}` |
| Role-specific `/api/...` calls | JSON; role-appropriate status | `PASS` | User-reported pilot |
| API fallback | No `/api/...` request returns `index.html` | `PASS` | P1O smoke confirmed `/api/auth/me` non-HTML |
| `/manifest.webmanifest` | Loads | `PASS` | P1O smoke |
| `/sw.js` | Loads | `PASS` | P1O smoke |
| `/favicon.ico` | Loads | `PASS` | P1O smoke |
| Icon/static assets | Load without broken paths | `PASS` | User-reported pilot plus P1O smoke |

## L. Issue Log Template

Her FAIL veya BLOCKED test icin bir issue satiri acilmalidir.

| Issue ID | Role | Test ID | Severity | Summary | Steps to reproduce | Expected | Actual | Evidence | Owner | Status |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| P1M-H-001 | TBD | TBD | TBD | TBD | TBD | TBD | TBD | Screenshot/log required | TBD | Open |

Issue yazim kurallari:

- Secret, password, cookie, token veya hassas veri yazilmaz.
- Gercek kullanici ismi gerekiyorsa rapor yerine guvenli dahili takipte tutulur.
- Gercek kayit id'si yazilacaksa kaydin P1M test kaydi oldugu net olmalidir.
- Real queue kaydi uzerinde yanlis islem yapildiysa severity en az `Critical`
  olmalidir.

## M. Current Result Summary

Bu dokuman ilk hazirlandiginda gercek insan pilot sonuclari pending idi.
2026-08-03 guncellemesinde kullanici Super Admin PC, Super Admin Mobile,
Admin ve Standard User/Ekip Uyesi testlerinin yapildigini, gorulen sorunlarin
cozuldugunu ve production parallel `/admin` rollout icin acik onay verdigini
bildirdi.

| Area | Current result |
| --- | --- |
| Super Admin Pilot | `PASS` on PC, user-reported |
| Admin Pilot | `PASS`, user-reported |
| Standard User Pilot | `PASS`, user-reported |
| Mobile Pilot | `PASS` as super admin mobile, user-reported |
| Login/logout/session | `PASS`, user-reported across pilot roles |
| Refresh/deep link | `PASS`, user-reported and smoke-verified |
| Role/permission boundaries | `PASS`, user-reported |
| User workflow | `PASS`, user-reported |
| Admin workflow | `PASS`, user-reported |
| Mobile workflow | `PASS` for super admin mobile, user-reported |
| API/asset role-level checks | `PASS`, user-reported plus P1O smoke |

## N. Go / Conditional Go / No-Go Template

39-user transition icin Go yalniz su sartlarin tamami saglanirsa verilebilir:

- Dort rolun tamami test edildi.
- Login/logout/session gecti.
- Refresh ve deep link gecti.
- Rol sinirlari dogru.
- Temel kullanici akislari gecti.
- Admin onay/red akislari yalniz guvenli test kaydiyla gecti.
- Mobil temel kullanim gecti.
- API HTML fallback yok.
- Asset path sorunu yok.
- Production etkilenmedi.
- Root `/` korundu.
- Public root aktif degil.
- Blocker veya Critical sorun yok.

Conditional Go yalniz su durumda dusunulebilir:

- Dort rolun tamami test edildi.
- Blocker/Critical yok.
- Yalniz Minor veya dusuk riskli Major sorunlar var.
- 39-user transition oncesi net fix veya operasyon workaround plani var.

No-Go su durumlardan herhangi birinde verilir:

- Dort rolun tamami test edilmedi.
- Herhangi bir Blocker veya Critical sorun var.
- Login/session problemi var.
- Rol/yetki ihlali var.
- `/api/...` HTML fallback var.
- Onay/red veya kullanici akisi bozuldu.
- Mobile temel kullanim bozuk.
- Production etkisi var.
- Root `/` degisti.
- Public archive aktif oldu.
- Gercek veriye zarar verildi.

Mevcut karar:

```text
Go for P1O production parallel /admin rollout.
Reason: Super Admin PC, Super Admin Mobile, Admin and Standard User/Ekip Uyesi
pilot results are user-reported PASS and preview/production smoke passed.

No automatic 39-user transition in P1O.
Reason: Team-wide communication and gradual adoption are separate P1P scope.
```

## O. Final Report Fill-In

Pilot tamamlandiktan sonra final rapor icin su alanlar doldurulacak:

| Field | Value |
| --- | --- |
| Preview URL used | `https://arsiv-kontrol-bxxlhrueb-ugurkarabulutts-projects.vercel.app/admin` |
| Four roles tested | PASS for Super Admin PC, Admin, Standard User/Ekip Uyesi and Super Admin Mobile by user report |
| Login/logout/session result | PASS by user report |
| Deep link/refresh result | PASS by user report and smoke evidence |
| Standard User result | PASS by user report |
| Admin result | PASS by user report |
| Super Admin result | PASS, user-reported PC/mobile |
| Mobile result | PASS for super admin mobile, user-reported |
| Role/permission boundaries | PASS by user report |
| Core workflows | PASS by user report |
| Issues found | Earlier pilot issues were reported resolved before P1O approval |
| Go/Conditional Go/No-Go | `Go for P1O production parallel /admin rollout; 39-user transition remains separate P1P scope` |
| Production untouched | No longer yes after P1O; production parallel `/admin` rollout executed, root remains preserved |
| Root `/` preserved | Must remain yes |
| Public root inactive | Must remain yes |
| Next safe step | P1P team communication and gradual `/admin` adoption |

## P. Next Step

P1O production parallel `/admin` rollout icin pilot gate kullanici bildirimiyle
tamamlandi. 39-user transition bu dokumanla otomatik baslamaz; ekip duyurusu,
gecis penceresi ve izleme P1P kapsaminda ayrica yurutulmelidir.
