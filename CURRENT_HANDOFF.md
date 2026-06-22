# CURRENT_HANDOFF — Arşiv Kontrol AI

Son güncelleme: 2026-06-22 — OpenAI Codex

## Durum

- Dal: `codex/vercel-arsiv-production`
- Uzak depo: `origin` → `https://github.com/ugurkarabulutt/arsiv-kontrol.git`
- Vercel projesi: `ugurkarabulutts-projects/arsiv-kontrol` oluşturuldu ve yerel klasöre bağlandı.
- Production deploy: `https://arsiv-kontrol.vercel.app` hazır.
- Özel alan adı: `https://arsiv.ibrahimlive.ai` production aliasına başarıyla bağlandı.
- Git: dosyalar stage edildi; Windows `.git/objects` ACL kilidi commit nesnesi yazımını engelliyor.
- Kullanıcı veya diğer ajan değişiklikleri izinsiz geri alınmamalı.

## Bu çalışma ağacındaki değişiklikler

- Her hata instance'ını ayrı issue yapan güçlendirilmiş AI promptu.
- Issue sayısına dayalı yetkili puanlama ve 60-altı kesin davranışı.
- SHA-256 tekrar gönderim kontrolü ve eski hash desteği.
- Güvenilir geçmiş detay API'si ve çalışan Gör butonu.
- PDFKit + Noto Serif ile gerçek PDF.
- Seed'i beklemeyen `GET /health` endpoint'i.
- Otomatik testler ve ortak ajan çalışma protokolü.
- Vercel uyumu: serverless export, imzalı cookie oturumu, 4 MB dosya sınırı ve dosya başına
  ayrı çalışan iki eşzamanlı toplu analiz işçisi.

## Doğrulama

- `npm test`: 5/5 başarılı.
- `node --check server.js`: başarılı.
- Frontend inline JavaScript parse kontrolü: başarılı.
- Yerel `GET /health`: HTTP 200 ve `{"status":"ok"}`.
- Vercel production `GET /health`: `{"status":"ok"}`.
- Vercel production `GET /api/auth/me`: `{"loggedIn":false}`.
- Canlı uçtan uca smoke test: geçici kullanıcıyla login ve GPT analizi başarılı;
  skor 87, 3 issue ve düzeltilmiş metin döndü. Test kullanıcısı/geçmişi silindi.
- Canlı Supabase salt-okunur kontrolü bağlantıda zaman aşımına uğradı; veri değiştirilmedi.

## Sonraki güvenli adım

1. `npm run check` çalıştır.
2. Geçerli ekip kullanıcısıyla geçmiş Gör ve PDF akışını kullanıcı arayüzünden doğrula.
3. `.git/objects` ACL kilidi kalkınca commit ve push yap; Vercel GitHub bağlantısını tamamla.

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
