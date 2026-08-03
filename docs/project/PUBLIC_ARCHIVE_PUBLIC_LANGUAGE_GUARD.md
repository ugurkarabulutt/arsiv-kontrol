# Public Arşiv Dil ve Veri Sızıntısı Koruması

Tarih: 2026-07-30
Durum: Test politikası, docs-only

## Amaç

Public arşiv, iç operasyon aracı gibi değil, public dini soru-cevap arşivi gibi okunmalıdır. Public UI, HTML, JSON-LD, sitemap-visible metinler ve public API response'ları iç süreç dilini veya operasyon verisini göstermemelidir.

## Public Görünür Yasak Kelimeler

Şu kelimeler public-visible output içinde görünmemeli:

- `AI`
- `prompt`
- `model`
- `admin`
- `denetim`
- `onay kuyruğu`
- `kalite kontrol`
- `test verisi`

Kapsam notu: Bu kelimeler iç dokümantasyonda, admin UI'da, loglarda, test dosyalarında veya bu politika dosyasında geçebilir. Guard yalnız public output içindir.

## Taranacak Public Yüzeyler

HTML route'lar:

- `/`
- `/soru/:slug`
- `/kategori/:slug`
- `/konu/:slug`
- `/arama`
- Public 404 sayfası

Metadata:

- `<title>`
- `<meta name="description">`
- Open Graph tags
- Twitter card tags

Structured data:

- Tüm `application/ld+json` blokları.

Public API response'ları eklenirse:

- `/api/public/search`
- `/api/public/qa/:slug`
- `/api/public/categories`
- `/api/public/topics`

SEO dosyaları:

- `/sitemap.xml`
- `/robots.txt`

Not: `/robots.txt` teknik olarak route path içerebilir; ancak public kullanıcıya görünen dilde iç operasyon pazarlama metni yazılmamalıdır. `/admin` sitemap'e girmemeli; admin için asıl koruma noindex header/meta olmalıdır.

## Eşleşme Mantığı

Test public output'u normalize etmelidir:

- Case-insensitive.
- Mümkünse Turkish locale aware.
- HTML entity decode edilmiş.
- JSON string value ve key'leri incelenmiş.
- Fazla whitespace collapse edilmiş.
- Apostrof varyasyonları normalize edilmiş.

Önerilen denylist matching:

| Terim | Match |
| --- | --- |
| `AI` | Word boundary uppercase/lowercase varyasyonları, `Arşiv AI` dahil. |
| `prompt` | Whole word, case-insensitive. |
| `model` | Whole word, case-insensitive. |
| `admin` | Whole word ve görünür path/metin bağlamı. |
| `denetim` | `denetimi`, `denetimler`, `denetleyen` gibi yaygın varyasyonları yakalayacak şekilde. |
| `onay kuyruğu` | Whitespace normalize edilmiş phrase match. |
| `kalite kontrol` | Whitespace normalize edilmiş phrase match. |
| `test verisi` | Whitespace normalize edilmiş phrase match. |

Yüksek riskli Türkçe varyasyonlar ayrıca explicit listede olmalı:

- `denetim`
- `denetimi`
- `denetimler`
- `denetimleriniz`
- `denetleyen`
- `onaya gönder`
- `onaya gönderme`
- `onay kuyruğu`
- `kalite kontrol`

## İç Veri Sızıntısı Terimleri

Public guard şu iç alan adlarında da fail etmeli:

- `history`
- `source_history_id`
- `text_hash`
- `prompt_version`
- `rules_hash`
- `approved_by`
- `approved_at`
- `score`
- `total_errors`
- `cat_counts`
- `chunk_draft`
- `submitted_part`
- `taslak`
- `bekliyor`
- `onaylandi`
- `reddedildi`

Exception: Bu alan adları kod içinde kullanılabilir; rendered public output ve public API response body içinde görünmemelidir.

## Fail Kriterleri

Build/check fail olmalı:

- Public HTML body içinde yasak kelime varsa.
- Public metadata içinde yasak kelime varsa.
- Public JSON-LD içinde yasak kelime varsa.
- Public API JSON key/value içinde yasak kelime varsa.
- Public API response içinde herhangi bir `history` operasyon alanı varsa.
- Non-published kayıt public output içinde görünürse.
- Public search draft/review/archived içerik döndürürse.
- Public sitemap `/admin`, `/api`, preview, draft, review, archived veya redirect-source URL içerirse.
- `/arama` indexlenebilir durumdaysa.

## Önerilen Check Yapısı

Gelecek check script'i şunları yapmalı:

1. Uygulamayı non-production test mode'da başlatır.
2. En az bir `public_qa.status='published'` ve bir non-published kayıt seed/mock eder.
3. Public route'ları fetch eder.
4. HTML ve JSON-LD parse eder.
5. Public API varsa fetch eder.
6. Denylist absence assert eder.
7. Sadece published kayıtların göründüğünü assert eder.
8. `/arama` için `noindex,follow` assert eder.
9. Sitemap'in yalnız canonical published public URL'leri içerdiğini assert eder.

Pseudo-flow:

```text
for each public route:
  body = fetch(route)
  normalized = normalize(body)
  assertNoPublicBannedTerms(normalized)
  assertNoInternalFieldNames(normalized)
  assertNoPrivateRecords(normalized)
```

## İnsan Gözüyle Review

Public launch öncesi manuel incelenecekler:

- Ana sayfa hero ve navigation.
- Search empty state.
- Search result cards.
- Soru detay sayfası.
- Kategori sayfası.
- Konu sayfası.
- Public 404 sayfası.
- Browser title ve snippet metinleri.
- View-source HTML.
- JSON-LD blokları.

Public copy şu arşiv dilini kullanmalı:

- `İbrahimLive Soru Cevap Arşivi`
- `soru-cevap`
- `konular`
- `kategoriler`
- `arşivde ara`
- `cevabı oku`
- `ilgili konular`
- `son eklenenler`

Public provenance için iç süreç dili yerine şu tip ifadeler tercih edilmeli:

- `arşiv kaydı`
- `yayın tarihi`
- `son güncelleme`
- `kaynak bağlantısı`
