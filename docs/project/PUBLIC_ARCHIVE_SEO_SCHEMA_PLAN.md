# Public Arşiv SEO ve Schema Planı

Tarih: 2026-07-30
Durum: Plan, güvenli geçiş ve schema kilidiyle güncellendi, kodlanmadı

## SEO Hedefi

`arsiv.ibrahimlive.ai` canonical soru-cevap arşivi olacak. Public sayfalar botlar ve kullanıcılar için HTML source içinde okunabilir olmalı. Meta, canonical, JSON-LD ve internal linkler server-side üretilmeli; yalnız client-side sonradan eklenen SEO sinyallerine güvenilmemeli.

## Indexleme Politikası

Indexlenecek sayfalar:

- `/`
- `/soru/:slug`
- `/konu/:slug`
- `/kategori/:slug`

Noindex olacak sayfalar:

- `/arama`
- `/arama?q=*`
- `/admin`
- `/admin/*`
- Public preview/draft URL'leri
- Hata/boş sonuç sayfaları

Geçiş notu: Public root açılmadan önce `PUBLIC_ARCHIVE_ENABLED=false` ve `PUBLIC_ARCHIVE_INDEXING=false` kalır. Public route testleri başladığında bile indexing önce kapalı tutulur. `PUBLIC_ARCHIVE_INDEXING=true` yalnız SEO, sitemap, language guard ve canonical kontrolleri geçtikten sonra açılır.

Index dışı tutulacak teknik alanlar:

- `/api/*`
- İç dosya indirme veya admin export URL'leri
- Demo/static preview artefact'leri

Önemli not: `noindex` etkili olsun diye sayfanın crawler tarafından görülebilir olması gerekir. `robots.txt` ile engellenen bir sayfada crawler meta veya header `noindex` kuralını okuyamaz. Bu yüzden `/arama` için `robots.txt` disallow değil, HTML meta veya `X-Robots-Tag: noindex, follow` önerilir.

## Canonical Plan

Canonical kuralları:

- Her indexlenebilir sayfa self-canonical olmalı.
- Canonical URL absolute, HTTPS ve `arsiv.ibrahimlive.ai` domainli olmalı.
- Internal linkler canonical path'e gitmeli.
- Sitemap içindeki URL ile HTML canonical aynı olmalı.
- Slug değişirse eski URL canonical değil redirect olmalı.
- Query parametreli arama sayfaları sitemap'e girmemeli.

Örnekler:

```html
<link rel="canonical" href="https://arsiv.ibrahimlive.ai/soru/hidayet-nedir">
```

```http
GET /soru/eski-slug
308 Location: /soru/yeni-slug
```

`ibrahimlive.com` için ilk model:

- Özet sayfası kendi içinde benzersiz kısa içerik taşır.
- Ana kaynak linki `https://arsiv.ibrahimlive.ai/soru/:slug` olur.
- Tam metin kopyalanırsa `ibrahimlive.com` sayfası canonical olarak archive URL'sini göstermelidir.

## Sitemap Plan

`/sitemap.xml` yalnız canonical public URL'leri içermeli:

- `/`
- published `/soru/:slug`
- published kategori sayfaları
- published konu sayfaları

Hariç tutulacaklar:

- `/arama`
- `/admin`
- `/api/*`
- draft/review/archived kayıtlar
- redirect kaynak path'leri
- demo preview çıktıları

Her URL için:

- `<loc>` absolute canonical URL.
- `<lastmod>` için `public_qa.updated_at` veya `published_at`.
- `changefreq` ve `priority` şart değil; kullanılırsa gerçekçi olmalı.

Veri büyürse sitemap index'e bölünmeli:

- `/sitemap.xml`
- `/sitemaps/questions-1.xml`
- `/sitemaps/categories.xml`
- `/sitemaps/topics.xml`

## Robots Plan

Başlangıç robots önerisi:

```txt
User-agent: *
Disallow: /api/
Disallow: /demo-public-preview/

Sitemap: https://arsiv.ibrahimlive.ai/sitemap.xml
```

`/admin` için yalnız robots disallow'a güvenilmemeli. Admin HTML response'a ayrıca şu header önerilir:

```http
X-Robots-Tag: noindex, nofollow, noarchive
```

`/arama` için disallow kullanılmamalı; sayfa crawl edilebilir kalmalı ve şu meta/header ile index dışı tutulmalı:

```html
<meta name="robots" content="noindex,follow">
```

## JSON-LD Plan

JSON-LD yalnız sayfada kullanıcıya görünen içeriği temsil etmeli. Public yasaklı iç terimler JSON-LD içinde de görünmemeli.

### Ana Sayfa `/`

Önerilen tipler:

- `WebPage`
- `CollectionPage`
- `ItemList`
- `BreadcrumbList`
- Opsiyonel `WebSite` ve `Organization`

Amaç: Ana sayfanın arşiv giriş/koleksiyon sayfası olduğunu, öne çıkan veya son kayıt listesini ve site hiyerarşisini anlatmak.

Minimum örnek yapı:

```json
{
  "@context": "https://schema.org",
  "@type": "CollectionPage",
  "name": "İbrahimLive Soru Cevap Arşivi",
  "url": "https://arsiv.ibrahimlive.ai/",
  "inLanguage": "tr-TR",
  "mainEntity": {
    "@type": "ItemList",
    "itemListElement": []
  }
}
```

### Soru Detay `/soru/:slug`

Önerilen tipler:

- `WebPage`
- `Article`
- `BreadcrumbList`

`Article` kullanılmalı; `QAPage` ve `FAQPage` kullanılmamalı. Bu arşiv tek yetkili cevap yayınlayan bir içerik arşividir. Kullanıcıların alternatif cevap eklediği forum veya çok cevaplı Q&A sayfası olmadığı sürece `QAPage` rich result kuralına uymaz. Liste halinde çoklu kısa soru-cevap zengin sonucu hedeflenmediği için ilk MVP'de `FAQPage` de kullanılmaz.

Article alanları:

- `headline`: public başlık.
- `description`: public özet.
- `datePublished`: `published_at`.
- `dateModified`: `updated_at` veya `last_reviewed_at`.
- `mainEntityOfPage`: canonical URL.
- `articleSection`: kategori adı.
- `keywords`: konu adları.
- `author` ve `publisher`: `Organization` olarak `İbrahimLive`.

### Kategori `/kategori/:slug`

Önerilen tipler:

- `CollectionPage`
- `ItemList`
- `BreadcrumbList`

`ItemList.itemListElement` yalnız o sayfada görünen published soru kayıtlarını içermeli. Pagination varsa her sayfanın listesi kendi görünen sırasını temsil etmeli.

### Konu `/konu/:slug`

Kategori ile aynı:

- `CollectionPage`
- `ItemList`
- `BreadcrumbList`

Konu sayfası konu adı, açıklama, canonical URL ve published kayıt listesiyle render edilmeli.

### Arama `/arama`

`/arama` noindex olduğu için rich result beklentisi olmamalı. Gerekirse sade `WebPage` JSON-LD kullanılabilir, ancak ilk MVP'de arama sayfasında JSON-LD zorunlu değil.

## Public HTML İçerik Kuralları

Her public soru detay sayfasında source HTML içinde görünmesi gerekenler:

- H1 başlık.
- Soru metni.
- Cevap metni.
- Kategori linki.
- Konu linkleri.
- Son güncelleme veya yayın tarihi.
- Canonical link.
- Meta description.
- Breadcrumb.
- İlgili soru-cevap linkleri.

Public HTML içinde görünmemesi gerekenler:

- İç operasyon terimleri denylist'i.
- Kullanıcı adı, ekip üyesi adı, onaylayan kişi.
- Skor, hata sayımı, kategori hata kırılımı.
- Source history ID veya UUID.
- İç dosya adı.
- Analiz/meta sürümü.

## `/arama` Noindex Mantığı

Arama query sayfaları sonsuz kombinasyon üretebilir ve zayıf/tekrarlı URL oluşturabilir. Bu yüzden:

- `/arama` ve `/arama?q=*` sitemap'e eklenmez.
- `<meta name="robots" content="noindex,follow">` döndürür.
- Internal result linkleri takip edilebilir kalır.
- Arama sonuç kartları yalnız published kayıtları gösterir.
- Boş veya kısa query için 200 + noindex döndürmek yeterlidir; özel 404 gerekmez.
- Query canonical'ı soru/kategori sayfasına yönlendirilmez.

## Public URL Standardı

Önerilen URL yapısı:

- Soru: `/soru/:slug`
- Kategori: `/kategori/:slug`
- Konu: `/konu/:slug`
- Arama: `/arama?q=...`

Slug kuralları:

- Türkçe karakterler okunabilir veya normalize edilebilir; bir standart seçilip değişmemeli.
- Küçük harf.
- Boşluklar `-`.
- Apostrof/şapka gibi varyasyonlar canonical slug üretiminde deterministic normalize edilmeli.
- Slug değişiminde redirect zorunlu.

## Validation Checklist

- Public route HTML source içinde canonical var.
- Canonical, sitemap ve internal link aynı URL'yi gösteriyor.
- `/arama` noindex, follow.
- `/admin` noindex header/meta alıyor.
- `/api/*` sitemap'te yok.
- Draft/review/archived kayıt sitemap'te yok.
- Public HTML ve JSON-LD public yasaklı iç terimleri içermiyor.
- Soru detay Article JSON-LD görünür içerikle eşleşiyor.
- Kategori/konu ItemList yalnız sayfada görünen kayıtları listeliyor.
- Rich Results Test veya schema validator ile JSON-LD parse ediliyor.
- `QAPage` ve `FAQPage` hiçbir public route'ta üretilmiyor.
- `PUBLIC_ARCHIVE_INDEXING=false` iken public test sayfaları noindex kalıyor.
- `PUBLIC_ARCHIVE_INDEXING=true` olmadan sitemap public question URL'lerini index kaynağı gibi sunmuyor.

## Public Language Guard

Public HTML, public JSON-LD ve public API responses şu terimleri içermemeli:

- `AI`
- `prompt`
- `model`
- `admin`
- `denetim`
- `onay kuyruğu`
- `kalite kontrol`
- `test verisi`

Bu kontrolün ayrıntılı fail kriterleri `PUBLIC_ARCHIVE_PUBLIC_LANGUAGE_GUARD.md` dosyasındadır.

## Kaynaklar

- Google Search Central, canonical: https://developers.google.com/search/docs/crawling-indexing/consolidate-duplicate-urls
- Google Search Central, sitemap: https://developers.google.com/search/docs/crawling-indexing/sitemaps/overview
- Google Search Central, robots.txt: https://developers.google.com/search/docs/crawling-indexing/robots/intro
- Google Search Central, noindex: https://developers.google.com/search/docs/crawling-indexing/block-indexing
- Google Search Central, structured data guidelines: https://developers.google.com/search/docs/appearance/structured-data/sd-policies
- Google Search Central, Article: https://developers.google.com/search/docs/appearance/structured-data/article
- Google Search Central, Breadcrumb: https://developers.google.com/search/docs/appearance/structured-data/breadcrumb
- Google Search Central, QAPage sınırı: https://developers.google.com/search/docs/appearance/structured-data/qapage
- Schema.org BreadcrumbList: https://schema.org/BreadcrumbList
