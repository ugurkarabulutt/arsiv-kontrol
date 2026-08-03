# Public Arşiv Veri Modeli Önerisi

Tarih: 2026-07-30
Durum: Güçlendirilmiş öneri, migration çalıştırılmadı

## Amaç

Mevcut `history` tablosu ekip operasyon kaydı olarak korunur. Public soru-cevap arşivi için ayrı, yayın odaklı ve gizlilik sınırı net bir veri modeli kurulur.

Ana ilke: Public route'lar ve public API'ler `history` okumaz. Yayınlanabilir içerik yalnız `public_qa` ve bağlı public tablolar üzerinden gelir.

## Durum Değerleri

Önerilen `public_qa.status` değerleri:

- `draft`: Public yayın için hazırlanıyor.
- `review`: Public editoryal kontrol bekliyor.
- `published`: Public'te görünür tek durum.
- `archived`: Yayından kaldırılmış, public'te görünmez.

Sadece `published` public sorgularda görünür. `draft`, `review`, `archived` admin-only olmalı ve preview URL'leri `noindex` olmalı.

## `public_categories`

Kategori, public koleksiyon sayfalarının ana taksonomisidir.

Önerilen alanlar:

| Alan | Tip | Not |
| --- | --- | --- |
| `id` | uuid pk | İç ID. |
| `name` | text not null | Public görünen kategori adı. |
| `slug` | text unique not null | Canonical path parçası. |
| `description` | text | Kategori açıklaması. |
| `parent_id` | uuid nullable | İleride hiyerarşi gerekirse. |
| `sort_order` | integer default 0 | Public sıralama. |
| `status` | text default `published` | Kategori görünürlüğü. |
| `seo_title` | text | Opsiyonel override. |
| `seo_description` | text | Opsiyonel override. |
| `created_at` | timestamptz | Oluşturma tarihi. |
| `updated_at` | timestamptz | Güncelleme tarihi. |

Önerilen indeksler:

- unique `public_categories_slug_key`
- `(status, sort_order, name)`

## `public_topics`

Konu/etiket katmanıdır. Bir soru-cevap birden çok konuya bağlanabilir.

Önerilen alanlar:

| Alan | Tip | Not |
| --- | --- | --- |
| `id` | uuid pk | İç ID. |
| `name` | text not null | Public görünen konu adı. |
| `slug` | text unique not null | Canonical path parçası. |
| `description` | text | Konu açıklaması. |
| `aliases` | text[] default `{}` | Arama varyasyonları. |
| `sort_order` | integer default 0 | Public sıralama. |
| `status` | text default `published` | Konu görünürlüğü. |
| `seo_title` | text | Opsiyonel override. |
| `seo_description` | text | Opsiyonel override. |
| `created_at` | timestamptz | Oluşturma tarihi. |
| `updated_at` | timestamptz | Güncelleme tarihi. |

Önerilen indeksler:

- unique `public_topics_slug_key`
- `(status, sort_order, name)`
- Gerekirse `aliases` için GIN indeks.

## `public_qa`

Public'te görünen asıl soru-cevap kayıtlarıdır.

Önerilen alanlar:

| Alan | Tip | Not |
| --- | --- | --- |
| `id` | uuid pk | Public kaydın iç ID'si. Public API bunu döndürmek zorunda değil. |
| `source_history_id` | uuid nullable | `history.id` iç referansı. Public response'a çıkmaz. |
| `category_id` | uuid references `public_categories(id)` | Ana kategori. |
| `title` | text not null | Public başlık. |
| `slug` | text unique not null | `/soru/:slug`. |
| `question` | text not null | Public soru metni. |
| `answer` | text not null | Public cevap metni. |
| `summary` | text not null | Public özet. `history.summary` doğrudan kopyalanmamalı. |
| `excerpt` | text | Liste kartı için kısa metin. |
| `status` | text not null default `draft` | Yalnız `published` görünür. |
| `published_at` | timestamptz nullable | Public yayın tarihi. |
| `unpublished_at` | timestamptz nullable | Yayından kaldırma tarihi. |
| `last_reviewed_at` | timestamptz nullable | Editoryal son kontrol. |
| `seo_title` | text | `<title>` override. |
| `seo_description` | text | Meta description. |
| `canonical_path` | text | Örn. `/soru/hidayet-nedir`. Tam domain uygulamada üretilir. |
| `read_time` | integer | Public okuma süresi. `read_time_minutes` yerine kısa ad istenirse bu alan kullanılabilir; tek standart seçilmeli. |
| `content_hash` | text | Duplicate yayın kontrolü. |
| `search_text` | text | Başlık, soru, cevap, özet, kategori, konu birleşimi. |
| `search_text_normalized` | text | Türkçe tolerant arama için normalize edilmiş metin. |
| `search_vector` | tsvector nullable | Faz 2 PostgreSQL full-text search için. İlk migration'da opsiyonel tutulabilir. |
| `is_featured` | boolean default false | Ana sayfa/öne çıkan listeler için. |
| `sort_order` | integer default 0 | Manuel sıralama gereken koleksiyonlarda. |
| `view_count` | bigint default 0 | Public görüntülenme sayısı; yazma yükü ve analytics politikası ayrıca değerlendirilmeli. |
| `created_by` | uuid nullable | İç kullanıcı referansı. Public'e çıkmaz. |
| `updated_by` | uuid nullable | İç kullanıcı referansı. Public'e çıkmaz. |
| `published_by` | uuid nullable | İç kullanıcı referansı. Public'e çıkmaz. |
| `source_snapshot` | jsonb default `{}` | Aktarım anındaki iç audit snapshot. Public'e çıkmaz. |
| `created_at` | timestamptz | Oluşturma tarihi. |
| `updated_at` | timestamptz | Güncelleme tarihi. |

Önerilen indeksler:

- unique `public_qa_slug_key`
- unique nullable veya partial `public_qa_source_history_id_key` where `source_history_id is not null`
- `(status, published_at desc)`
- `(category_id, status, published_at desc)`
- `(status, is_featured, sort_order, published_at desc)`
- `(content_hash)` duplicate kontrolü için
- `search_text_normalized` için ilk MVP'de btree/ILIKE yeterli olabilir; büyümede trigram veya full text search eklenmeli.
- `search_vector` için Faz 2'de GIN indeks.

## `public_qa_topics`

Soru-cevap ve konu ilişki tablosu.

Önerilen alanlar:

| Alan | Tip | Not |
| --- | --- | --- |
| `qa_id` | uuid references `public_qa(id)` on delete cascade | |
| `topic_id` | uuid references `public_topics(id)` on delete cascade | |
| `sort_order` | integer default 0 | Detay sayfasındaki konu sırası. |
| `created_at` | timestamptz | |

Primary key: `(qa_id, topic_id)`
Ek indeks: `(topic_id, qa_id)`

## `public_topic_aliases`

Konu arama varyasyonlarını ayrı yönetmek için opsiyonel alias tablosu önerilir. İlk MVP'de `public_topics.aliases text[]` yeterli olabilir; editoryal yönetim ve arama skoru büyürse ayrı tablo daha temizdir.

Önerilen alanlar:

| Alan | Tip | Not |
| --- | --- | --- |
| `id` | uuid pk | |
| `topic_id` | uuid references `public_topics(id)` on delete cascade | |
| `alias` | text not null | Görünen veya arama varyasyonu. |
| `alias_normalized` | text not null | Normalized arama formu. |
| `language` | text default `tr` | İleride çok dilli arama için. |
| `created_at` | timestamptz | |

Önerilen indeksler:

- unique `(topic_id, alias_normalized)`
- `(alias_normalized)`

## `public_related_qa`

İlgili soru-cevapları deterministik ve editoryal olarak yönetmek için opsiyonel ilişki tablosu önerilir.

Önerilen alanlar:

| Alan | Tip | Not |
| --- | --- | --- |
| `qa_id` | uuid references `public_qa(id)` on delete cascade | Kaynak kayıt. |
| `related_qa_id` | uuid references `public_qa(id)` on delete cascade | İlgili kayıt. |
| `relation_type` | text default `related` | `related`, `next`, `previous`, `same_topic` gibi. |
| `sort_order` | integer default 0 | Detay sayfası sırası. |
| `created_at` | timestamptz | |

Primary key: `(qa_id, related_qa_id)`
Kural: `qa_id <> related_qa_id`.

## `public_redirects`

Slug değişimleri ve kaldırılan public path'ler için yönlendirme tablosu.

Önerilen alanlar:

| Alan | Tip | Not |
| --- | --- | --- |
| `id` | uuid pk | |
| `from_path` | text unique not null | Eski path. Örn. `/soru/eski-slug`. |
| `to_path` | text not null | Yeni path. |
| `http_status` | integer default 301 | 301 veya 308. |
| `reason` | text | İç açıklama. |
| `active` | boolean default true | |
| `created_by` | uuid nullable | İç kullanıcı referansı. |
| `created_at` | timestamptz | |

Kurallar:

- `from_path` ve `to_path` absolute path olmalı, tam domain içermemeli.
- Redirect chain oluşmamalı.
- `from_path = to_path` yasak olmalı.
- Published slug değişimi varsa redirect kaydı zorunlu olmalı.
- Sitemap sadece canonical yeni URL'leri içermeli; redirect kaynak path'leri sitemap'e girmemeli.

## Slug Politikası

- `public_qa.slug` unique olacak.
- Slug mümkün olduğunca yayın öncesi kesinleştirilecek.
- Yayın sonrası slug mümkünse değişmeyecek.
- Yayın sonrası slug değişirse `public_redirects` ile eski path'ten yeni path'e 301 veya 308 üretilecek.
- Internal linkler ve sitemap yalnız yeni canonical URL'yi gösterecek.
- Slug değişimi `public_publish_events` içinde `slug_changed` ve `redirect_created` olaylarıyla izlenecek.
- Aynı içerik farklı slug'larla ikinci kez yayınlanmayacak; `content_hash` ve editoryal kontrol birlikte kullanılacak.

## `public_publish_events`

Public yayın audit defteridir. Silinmemeli, append-only davranmalı.

Önerilen alanlar:

| Alan | Tip | Not |
| --- | --- | --- |
| `id` | uuid pk | |
| `public_qa_id` | uuid references `public_qa(id)` | |
| `source_history_id` | uuid nullable | İç referans. |
| `event_type` | text not null | `created`, `updated`, `submitted_for_review`, `published`, `unpublished`, `archived`, `slug_changed`, `redirect_created`. |
| `from_status` | text nullable | |
| `to_status` | text nullable | |
| `actor_user_id` | uuid nullable | İç kullanıcı referansı. |
| `actor_name_snapshot` | text | İsim değişse bile audit okunur kalsın. |
| `metadata` | jsonb default `{}` | Slug, path, diff summary vb. |
| `created_at` | timestamptz | |

Önerilen indeksler:

- `(public_qa_id, created_at desc)`
- `(event_type, created_at desc)`
- `(source_history_id)`

## Public'e Çıkacak Alan Sözleşmesi

Public detay response/render için izinli alanlar:

- `title`
- `slug`
- `question`
- `answer`
- `summary`
- `excerpt`
- `category.name`
- `category.slug`
- `topics.name`
- `topics.slug`
- `published_at`
- `updated_at`
- `last_reviewed_at`
- `read_time`
- `canonical_path`
- `seo_title`
- `seo_description`

`view_count` public response'a ilk MVP'de zorunlu olarak çıkmamalıdır. Kullanılacaksa ayrı analytics/gizlilik kararıyla ve write-amplification riski değerlendirilerek açılmalıdır.

Public'e çıkmayacak alanlar:

- `source_history_id`
- `created_by`, `updated_by`, `published_by`
- `source_snapshot`
- `content_hash`
- `search_text`
- `search_text_normalized`
- Herhangi bir `history.*` alanı
- Herhangi bir `users.*` alanı
- Herhangi bir `alerts.*` alanı

## Aktarım Kuralları

- `history.status = 'onaylandi'` yalnız aktarım adayıdır; otomatik public yayın değildir.
- İlk fazda toplu otomatik yayın yapılmamalı.
- İlk seed için 20-50 kayıt manuel seçilmeli.
- `corrected_text` doğrudan `answer` yapılmadan önce editoryal kontrol edilmeli.
- `summary` public'e özel yeniden yazılmalı.
- `title`, `question`, `answer`, `category_id`, en az bir topic, `seo_description` ve `slug` olmadan `published` yapılamamalı.
- `content_hash` ile aynı cevabın ikinci kez yayınlanması engellenmeli veya bilinçli duplicate olarak audit'e yazılmalı.
- Slug değişimi redirect üretmeden kaydedilmemeli.

## Arama Planı

### Faz 1 - Normalized ILIKE

İlk MVP'de `search_text_normalized` alanı ve normalized query ile `ILIKE` yeterlidir.

Kapsam:

- Başlık.
- Soru.
- Özet.
- Cevap.
- Kategori adı.
- Konu adları.
- Alias dizisi veya `public_topic_aliases`.

### Faz 2 - PostgreSQL Full-Text Search

Kayıt sayısı ve sorgu hacmi büyüdüğünde `search_vector` alanı devreye alınır.

Kapsam:

- Weighted `title`, `question`, `summary`, `answer`.
- GIN indeks.
- Published filtreli sorgu.

### Faz 3 - `pg_trgm` + Aliases

Yazım toleransı, typo ve Türkçe karakter varyasyonları için trigram ve alias tablosu güçlendirilir.

Kapsam:

- `pg_trgm` similarity.
- `public_topic_aliases`.
- Şapka/apostrof/harf varyasyonu.
- Sıralama skoru: başlık > konu/kategori > soru > özet > cevap > alias/trigram.

### Faz 4 - Semantic Search / Embeddings

Yalnız published public içerik için semantik arama ileride ayrıca değerlendirilebilir.

Kısıtlar:

- İlk MVP kapsamı değildir.
- Public veri katmanından üretilmelidir.
- `history`, kullanıcı, skor, feedback veya iç operasyon verisi embedding'e dahil edilmemelidir.

## Arama Normalizasyonu

İlk MVP'de `search_text_normalized` alanı yeterli olur. Normalizasyon örnekleri:

- `Allah'a`, `Allah’a`, `Allaha` -> `allaha`
- `Kur'ân`, `Kur’ân`, `Kuran` -> ortak arama formu
- `mürşid`, `mursid` -> ortak arama formu veya alias
- `tâbiiyet`, `tabiiyet` -> ortak arama formu
- Şapka, apostrof, birleşik/ayrık varyasyonları arama toleransına dahil edilir; görünen public metin değiştirilmez.

Veri büyüdüğünde PostgreSQL full text search ve `pg_trgm` trigram arama ayrı fazda değerlendirilmeli.

## Güvenlik Notları

- Supabase service role key yalnız backend'de kalmalı.
- Public tarafa Supabase client/service key verilmemeli.
- Public sorgular backend fonksiyonları üzerinden ve yalnız `published` filtreli yapılmalı.
- İleride browser-side Supabase public client düşünülürse RLS ve public view zorunlu olur; ilk MVP için önerilmez.

## Migration Uygulama Notu

Bu belge migration değildir. SQL uygulanmadı. Gerçek migration ayrı PR'da, önce staging/preview veritabanında çalıştırılmalı ve mevcut `schema.sql` ile çakışmayacak şekilde hazırlanmalıdır.
