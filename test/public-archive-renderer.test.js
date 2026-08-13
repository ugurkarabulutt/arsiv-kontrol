const assert = require('node:assert/strict');
const test = require('node:test');
const { ROUTE_PATHS, renderPublicArchivePreviewRoute } = require('../public-archive-renderer');

const forbiddenSnippets = [
  'hocamız',
  'hoca',
  'uzmanlar',
  'uzman ekip',
  'uzmanlar inceler',
  'alanında uzman',
  'cevaplandırılması için hocamıza aktarılır',
  'uygun görülen sorular',
  'source_history_id',
  'text_hash',
  'prompt_version',
  'rules_hash',
  'approved_by',
  'approved_at',
  'total_errors',
  'cat_counts',
  'taslak',
  'bekliyor',
  'onaylandi',
  'reddedildi',
  'Arşiv Kontrol AI',
  'Metin Denetimi',
  'Yayın Paketi',
  'Onaya Gönder',
  'Profil',
  'Bildirim',
  'Kaydedilen',
  'görüntülenme',
  'Faydalı oldu mu'
];

function lower(value) {
  return String(value || '').toLocaleLowerCase('tr-TR');
}

function assertOnlyPublicPreviewApi(html) {
  const matches = String(html || '').match(/\/api\//g) || [];
  if (!matches.length) return;
  const unsafe = [...String(html).matchAll(/.{0,32}\/api\/.{0,56}/g)]
    .map(match => match[0])
    .filter(fragment => !fragment.includes('/public-preview/api/'));
  assert.deepEqual(unsafe, [], `Unexpected non-preview API reference: ${unsafe.join(' | ')}`);
}

test('public preview routes render isolated noindex pages', () => {
  for (const route of ROUTE_PATHS) {
    const rendered = renderPublicArchivePreviewRoute(route, route.endsWith('/arama') ? { q: 'zikir' } : {});
    assert.match(rendered.html, /<meta name="robots" content="noindex,nofollow">/);
    assert.match(rendered.html, /Dini Sorular/);
    assert.match(rendered.html, /ve Cevaplar Arşivi/);
    assert.match(rendered.html, /Hesab\u0131m/);
    assert.match(rendered.html, /Soru, cevap ve kavramları kaynak bağlamıyla birlikte okuyun\./);
    assertOnlyPublicPreviewApi(rendered.html);
  }
});

test('public preview shows direct authorship without broad expert language', () => {
  const home = renderPublicArchivePreviewRoute('/public-preview').html;
  const detail = renderPublicArchivePreviewRoute('/public-preview/soru/ornek-soru').html;
  const ask = renderPublicArchivePreviewRoute('/public-preview/soru-sor').html;

  assert.match(home, /Sorular Dr\. Abdulcabbar Boran tarafından yanıtlanır\./);
  assert.match(detail, /Yanıtlayan: Dr\. Abdulcabbar Boran/);
  assert.match(ask, /Sorular Dr\. Abdulcabbar Boran tarafından yanıtlanır\./);
});

test('public preview output avoids internal and fake feature language', () => {
  const pages = [
    renderPublicArchivePreviewRoute('/public-preview').html,
    renderPublicArchivePreviewRoute('/public-preview/arama', { q: 'zikir' }).html,
    renderPublicArchivePreviewRoute('/public-preview/soru/ornek-soru').html,
    renderPublicArchivePreviewRoute('/public-preview/konu/kalbin-yonelisi').html,
    renderPublicArchivePreviewRoute('/public-preview/kategori/allaha-ulasmayi-dilemek').html,
    renderPublicArchivePreviewRoute('/public-preview/soru-sor').html
  ].map(lower).join('\n');

  for (const term of forbiddenSnippets) {
    assert.equal(pages.includes(lower(term)), false, `Forbidden public phrase leaked: ${term}`);
  }
});

test('public preview uses final handoff assets and icon system', () => {
  const home = renderPublicArchivePreviewRoute('/public-preview').html;
  assert.match(home, /\/public-preview\/assets\/hero-bookshelf-light-mobile\.webp/);
  assert.match(home, /\/public-preview\/assets\/hero-bookshelf-dark-mobile\.webp/);
  assert.match(home, /\/public-preview\/assets\/hero-bookshelf-light-desktop\.webp/);
  assert.match(home, /\/public-preview\/assets\/hero-bookshelf-dark-desktop\.webp/);
  assert.match(home, /class="pa-svg-icon"/);
  assert.match(home, /href="\/public-preview\/hesabim"/);
  assert.match(home, />Ar\u015fiv<\/span>/);
  assert.match(home, /Arşiv ana kapıları/);
  assert.match(home, /data-concept-slider/);
  assert.match(home, /data-concept-track/);
  assert.match(home, /data-concept-rail/);
  assert.match(home, /Allah’a Ulaşmayı Dilemek/);
  assert.match(home, /Hidayet/);
  assert.match(home, /Tabiiyet/);
  assert.match(home, /Mürşid/);
  assert.match(home, /Zikir/);
  assert.match(home, /Nefs/);
  assert.match(home, /Ruh/);
  assert.match(home, /Teslimiyet/);
  assert.match(home, /href="\/public-preview\/konu\/nefs"/);
  assert.match(home, /href="\/public-preview\/konu\/ruh"/);
});

test('archive and account routes are explicit public preview pages', () => {
  const archive = renderPublicArchivePreviewRoute('/public-preview/arsiv').html;
  assert.match(archive, /Soru ve cevapları kavramlarıyla birlikte keşfedin\./);
  assert.match(archive, /Tüm Sorular/);
  assert.doesNotMatch(archive, /Ana Sayfa<\/a>\s*<a[^>]*>Arama/);
  assertOnlyPublicPreviewApi(archive);

  const account = renderPublicArchivePreviewRoute('/public-preview/hesabim').html;
  assert.match(account, /Hesabınızla soru gönderimini takip edin\./);
  assert.match(account, /Google ile Devam Et/);
  assert.match(account, /\/public-preview\/auth\/google/);
  assertOnlyPublicPreviewApi(account);
});

test('public preview search and missing states are deterministic', () => {
  const result = renderPublicArchivePreviewRoute('/public-preview/arama', { q: 'zikir' });
  assert.equal(result.status, 200);
  assert.match(result.html, /Zikir kalbi nasıl değiştirir/);

  const empty = renderPublicArchivePreviewRoute('/public-preview/arama', { q: 'bulunmayan-kelime' });
  assert.equal(empty.status, 200);
  assert.match(empty.html, /Sonuç bulunamadı\./);
  assert.match(empty.html, /Aklınızda bir soru mu var\?/);

  const missing = renderPublicArchivePreviewRoute('/public-preview/soru/gizli-icerik');
  assert.equal(missing.status, 404);
  assert.match(missing.html, /Sayfa bulunamadı\./);
});

test('public preview can render approved records instead of fixture data', () => {
  const approvedArchiveData = {
    brand: {},
    categories: [{
      id: 'category-hidayet',
      slug: 'hidayet',
      name: 'Hidayet',
      description: 'Hidayet başlığındaki soru ve cevaplar.',
      topicSlugs: ['zikir', 'takva'],
      featured: true
    }],
    topics: [
      {
        id: 'topic-zikir',
        slug: 'zikir',
        name: 'Zikir',
        description: 'Zikir kavramıyla ilişkili soru ve cevaplar.',
        categorySlug: 'hidayet',
        relatedTopicSlugs: ['takva'],
        featured: true
      },
      {
        id: 'topic-takva',
        slug: 'takva',
        name: 'Takva',
        description: 'Takva kavramıyla ilişkili soru ve cevaplar.',
        categorySlug: 'hidayet',
        relatedTopicSlugs: ['zikir'],
        featured: true
      }
    ],
    qa: [{
      id: 'qa-gercek-soru',
      slug: 'gercek-soru',
      title: 'Gerçek onaylı soru nasıl okunur?',
      question: 'Gerçek onaylı soru nasıl okunur?',
      summary: 'Bu kayıt onaylı veri köprüsünden gelen public soru kartını temsil eder.',
      answer: ['Bu cevap gerçek veri köprüsü testinde kullanılır.'],
      excerpt: 'Bu kayıt onaylı veri köprüsünden gelir.',
      categorySlug: 'hidayet',
      topicSlugs: ['zikir', 'takva'],
      sourceContext: { title: 'Kaynak ve bağlam', text: 'Public okuma bağlamı.' },
      publishedAt: '2026-08-13T09:00:00.000Z',
      updatedAt: '2026-08-13T09:00:00.000Z',
      readTime: 1,
      readCount: 12,
      isFeatured: true,
      relatedSlugs: []
    }]
  };

  const home = renderPublicArchivePreviewRoute('/public-preview', {}, approvedArchiveData).html;
  assert.match(home, /Gerçek onaylı soru nasıl okunur\?/);
  assert.match(home, /data-card-href="\/public-preview\/soru\/gercek-soru"/);
  assert.match(home, /12 okunma/);
  assert.doesNotMatch(home, /Zikir kalbi nasıl değiştirir/);

  const detail = renderPublicArchivePreviewRoute('/public-preview/soru/gercek-soru', {}, approvedArchiveData);
  assert.equal(detail.status, 200);
  assert.match(detail.html, /Gerçek onaylı soru nasıl okunur\?/);
  assert.match(detail.html, /Bu cevap gerçek veri köprüsü testinde kullanılır\./);

  const topic = renderPublicArchivePreviewRoute('/public-preview/konu/zikir', {}, approvedArchiveData);
  assert.equal(topic.status, 200);
  assert.match(topic.html, /Gerçek onaylı soru nasıl okunur\?/);
});

test('question, topic, category, and ask pages keep public boundaries', () => {
  const detail = renderPublicArchivePreviewRoute('/public-preview/soru/ornek-soru').html;
  assert.match(detail, /Soru/);
  assert.match(detail, /Cevap/);
  assert.match(detail, /Kaynak ve bağlam/);
  assert.match(detail, /İlgili Sorular/);
  assert.match(detail, /data-public-read-count="ornek-soru"/);
  assertOnlyPublicPreviewApi(detail);

  const topic = renderPublicArchivePreviewRoute('/public-preview/konu/kalbin-yonelisi').html;
  const category = renderPublicArchivePreviewRoute('/public-preview/kategori/allaha-ulasmayi-dilemek').html;
  assert.match(topic, /Kavram/);
  assert.match(category, /Kategori/);
  assert.match(category, /Bu Kategorideki Sorular/);
  assertOnlyPublicPreviewApi(topic);
  assertOnlyPublicPreviewApi(category);

  const ask = renderPublicArchivePreviewRoute('/public-preview/soru-sor').html;
  assert.match(ask, /data-question-form/);
  assert.doesNotMatch(ask, /data-static-question-form/);
  assert.match(ask, />Soruyu Gönder</);
  assert.doesNotMatch(ask, /disabled aria-disabled="true">Soruyu Gönder/);
  assert.match(ask, /\/public-preview\/api\/question-submissions/);
  assert.match(ask, /\/public-preview\/auth\/google/);
  assert.match(ask, /Sorunuzu kısa ve açık şekilde yazabilirsiniz./);
  assert.doesNotMatch(ask, /Bu ekranda kayıt alınmıyor|yalnızca arayüz davranışı gösteriliyor|Bu ekranda kayıt alınmaz/);
  assertOnlyPublicPreviewApi(ask);
});

test('question cards are whole-card navigable without helpful voting', () => {
  const home = renderPublicArchivePreviewRoute('/public-preview').html;
  assert.match(home, /data-card-href="\/public-preview\/soru\/ornek-soru"/);
  assert.match(home, /role="link"/);
  assert.match(home, /Cevabı oku/);
  assert.match(home, /data-read-count-label/);
  assert.match(home, /okunma/);
  assert.doesNotMatch(home, /pa-question-excerpt/);
  assert.doesNotMatch(home, /Kalbin Allah’a yönelme talebi; dua, tercih ve istikametle canlı tutulur\./);
  assert.doesNotMatch(home, /Faydalı oldu mu|helpful voting/);
});

test('mobile search copy stays compact but accessible', () => {
  const home = renderPublicArchivePreviewRoute('/public-preview').html;
  assert.match(home, /placeholder="Soru veya kavram yazın\.\.\."/);
  assert.match(home, /aria-label="Sorunuzu veya kavramınızı yazın"/);
  assert.doesNotMatch(home, /placeholder="Sorunuzu veya kavramınızı yazın/);
});

test('public preview exposes separate index and info pages', () => {
  for (const route of [
    '/public-preview/konular',
    '/public-preview/kategoriler',
    '/public-preview/hakkimizda',
    '/public-preview/iletisim',
    '/public-preview/gizlilik',
    '/public-preview/kullanim-kosullari'
  ]) {
    const rendered = renderPublicArchivePreviewRoute(route);
    assert.equal(rendered.status, 200);
    assert.match(rendered.html, /Dini Sorular/);
    assertOnlyPublicPreviewApi(rendered.html);
  }
});
