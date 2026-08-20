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
  'Faydalı oldu mu',
  'Public arşiv',
  'Google OAuth',
  'bu ortam',
  'ön izleme alanı',
  'önizleme alanı'
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
    assert.match(rendered.html, /Cevaplara delilleri ve kaynak bağlamıyla kolayca ulaşın\./);
    assertOnlyPublicPreviewApi(rendered.html);
  }
});

test('public preview shows direct authorship without broad expert language', () => {
  const home = renderPublicArchivePreviewRoute('/public-preview').html;
  const detail = renderPublicArchivePreviewRoute('/public-preview/soru/ornek-soru').html;
  const ask = renderPublicArchivePreviewRoute('/public-preview/soru-sor').html;

  assert.match(home, /Sorularınız Dr\. Abdulcabbar Boran tarafından Kur’an ve Hadis-i Şerif ışığında cevaplandırılır/);
  assert.match(home, /Cevapları nasıl keşfedebilirsiniz\?/);
  assert.doesNotMatch(home, /Okuma düzeni|Her cevap; soru, ana kapı ve ilgili kavramlarla birlikte hazırlanır\./);
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
  assert.match(home, /\/public-preview\/assets\/hero-open-book-warm\.jpg/);
  assert.doesNotMatch(home, /hero-bookshelf/);
  assert.match(home, /Sorularınıza, kaynaklarıyla birlikte cevap bulun\./);
  assert.match(home, /ilgili soruları, cevapları ve delilleri bir arada okuyun\./);
  assert.match(home, /class="pa-svg-icon"/);
  assert.match(home, /href="\/public-preview\/hesabim"/);
  assert.match(home, />Ar\u015fiv<\/span>/);
  assert.match(home, />Ara<\/span>/);
  assert.doesNotMatch(home, />Konular<\/span>|>Konular<\/a>|>Kategoriler<\/a>/);
  assert.doesNotMatch(home, /<strong>Ana Başlıklar<\/strong>|<strong>Kavramlar<\/strong>/);
  assert.match(home, /class="pa-mobile-nav"/);
  assert.match(home, /class="pa-scroll-top"/);
  assert.match(home, /data-scroll-top/);
  assert.match(home, /pa-scroll-top-icon/);
  assert.match(home, /aria-label="Yukarı çık"/);
  assert.match(home, /<a class="pa-archive-shortcut" href="\/public-preview\/arsiv"/);
  assert.match(home, /Arşivin tamamını açın\./);
  assert.match(home, /Tüm soru ve cevaplara hızlıca ulaşın\./);
  assert.match(home, /<span class="pa-archive-shortcut-link">Arşive Git/);
  assert.doesNotMatch(home, /Arşiv ana kapıları/);
  assert.doesNotMatch(home, /Cevapları yalnız liste olarak değil, kavram yolu olarak okuyun\./);
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
  assert.match(home, /href="\/public-preview\/kategori\/nefs"/);
  assert.match(home, /href="\/public-preview\/kategori\/ruh"/);
});

test('archive and account routes are explicit public preview pages', () => {
  const archive = renderPublicArchivePreviewRoute('/public-preview/arsiv').html;
  assert.match(archive, /Merak ettiğiniz konunun cevaplarına ulaşın\./);
  assert.match(archive, /Soru ve cevapları kategorilerine göre inceleyebilir, aradığınız konuyu alfabetik olarak kolayca bulabilirsiniz\./);
  assert.doesNotMatch(archive, /Soru ve cevapları kavramlarıyla birlikte keşfedin\./);
  assert.match(archive, /pa-alpha-index/);
  assert.match(archive, /pa-alpha-track/);
  assert.match(archive, /Bu harfte ara\.\.\./);
  assert.match(archive, /A harfiyle başlayan kategoriler/);
  assert.match(archive, /soru cevap/);
  assert.doesNotMatch(archive, /<span>11 soru<\/span>\s*<span>11 cevap<\/span>/);
  assert.match(archive, /Tüm Sorular/);
  assert.doesNotMatch(archive, /<h2>Kategoriler<\/h2>|<h2>Kavramlar<\/h2>|\/public-preview\/konular/);
  assert.doesNotMatch(archive, /Ana Sayfa<\/a>\s*<a[^>]*>Arama/);
  assertOnlyPublicPreviewApi(archive);

  const hArchive = renderPublicArchivePreviewRoute('/public-preview/arsiv', { harf: 'H' }).html;
  assert.match(hArchive, /H harfiyle başlayan kategoriler/);
  assert.match(hArchive, /href="\/public-preview\/arsiv\?harf=H&amp;kategori=hidayet#sorular"/);

  const filteredArchive = renderPublicArchivePreviewRoute('/public-preview/arsiv', { harf: 'H', kategori: 'hidayet' }).html;
  assert.match(filteredArchive, /Hidayet soruları/);
  assert.match(filteredArchive, /Tümünü göster/);
  assert.doesNotMatch(filteredArchive, /<h2>Tüm Sorular<\/h2>/);

  const account = renderPublicArchivePreviewRoute('/public-preview/hesabim').html;
  assert.match(account, /Hesabınızla soru gönderimini takip edin\./);
  assert.match(account, /Google ile Devam Et/);
  assert.match(account, /\/public-preview\/auth\/google/);
  assertOnlyPublicPreviewApi(account);
});

test('archive lists are paginated for large public data', () => {
  const largeData = {
    categories: [
      { slug: 'hidayet', name: 'Hidayet', description: 'Hidayet kategorisi.' }
    ],
    topics: [],
    qa: Array.from({ length: 75 }, (_, index) => {
      const number = index + 1;
      return {
        id: `qa-${number}`,
        slug: `soru-${number}`,
        title: `Soru ${number}`,
        question: `Soru ${number}`,
        answer: [`Cevap ${number}`],
        categorySlug: 'hidayet',
        categorySlugs: ['hidayet'],
        topicSlugs: [],
        publishedAt: '2026-08-10',
        readTime: 1,
        readCount: number
      };
    })
  };

  const firstPage = renderPublicArchivePreviewRoute('/public-preview/arsiv', {}, largeData).html;
  assert.equal((firstPage.match(/class="pa-question-card/g) || []).length, 30);
  assert.match(firstPage, /1-30 \/ 75 soru gösteriliyor/);
  assert.match(firstPage, /Sayfa 1 \/ 3/);
  assert.match(firstPage, /href="\/public-preview\/arsiv\?sayfa=2#sorular"/);
  assert.doesNotMatch(firstPage, /Soru 75/);

  const thirdPage = renderPublicArchivePreviewRoute('/public-preview/arsiv', { sayfa: '3' }, largeData).html;
  assert.equal((thirdPage.match(/class="pa-question-card/g) || []).length, 15);
  assert.match(thirdPage, /61-75 \/ 75 soru gösteriliyor/);
  assert.match(thirdPage, /Sayfa 3 \/ 3/);
  assert.match(thirdPage, /Soru 75/);

  const categorySecondPage = renderPublicArchivePreviewRoute('/public-preview/kategori/hidayet', { sayfa: '2' }, largeData).html;
  assert.equal((categorySecondPage.match(/class="pa-question-card/g) || []).length, 30);
  assert.match(categorySecondPage, /31-60 \/ 75 soru gösteriliyor/);
  assert.match(categorySecondPage, /href="\/public-preview\/kategori\/hidayet\?sayfa=3#sorular"/);
});

test('public renderer accepts route-sized server data with global stats', () => {
  const pagedRows = Array.from({ length: 30 }, (_, index) => {
    const number = index + 31;
    return {
      id: `qa-${number}`,
      slug: `soru-${number}`,
      title: `Soru ${number}`,
      question: `Soru ${number}`,
      answer: [],
      categorySlug: 'hidayet',
      categorySlugs: ['hidayet'],
      topicSlugs: ['hidayet'],
      publishedAt: '2026-08-10',
      readTime: 1
    };
  });
  const archive = renderPublicArchivePreviewRoute('/public-preview/arsiv', { sayfa: '2' }, {
    stats: { questionCount: 3147, answerCount: 3147 },
    pagination: { scope: 'archive', prePaginated: true, page: 2, pageSize: 30, total: 3147 },
    categories: [{ slug: 'hidayet', name: 'Hidayet', questionCount: 3147 }],
    topics: [],
    qa: pagedRows
  }).html;

  assert.equal((archive.match(/class="pa-question-card/g) || []).length, 30);
  assert.match(archive, /3\.147 soru cevap/);
  assert.match(archive, /31-60 \/ 3\.147 soru gösteriliyor/);
  assert.match(archive, /Sayfa 2 \/ 105/);
  assert.match(archive, /Hidayet/);
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
        description: 'Zikir kategorisindeki soru ve cevaplar.',
        categorySlug: 'hidayet',
        relatedTopicSlugs: ['takva'],
        featured: true
      },
      {
        id: 'topic-takva',
        slug: 'takva',
        name: 'Takva',
        description: 'Takva kategorisindeki soru ve cevaplar.',
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
      answer: ['Bu cevap gerçek veri köprüsü testinde kullanılır. Bakara-256 ve YÂSÎN-62 bu testte açık kaynak atfı olarak geçer.'],
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
  assert.match(detail.html, /Kaynak ve deliller/);
  assert.match(detail.html, /Bakara-256/);
  assert.match(detail.html, /Yâsîn-62/);
  assert.doesNotMatch(detail.html, /Public okuma bağlamı\./);

  const topic = renderPublicArchivePreviewRoute('/public-preview/konu/zikir', {}, approvedArchiveData);
  assert.equal(topic.status, 200);
  assert.match(topic.html, /Gerçek onaylı soru nasıl okunur\?/);

  const tagCategory = renderPublicArchivePreviewRoute('/public-preview/kategori/zikir', {}, approvedArchiveData);
  assert.equal(tagCategory.status, 200);
  assert.match(tagCategory.html, /Zikir/);
  assert.match(tagCategory.html, /Gerçek onaylı soru nasıl okunur\?/);
});

test('question, topic, category, and ask pages keep public boundaries', () => {
  const detail = renderPublicArchivePreviewRoute('/public-preview/soru/ornek-soru').html;
  assert.match(detail, /Soru/);
  assert.match(detail, /Cevap/);
  assert.match(detail, /Cevap bilgileri/);
  assert.match(detail, /İlgili Sorular/);
  assert.match(detail, /data-public-read-count="ornek-soru"/);
  assert.doesNotMatch(detail, /class="pa-detail-subtitle"/);
  assertOnlyPublicPreviewApi(detail);

  const topic = renderPublicArchivePreviewRoute('/public-preview/konu/kalbin-yonelisi').html;
  const category = renderPublicArchivePreviewRoute('/public-preview/kategori/allaha-ulasmayi-dilemek').html;
  assert.match(topic, /Kategori/);
  assert.doesNotMatch(topic, /Kavram/);
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
  assert.match(ask, /\/public-preview\/hesabim/);
  assert.match(ask, /Sorunuzu kısa ve açık şekilde yazabilirsiniz./);
  assert.match(ask, /Tek soruya odaklanın/);
  assert.match(ask, /Mahrem bilgi yazmayın/);
  assert.doesNotMatch(ask, /Kategori seçin|İsteğe bağlı kategori|İsteğe bağlı konu/);
  assert.doesNotMatch(ask, /Bu ekranda kayıt alınmıyor|yalnızca arayüz davranışı gösteriliyor|Bu ekranda kayıt alınmaz/);
  assertOnlyPublicPreviewApi(ask);
});

test('public account page offers Google and email authentication', () => {
  const account = renderPublicArchivePreviewRoute('/public-preview/hesabim').html;
  assert.match(account, /data-public-auth/);
  assert.match(account, /data-google-auth-button/);
  assert.match(account, /data-email-login-form/);
  assert.match(account, /data-email-register-form/);
  assert.match(account, /\/public-preview\/api\/auth\/email\/login/);
  assert.match(account, /\/public-preview\/api\/auth\/email\/register/);
  assert.match(account, /Google veya e-posta ile giriş yapabilirsiniz/);
});

test('question cards are whole-card navigable without helpful voting', () => {
  const home = renderPublicArchivePreviewRoute('/public-preview').html;
  assert.match(home, /data-card-href="\/public-preview\/soru\/ornek-soru"/);
  assert.match(home, /role="link"/);
  assert.match(home, /Öne Çıkan Sorular/);
  assert.doesNotMatch(home, /Öne Çıkan Cevaplar/);
  assert.match(home, /Aktif arşiv/);
  assert.match(home, /Yayındaki soru ve cevaplar/);
  assert.match(home, /aktif soru/);
  assert.match(home, /aktif cevap/);
  assert.match(home, /pa-active-stats/);
  assert.match(home, /pa-live-dot/);
  assert.match(home, /data-count-up/);
  assert.match(home, /data-count-target/);
  assert.doesNotMatch(home, /Kavram Haritası/);
  assert.doesNotMatch(home, /Ana Kategoriler/);
  const featuredSection = home.slice(home.indexOf('Öne Çıkan Sorular'), home.indexOf('Aktif arşiv'));
  assert.match(featuredSection, /has-strong-cta/);
  assert.doesNotMatch(featuredSection, /pa-card-meta/);
  assert.doesNotMatch(featuredSection, /class="pa-chip"/);
  const activeStatsSection = home.slice(home.indexOf('class="pa-active-stats"'), home.indexOf('Son Yayınlanan Sorular'));
  assert.doesNotMatch(activeStatsSection, /href=|Arşive Git|pa-active-stats-link/);
  assert.match(home, /Cevabı oku/);
  assert.match(home, /data-read-count-label/);
  assert.match(home, /okunma/);
  assert.doesNotMatch(home, /pa-question-excerpt/);
  assert.doesNotMatch(home, /Kalbin Allah’a yönelme talebi; dua, tercih ve istikametle canlı tutulur\./);
  assert.doesNotMatch(home, /Faydalı oldu mu|helpful voting/);
});

test('mobile search copy stays compact but accessible', () => {
  const home = renderPublicArchivePreviewRoute('/public-preview').html;
  assert.match(home, /placeholder="Soru veya kategori arayın\.\.\."/);
  assert.match(home, /aria-label="Sorunuzu veya kategorinizi yazın"/);
  assert.doesNotMatch(home, /placeholder="Sorunuzu veya kategorinizi yazın/);
});

test('public preview exposes separate index and info pages', () => {
  for (const route of [
    '/public-preview/konular',
    '/public-preview/kategoriler',
    '/public-preview/hakkimizda',
    '/public-preview/nasil-kullanilir',
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
