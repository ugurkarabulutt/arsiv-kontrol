const assert = require('node:assert/strict');
const test = require('node:test');
const {
  ROUTE_PATHS,
  publicArchiveFixtures,
  renderPublicArchivePreviewRoute,
  renderPublicArchiveUnavailableRoute
} = require('../public-archive-renderer');

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
    assert.doesNotMatch(rendered.html, /rel="canonical"/);
    assertOnlyPublicPreviewApi(rendered.html);
  }
});

test('public renderer can render root launch paths behind root mode', () => {
  const rootData = { ...publicArchiveFixtures, basePath: '', noindex: false };
  const home = renderPublicArchivePreviewRoute('/', {}, rootData).html;

  assert.match(home, /href="\/public-archive\.css\?v=20260903-detail-side-cards-v1"/);
  assert.match(home, /href="\/arsiv"/);
  assert.match(home, /href="\/hesabim"/);
  assert.match(home, /\/api\/session/);
  assert.match(home, /\/api\/my-question-submissions/);
  assert.match(home, /<meta name="robots" content="index,follow">/);
  assert.match(home, /<link rel="canonical" href="https:\/\/arsiv\.ibrahimlive\.ai\/">/);
  assert.match(home, /<title>Dini Sorular ve Cevaplar Arşivi<\/title>/);
  assert.match(home, /property="og:title" content="Dini Sorular ve Cevaplar Arşivi"/);
  assert.match(home, /property="og:updated_time" content="2026-08-23T14:42:53\+03:00"/);
  assert.match(home, /property="og:image" content="https:\/\/arsiv\.ibrahimlive\.ai\/assets\/public-share-card-20260823-v3\.png\?v=telegram-cache-refresh-20260823"/);
  assert.match(home, /property="og:image:secure_url" content="https:\/\/arsiv\.ibrahimlive\.ai\/assets\/public-share-card-20260823-v3\.png\?v=telegram-cache-refresh-20260823"/);
  assert.match(home, /property="og:image:type" content="image\/png"/);
  assert.match(home, /property="og:locale" content="tr_TR"/);
  assert.match(home, /name="twitter:card" content="summary_large_image"/);
  assert.match(home, /name="twitter:title"/);
  assert.match(home, /name="twitter:description"/);
  assert.match(home, /name="twitter:image:alt" content="Dini Sorular ve Cevaplar Arşivi"/);
  assert.match(home, /name="apple-mobile-web-app-title" content="Dini Sorular"/);
  assert.match(home, /name="apple-mobile-web-app-capable" content="yes"/);
  assert.match(home, /name="apple-mobile-web-app-status-bar-style" content="default"/);
  assert.match(home, /rel="apple-touch-icon" sizes="180x180" href="\/assets\/apple-touch-icon\.png\?v=20260903-detail-side-cards-v1"/);
  assert.match(home, /rel="manifest" href="\/assets\/site\.webmanifest\?v=20260903-detail-side-cards-v1"/);
  assert.match(home, /"@type":"WebSite"/);
  assert.match(home, /"@type":"SearchAction"/);
  assert.match(home, /"image":"https:\/\/arsiv\.ibrahimlive\.ai\/assets\/public-share-card-20260823-v3\.png\?v=telegram-cache-refresh-20260823"/);
  assert.match(home, /bindFastPublicNavigation/);
  assert.match(home, /dsca-page-cache:v6/);
  assert.match(home, /X-Public-Navigation/);
  assert.match(home, /data-pa-navigating/);
  assert.match(home, /data-pa-theme-boot/);
  assert.match(home, /<html lang="tr" data-theme="dark"/);
  assert.match(home, /name="theme-color" content="#0D1412"/);
  assert.match(home, /freezeRouteBackground/);
  assert.match(home, /replacePublicArchiveShell/);
  assert.match(home, /new DOMParser/);
  assert.match(home, /replaceWith/);
  assert.match(home, /cleanupPublicArchivePage/);
  assert.doesNotMatch(home, /document\.write\(/);
  assert.doesNotMatch(home, /document\.open\(/);
  assert.doesNotMatch(home, /\/public-preview\//);

  const detail = renderPublicArchivePreviewRoute('/soru/ornek-soru', {}, rootData);
  assert.equal(detail.status, 200);
  assert.match(detail.html, /href="\/kategori\//);
  assert.match(detail.html, /<link rel="canonical" href="https:\/\/arsiv\.ibrahimlive\.ai\/soru\/ornek-soru">/);
  assert.match(detail.html, /"@type":"Article"/);
  assert.match(detail.html, /"@type":"BreadcrumbList"/);
  assert.doesNotMatch(detail.html, /\/public-preview\//);

  for (const route of ['/arama', '/soru-sor', '/hesabim', '/kategoriler', '/gizlilik', '/kullanim-kosullari']) {
    const rendered = renderPublicArchivePreviewRoute(route, {}, rootData).html;
    assert.match(rendered, /<meta name="robots" content="noindex,follow">/);
    assert.doesNotMatch(rendered, /rel="canonical"/);
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
  assert.match(home, /\/public-preview\/assets\/arsiv-logo-mark\.png/);
  assert.match(home, /class="pa-logo-mark"/);
  assert.match(home, /class="pa-logo-text"/);
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
  assert.match(hArchive, /<button class="pa-alpha-nav" type="button" data-alpha-scroll="prev"/);
  assert.match(hArchive, /<button class="pa-alpha-nav" type="button" data-alpha-scroll="next"/);
  assert.doesNotMatch(hArchive, /class="pa-alpha-nav" href=/);

  const numericArchiveData = {
    ...publicArchiveFixtures,
    categories: [
      { slug: 'iki', name: '2', description: '2 başlığı.', topicSlugs: [] },
      { slug: 'adem', name: 'Âdem', description: 'Âdem soruları.', topicSlugs: [] }
    ],
    topics: [],
    qa: [
      {
        slug: 'iki-sorusu',
        title: '2 hakkında soru',
        question: '2 hakkında soru',
        answer: ['Cevap metni.'],
        categorySlug: 'iki',
        topicSlugs: [],
        publishedAt: '2026-08-23T00:00:00.000Z',
        updatedAt: '2026-08-23T00:00:00.000Z'
      },
      {
        slug: 'adem-sorusu',
        title: 'Âdem hakkında soru',
        question: 'Âdem hakkında soru',
        answer: ['Cevap metni.'],
        categorySlug: 'adem',
        topicSlugs: [],
        publishedAt: '2026-08-23T00:00:00.000Z',
        updatedAt: '2026-08-23T00:00:00.000Z'
      }
    ]
  };
  const defaultNumericArchive = renderPublicArchivePreviewRoute('/public-preview/arsiv', {}, numericArchiveData).html;
  assert.match(defaultNumericArchive, /A harfiyle başlayan kategoriler/);
  assert.doesNotMatch(defaultNumericArchive, /# harfiyle başlayan kategoriler/);
  const hashArchive = renderPublicArchivePreviewRoute('/public-preview/arsiv', { harf: '#' }, numericArchiveData).html;
  assert.match(hashArchive, /# harfiyle başlayan kategoriler/);
  assert.match(hashArchive, />2<\/strong>/);

  const circumflexArchive = renderPublicArchivePreviewRoute('/public-preview/arsiv', { harf: 'Â' }, {
    ...publicArchiveFixtures,
    categories: [
      { slug: 'adem', name: 'Âdem', description: 'Âdem soruları.', topicSlugs: [] },
      { slug: 'ahlak', name: 'Ahlak', description: 'Ahlak soruları.', topicSlugs: [] }
    ],
    topics: [],
    qa: [{
      slug: 'adem-sorusu',
      title: 'Âdem hakkında soru',
      question: 'Âdem hakkında soru',
      answer: ['Cevap metni.'],
      categorySlug: 'adem',
      topicSlugs: [],
      publishedAt: '2026-08-23T00:00:00.000Z',
      updatedAt: '2026-08-23T00:00:00.000Z'
    }]
  }).html;
  assert.match(circumflexArchive, /A harfiyle başlayan kategoriler/);
  assert.match(circumflexArchive, /Âdem/);
  assert.doesNotMatch(circumflexArchive, /Â harfiyle başlayan kategoriler|harf=Â/);

  const filteredArchive = renderPublicArchivePreviewRoute('/public-preview/arsiv', { harf: 'H', kategori: 'hidayet' }).html;
  assert.match(filteredArchive, /Hidayet soruları/);
  assert.match(filteredArchive, /Tümünü göster/);
  assert.doesNotMatch(filteredArchive, /<h2>Tüm Sorular<\/h2>/);

  const account = renderPublicArchivePreviewRoute('/public-preview/hesabim').html;
  assert.match(account, /Soru göndermek için hesabınıza giriş yapın\./);
  assert.match(account, /Google ile Devam Et/);
  assert.match(account, /data-auth-tab="login"/);
  assert.match(account, /data-auth-tab="register"/);
  assert.match(account, /class="pa-google-button"/);
  assert.match(account, /\/public-preview\/auth\/google/);
  assert.match(account, /data-user-questions/);
  assert.match(account, /data-user-questions-list/);
  assert.match(account, /\/public-preview\/api\/my-question-submissions/);
  assertOnlyPublicPreviewApi(account);

  const ask = renderPublicArchivePreviewRoute('/public-preview/soru-sor').html;
  assert.match(ask, /<h2>Gönderdiğiniz sorular<\/h2>/);
  assert.match(ask, /Sorduğunuz sorular, inceleme durumu ve gelen cevaplar bu alanda görünür\./);
  assert.match(ask, /class="pa-account-questions pa-ask-questions"/);
  assert.match(ask, /data-user-questions-list/);
  assert.match(ask, /\/public-preview\/api\/my-question-submissions/);
  assertOnlyPublicPreviewApi(ask);
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

test('weak category pages stay visible but are not indexed', () => {
  const weakData = {
    noindex: false,
    categories: [
      { slug: 'cok-dar-baslik', name: 'Çok Dar Başlık', description: 'Az sorulu kategori.' }
    ],
    topics: [],
    qa: [{
      id: 'qa-weak',
      slug: 'weak-soru',
      title: 'Az sorulu kategori görünür mü?',
      question: 'Az sorulu kategori görünür mü?',
      answer: ['Evet, kullanıcı için görünür kalır.'],
      categorySlug: 'cok-dar-baslik',
      categorySlugs: ['cok-dar-baslik'],
      topicSlugs: ['cok-dar-baslik'],
      publishedAt: '2026-08-10',
      readTime: 1
    }]
  };
  const weak = renderPublicArchivePreviewRoute('/public-preview/kategori/cok-dar-baslik', {}, weakData).html;
  assert.match(weak, /Az sorulu kategori görünür mü\?/);
  assert.match(weak, /<meta name="robots" content="noindex,follow">/);
  assert.doesNotMatch(weak, /<link rel="canonical" href="https:\/\/arsiv\.ibrahimlive\.ai\/kategori\/cok-dar-baslik">/);

  const strategicData = {
    noindex: false,
    categories: [
      { slug: 'hidayet', name: 'Hidayet', description: 'Stratejik kategori.' }
    ],
    topics: [],
    qa: [{
      id: 'qa-hidayet-small',
      slug: 'hidayet-small',
      title: 'Hidayet az soruyla indexlenir mi?',
      question: 'Hidayet az soruyla indexlenir mi?',
      answer: ['Evet, stratejik ana kategori olduğu için indexlenebilir.'],
      categorySlug: 'hidayet',
      categorySlugs: ['hidayet'],
      topicSlugs: ['hidayet'],
      publishedAt: '2026-08-10',
      readTime: 1
    }]
  };
  const strategic = renderPublicArchivePreviewRoute('/public-preview/kategori/hidayet', {}, strategicData).html;
  assert.match(strategic, /<meta name="robots" content="index,follow">/);
  assert.match(strategic, /<link rel="canonical" href="https:\/\/arsiv\.ibrahimlive\.ai\/kategori\/hidayet">/);
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

test('archive selected category shows its questions immediately', () => {
  const archive = renderPublicArchivePreviewRoute('/public-preview/arsiv', { harf: 'A', kategori: 'ana-baslik' }, {
    stats: { questionCount: 1, answerCount: 1 },
    pagination: { scope: 'archive', prePaginated: true, page: 1, pageSize: 30, total: 1 },
    categories: [
      { slug: 'ana-baslik', name: 'Ana Başlık', questionCount: 1 },
      { slug: 'ayni-harf-baska-baslik', name: 'Aynı Harf Başka Başlık', questionCount: 4 }
    ],
    topics: [],
    qa: [{
      id: 'qa-selected-category',
      slug: 'secili-kategori-sorusu',
      title: 'Seçili kategori sorusu görünür mü?',
      question: 'Seçili kategori sorusu görünür mü?',
      answer: ['Evet, kategori seçilince ilgili soru listesi hemen görünür.'],
      categorySlug: 'ana-baslik',
      categorySlugs: ['ana-baslik'],
      topicSlugs: ['ana-baslik'],
      publishedAt: '2026-08-10',
      readTime: 1
    }]
  }).html;

  assert.match(archive, /Ana Başlık seçildi/);
  assert.match(archive, /Ana Başlık soruları/);
  assert.match(archive, /Seçili kategori sorusu görünür mü\?/);
  assert.equal((archive.match(/class="pa-index-category/g) || []).length, 1);
  assert.doesNotMatch(archive, /Aynı Harf Başka Başlık/);
});

test('public unavailable mode keeps site shell without fixture questions', () => {
  const result = renderPublicArchiveUnavailableRoute('/', {}, { basePath: '' });

  assert.equal(result.status, 200);
  assert.match(result.html, /Sorularınıza, kaynaklarıyla birlikte cevap bulun\./);
  assert.match(result.html, /Aklınızda bir soru mu var\?/);
  assert.match(result.html, /<meta name="robots" content="noindex,nofollow">/);
  assert.doesNotMatch(result.html, /Hidayet yolu nasıl başlar\?/);
  assert.doesNotMatch(result.html, /Arşiv geçici olarak hazırlanıyor/);
  assert.doesNotMatch(result.html, /Öne Çıkan Sorular/);
  assert.doesNotMatch(result.html, /<link rel="canonical"/);

  const archive = renderPublicArchiveUnavailableRoute('/arsiv', {}, { basePath: '' });
  assert.equal(archive.status, 200);
  assert.match(archive.html, /Merak ettiğiniz konunun cevaplarına ulaşın\./);
  assert.doesNotMatch(archive.html, /<section class="pa-section" id="sorular">/);
  assert.doesNotMatch(archive.html, /Hidayet yolu nasıl başlar\?/);
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
  assert.match(detail.html, /application\/ld\+json/);
  assert.match(detail.html, /"@type":"Article"/);
  assert.match(detail.html, /"mainEntityOfPage"/);
  assert.match(detail.html, /"@type":"BreadcrumbList"/);
  assert.match(detail.html, /"citation":\["Bakara-256","Yâsîn-62"\]/);
  assert.doesNotMatch(detail.html, /"@type":"QAPage"/);
  assert.doesNotMatch(detail.html, /"acceptedAnswer"/);
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
  assert.match(detail, /"@type":"SearchAction"/);
  assert.doesNotMatch(detail, /Yazdır|data-print/);
  assert.doesNotMatch(detail, /class="pa-detail-subtitle"/);
  assert.doesNotMatch(detail, /<h1>Allah’a ulaşmayı dilemek ne demektir\?<\/h1>/);
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
  assert.match(account, /class="pa-google-button"/);
  assert.match(account, /data-auth-mode="login"/);
  assert.match(account, /data-auth-tab="login"/);
  assert.match(account, /data-auth-tab="register"/);
  assert.match(account, /data-email-login-form/);
  assert.match(account, /data-email-register-form/);
  assert.match(account, /data-user-questions/);
  assert.match(account, /Gönderdiğiniz sorular ve cevap durumları/);
  assert.match(account, /\/public-preview\/api\/auth\/email\/login/);
  assert.match(account, /\/public-preview\/api\/auth\/email\/register/);
  assert.match(account, /\/public-preview\/api\/my-question-submissions/);
  assert.match(account, /Google hesabınızla hızlıca devam edebilir/);
});

test('question detail hides same-question related links and shows popular links separately', () => {
  const archiveData = {
    brand: {},
    categories: [{ slug: 'mursid', name: 'Mürşid', description: 'Mürşid soruları.', topicSlugs: ['mursid'] }],
    topics: [],
    qa: [
      {
        slug: 'ana-soru',
        title: 'Mürşide neden ihtiyaç vardır?',
        question: 'Mürşide neden ihtiyaç vardır?',
        answer: ['Ana cevap.'],
        categorySlug: 'mursid',
        topicSlugs: ['mursid'],
        relatedSlugs: ['ana-soru-kopya', 'farkli-soru'],
        publishedAt: '2026-08-20T09:00:00.000Z',
        readCount: 20
      },
      {
        slug: 'ana-soru-kopya',
        title: 'Mürşide neden ihtiyaç vardır?',
        question: 'Mürşide neden ihtiyaç vardır?',
        answer: ['Aynı sorunun farklı cevabı.'],
        categorySlug: 'mursid',
        topicSlugs: ['mursid'],
        publishedAt: '2026-08-19T09:00:00.000Z',
        readCount: 30
      },
      {
        slug: 'farkli-soru',
        title: 'Doğru mürşid nasıl tanınır?',
        question: 'Doğru mürşid nasıl tanınır?',
        answer: ['Farklı ilgili cevap.'],
        categorySlug: 'mursid',
        topicSlugs: ['mursid'],
        publishedAt: '2026-08-18T09:00:00.000Z',
        readCount: 12
      },
      {
        slug: 'populer-soru',
        title: 'En çok okunan soru',
        question: 'En çok okunan soru',
        answer: ['Popüler cevap.'],
        categorySlug: 'mursid',
        topicSlugs: ['mursid'],
        publishedAt: '2026-08-17T09:00:00.000Z',
        readCount: 99,
        isDetailPopular: true
      }
    ]
  };

  const html = renderPublicArchivePreviewRoute('/public-preview/soru/ana-soru', {}, archiveData).html;
  const relatedSection = html.slice(html.indexOf('İlgili Sorular'), html.indexOf('En Çok Okunanlar'));
  const popularSection = html.slice(html.indexOf('En Çok Okunanlar'), html.indexOf('Kategoriler'));
  assert.match(relatedSection, /Doğru mürşid nasıl tanınır\?/);
  assert.doesNotMatch(relatedSection, /ana-soru-kopya/);
  assert.match(html, /En Çok Okunanlar/);
  assert.match(popularSection, /En çok okunan soru/);
  assert.match(popularSection, /99 okunma/);
  assert.match(html, /pa-side-question-title/);
  assert.match(html, /pa-side-question-bottom/);
  assert.match(html, /pa-side-question-cta/);
  assert.doesNotMatch(html, /pa-side-question-index/);
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

test('home page question selection only deduplicates exact question-answer copies', () => {
  const archiveData = {
    brand: { sentence: 'Cevaplara delilleri ve kaynak bağlamıyla kolayca ulaşın.' },
    categories: [{ slug: 'karar-vermek', name: 'Karar Vermek', description: 'Karar verme soruları.', topicSlugs: [] }],
    topics: [],
    qa: [
      {
        slug: 'mukerrer-soru-a',
        title: 'Aynı karar sorusu mükerrer görünmemeli mi?',
        question: 'Aynı karar sorusu mükerrer görünmemeli mi?',
        answer: ['Bu kayıt ilk örnek olarak gelir.'],
        categorySlug: 'karar-vermek',
        publishedAt: '2026-08-20T09:00:00.000Z',
        readCount: 1,
        isFeatured: true
      },
      {
        slug: 'mukerrer-soru-b',
        title: 'Aynı karar sorusu mükerrer görünmemeli mi?',
        question: 'Aynı karar sorusu mükerrer görünmemeli mi?',
        answer: ['Bu kayıt aynı sorunun daha çok okunan sürümüdür.'],
        categorySlug: 'karar-vermek',
        publishedAt: '2026-08-21T09:00:00.000Z',
        readCount: 20,
        isFeatured: true
      },
      {
        slug: 'mukerrer-soru-c',
        title: 'Aynı karar sorusu mükerrer görünmemeli mi?',
        question: 'Aynı karar sorusu mükerrer görünmemeli mi?',
        answer: ['Bu kayıt aynı sorunun daha çok okunan sürümüdür.'],
        categorySlug: 'karar-vermek',
        publishedAt: '2026-08-18T09:00:00.000Z',
        readCount: 2,
        isFeatured: true
      },
      {
        slug: 'cok-okunan-vitrin-sorusu',
        title: 'Çok okunan soru vitrinde yer bulur mu?',
        question: 'Çok okunan soru vitrinde yer bulur mu?',
        answer: ['Bu kayıt okuma ağırlığı kontrolü için kullanılır.'],
        categorySlug: 'karar-vermek',
        publishedAt: '2026-08-19T09:00:00.000Z',
        readCount: 999
      }
    ]
  };
  const home = renderPublicArchivePreviewRoute('/public-preview', {}, archiveData).html;

  assert.match(home, /\/public-preview\/soru\/mukerrer-soru-b/);
  assert.match(home, /\/public-preview\/soru\/mukerrer-soru-a/);
  assert.doesNotMatch(home, /\/public-preview\/soru\/mukerrer-soru-c/);
  assert.match(home, /Çok okunan soru vitrinde yer bulur mu\?/);
});

test('home page featured questions rotate across hours from a wider pool', () => {
  const archiveData = {
    brand: {},
    categories: [{ slug: 'genel', name: 'Genel', description: 'Genel sorular.', topicSlugs: ['genel'] }],
    topics: [],
    qa: Array.from({ length: 24 }, (_, index) => ({
      slug: `saatlik-soru-${index + 1}`,
      title: `Saatlik soru ${index + 1}`,
      question: `Saatlik soru ${index + 1}`,
      answer: [`Saatlik cevap ${index + 1}`],
      categorySlug: 'genel',
      topicSlugs: ['genel'],
      publishedAt: `2026-08-${String(10 + index).padStart(2, '0')}T09:00:00.000Z`,
      readCount: 10 + index,
      isFeatured: true
    }))
  };
  const originalNow = Date.now;
  try {
    Date.now = () => Date.UTC(2026, 7, 20, 9, 0, 0);
    const first = renderPublicArchivePreviewRoute('/public-preview', {}, archiveData).html;
    Date.now = () => Date.UTC(2026, 7, 20, 10, 0, 0);
    const second = renderPublicArchivePreviewRoute('/public-preview', {}, archiveData).html;
    const firstFeatured = first.slice(first.indexOf('Öne Çıkan Sorular'), first.indexOf('Aktif arşiv'));
    const secondFeatured = second.slice(second.indexOf('Öne Çıkan Sorular'), second.indexOf('Aktif arşiv'));
    assert.notEqual(firstFeatured, secondFeatured);
  } finally {
    Date.now = originalNow;
  }
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

test('public info pages have page-specific explanatory copy and actions', () => {
  const about = renderPublicArchivePreviewRoute('/public-preview/hakkimizda').html;
  assert.match(about, /Dini soruların cevaplarını delilleri ve kaynak bağlamıyla birlikte sunan bir arşiv\./);
  assert.match(about, /Arşivi İncele/);
  assert.match(about, /Nasıl Kullanılır\?/);

  const howTo = renderPublicArchivePreviewRoute('/public-preview/nasil-kullanilir').html;
  assert.match(howTo, /Aradığınız cevaba arama, arşiv ve kategoriler üzerinden ulaşabilirsiniz\./);
  assert.match(howTo, /Arama Yap/);
  assert.match(howTo, /Arşive Git/);

  const contact = renderPublicArchivePreviewRoute('/public-preview/iletisim').html;
  assert.match(contact, /düzeltme, eksik bilgi ve soru taleplerinizi doğru yerden iletebilirsiniz/);
  assert.match(contact, /Düzeltme notu/);
  assert.match(contact, /Gizliliği Oku/);

  const privacy = renderPublicArchivePreviewRoute('/public-preview/gizlilik').html;
  assert.match(privacy, /mahremiyetinizi korumanız önemlidir/);
  assert.match(privacy, /Üçüncü kişiler/);
  assert.match(privacy, /Soru Sorarken Dikkat Edin/);

  const terms = renderPublicArchivePreviewRoute('/public-preview/kullanim-kosullari').html;
  assert.match(terms, /geçerli temel kullanım ilkeleri/);
  assert.match(terms, /Okuma ve paylaşım/);
  assert.match(terms, /Arşivi Aç/);
});
