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
    const rendered = renderPublicArchivePreviewRoute(route, route.endsWith('/arama') ? { q: 'namaz' } : {});
    assert.match(rendered.html, /<meta name="robots" content="noindex,nofollow">/);
    assert.match(rendered.html, /Dini Sorular/);
    assert.match(rendered.html, /ve Cevaplar Arşivi/);
    assert.match(rendered.html, /Hesab\u0131m/);
    assert.match(rendered.html, /Sorularınız Kur’ân ışığında cevaplanır\./);
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
    renderPublicArchivePreviewRoute('/public-preview/arama', { q: 'namaz' }).html,
    renderPublicArchivePreviewRoute('/public-preview/soru/ornek-soru').html,
    renderPublicArchivePreviewRoute('/public-preview/konu/ornek-kavram').html,
    renderPublicArchivePreviewRoute('/public-preview/kategori/ornek-kategori').html,
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
});

test('archive and account routes are explicit public preview pages', () => {
  const archive = renderPublicArchivePreviewRoute('/public-preview/arsiv').html;
  assert.match(archive, /Soru ve cevapları sakince keşfedin\./);
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
  const result = renderPublicArchivePreviewRoute('/public-preview/arama', { q: 'namaz' });
  assert.equal(result.status, 200);
  assert.match(result.html, /Namaz kılarken akla gelen kötü düşünceler/);

  const empty = renderPublicArchivePreviewRoute('/public-preview/arama', { q: 'bulunmayan-kelime' });
  assert.equal(empty.status, 200);
  assert.match(empty.html, /Sonuç bulunamadı\./);
  assert.match(empty.html, /Aklınızda bir soru mu var\?/);

  const missing = renderPublicArchivePreviewRoute('/public-preview/soru/gizli-icerik');
  assert.equal(missing.status, 404);
  assert.match(missing.html, /Sayfa bulunamadı\./);
});

test('question, topic, category, and ask pages keep public boundaries', () => {
  const detail = renderPublicArchivePreviewRoute('/public-preview/soru/ornek-soru').html;
  assert.match(detail, /Orijinal Soru/);
  assert.match(detail, /Cevap/);
  assert.match(detail, /Kaynak ve bağlam/);
  assert.match(detail, /İlgili Sorular/);
  assert.match(detail, /data-public-read-count="ornek-soru"/);
  assertOnlyPublicPreviewApi(detail);

  const topic = renderPublicArchivePreviewRoute('/public-preview/konu/ornek-kavram').html;
  const category = renderPublicArchivePreviewRoute('/public-preview/kategori/ornek-kategori').html;
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
