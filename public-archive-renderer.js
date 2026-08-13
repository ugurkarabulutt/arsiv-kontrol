const express = require('express');
const fs = require('fs');
const path = require('path');
const { publicArchiveFixtures } = require('./public-archive-fixtures');

const PREVIEW_BASE = '/public-preview';
const CSS_PATH = `${PREVIEW_BASE}/public-archive.css`;
const ASSET_PATH = `${PREVIEW_BASE}/assets`;
const ICON_DIR = path.join(__dirname, 'public-archive-assets', 'icons');

function normalizePublicArchiveData(archiveData = {}) {
  return {
    brand: { ...publicArchiveFixtures.brand, ...(archiveData.brand || {}) },
    categories: Array.isArray(archiveData.categories) ? archiveData.categories : publicArchiveFixtures.categories,
    topics: Array.isArray(archiveData.topics) ? archiveData.topics : publicArchiveFixtures.topics,
    qa: Array.isArray(archiveData.qa) ? archiveData.qa : publicArchiveFixtures.qa
  };
}

function withPublicArchiveData(archiveData, renderFn) {
  if (!archiveData || archiveData === publicArchiveFixtures) return renderFn();
  const previous = {
    brand: publicArchiveFixtures.brand,
    categories: publicArchiveFixtures.categories,
    topics: publicArchiveFixtures.topics,
    qa: publicArchiveFixtures.qa
  };
  const next = normalizePublicArchiveData(archiveData);
  publicArchiveFixtures.brand = next.brand;
  publicArchiveFixtures.categories = next.categories;
  publicArchiveFixtures.topics = next.topics;
  publicArchiveFixtures.qa = next.qa;
  try {
    return renderFn();
  } finally {
    publicArchiveFixtures.brand = previous.brand;
    publicArchiveFixtures.categories = previous.categories;
    publicArchiveFixtures.topics = previous.topics;
    publicArchiveFixtures.qa = previous.qa;
  }
}

const ROUTE_PATHS = [
  PREVIEW_BASE,
  `${PREVIEW_BASE}/arsiv`,
  `${PREVIEW_BASE}/arama`,
  `${PREVIEW_BASE}/konular`,
  `${PREVIEW_BASE}/kategoriler`,
  `${PREVIEW_BASE}/soru/ornek-soru`,
  `${PREVIEW_BASE}/konu/kalbin-yonelisi`,
  `${PREVIEW_BASE}/kategori/allaha-ulasmayi-dilemek`,
  `${PREVIEW_BASE}/hesabim`,
  `${PREVIEW_BASE}/soru-sor`,
  `${PREVIEW_BASE}/hakkimizda`,
  `${PREVIEW_BASE}/iletisim`,
  `${PREVIEW_BASE}/gizlilik`,
  `${PREVIEW_BASE}/kullanim-kosullari`,
  `${PREVIEW_BASE}/bulunamadi`
];

function escapeHtml(value) {
  return String(value ?? '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

function normalizeSearchText(value) {
  return String(value || '')
    .toLocaleLowerCase('tr-TR')
    .normalize('NFD')
    .replace(/[\u0300-\u036f]/g, '')
    .replace(/[^\p{L}\p{N}\s]/gu, ' ')
    .replace(/\s+/g, ' ')
    .trim();
}

function formatDate(value) {
  if (!value) return '';
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return '';
  return new Intl.DateTimeFormat('tr-TR', {
    day: 'numeric',
    month: 'long',
    year: 'numeric'
  }).format(date);
}

function bySlug(items, slug) {
  return items.find(item => item.slug === slug) || null;
}

function categoryFor(entry) {
  return bySlug(publicArchiveFixtures.categories, entry.categorySlug);
}

function topicsFor(entry) {
  return (entry.topicSlugs || [])
    .map(slug => bySlug(publicArchiveFixtures.topics, slug))
    .filter(Boolean);
}

function entriesForTopic(slug) {
  return publicArchiveFixtures.qa.filter(entry => (entry.topicSlugs || []).includes(slug));
}

function entriesForCategory(slug) {
  return publicArchiveFixtures.qa.filter(entry => entry.categorySlug === slug);
}

function relatedEntries(entry) {
  return (entry.relatedSlugs || [])
    .map(slug => bySlug(publicArchiveFixtures.qa, slug))
    .filter(Boolean);
}

function relatedTopics(topic) {
  return (topic.relatedTopicSlugs || [])
    .map(slug => bySlug(publicArchiveFixtures.topics, slug))
    .filter(Boolean);
}

function href(route) {
  if (!route) return PREVIEW_BASE;
  return route.startsWith('/') ? route : `${PREVIEW_BASE}/${route}`;
}

function pageTitle(title) {
  const brand = publicArchiveFixtures.brand.name;
  return title ? `${title} | ${brand}` : brand;
}

const svgIconCache = new Map();

const BOTTOM_NAV_ICONS = {
  home: 'home',
  archive: 'archive',
  search: 'search',
  topics: 'topics',
  ask: 'edit'
};

const CATEGORY_ICONS = {
  'allaha-ulasmayi-dilemek': 'dua',
  hidayet: 'tevhid',
  mursid: 'takva',
  zikir: 'ibadet',
  teslimiyet: 'ihlas'
};

const TOPIC_ICONS = {
  'kalbin-yonelisi': 'takva',
  dua: 'dua',
  takva: 'takva',
  'sirati-mustakim': 'tevhid',
  tabiiyet: 'takva',
  zikir: 'ibadet',
  'daimi-zikir': 'ibadet',
  nefs: 'sukur',
  'nefs-tezkiyesi': 'sukur',
  teslim: 'ihlas',
  ruh: 'ihlas',
  irsad: 'help-circle',
  kalp: 'iman',
  irade: 'niyet',
  tevekkul: 'sabir',
  rahmet: 'dua'
};

function iconSvg(name, className = 'pa-svg-icon') {
  const safeName = String(name || '').replace(/[^a-z0-9-]/gi, '');
  if (!safeName) return '';
  if (!svgIconCache.has(safeName)) {
    try {
      const svg = fs.readFileSync(path.join(ICON_DIR, safeName + '.svg'), 'utf8');
      const openTag = '<svg class=\"' + className + '\" aria-hidden=\"true\" focusable=\"false\" ';
      svgIconCache.set(safeName, svg.replace('<svg ', openTag));
    } catch (error) {
      svgIconCache.set(safeName, '');
    }
  }
  return svgIconCache.get(safeName);
}

function categoryIconName(category) {
  return CATEGORY_ICONS[category?.slug] || 'diger';
}

function topicIconName(topic) {
  return TOPIC_ICONS[topic?.slug] || 'topics';
}

function questionIconName(entry, category, topics) {
  const primaryTopic = (topics || [])[0];
  return topicIconName(primaryTopic) || categoryIconName(category) || 'help-circle';
}

function previewActionNav(active) {
  const items = [
    ['Ana Sayfa', PREVIEW_BASE, 'home'],
    ['Arşiv', `${PREVIEW_BASE}/arsiv`, 'archive'],
    ['Ara', `${PREVIEW_BASE}/arama#arama`, 'search'],
    ['Konular', `${PREVIEW_BASE}/konular`, 'topics'],
    ['Soru Sor', `${PREVIEW_BASE}/soru-sor`, 'ask']
  ];
  return items.map(([label, url, key]) => `
    <a class="pa-bottom-link${active === key ? ' is-active' : ''}" href="${escapeHtml(url)}">
      <span class="pa-bottom-icon">${iconSvg(BOTTOM_NAV_ICONS[key] || key)}</span>
      <span>${escapeHtml(label)}</span>
    </a>
  `).join('');
}

function header(active) {
  const nav = [
    ['Ana Sayfa', PREVIEW_BASE, 'home'],
    ['Ar\u015fiv', PREVIEW_BASE + '/arsiv', 'archive'],
    ['Konular', PREVIEW_BASE + '/konular', 'topics'],
    ['Kategoriler', PREVIEW_BASE + '/kategoriler', 'categories'],
    ['Soru Sor', PREVIEW_BASE + '/soru-sor', 'ask']
  ];
  const logo = publicArchiveFixtures.brand.logoLines.map(line => `<span>${escapeHtml(line)}</span>`).join('');
  return `
    <header class="pa-header">
      <a class="pa-logo" href="${PREVIEW_BASE}" aria-label="${escapeHtml(publicArchiveFixtures.brand.name)}">${logo}</a>
      <nav class="pa-desktop-nav" aria-label="Ana gezinme">
        ${nav.map(([label, url, key]) => `<a class="${active === key ? 'is-active' : ''}" href="${escapeHtml(url)}">${escapeHtml(label)}</a>`).join('')}
      </nav>
      <div class="pa-header-actions">
        <a class="pa-account-button${active === 'account' ? ' is-active' : ''}" href="${PREVIEW_BASE}/hesabim" aria-label="Hesab\u0131m">
          <span class="pa-account-icon">${iconSvg('user')}</span>
          <span class="pa-account-text">Hesab\u0131m</span>
        </a>
        <button class="pa-theme-toggle" type="button" data-theme-toggle aria-label="Tema de\u011fi\u015ftir">
          <span class="pa-theme-toggle-icon"><span class="pa-theme-sun">${iconSvg('sun')}</span><span class="pa-theme-moon">${iconSvg('moon')}</span></span>
        </button>
      </div>
    </header>
  `;
}

function footer() {
  const logo = publicArchiveFixtures.brand.logoLines.map(line => `<span>${escapeHtml(line)}</span>`).join('');
  return `
    <footer class="pa-footer">
      <div class="pa-footer-brand">
        <a class="pa-logo" href="${PREVIEW_BASE}" aria-label="${escapeHtml(publicArchiveFixtures.brand.name)}">${logo}</a>
        <p>${escapeHtml(publicArchiveFixtures.brand.sentence)}</p>
      </div>
      <nav class="pa-footer-links" aria-label="Alt bağlantılar">
        <a href="${PREVIEW_BASE}/hakkimizda">Hakkımızda</a>
        <a href="${PREVIEW_BASE}/iletisim">İletişim</a>
        <a href="${PREVIEW_BASE}/gizlilik">Gizlilik</a>
        <a href="${PREVIEW_BASE}/kullanim-kosullari">Kullanım Koşulları</a>
      </nav>
      <p class="pa-copyright">© 2026 Dini Sorular ve Cevaplar Arşivi. Tüm hakları saklıdır.</p>
    </footer>
  `;
}

function searchBox(value = '', label = 'Arşivde ara') {
  return `
    <form class="pa-search" action="${PREVIEW_BASE}/arama" method="get" role="search" id="arama">
      <label class="pa-sr-only" for="pa-search-input">${escapeHtml(label)}</label>
      <span class="pa-search-leading">${iconSvg('search')}</span>
      <input id="pa-search-input" name="q" value="${escapeHtml(value)}" placeholder="Soru veya kavram yazın..." autocomplete="off" inputmode="search" enterkeyhint="search" aria-label="Sorunuzu veya kavramınızı yazın">
      <button type="submit" aria-label="Ara">
        <span class="pa-search-icon">${iconSvg('arrow-right')}</span>
      </button>
    </form>
  `;
}

function stillLife() {
  return `
    <div class="pa-still-life" aria-hidden="true">
      <picture class="pa-hero-asset pa-hero-asset-light">
        <source media="(max-width: 899px)" srcset="${ASSET_PATH}/hero-bookshelf-light-mobile.webp" type="image/webp">
        <img src="${ASSET_PATH}/hero-bookshelf-light-desktop.webp" alt="" loading="eager" decoding="async">
      </picture>
      <picture class="pa-hero-asset pa-hero-asset-dark">
        <source media="(max-width: 899px)" srcset="${ASSET_PATH}/hero-bookshelf-dark-mobile.webp" type="image/webp">
        <img src="${ASSET_PATH}/hero-bookshelf-dark-desktop.webp" alt="" loading="eager" decoding="async">
      </picture>
    </div>
  `;
}

function sectionHeader(title, actionText, actionHref) {
  return `
    <div class="pa-section-head">
      <h2>${escapeHtml(title)}</h2>
      ${actionHref ? `<a href="${escapeHtml(actionHref)}">${escapeHtml(actionText || 'Tümünü Gör')} ${iconSvg('chevron-right', 'pa-inline-chevron')}</a>` : ''}
    </div>
  `;
}

function chip(label, hrefValue) {
  const content = `<span class="pa-chip">${escapeHtml(label)}</span>`;
  if (!hrefValue) return content;
  return `<a class="pa-chip" href="${escapeHtml(hrefValue)}">${escapeHtml(label)}</a>`;
}

const HERO_CONCEPT_ITEMS = [
  ['Hidayet', `${PREVIEW_BASE}/kategori/hidayet`],
  ['Zikir', `${PREVIEW_BASE}/kategori/zikir`],
  ['Takva', `${PREVIEW_BASE}/konu/takva`],
  ['Tabiiyet', `${PREVIEW_BASE}/konu/tabiiyet`],
  ['Allah’a Ulaşmayı Dilemek', `${PREVIEW_BASE}/kategori/allaha-ulasmayi-dilemek`],
  ['Nefs', `${PREVIEW_BASE}/konu/nefs`],
  ['Ruh', `${PREVIEW_BASE}/konu/ruh`]
];

function conceptSliderItems(isClone = false) {
  return HERO_CONCEPT_ITEMS.map(([label, url]) => `
    <a class="pa-concept-pill" href="${escapeHtml(url)}"${isClone ? ' tabindex="-1" aria-hidden="true"' : ''}>
      <span>${escapeHtml(label)}</span>
    </a>
  `).join('');
}

function heroConceptLane() {
  return `
    <div class="pa-hero-concepts" data-concept-slider aria-label="Öne çıkan kavramlar">
      <div class="pa-concept-head">
        <span>Sık okunan kavramlar</span>
        <span aria-hidden="true">→</span>
      </div>
      <div class="pa-concept-track" data-concept-track>
        <div class="pa-concept-rail" data-concept-rail>
          <div class="pa-concept-set" data-concept-set>${conceptSliderItems(false)}</div>
          <div class="pa-concept-set" aria-hidden="true">${conceptSliderItems(true)}</div>
        </div>
      </div>
    </div>
  `;
}

function readingPath(categories) {
  return `
    <section class="pa-reading-path" aria-label="Arşiv ana kapıları">
      <div class="pa-path-copy">
        <p class="pa-kicker">Arşiv ana kapıları</p>
        <h2>Cevapları yalnız liste olarak değil, kavram yolu olarak okuyun.</h2>
      </div>
      <div class="pa-path-grid">
        ${categories.map((category, index) => `
          <a class="pa-path-step" href="${PREVIEW_BASE}/kategori/${escapeHtml(category.slug)}">
            <span>${String(index + 1).padStart(2, '0')}</span>
            <strong>${escapeHtml(category.name)}</strong>
            <em>${entriesForCategory(category.slug).length} soru</em>
          </a>
        `).join('')}
      </div>
    </section>
  `;
}

function normalizedReadCount(entry = {}) {
  const count = Number(entry.readCount ?? entry.viewCount ?? 0);
  if (!Number.isFinite(count) || count < 0) return 0;
  return Math.round(count);
}

function readCountLabel(count) {
  return `${Number(count || 0).toLocaleString('tr-TR')} okunma`;
}

function readCountNode(entry) {
  const count = normalizedReadCount(entry);
  return `<span class="pa-read-count" data-public-read-count="${escapeHtml(entry.slug)}" data-read-count-fallback="${count}">${iconSvg('eye', 'pa-meta-icon')}<span data-read-count-label>${escapeHtml(readCountLabel(count))}</span></span>`;
}

function questionCard(entry, compact = false) {
  const category = categoryFor(entry);
  const topics = topicsFor(entry);
  const visibleTopics = topics.filter(topic => !category || topic.slug !== category.slug);
  const countNode = readCountNode(entry);
  const href = `${PREVIEW_BASE}/soru/${escapeHtml(entry.slug)}`;
  return `
    <article class="pa-question-card${compact ? ' is-compact' : ''}" data-card-href="${href}" role="link" tabindex="0" aria-label="${escapeHtml(entry.title)}">
      <span class="pa-card-icon">${iconSvg(questionIconName(entry, category, topics))}</span>
      <a class="pa-question-title" href="${href}">${escapeHtml(entry.title)}</a>
      <div class="pa-card-meta">
        ${category ? chip(category.name, `${PREVIEW_BASE}/kategori/${category.slug}`) : ''}
        ${visibleTopics.slice(0, 2).map(topic => chip(topic.name, `${PREVIEW_BASE}/konu/${topic.slug}`)).join('')}
      </div>
      <div class="pa-card-bottom">
        <p class="pa-card-foot">${countNode}</p>
        <span class="pa-card-cta">Cevabı oku ${iconSvg('arrow-right', 'pa-cta-icon')}</span>
      </div>
    </article>
  `;
}

function topicCard(topic) {
  return `
    <a class="pa-topic-card" href="${PREVIEW_BASE}/konu/${escapeHtml(topic.slug)}">
      <span class="pa-topic-mark">${iconSvg(topicIconName(topic))}</span>
      <strong>${escapeHtml(topic.name)}</strong>
      <span>${entriesForTopic(topic.slug).length} soru</span>
    </a>
  `;
}

function categoryCard(category) {
  return `
    <a class="pa-category-card" href="${PREVIEW_BASE}/kategori/${escapeHtml(category.slug)}">
      <span class="pa-category-mark">${iconSvg(categoryIconName(category))}</span>
      <span class="pa-category-copy">
        <strong>${escapeHtml(category.name)}</strong>
        <span>${entriesForCategory(category.slug).length} soru</span>
      </span>
    </a>
  `;
}

function breadcrumb(items) {
  return `
    <nav class="pa-breadcrumb" aria-label="Sayfa yolu">
      <a href="${PREVIEW_BASE}">Ana Sayfa</a>
      ${items.map(item => `${item.href ? `<a href="${escapeHtml(item.href)}">${escapeHtml(item.label)}</a>` : `<span>${escapeHtml(item.label)}</span>`}`).join('')}
    </nav>
  `;
}

function ctaBand() {
  return `
    <section class="pa-cta-band">
      <span class="pa-cta-icon">${iconSvg('help-circle')}</span>
      <div>
        <h2>Aklınızda bir soru mu var?</h2>
        <p>Sorunuzu kısa ve açık şekilde yazabilirsiniz.</p>
      </div>
      <a class="pa-button" href="${PREVIEW_BASE}/soru-sor">Soru Sor ${iconSvg('arrow-right', 'pa-button-icon')}</a>
    </section>
  `;
}

function trustBand() {
  return `
    <section class="pa-context-band" id="baglam">
      <div>
        <p class="pa-kicker">Okuma düzeni</p>
        <h2>Her cevap; soru, ana kapı ve ilgili kavramlarla birlikte hazırlanır.</h2>
        <p>${escapeHtml(publicArchiveFixtures.brand.sentence)} ${escapeHtml(publicArchiveFixtures.brand.authorLine)}</p>
        <p>Bu yapı, bir cevabı tek başına bırakmadan hidayet, mürşid, zikir ve teslimiyet gibi bağlı başlıklarla beraber takip etmeyi kolaylaştırır.</p>
      </div>
      ${stillLife()}
    </section>
  `;
}

function renderHome() {
  const featured = publicArchiveFixtures.qa.filter(entry => entry.isFeatured).slice(0, 3);
  const latest = [...publicArchiveFixtures.qa].sort((a, b) => String(b.publishedAt).localeCompare(String(a.publishedAt))).slice(0, 3);
  const topics = publicArchiveFixtures.topics.filter(topic => topic.featured).slice(0, 6);
  const categories = publicArchiveFixtures.categories.filter(category => category.featured);
  return renderShell({
    active: 'home',
    title: 'Ana Sayfa',
    description: 'Dini Sorular ve Cevaplar Arşivi içinde soru, cevap ve kavramları birlikte okuyun.',
    content: `
      <main class="pa-main">
        <section class="pa-hero">
          <div class="pa-hero-copy">
            <p class="pa-kicker">${escapeHtml(publicArchiveFixtures.brand.sentence)}</p>
            <h1>Soruları kavramlarıyla birlikte okuyun.</h1>
            <p>Hidayet, mürşid, zikir ve teslimiyet gibi ana başlıklardan başlayın; aradığınız cevaba bağlı kavramlarla ulaşın.</p>
            ${searchBox()}
            ${heroConceptLane()}
          </div>
          ${stillLife()}
        </section>

        ${readingPath(categories)}

        <section class="pa-section">
          ${sectionHeader('Öne Çıkan Cevaplar', 'Tümünü Gör', `${PREVIEW_BASE}/arsiv`)}
          <div class="pa-question-grid">${featured.map(entry => questionCard(entry)).join('')}</div>
        </section>

        <section class="pa-section">
          ${sectionHeader('Kavram Haritası', 'Tümünü Gör', `${PREVIEW_BASE}/konular`)}
          <div class="pa-topic-grid">${topics.map(topicCard).join('')}</div>
        </section>

        <section class="pa-section">
          ${sectionHeader('Ana Kategoriler', 'Tümünü Gör', `${PREVIEW_BASE}/kategoriler`)}
          <div class="pa-category-grid">${categories.map(categoryCard).join('')}</div>
        </section>

        <section class="pa-section">
          ${sectionHeader('Son Yayınlanan Sorular', 'Arşive Git', `${PREVIEW_BASE}/arsiv`)}
          <div class="pa-list">${latest.map(entry => questionCard(entry, true)).join('')}</div>
        </section>

        ${ctaBand()}
        ${trustBand()}
      </main>
    `
  });
}

function searchResults(query) {
  const normalized = normalizeSearchText(query);
  if (!normalized) return publicArchiveFixtures.qa;
  return publicArchiveFixtures.qa.filter(entry => {
    const category = categoryFor(entry);
    const topics = topicsFor(entry).map(topic => topic.name).join(' ');
    const haystack = normalizeSearchText([
      entry.title,
      entry.question,
      entry.summary,
      entry.excerpt,
      entry.answer.join(' '),
      category?.name,
      topics
    ].join(' '));
    return normalized.split(' ').every(part => haystack.includes(part));
  });
}

function renderArchive() {
  const entries = [...publicArchiveFixtures.qa].sort((a, b) => String(b.publishedAt).localeCompare(String(a.publishedAt)));
  const categories = publicArchiveFixtures.categories.filter(category => category.featured);
  const topics = publicArchiveFixtures.topics.filter(topic => topic.featured).slice(0, 8);
  return renderShell({
    active: 'archive',
    title: 'Arşiv',
    description: 'Soru-cevap kayıtlarını ana kapı ve kavram bağlantılarıyla birlikte inceleyin.',
    content: `
      <main class="pa-main pa-narrow-main">
        <section class="pa-archive-hero">
          <p class="pa-kicker">Arşiv</p>
          <h1>Soru ve cevapları kavramlarıyla birlikte keşfedin.</h1>
          <p>Yayınlanan kayıtları Allah’a ulaşmayı dilemek, hidayet, mürşid, zikir ve teslimiyet ana kapıları üzerinden okuyabilirsiniz.</p>
          <div class="pa-collection-meta">
            <span>${entries.length} soru</span>
            <span>${categories.length} kategori</span>
            <span>${topics.length} kavram</span>
          </div>
        </section>
        <section class="pa-section">
          ${sectionHeader('Kategoriler', 'Tümünü Gör', `${PREVIEW_BASE}/kategoriler`)}
          <div class="pa-category-grid">${categories.map(categoryCard).join('')}</div>
        </section>
        <section class="pa-section">
          ${sectionHeader('Kavramlar', 'Tümünü Gör', `${PREVIEW_BASE}/konular`)}
          <div class="pa-topic-grid">${topics.map(topicCard).join('')}</div>
        </section>
        <section class="pa-section">
          ${sectionHeader('Tüm Sorular')}
          <div class="pa-list">${entries.map(entry => questionCard(entry, true)).join('')}</div>
        </section>
      </main>
    `
  });
}

function renderSearch(query = '') {
  const cleanQuery = String(query || '').trim();
  const results = searchResults(cleanQuery);
  return renderShell({
    active: 'search',
    title: cleanQuery ? `"${cleanQuery}" için arama` : 'Arama',
    description: 'Arşivde soru, konu ve kategori arayın.',
    content: `
      <main class="pa-main pa-narrow-main">
        <section class="pa-search-page">
          <p class="pa-kicker">Arşivde ara</p>
          <h1>Aradığınız cevaba en kısa yoldan ulaşın.</h1>
          <p class="pa-page-intro">Soru başlıkları, cevap özetleri, kavramlar ve kategoriler içinde sade bir arama yapabilirsiniz.</p>
          ${searchBox(cleanQuery)}
        </section>
        <section class="pa-section">
          ${sectionHeader(cleanQuery ? `"${cleanQuery}" araması` : 'Arşivdeki Sorular')}
          <p class="pa-result-count">${results.length ? `${results.length} kayıt listeleniyor.` : 'Eşleşen kayıt bulunamadı.'}</p>
          ${results.length
            ? `<div class="pa-list">${results.map(entry => questionCard(entry, true)).join('')}</div>`
            : renderNoResults(cleanQuery)}
        </section>
      </main>
    `
  });
}

function renderTopicsIndex() {
  const topics = publicArchiveFixtures.topics;
  return renderShell({
    active: 'topics',
    title: 'Konular',
    description: 'Public arşivdeki kavram ve konu başlıkları.',
    content: `
      <main class="pa-main pa-narrow-main">
        <section class="pa-collection-hero">
          <p class="pa-kicker">Konular</p>
          <h1>Kavramlar üzerinden sakin bir okuma yolu kurun.</h1>
          <p>Soru-cevap kayıtlarını hidayet, mürşid, zikir, tâbiiyet, takva ve teslimiyet gibi bağlı kavramlarla keşfedebilirsiniz.</p>
          <div class="pa-collection-meta">
            <span>${topics.length} kavram</span>
            <span>${publicArchiveFixtures.qa.length} soru</span>
          </div>
        </section>
        <section class="pa-section">
          ${sectionHeader('Tüm Kavramlar')}
          <div class="pa-topic-grid">${topics.map(topicCard).join('')}</div>
        </section>
      </main>
    `
  });
}

function renderCategoriesIndex() {
  const categories = publicArchiveFixtures.categories;
  return renderShell({
    active: 'categories',
    title: 'Kategoriler',
    description: 'Public arşivdeki soru-cevap kategorileri.',
    content: `
      <main class="pa-main pa-narrow-main">
        <section class="pa-collection-hero">
          <p class="pa-kicker">Kategoriler</p>
          <h1>Soruları ana başlıklarına göre inceleyin.</h1>
          <p>Kategoriler, arşivdeki soru ve cevapları daha düzenli taramak için ana kapılar olarak kullanılır.</p>
          <div class="pa-collection-meta">
            <span>${categories.length} kategori</span>
            <span>${publicArchiveFixtures.qa.length} soru</span>
          </div>
        </section>
        <section class="pa-section">
          ${sectionHeader('Tüm Kategoriler')}
          <div class="pa-category-grid">${categories.map(categoryCard).join('')}</div>
        </section>
      </main>
    `
  });
}

function renderNoResults(query) {
  return `
    <div class="pa-empty-state">
      <h2>Sonuç bulunamadı.</h2>
      <p>${query ? `"${escapeHtml(query)}" için arşivde eşleşen bir kayıt görünmüyor.` : 'Bu aramada eşleşen bir kayıt görünmüyor.'}</p>
      <div class="pa-empty-actions">
        <a class="pa-button" href="${PREVIEW_BASE}/soru-sor">Aklınızda bir soru mu var?</a>
        <a class="pa-button is-secondary" href="${PREVIEW_BASE}/arsiv">Arşive Dön</a>
      </div>
    </div>
  `;
}

function renderQuestion(slug) {
  const entry = bySlug(publicArchiveFixtures.qa, slug);
  if (!entry) return renderNotFound();
  const category = categoryFor(entry);
  const topics = topicsFor(entry);
  const related = relatedEntries(entry);
  return renderShell({
    active: 'archive',
    title: entry.title,
    description: entry.excerpt || entry.summary,
    questionSlug: entry.slug,
    content: `
      <main class="pa-main pa-detail-main">
        ${breadcrumb([
          { label: 'Arşiv', href: `${PREVIEW_BASE}/arsiv` },
          category ? { label: category.name, href: `${PREVIEW_BASE}/kategori/${category.slug}` } : { label: 'Soru' },
          { label: entry.title }
        ])}
        <article class="pa-answer-layout">
          <div class="pa-answer-primary">
            <div class="pa-detail-meta">
              ${category ? chip(category.name, `${PREVIEW_BASE}/kategori/${category.slug}`) : ''}
              ${topics.map(topic => chip(topic.name, `${PREVIEW_BASE}/konu/${topic.slug}`)).join('')}
            </div>
            <h1>${escapeHtml(entry.title)}</h1>
            <p class="pa-detail-subtitle">${escapeHtml(entry.summary)}</p>
            <div class="pa-date-line">
              ${entry.publishedAt ? `<span>Yayın tarihi: ${escapeHtml(formatDate(entry.publishedAt))}</span>` : ''}
              ${entry.updatedAt ? `<span>Son güncelleme: ${escapeHtml(formatDate(entry.updatedAt))}</span>` : ''}
              ${entry.readTime ? `<span>${entry.readTime} dk okuma</span>` : ''}
              ${readCountNode(entry)}
              ${publicArchiveFixtures.brand.answererLabel ? `<span>${escapeHtml(publicArchiveFixtures.brand.answererLabel)}</span>` : ''}
            </div>
            <section class="pa-reading-block">
              <h2>Soru</h2>
              <p>${escapeHtml(entry.question)}</p>
            </section>
            <section class="pa-reading-block">
              <h2>Cevap</h2>
              ${entry.answer.map(paragraph => `<p>${escapeHtml(paragraph)}</p>`).join('')}
            </section>
            ${entry.sourceContext ? `
              <aside class="pa-source-box">
                <h2>${escapeHtml(entry.sourceContext.title)}</h2>
                <p>${escapeHtml(entry.sourceContext.text)}</p>
              </aside>
            ` : ''}
            <div class="pa-tool-row" aria-label="Sayfa araçları">
              <button type="button" class="pa-icon-button" data-share>Paylaş</button>
              <button type="button" class="pa-icon-button" data-copy-link>Bağlantıyı kopyala</button>
              <button type="button" class="pa-icon-button" data-print>Yazdır</button>
            </div>
          </div>
          <aside class="pa-answer-aside">
            ${related.length ? `
              <section>
                <h2>İlgili Sorular</h2>
                <div class="pa-side-list">${related.map(item => `<a href="${PREVIEW_BASE}/soru/${escapeHtml(item.slug)}">${escapeHtml(item.title)}</a>`).join('')}</div>
              </section>
            ` : ''}
            <section>
              <h2>İlgili Kavramlar</h2>
              <div class="pa-chip-wrap">${topics.map(topic => chip(topic.name, `${PREVIEW_BASE}/konu/${topic.slug}`)).join('')}</div>
            </section>
          </aside>
        </article>
      </main>
    `
  });
}

function renderTopic(slug) {
  const topic = bySlug(publicArchiveFixtures.topics, slug);
  if (!topic) return renderNotFound();
  const category = bySlug(publicArchiveFixtures.categories, topic.categorySlug);
  const entries = entriesForTopic(topic.slug);
  const related = relatedTopics(topic);
  return renderShell({
    active: 'topics',
    title: topic.name,
    description: topic.description,
    content: `
      <main class="pa-main pa-narrow-main">
        ${breadcrumb([{ label: 'Konular', href: `${PREVIEW_BASE}/konular` }, { label: topic.name }])}
        <section class="pa-collection-hero">
          <p class="pa-kicker">Kavram</p>
          <h1>${escapeHtml(topic.name)}</h1>
          <p>${escapeHtml(topic.description)}</p>
          <div class="pa-collection-meta">
            <span>${entries.length} ilgili soru</span>
            ${related.length ? `<span>${related.length} ilişkili kavram</span>` : ''}
          </div>
          ${category ? `<a class="pa-inline-link" href="${PREVIEW_BASE}/kategori/${escapeHtml(category.slug)}">Kategori: ${escapeHtml(category.name)}</a>` : ''}
        </section>
        <section class="pa-section">
          ${sectionHeader('İlgili Sorular')}
          <div class="pa-list">${entries.map(entry => questionCard(entry, true)).join('')}</div>
        </section>
        ${related.length ? `
          <section class="pa-section">
            ${sectionHeader('İlişkili Kavramlar')}
            <div class="pa-topic-grid">${related.map(topicCard).join('')}</div>
          </section>
        ` : ''}
      </main>
    `
  });
}

function renderCategory(slug) {
  const category = bySlug(publicArchiveFixtures.categories, slug);
  if (!category) return renderNotFound();
  const entries = entriesForCategory(category.slug);
  const topics = (category.topicSlugs || [])
    .map(topicSlug => bySlug(publicArchiveFixtures.topics, topicSlug))
    .filter(Boolean);
  return renderShell({
    active: 'categories',
    title: category.name,
    description: category.description,
    content: `
      <main class="pa-main pa-narrow-main">
        ${breadcrumb([{ label: 'Kategoriler', href: `${PREVIEW_BASE}/kategoriler` }, { label: category.name }])}
        <section class="pa-collection-hero">
          <p class="pa-kicker">Kategori</p>
          <h1>${escapeHtml(category.name)}</h1>
          <p>${escapeHtml(category.description)}</p>
          <div class="pa-collection-meta">
            <span>${entries.length} ilgili soru</span>
            ${topics.length ? `<span>${topics.length} kavram</span>` : ''}
          </div>
        </section>
        <section class="pa-section">
          ${sectionHeader('Bu Kategorideki Sorular')}
          <div class="pa-list">${entries.map(entry => questionCard(entry, true)).join('')}</div>
        </section>
        ${topics.length ? `
          <section class="pa-section">
            ${sectionHeader('İlgili Kavramlar')}
            <div class="pa-topic-grid">${topics.map(topicCard).join('')}</div>
          </section>
        ` : ''}
      </main>
    `
  });
}

function renderAccount() {
  return renderShell({
    active: 'account',
    title: 'Hesabım',
    description: 'Public arşiv hesabı ve soru gönderimi.',
    content: `
      <main class="pa-main pa-narrow-main">
        <section class="pa-account-page" data-account-panel>
          <p class="pa-kicker">Hesabım</p>
          <h1>Hesabınızla soru gönderimini takip edin.</h1>
          <p>Google hesabınızla oturum açarak Soru Sor ekranından gönderdiğiniz soruların kayıt altına alınmasını sağlayabilirsiniz.</p>
          <div class="pa-account-status" data-account-status>Oturum durumu kontrol ediliyor...</div>
          <div class="pa-empty-actions" data-account-actions>
            <a class="pa-button" href="${PREVIEW_BASE}/auth/google?returnTo=${encodeURIComponent(PREVIEW_BASE + '/hesabim')}">Google ile Devam Et</a>
            <a class="pa-button is-secondary" href="${PREVIEW_BASE}/arsiv">Arşive Git</a>
          </div>
        </section>
      </main>
    `
  });
}

function renderAsk() {
  return renderShell({
    active: 'ask',
    title: 'Soru Sor',
    description: 'Soru sorma ekranı.',
    content: `
      <main class="pa-main pa-form-main">
        ${breadcrumb([{ label: 'Soru Sor' }])}
        <section class="pa-form-layout">
          <div class="pa-form-copy">
            <p class="pa-kicker">Soru Sor</p>
            <h1>Aklınızda bir soru mu var?</h1>
            <p>Sorunuzu kısa ve açık şekilde yazabilirsiniz. ${escapeHtml(publicArchiveFixtures.brand.authorLine)}</p>
            <div class="pa-account-status" data-ask-session>Oturum durumu kontrol ediliyor...</div>
            <div class="pa-note-box" id="gizlilik">
              <strong>Gizlilik notu</strong>
              <p>Kişisel bilgi, özel sağlık bilgisi veya üçüncü kişilere ait mahrem ayrıntılar paylaşmayın.</p>
            </div>
          </div>
          <form class="pa-ask-form" data-question-form>
            <label>
              <span>Soru metni</span>
              <textarea name="question" rows="7" maxlength="2000" minlength="20" placeholder="Sorunuzu yazın..." required></textarea>
            </label>
            <label>
              <span>İsteğe bağlı kategori</span>
              <select name="category">
                <option value="">Kategori seçin</option>
                ${publicArchiveFixtures.categories.map(category => `<option value="${escapeHtml(category.name)}">${escapeHtml(category.name)}</option>`).join('')}
              </select>
            </label>
            <label>
              <span>İsteğe bağlı konu</span>
              <input name="topic" maxlength="120" placeholder="Örn. Zikir, hidayet, mürşid...">
            </label>
            <label class="pa-check-row" id="kullanim">
              <input name="privacyAccepted" type="checkbox" required>
              <span>Kişisel bilgi paylaşmadığımı anladım.</span>
            </label>
            <button class="pa-button" type="submit">Soruyu Gönder</button>
            <p class="pa-form-status" data-question-form-status aria-live="polite"></p>
          </form>
        </section>
      </main>
    `
  });
}

function renderInfoPage(kind) {
  const pages = {
    hakkimizda: {
      title: 'Hakkımızda',
      kicker: 'Hakkımızda',
      heading: 'Sakin, okunabilir ve kaynak bağlamını koruyan bir arşiv.',
      copy: [
        'Dini Sorular ve Cevaplar Arşivi, soru-cevap kayıtlarını kavram ve kategori bağlantılarıyla okunabilir hale getirmek için hazırlanır.',
        `${publicArchiveFixtures.brand.sentence} ${publicArchiveFixtures.brand.authorLine}`
      ]
    },
    iletisim: {
      title: 'İletişim',
      kicker: 'İletişim',
      heading: 'Arşivle ilgili notlarınızı sade şekilde iletebilirsiniz.',
      copy: [
        'Public arşiv yayına hazırlık sürecindedir. Soru göndermek için Soru Sor ekranını kullanabilirsiniz.',
        'Kişisel bilgi ve mahrem ayrıntı paylaşmamanız önemlidir.'
      ]
    },
    gizlilik: {
      title: 'Gizlilik',
      kicker: 'Gizlilik',
      heading: 'Public arşiv kişisel bilgiyi azaltarak çalışacak şekilde tasarlanır.',
      copy: [
        'Soru gönderirken kişisel bilgi, özel sağlık bilgisi veya üçüncü kişilere ait mahrem ayrıntılar yazmayın.',
        'Google oturumu yalnız soru gönderimini kullanıcı hesabıyla ilişkilendirmek için kullanılır.'
      ]
    },
    'kullanim-kosullari': {
      title: 'Kullanım Koşulları',
      kicker: 'Kullanım',
      heading: 'Arşiv okuma ve soru gönderimi için sade kullanım ilkeleri.',
      copy: [
        'Public arşiv, soru-cevap içeriklerini okumak, aramak ve kavramlar üzerinden keşfetmek için sunulur.',
        'Soru gönderimi, cevabın hemen yayınlanacağı veya belirli sürede yanıtlanacağı anlamına gelmez.'
      ]
    }
  };
  const page = pages[kind] || pages.hakkimizda;
  return renderShell({
    active: kind === 'iletisim' ? 'ask' : 'archive',
    title: page.title,
    description: page.heading,
    content: `
      <main class="pa-main pa-narrow-main">
        <section class="pa-account-page">
          <p class="pa-kicker">${escapeHtml(page.kicker)}</p>
          <h1>${escapeHtml(page.heading)}</h1>
          ${page.copy.map(paragraph => `<p>${escapeHtml(paragraph)}</p>`).join('')}
          <div class="pa-empty-actions">
            <a class="pa-button" href="${PREVIEW_BASE}/arsiv">Arşive Git</a>
            <a class="pa-button is-secondary" href="${PREVIEW_BASE}/soru-sor">Soru Sor</a>
          </div>
        </section>
      </main>
    `
  });
}

function renderNotFound() {
  return renderShell({
    active: 'search',
    title: 'Sayfa bulunamadı',
    description: 'Aradığınız içerik bu ön izleme alanında bulunamadı.',
    status: 404,
    content: `
      <main class="pa-main pa-narrow-main">
        <section class="pa-empty-state is-large">
          <p class="pa-kicker">404</p>
          <h1>Sayfa bulunamadı.</h1>
          <p>Aradığınız içerik bu ön izleme alanında görünmüyor. Arama yapabilir veya ana sayfaya dönebilirsiniz.</p>
          ${searchBox()}
          <div class="pa-empty-actions">
            <a class="pa-button" href="${PREVIEW_BASE}">Ana Sayfa</a>
            <a class="pa-button is-secondary" href="${PREVIEW_BASE}/arama">Arşivde Ara</a>
          </div>
        </section>
      </main>
    `
  });
}

function renderShell({ title, description, active, content, status = 200, questionSlug = '' }) {
  const safeTitle = pageTitle(title);
  const safeDescription = description || publicArchiveFixtures.brand.sentence;
  return {
    status,
    html: `<!doctype html>
<html lang="tr" data-theme="light">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">
  <meta name="robots" content="noindex,nofollow">
  <meta name="description" content="${escapeHtml(safeDescription)}">
  <meta name="theme-color" content="#F7F3EA">
  <title>${escapeHtml(safeTitle)}</title>
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=Playfair+Display:wght@500;600;700&display=swap" rel="stylesheet">
  <link rel="stylesheet" href="${CSS_PATH}">
  <script>
    (function(){
      try {
        var saved = localStorage.getItem('dsca-theme');
        var preferred = window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light';
        var theme = saved === 'dark' || saved === 'light' ? saved : preferred;
        document.documentElement.setAttribute('data-theme', theme);
        document.querySelector('meta[name="theme-color"]').setAttribute('content', theme === 'dark' ? '#0D1412' : '#F7F3EA');
      } catch (error) {}
    })();
  </script>
</head>
<body${questionSlug ? ` data-question-slug="${escapeHtml(questionSlug)}"` : ''}>
  <div class="pa-page">
    ${header(active)}
    ${content}
    ${footer()}
  </div>
  <nav class="pa-mobile-nav" aria-label="Mobil alt gezinme">
    ${previewActionNav(active)}
  </nav>
  <script>
    (function(){
      function applyTheme(theme) {
        document.documentElement.setAttribute('data-theme', theme);
        var meta = document.querySelector('meta[name="theme-color"]');
        if (meta) meta.setAttribute('content', theme === 'dark' ? '#0D1412' : '#F7F3EA');
        document.querySelectorAll('[data-theme-toggle]').forEach(function(button){
          button.setAttribute('aria-label', theme === 'dark' ? 'Açık temaya geç' : 'Koyu temaya geç');
        });
      }
      document.querySelectorAll('[data-theme-toggle]').forEach(function(button){
        button.addEventListener('click', function(){
          var next = document.documentElement.getAttribute('data-theme') === 'dark' ? 'light' : 'dark';
          try { localStorage.setItem('dsca-theme', next); } catch (error) {}
          applyTheme(next);
        });
      });
      applyTheme(document.documentElement.getAttribute('data-theme') || 'light');

      document.querySelectorAll('[data-copy-link]').forEach(function(button){
        button.addEventListener('click', async function(){
          try {
            await navigator.clipboard.writeText(window.location.href);
            button.textContent = 'Bağlantı kopyalandı';
            setTimeout(function(){ button.textContent = 'Bağlantıyı kopyala'; }, 1800);
          } catch (error) {
            button.textContent = 'Bağlantı hazır';
            setTimeout(function(){ button.textContent = 'Bağlantıyı kopyala'; }, 1800);
          }
        });
      });
      document.querySelectorAll('[data-share]').forEach(function(button){
        button.addEventListener('click', async function(){
          if (navigator.share) {
            try { await navigator.share({ title: document.title, url: window.location.href }); } catch (error) {}
          } else {
            var copyButton = document.querySelector('[data-copy-link]');
            if (copyButton) copyButton.click();
          }
        });
      });
      document.querySelectorAll('[data-print]').forEach(function(button){
        button.addEventListener('click', function(){ window.print(); });
      });
      document.querySelectorAll('[data-card-href]').forEach(function(card){
        function openCard(event) {
          if (event.target && event.target.closest && event.target.closest('a, button, input, select, textarea')) return;
          var href = card.getAttribute('data-card-href');
          if (href) window.location.href = href;
        }
        card.addEventListener('click', openCard);
        card.addEventListener('keydown', function(event){
          if (event.key !== 'Enter' && event.key !== ' ') return;
          event.preventDefault();
          var href = card.getAttribute('data-card-href');
          if (href) window.location.href = href;
        });
      });
      function bindConceptSliders() {
        document.querySelectorAll('[data-concept-slider]').forEach(function(slider){
          var track = slider.querySelector('[data-concept-track]');
          var rail = slider.querySelector('[data-concept-rail]');
          var firstSet = slider.querySelector('[data-concept-set]');
          if (!track || !rail || !firstSet) return;
          var resumeTimer = 0;
          var rafId = 0;
          var lastFrame = 0;
          var offset = 0;
          var cycleWidth = 0;
          var speed = 24;
          var dragging = false;
          var didDrag = false;
          var dragStartX = 0;
          var dragStartOffset = 0;
          function railGap() {
            var styles = window.getComputedStyle ? window.getComputedStyle(rail) : null;
            return styles ? (parseFloat(styles.columnGap || styles.gap || '0') || 0) : 0;
          }
          function normalizeOffset() {
            if (!cycleWidth) return;
            offset = ((offset % cycleWidth) + cycleWidth) % cycleWidth;
          }
          function paint() {
            rail.style.transform = 'translate3d(' + (-offset).toFixed(2) + 'px, 0, 0)';
          }
          function measure() {
            cycleWidth = firstSet.getBoundingClientRect().width + railGap();
            if (!cycleWidth) cycleWidth = rail.scrollWidth / 2;
            normalizeOffset();
            paint();
          }
          function setPaused(paused) {
            if (paused) slider.setAttribute('data-paused', 'true');
            else slider.removeAttribute('data-paused');
          }
          function pauseBriefly() {
            setPaused(true);
            window.clearTimeout(resumeTimer);
            resumeTimer = window.setTimeout(function(){ setPaused(false); }, 2000);
          }
          function endDrag(event) {
            if (!dragging) return;
            dragging = false;
            track.removeAttribute('data-dragging');
            if (event && event.pointerId !== undefined && track.releasePointerCapture) {
              try { track.releasePointerCapture(event.pointerId); } catch (error) {}
            }
            pauseBriefly();
          }
          function loop(time) {
            if (!lastFrame) lastFrame = time;
            var delta = Math.min(time - lastFrame, 50);
            lastFrame = time;
            if (slider.getAttribute('data-paused') !== 'true' && !dragging) {
              offset += (delta * speed) / 1000;
              normalizeOffset();
              paint();
            }
            rafId = window.requestAnimationFrame(loop);
          }
          track.addEventListener('pointerdown', function(event){
            if (event.button && event.button !== 0) return;
            dragging = true;
            didDrag = false;
            dragStartX = event.clientX;
            dragStartOffset = offset;
            setPaused(true);
            window.clearTimeout(resumeTimer);
            track.setAttribute('data-dragging', 'true');
            if (event.pointerId !== undefined && track.setPointerCapture) {
              try { track.setPointerCapture(event.pointerId); } catch (error) {}
            }
          });
          track.addEventListener('pointermove', function(event){
            if (!dragging) return;
            var dx = event.clientX - dragStartX;
            if (Math.abs(dx) > 3) didDrag = true;
            offset = dragStartOffset - dx;
            normalizeOffset();
            paint();
          });
          track.addEventListener('pointerup', endDrag);
          track.addEventListener('pointercancel', endDrag);
          track.addEventListener('lostpointercapture', endDrag);
          track.addEventListener('wheel', function(event){
            var delta = Math.abs(event.deltaX) >= Math.abs(event.deltaY) ? event.deltaX : event.deltaY;
            if (delta) {
              offset += delta;
              normalizeOffset();
              paint();
            }
            pauseBriefly();
          }, { passive: true });
          track.addEventListener('focusin', function(){ setPaused(true); });
          track.addEventListener('focusout', pauseBriefly);
          track.addEventListener('mouseenter', function(){ setPaused(true); });
          track.addEventListener('mouseleave', pauseBriefly);
          slider.addEventListener('click', function(event){
            if (didDrag) {
              event.preventDefault();
              event.stopPropagation();
              didDrag = false;
              return;
            }
            if (event.target && event.target.closest && event.target.closest('a')) pauseBriefly();
          }, true);
          measure();
          window.addEventListener('resize', measure, { passive: true });
          window.addEventListener('load', measure, { once: true });
          window.setTimeout(measure, 250);
          rafId = window.requestAnimationFrame(loop);
          window.addEventListener('pagehide', function(){ if (rafId) window.cancelAnimationFrame(rafId); }, { once: true });
        });
      }
      function formatReadCount(value) {
        var count = Number(value || 0);
        return count.toLocaleString('tr-TR') + ' okunma';
      }
      function updateReadCount(slug, count) {
        document.querySelectorAll('[data-public-read-count="' + slug + '"]').forEach(function(node){
          var label = node.querySelector('[data-read-count-label]');
          if (label) label.textContent = formatReadCount(count);
          node.hidden = false;
        });
      }
      async function loadReadCounts() {
        var nodes = Array.from(document.querySelectorAll('[data-public-read-count]'));
        var slugs = Array.from(new Set(nodes.map(function(node){ return node.getAttribute('data-public-read-count'); }).filter(Boolean)));
        if (!slugs.length) return;
        try {
          var response = await fetch('${PREVIEW_BASE}/api/question-stats?slugs=' + encodeURIComponent(slugs.join(',')), { headers: { Accept: 'application/json' } });
          var data = await response.json();
          Object.keys(data.counts || {}).forEach(function(slug){ updateReadCount(slug, data.counts[slug]); });
        } catch (error) {}
      }
      async function trackQuestionRead() {
        var slug = document.body.getAttribute('data-question-slug');
        if (!slug) return;
        try {
          var key = 'dsca-read-' + slug;
          var last = Number(localStorage.getItem(key) || 0);
          var now = Date.now();
          if (last && now - last < 12 * 60 * 60 * 1000) return loadReadCounts();
          var response = await fetch('${PREVIEW_BASE}/api/questions/' + encodeURIComponent(slug) + '/read', {
            method: 'POST',
            headers: { Accept: 'application/json' }
          });
          var data = await response.json();
          if (data && data.available) {
            localStorage.setItem(key, String(now));
            updateReadCount(slug, data.readCount);
          } else {
            await loadReadCounts();
          }
        } catch (error) {
          await loadReadCounts();
        }
      }
      async function loadPublicSession() {
        try {
          var response = await fetch('${PREVIEW_BASE}/api/session', { headers: { Accept: 'application/json' } });
          return await response.json();
        } catch (error) {
          return { loggedIn: false, googleConfigured: false };
        }
      }
      function renderSessionUi(session) {
        var status = document.querySelector('[data-account-status]');
        var actions = document.querySelector('[data-account-actions]');
        var askSession = document.querySelector('[data-ask-session]');
        if (status) {
          if (session.loggedIn && session.user) status.textContent = 'Oturum açık: ' + (session.user.name || session.user.email);
          else if (session.googleConfigured) status.textContent = 'Soru göndermek için Google hesabınızla oturum açabilirsiniz.';
          else status.textContent = 'Google ile oturum açma bağlantısı bu ortamda henüz tanımlı değil.';
        }
        if (actions && session.loggedIn) {
          actions.innerHTML = '<button class="pa-button is-secondary" type="button" data-public-logout>Çıkış Yap</button><a class="pa-button" href="${PREVIEW_BASE}/soru-sor">Soru Sor</a>';
        }
        if (askSession) {
          if (session.loggedIn && session.user) askSession.textContent = 'Soru gönderimi ' + (session.user.name || session.user.email) + ' hesabıyla kaydedilecek.';
          else if (session.googleConfigured) askSession.innerHTML = 'Soru göndermek için önce <a href="${PREVIEW_BASE}/auth/google?returnTo=${encodeURIComponent(PREVIEW_BASE + '/soru-sor')}">Google ile oturum açın</a>.';
          else askSession.textContent = 'Google ile oturum açma bağlantısı bu ortamda henüz tanımlı değil.';
        }
        document.querySelectorAll('[data-public-logout]').forEach(function(button){
          button.addEventListener('click', async function(){
            await fetch('${PREVIEW_BASE}/auth/logout', { method: 'POST', headers: { Accept: 'application/json' } });
            window.location.href = '${PREVIEW_BASE}/hesabim';
          });
        });
      }
      function bindQuestionForm() {
        var form = document.querySelector('[data-question-form]');
        if (!form) return;
        var status = document.querySelector('[data-question-form-status]');
        form.addEventListener('submit', async function(event){
          event.preventDefault();
          var button = form.querySelector('button[type="submit"]');
          var payload = {
            question: form.elements.question && form.elements.question.value,
            category: form.elements.category && form.elements.category.value,
            topic: form.elements.topic && form.elements.topic.value,
            privacyAccepted: Boolean(form.elements.privacyAccepted && form.elements.privacyAccepted.checked)
          };
          if (button) button.disabled = true;
          if (status) status.textContent = 'Sorunuz kaydediliyor...';
          try {
            var response = await fetch('${PREVIEW_BASE}/api/question-submissions', {
              method: 'POST',
              headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
              body: JSON.stringify(payload)
            });
            var data = await response.json();
            if (!response.ok) {
              if (response.status === 401) {
                if (status) status.innerHTML = 'Soru göndermek için önce <a href="${PREVIEW_BASE}/auth/google?returnTo=${encodeURIComponent(PREVIEW_BASE + '/soru-sor')}">Google ile oturum açın</a>.';
              } else if (status) status.textContent = data.error || 'Soru kaydedilemedi.';
              return;
            }
            form.reset();
            if (status) status.textContent = 'Sorunuz kaydedildi.';
          } catch (error) {
            if (status) status.textContent = 'Bağlantı kurulamadı. Lütfen tekrar deneyin.';
          } finally {
            if (button) button.disabled = false;
          }
        });
      }
      loadReadCounts();
      trackQuestionRead();
      bindConceptSliders();
      loadPublicSession().then(renderSessionUi);
      bindQuestionForm();
    })();
  </script>
</body>
</html>`
  };
}

function renderPublicArchivePreviewRoute(routePath, query = {}, archiveData = publicArchiveFixtures) {
  return withPublicArchiveData(archiveData, () => {
    const pathname = routePath.replace(/\/+$/, '') || PREVIEW_BASE;
    if (pathname === PREVIEW_BASE) return renderHome();
    if (pathname === `${PREVIEW_BASE}/arsiv`) return renderArchive();
    if (pathname === `${PREVIEW_BASE}/arama`) return renderSearch(query.q || '');
    if (pathname === `${PREVIEW_BASE}/konular`) return renderTopicsIndex();
    if (pathname === `${PREVIEW_BASE}/kategoriler`) return renderCategoriesIndex();
    if (pathname === `${PREVIEW_BASE}/hesabim`) return renderAccount();
    if (pathname === `${PREVIEW_BASE}/soru-sor`) return renderAsk();
    if (pathname === `${PREVIEW_BASE}/hakkimizda`) return renderInfoPage('hakkimizda');
    if (pathname === `${PREVIEW_BASE}/iletisim`) return renderInfoPage('iletisim');
    if (pathname === `${PREVIEW_BASE}/gizlilik`) return renderInfoPage('gizlilik');
    if (pathname === `${PREVIEW_BASE}/kullanim-kosullari`) return renderInfoPage('kullanim-kosullari');
    const questionMatch = pathname.match(/^\/public-preview\/soru\/([^/]+)$/);
    if (questionMatch) return renderQuestion(questionMatch[1]);
    const topicMatch = pathname.match(/^\/public-preview\/konu\/([^/]+)$/);
    if (topicMatch) return renderTopic(topicMatch[1]);
    const categoryMatch = pathname.match(/^\/public-preview\/kategori\/([^/]+)$/);
    if (categoryMatch) return renderCategory(categoryMatch[1]);
    return renderNotFound();
  });
}

function sendRendered(res, rendered) {
  res.status(rendered.status || 200).type('html').send(rendered.html);
}

function createPublicArchivePreviewRouter(options = {}) {
  const router = express.Router();
  const cssFile = options.cssFile || path.join(__dirname, 'public-archive.css');
  const assetDir = options.assetDir || path.join(__dirname, 'public-archive-assets', 'assets');
  const loadArchiveData = typeof options.loadArchiveData === 'function'
    ? options.loadArchiveData
    : async () => publicArchiveFixtures;
  async function sendRoute(req, res, next, routePath, query = {}) {
    try {
      const archiveData = await loadArchiveData(req);
      sendRendered(res, renderPublicArchivePreviewRoute(routePath, query, archiveData));
    } catch (error) {
      next(error);
    }
  }
  router.use((req, res, next) => {
    res.set('X-Robots-Tag', 'noindex, nofollow');
    res.set('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate');
    next();
  });
  router.use('/assets', express.static(assetDir, {
    etag: false,
    index: false,
    maxAge: 0
  }));
  router.get('/public-archive.css', (req, res) => {
    res.type('text/css').sendFile(cssFile);
  });
  router.get(['/', ''], (req, res, next) => sendRoute(req, res, next, PREVIEW_BASE));
  router.get('/arsiv', (req, res, next) => sendRoute(req, res, next, `${PREVIEW_BASE}/arsiv`));
  router.get('/arama', (req, res, next) => sendRoute(req, res, next, `${PREVIEW_BASE}/arama`, { q: req.query.q || '' }));
  router.get('/konular', (req, res, next) => sendRoute(req, res, next, `${PREVIEW_BASE}/konular`));
  router.get('/kategoriler', (req, res, next) => sendRoute(req, res, next, `${PREVIEW_BASE}/kategoriler`));
  router.get('/hesabim', (req, res, next) => sendRoute(req, res, next, `${PREVIEW_BASE}/hesabim`));
  router.get('/soru-sor', (req, res, next) => sendRoute(req, res, next, `${PREVIEW_BASE}/soru-sor`));
  router.get('/hakkimizda', (req, res, next) => sendRoute(req, res, next, `${PREVIEW_BASE}/hakkimizda`));
  router.get('/iletisim', (req, res, next) => sendRoute(req, res, next, `${PREVIEW_BASE}/iletisim`));
  router.get('/gizlilik', (req, res, next) => sendRoute(req, res, next, `${PREVIEW_BASE}/gizlilik`));
  router.get('/kullanim-kosullari', (req, res, next) => sendRoute(req, res, next, `${PREVIEW_BASE}/kullanim-kosullari`));
  router.get('/soru/:slug', (req, res, next) => sendRoute(req, res, next, `${PREVIEW_BASE}/soru/${req.params.slug}`));
  router.get('/konu/:slug', (req, res, next) => sendRoute(req, res, next, `${PREVIEW_BASE}/konu/${req.params.slug}`));
  router.get('/kategori/:slug', (req, res, next) => sendRoute(req, res, next, `${PREVIEW_BASE}/kategori/${req.params.slug}`));
  router.use((req, res, next) => sendRoute(req, res, next, `${PREVIEW_BASE}/bulunamadi`));
  return router;
}

module.exports = {
  PREVIEW_BASE,
  ROUTE_PATHS,
  createPublicArchivePreviewRouter,
  normalizePublicArchiveData,
  renderPublicArchivePreviewRoute,
  publicArchiveFixtures
};
