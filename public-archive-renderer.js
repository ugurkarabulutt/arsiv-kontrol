const express = require('express');
const fs = require('fs');
const path = require('path');
const { publicArchiveFixtures } = require('./public-archive-fixtures');

const DEFAULT_PUBLIC_ARCHIVE_BASE = '/public-preview';
let PREVIEW_BASE = DEFAULT_PUBLIC_ARCHIVE_BASE;
let CSS_PATH = `${PREVIEW_BASE}/public-archive.css`;
let ASSET_PATH = `${PREVIEW_BASE}/assets`;
let PUBLIC_ARCHIVE_NOINDEX = true;
const ICON_DIR = path.join(__dirname, 'public-archive-assets', 'icons');
const ARCHIVE_PAGE_SIZE = 30;
const PUBLIC_ARCHIVE_CANONICAL_ORIGIN = 'https://arsiv.ibrahimlive.ai';
const PUBLIC_SHARE_IMAGE_FILE = 'public-share-card.png';

function normalizePublicArchiveBasePath(value = DEFAULT_PUBLIC_ARCHIVE_BASE) {
  const raw = String(value ?? DEFAULT_PUBLIC_ARCHIVE_BASE).trim();
  if (!raw || raw === '/') return '';
  return `/${raw.replace(/^\/+|\/+$/g, '')}`;
}

function publicArchiveHomeHref() {
  return PREVIEW_BASE || '/';
}

function publicArchivePath(pathname = '') {
  const clean = String(pathname || '').trim();
  if (!clean || clean === '/') return publicArchiveHomeHref();
  const suffix = clean.startsWith('/') ? clean : `/${clean}`;
  return `${PREVIEW_BASE}${suffix}` || '/';
}

function publicArchiveCanonicalUrl(pathname = '') {
  const clean = String(pathname || '').trim();
  const suffix = !clean || clean === '/' ? '/' : clean.startsWith('/') ? clean : `/${clean}`;
  return `${PUBLIC_ARCHIVE_CANONICAL_ORIGIN}${suffix === '/' ? '/' : suffix}`;
}

function publicArchiveAssetHref(filename) {
  return `${ASSET_PATH}/${filename}`;
}

function publicArchiveAssetUrl(filename) {
  return publicArchiveCanonicalUrl(`/assets/${filename}`);
}

function publicArchiveRoutePattern(section = '') {
  const escapedBase = PREVIEW_BASE.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  return new RegExp(`^${escapedBase}/${section}/([^/]+)$`);
}

function setPublicArchiveRuntime({ basePath = DEFAULT_PUBLIC_ARCHIVE_BASE, noindex = true } = {}) {
  PREVIEW_BASE = normalizePublicArchiveBasePath(basePath);
  CSS_PATH = publicArchivePath('public-archive.css');
  ASSET_PATH = publicArchivePath('assets');
  PUBLIC_ARCHIVE_NOINDEX = noindex !== false;
}

function normalizePublicArchiveData(archiveData = {}) {
  return {
    brand: { ...publicArchiveFixtures.brand, ...(archiveData.brand || {}) },
    categories: Array.isArray(archiveData.categories) ? archiveData.categories : publicArchiveFixtures.categories,
    topics: Array.isArray(archiveData.topics) ? archiveData.topics : publicArchiveFixtures.topics,
    qa: Array.isArray(archiveData.qa) ? archiveData.qa : publicArchiveFixtures.qa,
    stats: archiveData.stats || null,
    pagination: archiveData.pagination || null,
    search: archiveData.search || null,
    basePath: normalizePublicArchiveBasePath(archiveData.basePath ?? DEFAULT_PUBLIC_ARCHIVE_BASE),
    noindex: archiveData.noindex !== false
  };
}

function withPublicArchiveData(archiveData, renderFn) {
  if (!archiveData || archiveData === publicArchiveFixtures) {
    setPublicArchiveRuntime({ basePath: DEFAULT_PUBLIC_ARCHIVE_BASE, noindex: true });
    return renderFn();
  }
  const previous = {
    brand: publicArchiveFixtures.brand,
    categories: publicArchiveFixtures.categories,
    topics: publicArchiveFixtures.topics,
    qa: publicArchiveFixtures.qa,
    stats: publicArchiveFixtures.stats,
    pagination: publicArchiveFixtures.pagination,
    search: publicArchiveFixtures.search,
    basePath: PREVIEW_BASE,
    noindex: PUBLIC_ARCHIVE_NOINDEX
  };
  const next = normalizePublicArchiveData(archiveData);
  setPublicArchiveRuntime({ basePath: next.basePath, noindex: next.noindex });
  publicArchiveFixtures.brand = next.brand;
  publicArchiveFixtures.categories = next.categories;
  publicArchiveFixtures.topics = next.topics;
  publicArchiveFixtures.qa = next.qa;
  publicArchiveFixtures.stats = next.stats;
  publicArchiveFixtures.pagination = next.pagination;
  publicArchiveFixtures.search = next.search;
  try {
    return renderFn();
  } finally {
    publicArchiveFixtures.brand = previous.brand;
    publicArchiveFixtures.categories = previous.categories;
    publicArchiveFixtures.topics = previous.topics;
    publicArchiveFixtures.qa = previous.qa;
    publicArchiveFixtures.stats = previous.stats;
    publicArchiveFixtures.pagination = previous.pagination;
    publicArchiveFixtures.search = previous.search;
    setPublicArchiveRuntime({ basePath: previous.basePath, noindex: previous.noindex });
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
  `${PREVIEW_BASE}/nasil-kullanilir`,
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

function jsonLdScript(data) {
  const payload = JSON.stringify(data).replace(/</g, '\\u003c');
  return `<script type="application/ld+json">${payload}</script>`;
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

function asPublicCategory(item) {
  if (!item) return null;
  return {
    id: item.id || `category-${item.slug}`,
    slug: item.slug,
    name: item.name,
    description: `${item.name} kategorisindeki soru ve cevaplar.`,
    topicSlugs: Array.isArray(item.topicSlugs) && item.topicSlugs.length ? item.topicSlugs : [item.slug],
    featured: item.featured !== false,
    questionCount: Number(item.questionCount ?? item.question_count ?? 0) || 0
  };
}

function publicCategories() {
  const categories = new Map();
  for (const category of publicArchiveFixtures.categories || []) {
    const normalized = asPublicCategory(category);
    if (normalized?.slug) categories.set(normalized.slug, normalized);
  }
  for (const topic of publicArchiveFixtures.topics || []) {
    const normalized = asPublicCategory(topic);
    if (normalized?.slug && !categories.has(normalized.slug)) categories.set(normalized.slug, normalized);
  }
  return [...categories.values()];
}

function publicCategoryBySlug(slug) {
  return bySlug(publicCategories(), slug);
}

function categorySlugsFor(entry) {
  const raw = Array.isArray(entry.categorySlugs) && entry.categorySlugs.length
    ? entry.categorySlugs
    : [entry.categorySlug, ...(entry.topicSlugs || [])];
  return raw.filter(Boolean).filter((slug, index, arr) => arr.indexOf(slug) === index);
}

function categoryFor(entry) {
  return publicCategoryBySlug(entry.categorySlug) || publicCategoryBySlug(categorySlugsFor(entry)[0]);
}

function categoriesFor(entry) {
  return categorySlugsFor(entry).map(publicCategoryBySlug).filter(Boolean);
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
  return publicArchiveFixtures.qa.filter(entry => categorySlugsFor(entry).includes(slug));
}

function categoryQuestionCount(category) {
  const count = Number(category?.questionCount ?? category?.question_count);
  return Number.isFinite(count) && count > 0 ? Math.round(count) : entriesForCategory(category?.slug).length;
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
  if (!route) return publicArchiveHomeHref();
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
  const cacheKey = `${safeName}|${className}`;
  if (!svgIconCache.has(cacheKey)) {
    try {
      const svg = fs.readFileSync(path.join(ICON_DIR, safeName + '.svg'), 'utf8');
      const openTag = '<svg class=\"' + className + '\" aria-hidden=\"true\" focusable=\"false\" ';
      svgIconCache.set(cacheKey, svg.replace('<svg ', openTag));
    } catch (error) {
      svgIconCache.set(cacheKey, '');
    }
  }
  return svgIconCache.get(cacheKey);
}

function categoryIconName(category) {
  return CATEGORY_ICONS[category?.slug] || TOPIC_ICONS[category?.slug] || 'diger';
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
    ['Ana Sayfa', publicArchiveHomeHref(), 'home'],
    ['Arşiv', `${PREVIEW_BASE}/arsiv`, 'archive'],
    ['Ara', `${PREVIEW_BASE}/arama#arama`, 'search'],
    ['Soru Sor', `${PREVIEW_BASE}/soru-sor`, 'ask']
  ];
  return items.map(([label, url, key]) => `
    <a class="pa-bottom-link${active === key ? ' is-active' : ''}" href="${escapeHtml(url)}">
      <span class="pa-bottom-icon">${iconSvg(BOTTOM_NAV_ICONS[key] || key)}</span>
      <span>${escapeHtml(label)}</span>
    </a>
  `).join('');
}

function brandLogo() {
  const logoText = publicArchiveFixtures.brand.logoLines.map(line => `<span>${escapeHtml(line)}</span>`).join('');
  return `
    <img class="pa-logo-mark" src="${ASSET_PATH}/arsiv-logo-mark.png" alt="" aria-hidden="true" width="256" height="256" decoding="async">
    <span class="pa-logo-text">${logoText}</span>
  `;
}

function header(active) {
  const nav = [
    ['Ana Sayfa', publicArchiveHomeHref(), 'home'],
    ['Ar\u015fiv', PREVIEW_BASE + '/arsiv', 'archive'],
    ['Ara', PREVIEW_BASE + '/arama#arama', 'search'],
    ['Soru Sor', PREVIEW_BASE + '/soru-sor', 'ask']
  ];
  return `
    <header class="pa-header">
      <a class="pa-logo" href="${publicArchiveHomeHref()}" aria-label="${escapeHtml(publicArchiveFixtures.brand.name)}">${brandLogo()}</a>
      <nav class="pa-desktop-nav" aria-label="Ana gezinme">
        ${nav.map(([label, url, key]) => `<a class="${active === key ? 'is-active' : ''}" href="${escapeHtml(url)}">${escapeHtml(label)}</a>`).join('')}
      </nav>
      <div class="pa-header-actions">
        <a class="pa-account-button${active === 'account' ? ' is-active' : ''}" href="${PREVIEW_BASE}/hesabim" aria-label="Hesab\u0131m">
          <span class="pa-account-notice-dot" data-account-notice-dot hidden aria-hidden="true"></span>
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
  return `
    <footer class="pa-footer">
      <div class="pa-footer-brand">
        <a class="pa-logo" href="${publicArchiveHomeHref()}" aria-label="${escapeHtml(publicArchiveFixtures.brand.name)}">${brandLogo()}</a>
        <p>${escapeHtml(publicArchiveFixtures.brand.sentence)}</p>
      </div>
      <div class="pa-footer-groups">
        <nav class="pa-footer-links" aria-label="Arşiv bağlantıları">
          <strong>Arşiv</strong>
          <a href="${PREVIEW_BASE}/arsiv">Tüm Sorular</a>
          <a href="${PREVIEW_BASE}/arama#arama">Arama</a>
          <a href="${PREVIEW_BASE}/soru-sor">Soru Sor</a>
        </nav>
        <nav class="pa-footer-links" aria-label="Bilgilendirme">
          <strong>Bilgi</strong>
          <a href="${PREVIEW_BASE}/hakkimizda">Hakkımızda</a>
          <a href="${PREVIEW_BASE}/nasil-kullanilir">Nasıl Kullanılır</a>
          <a href="${PREVIEW_BASE}/iletisim">İletişim</a>
          <a href="${PREVIEW_BASE}/gizlilik">Gizlilik</a>
          <a href="${PREVIEW_BASE}/kullanim-kosullari">Kullanım Koşulları</a>
        </nav>
      </div>
      <p class="pa-copyright">© 2026 Dini Sorular ve Cevaplar Arşivi. Tüm hakları saklıdır.</p>
    </footer>
  `;
}

function searchBox(value = '', label = 'Arşivde ara') {
  return `
    <form class="pa-search" action="${PREVIEW_BASE}/arama" method="get" role="search" id="arama">
      <label class="pa-sr-only" for="pa-search-input">${escapeHtml(label)}</label>
      <span class="pa-search-leading">${iconSvg('search')}</span>
      <input id="pa-search-input" name="q" value="${escapeHtml(value)}" placeholder="Soru veya kategori arayın..." autocomplete="off" inputmode="search" enterkeyhint="search" aria-label="Sorunuzu veya kategorinizi yazın">
      <button type="submit" aria-label="Ara">
        <span class="pa-search-icon">${iconSvg('arrow-right')}</span>
      </button>
    </form>
  `;
}

function stillLife() {
  return `
    <div class="pa-still-life" aria-hidden="true">
      <picture class="pa-hero-asset pa-hero-asset-book">
        <img src="${ASSET_PATH}/hero-open-book-warm.jpg" alt="" loading="eager" decoding="async">
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
  ['Hidayet', 'hidayet'],
  ['Zikir', 'zikir'],
  ['Takva', 'takva'],
  ['Tabiiyet', 'tabiiyet'],
  ['Allah’a Ulaşmayı Dilemek', 'allaha-ulasmayi-dilemek'],
  ['Nefs', 'nefs'],
  ['Ruh', 'ruh']
];

function conceptSliderItems(isClone = false) {
  return HERO_CONCEPT_ITEMS.map(([label, slug]) => `
    <a class="pa-concept-pill" href="${PREVIEW_BASE}/kategori/${escapeHtml(slug)}"${isClone ? ' tabindex="-1" aria-hidden="true"' : ''}>
      <span>${escapeHtml(label)}</span>
    </a>
  `).join('');
}

function heroConceptLane() {
  return `
    <div class="pa-hero-concepts" data-concept-slider aria-label="Öne çıkan kategoriler">
      <div class="pa-concept-head">
        <span>Öne çıkan kategoriler</span>
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

function archiveShortcutBand() {
  return `
    <a class="pa-archive-shortcut" href="${PREVIEW_BASE}/arsiv" aria-label="Arşivin tamamına git">
      <span class="pa-archive-shortcut-icon">${iconSvg('archive')}</span>
      <div class="pa-archive-shortcut-copy">
        <strong>Arşivin tamamını açın.</strong>
        <span>Tüm soru ve cevaplara hızlıca ulaşın.</span>
      </div>
      <span class="pa-archive-shortcut-link">Arşive Git ${iconSvg('arrow-right', 'pa-cta-icon')}</span>
    </a>
  `;
}

function archiveCountLabel(count) {
  return Number(count || 0).toLocaleString('tr-TR');
}

function archiveStatCount(key, fallback = 0) {
  const value = Number(publicArchiveFixtures.stats?.[key]);
  return Number.isFinite(value) && value >= 0 ? Math.round(value) : fallback;
}

function activeArchiveStatsBand(entries = []) {
  const fallbackAnswerCount = entries.filter(entry => Array.isArray(entry.answer)
    ? entry.answer.some(paragraph => String(paragraph || '').trim())
    : String(entry.answer || entry.answerText || entry.answer_text || '').trim()).length;
  const questionCount = archiveStatCount('questionCount', entries.length);
  const answerCount = archiveStatCount('answerCount', fallbackAnswerCount);
  return `
    <section class="pa-active-stats" data-active-stats aria-label="Arşiv sayacı">
      <div class="pa-active-stats-copy">
        <span class="pa-live-label"><span class="pa-live-dot" aria-hidden="true"><span></span></span>Aktif arşiv</span>
        <h2>Yayındaki soru ve cevaplar</h2>
        <p>Arşivde şu anda okunabilir durumda olan kayıtlar.</p>
      </div>
      <div class="pa-active-stats-grid">
        <div class="pa-active-stat" role="group" aria-label="${escapeHtml(`${archiveCountLabel(questionCount)} aktif soru`)}">
          <strong data-count-up data-count-target="${questionCount}">${escapeHtml(archiveCountLabel(questionCount))}</strong>
          <span>aktif soru</span>
        </div>
        <div class="pa-active-stat" role="group" aria-label="${escapeHtml(`${archiveCountLabel(answerCount)} aktif cevap`)}">
          <strong data-count-up data-count-target="${answerCount}">${escapeHtml(archiveCountLabel(answerCount))}</strong>
          <span>aktif cevap</span>
        </div>
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

function quranReferenceKey(value) {
  return String(value || '')
    .normalize('NFD')
    .replace(/[\u0300-\u036f]/g, '')
    .replace(/[Çç]/g, 'C')
    .replace(/[Ğğ]/g, 'G')
    .replace(/[İIı]/g, 'I')
    .replace(/[Öö]/g, 'O')
    .replace(/[Şş]/g, 'S')
    .replace(/[Üü]/g, 'U')
    .toUpperCase()
    .replace(/[^A-Z0-9]/g, '');
}

const QURAN_SURAH_NAMES = [
  'Fatiha', 'Bakara', 'Âl-i İmrân', 'Nisâ', 'Mâide', 'Enâm', 'Araf', 'Enfâl',
  'Tevbe', 'Yûnus', 'Hûd', 'Yûsuf', 'Rad', 'İbrâhîm', 'Hicr', 'Nahl', 'İsrâ',
  'Kehf', 'Meryem', 'Tâhâ', 'Enbiyâ', 'Hac', 'Müminûn', 'Nûr', 'Furkân',
  'Şuarâ', 'Neml', 'Kasas', 'Ankebût', 'Rûm', 'Lokmân', 'Secde', 'Ahzâb',
  'Sebe', 'Fâtır', 'Yâsîn', 'Sâffât', 'Sâd', 'Zümer', 'Mümin', 'Fussilet',
  'Şûrâ', 'Zuhruf', 'Duhân', 'Câsiye', 'Ahkâf', 'Muhammed', 'Fetih', 'Hucurât',
  'Kâf', 'Zâriyât', 'Tûr', 'Necm', 'Kamer', 'Rahmân', 'Vâkıa', 'Hadîd',
  'Mücâdele', 'Haşr', 'Mümtehine', 'Saf', 'Cuma', 'Münâfikûn', 'Tegâbün',
  'Talâk', 'Tahrîm', 'Mülk', 'Kalem', 'Hâkka', 'Meâric', 'Nûh', 'Cin',
  'Müzzemmil', 'Müddessir', 'Kıyâmet', 'İnsan', 'Mürselât', 'Nebe', 'Nâziât',
  'Abese', 'Tekvîr', 'İnfitâr', 'Mutaffifîn', 'İnşikâk', 'Bürûc', 'Târık',
  'Alâ', 'Gâşiye', 'Fecr', 'Beled', 'Şems', 'Leyl', 'Duhâ', 'İnşirâh',
  'Tîn', 'Alak', 'Kadir', 'Beyyine', 'Zilzâl', 'Âdiyât', 'Kâria', 'Tekâsür',
  'Asr', 'Hümeze', 'Fîl', 'Kureyş', 'Mâûn', 'Kevser', 'Kâfirûn', 'Nasr',
  'Tebbet', 'İhlâs', 'Felak', 'Nâs'
];

const QURAN_SURAH_BY_KEY = new Map(QURAN_SURAH_NAMES.map(name => [quranReferenceKey(name), name]));
for (const [alias, displayName] of Object.entries({
  ALIMRAN: 'Âl-i İmrân',
  GAFIR: 'Mümin',
  MUMINUN: 'Müminûn',
  MUMININ: 'Müminûn',
  YASIN: 'Yâsîn'
})) {
  QURAN_SURAH_BY_KEY.set(alias, displayName);
}

function answerTextForReferences(entry = {}) {
  const answer = Array.isArray(entry.answer) ? entry.answer.join(' ') : String(entry.answer || '');
  return [
    answer,
    entry.answerText,
    entry.answer_text,
    entry.fullAnswer,
    entry.body
  ].filter(Boolean).join(' ');
}

function surahNameFromCandidate(value) {
  const words = String(value || '').trim().split(/\s+/).filter(Boolean);
  for (let index = 0; index < words.length; index += 1) {
    const candidate = words.slice(index).join(' ');
    const surahName = QURAN_SURAH_BY_KEY.get(quranReferenceKey(candidate));
    if (surahName) return surahName;
  }
  return '';
}

function extractQuranReferences(entry = {}) {
  const text = answerTextForReferences(entry);
  const references = [];
  const seen = new Set();
  const word = "[A-Za-zÇĞİÖŞÜçğıöşüÂÎÛâîû'’]+";
  const pattern = new RegExp(`(^|[^\\p{L}])(${word}(?:\\s+${word}){0,2}?)(?:\\s+[Ss]uresi)?\\s*[-–—]\\s*(\\d{1,3})(?=$|[^\\d])`, 'gu');
  let match;
  while ((match = pattern.exec(text))) {
    const surahName = surahNameFromCandidate(match[2]);
    const verseNumber = Number(match[3]);
    if (!surahName || !Number.isFinite(verseNumber) || verseNumber < 1 || verseNumber > 286) continue;
    const key = `${quranReferenceKey(surahName)}-${verseNumber}`;
    if (seen.has(key)) continue;
    seen.add(key);
    references.push({ label: `${surahName}-${verseNumber}`, surahName, verseNumber });
  }
  return references;
}

function detailInfoPanel(entry) {
  const items = [];
  if (publicArchiveFixtures.brand.answererLabel) {
    items.push({ icon: 'user', label: publicArchiveFixtures.brand.answererLabel });
  }
  if (entry.publishedAt) {
    items.push({ icon: 'calendar', label: `Yayın tarihi: ${formatDate(entry.publishedAt)}` });
  }
  if (entry.updatedAt) {
    items.push({ icon: 'guncel', label: `Son güncelleme: ${formatDate(entry.updatedAt)}` });
  }
  if (entry.readTime) {
    items.push({ icon: 'clock', label: `${entry.readTime} dk okuma` });
  }
  items.push({ html: readCountNode(entry) });
  return `
    <section class="pa-detail-info" aria-label="Cevap bilgileri">
      ${items.map(item => item.html || `<span>${iconSvg(item.icon, 'pa-meta-icon')}<span>${escapeHtml(item.label)}</span></span>`).join('')}
    </section>
  `;
}

function sourceReferencesPanel(entry) {
  const references = extractQuranReferences(entry);
  if (!references.length) return '';
  return `
    <aside class="pa-source-box">
      <h2>Kaynak ve deliller</h2>
      <p>Bu cevapta açıkça adı geçen ayet atıfları:</p>
      <div class="pa-source-references">
        ${references.map(reference => {
          const href = `${PREVIEW_BASE}/arama?q=${encodeURIComponent(reference.label)}`;
          return `<a class="pa-source-reference" href="${escapeHtml(href)}" data-source-reference="${escapeHtml(reference.label)}">${escapeHtml(reference.label)}</a>`;
        }).join('')}
      </div>
    </aside>
  `;
}

function plainText(value) {
  if (Array.isArray(value)) return value.map(plainText).filter(Boolean).join('\n\n');
  return String(value || '').replace(/\s+/g, ' ').trim();
}

function publicArchiveSiteStructuredData() {
  return {
    '@context': 'https://schema.org',
    '@type': 'WebSite',
    '@id': `${publicArchiveCanonicalUrl('/')}#website`,
    url: publicArchiveCanonicalUrl('/'),
    name: publicArchiveFixtures.brand.name,
    description: publicArchiveFixtures.brand.sentence,
    inLanguage: 'tr',
    image: publicArchiveAssetUrl(PUBLIC_SHARE_IMAGE_FILE),
    publisher: {
      '@type': 'Organization',
      name: publicArchiveFixtures.brand.name,
      logo: {
        '@type': 'ImageObject',
        url: publicArchiveAssetUrl('app-icon-512.png')
      }
    },
    potentialAction: {
      '@type': 'SearchAction',
      target: {
        '@type': 'EntryPoint',
        urlTemplate: `${publicArchiveCanonicalUrl('/arama')}?q={search_term_string}`
      },
      'query-input': 'required name=search_term_string'
    }
  };
}

function questionPageStructuredData(entry, category) {
  const canonicalUrl = publicArchiveCanonicalUrl(`/soru/${entry.slug}`);
  const categoryNames = categoriesFor(entry).map(item => item.name).filter(Boolean);
  const references = extractQuranReferences(entry).map(reference => reference.label);
  const answerText = plainText(entry.answer || entry.answerText || entry.answer_text || entry.fullAnswer || entry.body);
  const answererName = publicArchiveFixtures.brand.authorName || publicArchiveFixtures.brand.answererLabel || '';
  const question = plainText(entry.question || entry.title);
  const acceptedAnswer = {
    '@type': 'Answer',
    text: answerText,
    author: answererName ? { '@type': 'Person', name: answererName } : undefined,
    datePublished: entry.publishedAt || undefined,
    dateModified: entry.updatedAt || undefined,
    citation: references.length ? references : undefined
  };
  const breadcrumbItems = [
    { name: 'Ana Sayfa', url: publicArchiveCanonicalUrl('/') },
    { name: 'Arşiv', url: publicArchiveCanonicalUrl('/arsiv') },
    category ? { name: category.name, url: publicArchiveCanonicalUrl(`/kategori/${category.slug}`) } : null,
    { name: entry.title, url: canonicalUrl }
  ].filter(Boolean);

  return [
    {
      '@context': 'https://schema.org',
      '@type': 'QAPage',
      '@id': `${canonicalUrl}#qa`,
      url: canonicalUrl,
      name: entry.title,
      description: entry.excerpt || entry.summary || question,
      inLanguage: 'tr',
      about: categoryNames,
      keywords: categoryNames.join(', '),
      mainEntity: {
        '@type': 'Question',
        name: entry.title,
        text: question,
        answerCount: 1,
        datePublished: entry.publishedAt || undefined,
        acceptedAnswer
      }
    },
    {
      '@context': 'https://schema.org',
      '@type': 'BreadcrumbList',
      itemListElement: breadcrumbItems.map((item, index) => ({
        '@type': 'ListItem',
        position: index + 1,
        name: item.name,
        item: item.url
      }))
    }
  ];
}

function questionCard(entry, options = {}) {
  const cardOptions = typeof options === 'boolean' ? { compact: options } : options;
  const compact = Boolean(cardOptions.compact);
  const showMeta = cardOptions.showMeta !== false;
  const strongCta = Boolean(cardOptions.strongCta);
  const category = categoryFor(entry);
  const topics = topicsFor(entry);
  const cardCategories = categoriesFor(entry);
  const countNode = readCountNode(entry);
  const href = `${PREVIEW_BASE}/soru/${escapeHtml(entry.slug)}`;
  return `
    <article class="pa-question-card${compact ? ' is-compact' : ''}${strongCta ? ' has-strong-cta' : ''}" data-card-href="${href}" role="link" tabindex="0" aria-label="${escapeHtml(entry.title)}">
      <span class="pa-card-icon">${iconSvg(questionIconName(entry, category, topics))}</span>
      <a class="pa-question-title" href="${href}">${escapeHtml(entry.title)}</a>
      ${showMeta ? `<div class="pa-card-meta">
        ${cardCategories.slice(0, 3).map(category => chip(category.name, `${PREVIEW_BASE}/kategori/${category.slug}`)).join('')}
      </div>` : ''}
      <div class="pa-card-bottom">
        <p class="pa-card-foot">${countNode}</p>
        <span class="pa-card-cta">Cevabı oku ${iconSvg('arrow-right', 'pa-cta-icon')}</span>
      </div>
    </article>
  `;
}

function homeQuestionIdentity(entry = {}) {
  const question = normalizeSearchText(entry.question || entry.title || '');
  const answer = normalizeSearchText(plainText(entry.answer || entry.answerText || entry.answer_text || entry.fullAnswer || entry.body || ''));
  if (question && answer) return `${question}\u0000${answer}`;
  return question || answer || String(entry.slug || entry.id || '');
}

function entryPublishedTime(entry = {}) {
  const date = new Date(entry.publishedAt || entry.updatedAt || 0);
  const time = date.getTime();
  return Number.isFinite(time) ? time : 0;
}

function betterHomeDuplicate(nextEntry = {}, currentEntry = {}) {
  const readDiff = normalizedReadCount(nextEntry) - normalizedReadCount(currentEntry);
  if (readDiff !== 0) return readDiff > 0;
  if (Boolean(nextEntry.isFeatured) !== Boolean(currentEntry.isFeatured)) return Boolean(nextEntry.isFeatured);
  const dateDiff = entryPublishedTime(nextEntry) - entryPublishedTime(currentEntry);
  if (dateDiff !== 0) return dateDiff > 0;
  return String(nextEntry.slug || '').localeCompare(String(currentEntry.slug || ''), 'tr') < 0;
}

function uniqueHomeQuestions(entries = []) {
  const byIdentity = new Map();
  for (const entry of entries || []) {
    if (!entry?.slug) continue;
    const key = homeQuestionIdentity(entry);
    if (!key) continue;
    const current = byIdentity.get(key);
    if (!current || betterHomeDuplicate(entry, current)) byIdentity.set(key, entry);
  }
  return [...byIdentity.values()];
}

function hashString(value) {
  let hash = 2166136261;
  for (const character of String(value || '')) {
    hash ^= character.charCodeAt(0);
    hash = Math.imul(hash, 16777619);
  }
  return hash >>> 0;
}

function homeRotationHour(now = Date.now()) {
  return Math.floor(Number(now || 0) / 3600000);
}

function weightedHomeScore(entry = {}, hour = homeRotationHour(), slot = 'popular') {
  const reads = Math.log1p(normalizedReadCount(entry)) * 1100;
  const featuredBoost = entry.isFeatured ? 450 : 0;
  const publishedBoost = entryPublishedTime(entry) ? Math.min(320, Math.max(0, entryPublishedTime(entry) / 100000000000)) : 0;
  const rotation = hashString(`${slot}:${hour}:${entry.slug || ''}:${entry.title || ''}`) % 720;
  return reads + featuredBoost + publishedBoost + rotation;
}

function rotateByHour(entries = [], hour = homeRotationHour()) {
  if (!entries.length) return [];
  const offset = hour % entries.length;
  return [...entries.slice(offset), ...entries.slice(0, offset)];
}

function homeQuestionSets(entries = []) {
  const unique = uniqueHomeQuestions(entries);
  const hour = homeRotationHour();
  const featured = unique
    .map(entry => ({ entry, score: weightedHomeScore(entry, hour, 'featured') }))
    .sort((a, b) => b.score - a.score)
    .slice(0, 3)
    .map(item => item.entry);
  const used = new Set(featured.map(homeQuestionIdentity));
  const latestPool = unique
    .filter(entry => !used.has(homeQuestionIdentity(entry)))
    .sort((a, b) => entryPublishedTime(b) - entryPublishedTime(a))
    .slice(0, 18);
  const latest = rotateByHour(latestPool, hour).slice(0, 3);
  const latestUsed = new Set([...used, ...latest.map(homeQuestionIdentity)]);
  if (latest.length < 3) {
    const fallback = unique
      .filter(entry => !latestUsed.has(homeQuestionIdentity(entry)))
      .map(entry => ({ entry, score: weightedHomeScore(entry, hour, 'latest') }))
      .sort((a, b) => b.score - a.score)
      .slice(0, 3 - latest.length)
      .map(item => item.entry);
    latest.push(...fallback);
  }
  return { featured, latest };
}

function topicCard(topic) {
  return `
    <a class="pa-topic-card" href="${PREVIEW_BASE}/kategori/${escapeHtml(topic.slug)}">
      <span class="pa-topic-mark">${iconSvg(topicIconName(topic))}</span>
      <strong>${escapeHtml(topic.name)}</strong>
      <span>${categoryQuestionCount(topic)} soru</span>
    </a>
  `;
}

function categoryCard(category) {
  return `
    <a class="pa-category-card" href="${PREVIEW_BASE}/kategori/${escapeHtml(category.slug)}">
      <span class="pa-category-mark">${iconSvg(categoryIconName(category))}</span>
      <span class="pa-category-copy">
        <strong>${escapeHtml(category.name)}</strong>
        <span>${categoryQuestionCount(category)} soru</span>
      </span>
    </a>
  `;
}

function breadcrumb(items) {
  return `
    <nav class="pa-breadcrumb" aria-label="Sayfa yolu">
      <a href="${publicArchiveHomeHref()}">Ana Sayfa</a>
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

function guideList(items = []) {
  return `
    <div class="pa-guide-list">
      ${items.map((item, index) => `
        <div class="pa-guide-item">
          <span>${String(index + 1).padStart(2, '0')}</span>
          <div>
            <strong>${escapeHtml(item.title)}</strong>
            <p>${escapeHtml(item.text)}</p>
          </div>
        </div>
      `).join('')}
    </div>
  `;
}

function trustBand() {
  return `
    <section class="pa-context-band" id="baglam">
      <div>
        <h2>Cevapları nasıl keşfedebilirsiniz?</h2>
        <p>Her cevap, ilgili kategorilerle birlikte daha kolay bulunur. Sorularınız Dr. Abdulcabbar Boran tarafından Kur’an ve Hadis-i Şerif ışığında cevaplandırılır; her cevap, ilgili kategorilerle birlikte arşivlenir. Böylece yalnızca aradığınız sorunun cevabına değil; aynı kategori altındaki diğer sorulara da kolayca ulaşabilirsiniz.</p>
      </div>
      ${stillLife()}
    </section>
  `;
}

function renderHome() {
  const { featured, latest } = homeQuestionSets(publicArchiveFixtures.qa);
  return renderShell({
    active: 'home',
    title: 'Ana Sayfa',
    description: 'Dini Sorular ve Cevaplar Arşivi içinde soru, cevap ve kategorileri birlikte okuyun.',
    canonicalPath: '/',
    content: `
      <main class="pa-main">
        <section class="pa-hero">
          <div class="pa-hero-copy">
            <p class="pa-kicker">${escapeHtml(publicArchiveFixtures.brand.sentence)}</p>
            <h1>Sorularınıza, kaynaklarıyla birlikte cevap bulun.</h1>
            <p>Hidayet, mürşid, zikir ve teslimiyet gibi temel kategorilerden başlayın; ilgili soruları, cevapları ve delilleri bir arada okuyun.</p>
            ${searchBox()}
            ${heroConceptLane()}
          </div>
          ${stillLife()}
        </section>

        ${archiveShortcutBand()}

        <section class="pa-section">
          ${sectionHeader('Öne Çıkan Sorular', 'Tümünü Gör', `${PREVIEW_BASE}/arsiv`)}
          <div class="pa-question-grid">${featured.map(entry => questionCard(entry, { showMeta: false, strongCta: true })).join('')}</div>
        </section>

        ${activeArchiveStatsBand(publicArchiveFixtures.qa)}

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
  const preFiltered = publicArchiveFixtures.search?.preFiltered === true;
  const preFilteredQuery = normalizeSearchText(publicArchiveFixtures.search?.query || '');
  if (preFiltered && normalized === preFilteredQuery) return publicArchiveFixtures.qa;
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

const trCollator = new Intl.Collator('tr-TR', { numeric: true, sensitivity: 'base' });

function sortedCategories() {
  return publicCategories().sort((a, b) => trCollator.compare(a.name || '', b.name || ''));
}

function categoryInitial(category) {
  const firstLetter = Array.from(String(category?.name || '').trim()).find(char => /\p{L}/u.test(char));
  return firstLetter ? firstLetter.toLocaleUpperCase('tr-TR') : '#';
}

function compareArchiveLetters(a, b) {
  if (a === b) return 0;
  if (a === '#') return 1;
  if (b === '#') return -1;
  return trCollator.compare(a, b);
}

function archiveQueryUrl(params = {}) {
  return queryPageUrl(`${PREVIEW_BASE}/arsiv`, params);
}

function queryPageUrl(basePath, params = {}) {
  const search = new URLSearchParams();
  if (params.harf) search.set('harf', params.harf);
  if (params.kategori) search.set('kategori', params.kategori);
  if (params.kategoriAra) search.set('kategoriAra', params.kategoriAra);
  const page = archivePageNumber(params.sayfa);
  if (page > 1) search.set('sayfa', String(page));
  const query = search.toString();
  return `${basePath}${query ? `?${query}` : ''}${params.hash ? `#${params.hash}` : ''}`;
}

function archivePageNumber(value) {
  const page = Number.parseInt(String(value || '1'), 10);
  return Number.isFinite(page) && page > 1 ? page : 1;
}

function archivePaginationState(entries = [], requestedPage = 1, serverState = null) {
  const serverTotal = Number(serverState?.total);
  const pageSize = Number(serverState?.pageSize) > 0 ? Number(serverState.pageSize) : ARCHIVE_PAGE_SIZE;
  const total = Number.isFinite(serverTotal) && serverTotal >= 0 ? Math.round(serverTotal) : entries.length;
  const totalPages = Math.max(1, Math.ceil(total / pageSize));
  const page = Math.min(Math.max(archivePageNumber(serverState?.page || requestedPage), 1), totalPages);
  const startIndex = (page - 1) * pageSize;
  const pageEntries = serverState?.prePaginated ? entries : entries.slice(startIndex, startIndex + pageSize);
  return {
    end: total ? Math.min(total, startIndex + pageEntries.length) : 0,
    page,
    pageEntries,
    start: total ? startIndex + 1 : 0,
    total,
    totalPages
  };
}

function archivePagination(basePath, params = {}, state) {
  if (!state || state.totalPages <= 1) {
    return state?.total
      ? `<p class="pa-list-status">${archiveCountLabel(state.total)} soru gösteriliyor.</p>`
      : '';
  }
  const prevHref = state.page > 1
    ? queryPageUrl(basePath, { ...params, sayfa: state.page - 1, hash: 'sorular' })
    : '';
  const nextHref = state.page < state.totalPages
    ? queryPageUrl(basePath, { ...params, sayfa: state.page + 1, hash: 'sorular' })
    : '';
  return `
    <nav class="pa-pagination" aria-label="Arşiv sayfaları">
      <span class="pa-pagination-status">${archiveCountLabel(state.start)}-${archiveCountLabel(state.end)} / ${archiveCountLabel(state.total)} soru gösteriliyor</span>
      <div class="pa-pagination-actions">
        ${prevHref
          ? `<a class="pa-page-link" href="${escapeHtml(prevHref)}">${iconSvg('arrow-left', 'pa-cta-icon')} Önceki</a>`
          : `<span class="pa-page-link is-disabled" aria-disabled="true">${iconSvg('arrow-left', 'pa-cta-icon')} Önceki</span>`}
        <span class="pa-page-current">Sayfa ${archiveCountLabel(state.page)} / ${archiveCountLabel(state.totalPages)}</span>
        ${nextHref
          ? `<a class="pa-page-link" href="${escapeHtml(nextHref)}">Sonraki ${iconSvg('arrow-right', 'pa-cta-icon')}</a>`
          : `<span class="pa-page-link is-disabled" aria-disabled="true">Sonraki ${iconSvg('arrow-right', 'pa-cta-icon')}</span>`}
      </div>
    </nav>
  `;
}

function archiveCategoryIndexState(query = {}) {
  const categories = sortedCategories();
  const categoriesByLetter = new Map();
  for (const category of categories) {
    const letter = categoryInitial(category);
    if (!categoriesByLetter.has(letter)) categoriesByLetter.set(letter, []);
    categoriesByLetter.get(letter).push(category);
  }
  const letters = [...categoriesByLetter.keys()].sort(compareArchiveLetters);
  const queryCategory = String(query.kategori || '').trim();
  const selectedCategory = queryCategory ? bySlug(categories, queryCategory) : null;
  const queryLetter = String(query.harf || '').trim().toLocaleUpperCase('tr-TR');
  const activeLetter = selectedCategory
    ? categoryInitial(selectedCategory)
    : letters.includes(queryLetter)
      ? queryLetter
      : letters[0] || '';
  const letterCategories = categoriesByLetter.get(activeLetter) || [];
  const categorySearch = String(query.kategoriAra || '').trim();
  const normalizedCategorySearch = normalizeSearchText(categorySearch);
  const visibleCategories = normalizedCategorySearch
    ? letterCategories.filter(category => normalizeSearchText(category.name).includes(normalizedCategorySearch))
    : letterCategories;
  return {
    activeLetter,
    categorySearch,
    letters,
    selectedCategory,
    visibleCategories
  };
}

function archiveCategoryIndex(query = {}) {
  const state = archiveCategoryIndexState(query);
  if (!state.letters.length) return { html: '', selectedCategory: null, activeLetter: '' };
  return {
    ...state,
    html: `
      <div class="pa-alpha-index" aria-label="Alfabetik kategori dizini">
        <div class="pa-alpha-track" role="list" aria-label="Kategori harfleri">
          ${state.letters.map(letter => `
            <a class="pa-alpha-letter${letter === state.activeLetter ? ' is-active' : ''}" href="${escapeHtml(archiveQueryUrl({ harf: letter }))}"${letter === state.activeLetter ? ' aria-current="true"' : ''} role="listitem">${escapeHtml(letter)}</a>
          `).join('')}
        </div>
        <div class="pa-letter-panel">
          <div class="pa-letter-head">
            <span class="pa-letter-badge">${escapeHtml(state.activeLetter)}</span>
            <strong>${escapeHtml(state.activeLetter)} harfiyle başlayan kategoriler</strong>
            ${state.selectedCategory || state.categorySearch ? `<a href="${escapeHtml(archiveQueryUrl({ harf: state.activeLetter }))}">Tümünü göster</a>` : ''}
          </div>
          <form class="pa-letter-search" action="${PREVIEW_BASE}/arsiv" method="get" role="search">
            <input type="hidden" name="harf" value="${escapeHtml(state.activeLetter)}">
            <span>${iconSvg('search')}</span>
            <input name="kategoriAra" value="${escapeHtml(state.categorySearch)}" placeholder="Bu harfte ara..." aria-label="${escapeHtml(state.activeLetter)} harfindeki kategorilerde ara" autocomplete="off">
            <button type="submit" aria-label="Kategori ara">${iconSvg('arrow-right')}</button>
          </form>
          ${state.visibleCategories.length ? `
            <div class="pa-letter-categories">
              ${state.visibleCategories.map(category => `
                <a class="pa-index-category${state.selectedCategory?.slug === category.slug ? ' is-active' : ''}" href="${escapeHtml(archiveQueryUrl({ harf: state.activeLetter, kategori: category.slug, hash: 'sorular' }))}">
                  <strong>${escapeHtml(category.name)}</strong>
                  <span>${categoryQuestionCount(category)} soru</span>
                </a>
              `).join('')}
            </div>
          ` : `<p class="pa-index-empty">Bu harfte aramanızla eşleşen kategori bulunamadı.</p>`}
        </div>
      </div>
    `
  };
}

function renderArchive(query = {}) {
  const serverPagination = publicArchiveFixtures.pagination?.scope === 'archive'
    ? publicArchiveFixtures.pagination
    : null;
  const entries = [...publicArchiveFixtures.qa].sort((a, b) => String(b.publishedAt).localeCompare(String(a.publishedAt)));
  const answeredCount = archiveStatCount('answerCount', entries.filter(entry => Array.isArray(entry.answer) && entry.answer.length).length || entries.length);
  const categoryIndex = archiveCategoryIndex(query);
  const visibleEntries = serverPagination?.prePaginated
    ? entries
    : categoryIndex.selectedCategory
    ? entries.filter(entry => categorySlugsFor(entry).includes(categoryIndex.selectedCategory.slug))
    : entries;
  const pageState = archivePaginationState(visibleEntries, query.sayfa, serverPagination);
  const paginationParams = {
    harf: (query.harf || categoryIndex.selectedCategory || categoryIndex.categorySearch) ? categoryIndex.activeLetter : '',
    kategori: categoryIndex.selectedCategory?.slug || '',
    kategoriAra: categoryIndex.categorySearch || ''
  };
  const listTitle = categoryIndex.selectedCategory ? `${categoryIndex.selectedCategory.name} soruları` : 'Tüm Sorular';
  return renderShell({
    active: 'archive',
    title: 'Arşiv',
    description: 'Merak ettiğiniz konunun cevaplarına ulaşın.',
    canonicalPath: '/arsiv',
    content: `
      <main class="pa-main pa-narrow-main">
        <section class="pa-archive-hero">
          <p class="pa-kicker">Arşiv</p>
          <h1>Merak ettiğiniz konunun cevaplarına ulaşın.</h1>
          <p>Soru ve cevapları kategorilerine göre inceleyebilir, aradığınız konuyu alfabetik olarak kolayca bulabilirsiniz.</p>
          <div class="pa-collection-meta">
            <span>${archiveCountLabel(answeredCount)} soru cevap</span>
          </div>
          ${categoryIndex.html}
        </section>
        <section class="pa-section" id="sorular">
          ${sectionHeader(listTitle, categoryIndex.selectedCategory ? 'Tümünü göster' : '', categoryIndex.selectedCategory ? archiveQueryUrl({ harf: categoryIndex.activeLetter, hash: 'sorular' }) : '')}
          ${visibleEntries.length
            ? `<div class="pa-list">${pageState.pageEntries.map(entry => questionCard(entry, true)).join('')}</div>${archivePagination(`${PREVIEW_BASE}/arsiv`, paginationParams, pageState)}`
            : `<div class="pa-empty-state"><h2>Bu kategoride soru görünmüyor.</h2><p>Arşivdeki diğer kategorileri inceleyebilirsiniz.</p></div>`}
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
    description: 'Arşivde soru ve kategori arayın.',
    canonicalPath: '/arama',
    content: `
      <main class="pa-main pa-narrow-main">
        <section class="pa-search-page">
          <p class="pa-kicker">Arşivde ara</p>
          <h1>Aradığınız cevaba en kısa yoldan ulaşın.</h1>
          <p class="pa-page-intro">Soru başlıkları, cevap metinleri ve kategoriler içinde sade bir arama yapabilirsiniz.</p>
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
  return renderCategoriesIndex();
}

function renderCategoriesIndex() {
  const categories = sortedCategories();
  const questionCount = archiveStatCount('questionCount', publicArchiveFixtures.qa.length);
  return renderShell({
    active: 'categories',
    title: 'Kategoriler',
    description: 'Arşivdeki soru-cevap kategorileri.',
    canonicalPath: '/kategoriler',
    content: `
      <main class="pa-main pa-narrow-main">
        <section class="pa-collection-hero">
          <p class="pa-kicker">Kategoriler</p>
          <h1>Soruları ana başlıklarına göre inceleyin.</h1>
          <p>Kategoriler, arşivdeki soru ve cevapları daha düzenli taramak için ana kapılar olarak kullanılır.</p>
          <div class="pa-collection-meta">
            <span>${categories.length} kategori</span>
            <span>${archiveCountLabel(questionCount)} soru</span>
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
    canonicalPath: `/soru/${entry.slug}`,
    structuredData: questionPageStructuredData(entry, category),
    questionSlug: entry.slug,
    content: `
      <main class="pa-main pa-detail-main">
        ${breadcrumb([
          { label: 'Arşiv', href: `${PREVIEW_BASE}/arsiv` },
          category ? { label: category.name, href: `${PREVIEW_BASE}/kategori/${category.slug}` } : { label: 'Soru' }
        ])}
        <article class="pa-answer-layout">
          <div class="pa-answer-primary">
            <h1 class="pa-sr-only">${escapeHtml(entry.title)}</h1>
            <section class="pa-reading-block">
              <h2>Soru</h2>
              <p>${escapeHtml(entry.question)}</p>
            </section>
            <section class="pa-reading-block">
              <h2>Cevap</h2>
              ${entry.answer.map(paragraph => `<p>${escapeHtml(paragraph)}</p>`).join('')}
            </section>
            ${detailInfoPanel(entry)}
            ${sourceReferencesPanel(entry)}
            <div class="pa-tool-row" aria-label="Sayfa araçları">
              <button type="button" class="pa-icon-button" data-share>Paylaş</button>
              <button type="button" class="pa-icon-button" data-copy-link>Bağlantıyı kopyala</button>
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
              <h2>Kategoriler</h2>
              <div class="pa-chip-wrap">${categoriesFor(entry).map(category => chip(category.name, `${PREVIEW_BASE}/kategori/${category.slug}`)).join('')}</div>
            </section>
          </aside>
        </article>
      </main>
    `
  });
}

function renderTopic(slug, query = {}) {
  return renderCategory(slug, query, `${PREVIEW_BASE}/konu/${slug}`);
}

function renderCategory(slug, query = {}, basePath = `${PREVIEW_BASE}/kategori/${slug}`) {
  const category = publicCategoryBySlug(slug);
  if (!category) return renderNotFound();
  const serverPagination = publicArchiveFixtures.pagination?.scope === 'category' && publicArchiveFixtures.pagination?.slug === slug
    ? publicArchiveFixtures.pagination
    : null;
  const entries = serverPagination?.prePaginated ? publicArchiveFixtures.qa : entriesForCategory(category.slug);
  const pageState = archivePaginationState(entries, query.sayfa, serverPagination);
  return renderShell({
    active: 'categories',
    title: category.name,
    description: category.description,
    canonicalPath: `/kategori/${category.slug}`,
    content: `
      <main class="pa-main pa-narrow-main">
        ${breadcrumb([{ label: 'Kategoriler', href: `${PREVIEW_BASE}/kategoriler` }, { label: category.name }])}
        <section class="pa-collection-hero">
          <p class="pa-kicker">Kategori</p>
          <h1>${escapeHtml(category.name)}</h1>
          <p>${escapeHtml(category.description)}</p>
          <div class="pa-collection-meta">
            <span>${archiveCountLabel(pageState.total)} ilgili soru</span>
          </div>
        </section>
        <section class="pa-section" id="sorular">
          ${sectionHeader('Bu Kategorideki Sorular')}
          <div class="pa-list">${pageState.pageEntries.map(entry => questionCard(entry, true)).join('')}</div>
          ${archivePagination(basePath, {}, pageState)}
        </section>
      </main>
    `
  });
}

function renderAccount() {
  const googleIcon = '<span class="pa-google-mark" aria-hidden="true"><svg viewBox="0 0 24 24" focusable="false"><path fill="#4285F4" d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92c-.26 1.37-1.04 2.53-2.21 3.31v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.09z"/><path fill="#34A853" d="M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z"/><path fill="#FBBC05" d="M5.84 14.1c-.22-.66-.35-1.36-.35-2.1s.13-1.44.35-2.1V7.06H2.18C1.43 8.55 1 10.22 1 12s.43 3.45 1.18 4.94l3.66-2.84z"/><path fill="#EA4335" d="M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 14.97 1 12 1 7.7 1 3.99 3.47 2.18 7.06L5.84 9.9C6.71 7.3 9.14 5.38 12 5.38z"/></svg></span>';
  return renderShell({
    active: 'account',
    title: 'Hesabım',
    description: 'Soru gönderimi için hesap sayfası.',
    canonicalPath: '/hesabim',
    content: `
      <main class="pa-main pa-narrow-main">
        <section class="pa-account-page pa-auth-shell" data-account-panel>
          <div class="pa-auth-intro">
            <p class="pa-kicker">Hesabım</p>
            <h1>Soru göndermek için hesabınıza giriş yapın.</h1>
            <p>Google hesabınızla hızlıca devam edebilir veya e-posta adresinizle oturum açabilirsiniz. Gönderdiğiniz sorular hesabınıza bağlanır.</p>
          </div>
          <div class="pa-account-status" data-account-status>Oturum durumu kontrol ediliyor...</div>
          <div class="pa-empty-actions" data-account-actions></div>
          <div class="pa-auth-panel" data-public-auth data-auth-mode="login">
            <a class="pa-google-button" data-google-auth-button href="${PREVIEW_BASE}/auth/google?returnTo=${encodeURIComponent(PREVIEW_BASE + '/hesabim')}">${googleIcon}<span>Google ile Devam Et</span></a>
            <div class="pa-auth-divider"><span>veya e-posta ile</span></div>
            <div class="pa-auth-tabs" role="tablist" aria-label="Hesap işlemi">
              <button type="button" class="is-active" data-auth-tab="login" role="tab" aria-selected="true">Oturum Aç</button>
              <button type="button" data-auth-tab="register" role="tab" aria-selected="false">Kayıt Ol</button>
            </div>
            <div class="pa-auth-forms">
              <form class="pa-auth-form is-active" data-email-login-form data-auth-form="login" data-auth-endpoint="${PREVIEW_BASE}/api/auth/email/login">
                <label>
                  <span>E-posta</span>
                  <input name="email" type="email" autocomplete="email" placeholder="ornek@mail.com" required>
                </label>
                <label>
                  <span>Şifre</span>
                  <input name="password" type="password" autocomplete="current-password" minlength="8" required>
                </label>
                <button class="pa-button" type="submit">Oturum Aç</button>
              </form>
              <form class="pa-auth-form" data-email-register-form data-auth-form="register" data-auth-endpoint="${PREVIEW_BASE}/api/auth/email/register">
                <label>
                  <span>Adınız</span>
                  <input name="name" type="text" autocomplete="name" placeholder="Adınız" required>
                </label>
                <label>
                  <span>E-posta</span>
                  <input name="email" type="email" autocomplete="email" placeholder="ornek@mail.com" required>
                </label>
                <label>
                  <span>Şifre</span>
                  <input name="password" type="password" autocomplete="new-password" minlength="8" required>
                </label>
                <button class="pa-button" type="submit">Kayıt Ol</button>
              </form>
            </div>
          </div>
          <p class="pa-form-status" data-email-auth-status aria-live="polite"></p>
        </section>
        <section class="pa-account-questions" data-user-questions hidden>
          <div class="pa-section-heading">
            <div>
              <p class="pa-kicker">Sorularım</p>
              <h2>Gönderdiğiniz sorular ve cevap durumları</h2>
            </div>
          </div>
          <div class="pa-user-question-list" data-user-questions-list>
            <div class="pa-mini-empty">Sorularınız yükleniyor...</div>
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
    description: 'Arşive soru göndermek için sade form.',
    canonicalPath: '/soru-sor',
    content: `
      <main class="pa-main pa-form-main">
        ${breadcrumb([{ label: 'Soru Sor' }])}
        <section class="pa-form-layout">
          <div class="pa-form-copy">
            <p class="pa-kicker">Soru Sor</p>
            <h1>Sorunuzu anlaşılır bir şekilde yazın.</h1>
            <p>Sorunuzu kısa ve açık şekilde yazabilirsiniz. ${escapeHtml(publicArchiveFixtures.brand.authorLine)}</p>
            <div class="pa-account-status" data-ask-session>Oturum durumu kontrol ediliyor...</div>
            ${guideList([
              {
                title: 'Tek soruya odaklanın',
                text: 'Ana meselenizi bir cümlede yazın; gerekiyorsa kısa bir bağlam ekleyin.'
              },
              {
                title: 'Mahrem bilgi yazmayın',
                text: 'Ad, telefon, adres, özel sağlık bilgisi veya üçüncü kişilere ait ayrıntı paylaşmayın.'
              },
              {
                title: 'Önce arşive bakabilirsiniz',
                text: 'Benzer cevaplar varsa arama ve kategori sayfaları sizi hızlıca ilgili kayda götürür.'
              }
            ])}
          </div>
          <form class="pa-ask-form" data-question-form>
            <div class="pa-form-heading">
              <strong>Sorunuz</strong>
              <p>Soruyu açık, kısa ve tek konuya odaklı yazmanız yeterlidir.</p>
            </div>
            <label>
              <span>Soru metni</span>
              <textarea name="question" rows="8" maxlength="2000" minlength="20" placeholder="Sorunuzu buraya yazın..." required></textarea>
              <small class="pa-field-help">Kategori seçmeniz gerekmez; soru arşive alınırken ilgili başlıklarla bağlanır.</small>
            </label>
            <label class="pa-check-row" id="kullanim">
              <input name="privacyAccepted" type="checkbox" required>
              <span>Kişisel veya mahrem bilgi yazmadığımı anladım.</span>
            </label>
            <button class="pa-button" type="submit">Soruyu Gönder</button>
            <p class="pa-form-note">Gönderdiğiniz soru kayda alınır. Cevap süresi ve yayın durumu sorunun içeriğine göre değişebilir.</p>
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
      heading: 'Dini soruların cevaplarını delilleri ve kaynak bağlamıyla birlikte sunan bir arşiv.',
      copy: [
        'Dini Sorular ve Cevaplar Arşivi, yayınlanmış soru-cevapları tek tek aramak yerine düzenli bir okuma yapısı içinde bulabilmeniz için hazırlanır.',
        `${publicArchiveFixtures.brand.authorLine} Her cevap; ilgili kategori, bağlantılı sorular ve kaynak bağlamıyla birlikte sunularak okuyucunun konuyu daha rahat takip etmesine yardımcı olur.`
      ],
      points: [
        { title: 'Amacı', text: 'Merak edilen sorulara hızlı ulaşmayı, cevabı okurken ilgili başlıkları da görmeyi sağlar.' },
        { title: 'Düzeni', text: 'Cevaplar kategori ve ilişkili soru bağlantılarıyla birlikte arşivlenir; böylece konu tek sayfada kalmaz.' },
        { title: 'Okuma deneyimi', text: 'Uzun cevaplar mobil ve masaüstünde paragraflı, sakin ve takip edilebilir bir düzende gösterilir.' }
      ],
      actions: [
        { label: 'Arşivi İncele', href: `${PREVIEW_BASE}/arsiv` },
        { label: 'Nasıl Kullanılır?', href: `${PREVIEW_BASE}/nasil-kullanilir`, secondary: true }
      ]
    },
    'nasil-kullanilir': {
      title: 'Nasıl Kullanılır',
      kicker: 'Nasıl Kullanılır',
      heading: 'Aradığınız cevaba arama, arşiv ve kategoriler üzerinden ulaşabilirsiniz.',
      copy: [
        'Ana sayfadaki arama kutusuna bir soru, kelime veya kategori yazabilirsiniz. Sonuçlarda ilgili soru kartını açarak cevabın tamamına geçebilirsiniz.',
        'Arşiv sayfasında kayıtları alfabetik olarak inceleyebilir, bir harf seçip o harfe ait kategoriler içinden aradığınız başlığa ulaşabilirsiniz.'
      ],
      points: [
        { title: 'Arayın', text: 'Soru veya kategori yazarak başlayın; kısa ve doğrudan kelimeler daha iyi sonuç verir.' },
        { title: 'Cevabı okuyun', text: 'Soru detayında cevabı, yayın bilgisini, okunma sayısını ve ilgili kategorileri birlikte görün.' },
        { title: 'Devam edin', text: 'Aynı kategori veya ilgili sorular üzerinden okumayı genişletin.' }
      ],
      actions: [
        { label: 'Arama Yap', href: `${PREVIEW_BASE}/arama` },
        { label: 'Arşive Git', href: `${PREVIEW_BASE}/arsiv`, secondary: true }
      ]
    },
    iletisim: {
      title: 'İletişim',
      kicker: 'İletişim',
      heading: 'Arşivle ilgili düzeltme, eksik bilgi ve soru taleplerinizi doğru yerden iletebilirsiniz.',
      copy: [
        'Bir sayfada yazım hatası, çalışmayan bağlantı veya eksik görünen bir bilgi fark ederseniz bunu kısa ve anlaşılır bir notla iletebilirsiniz.',
        'Yeni bir dini soru sormak istiyorsanız doğrudan Soru Sor sayfasını kullanmanız gerekir; böylece soru doğru akışa alınır.'
      ],
      points: [
        { title: 'Düzeltme notu', text: 'Hangi sayfada ne gördüğünüzü belirtin; mümkünse sayfa başlığını veya bağlantıyı ekleyin.' },
        { title: 'Yeni soru', text: 'Cevaplanmasını istediğiniz dini sorular için Soru Sor formunu kullanın.' },
        { title: 'Mahremiyet', text: 'İletişim veya soru metninde telefon, adres, özel sağlık bilgisi ya da üçüncü kişilere ait mahrem bilgi yazmayın.' }
      ],
      actions: [
        { label: 'Soru Sor', href: `${PREVIEW_BASE}/soru-sor` },
        { label: 'Gizliliği Oku', href: `${PREVIEW_BASE}/gizlilik`, secondary: true }
      ]
    },
    gizlilik: {
      title: 'Gizlilik',
      kicker: 'Gizlilik',
      heading: 'Soru gönderirken ve arşivi kullanırken mahremiyetinizi korumanız önemlidir.',
      copy: [
        'Soru metninde ad, telefon, adres, özel sağlık bilgisi, aile içi ayrıntılar veya üçüncü kişilere ait mahrem bilgiler paylaşılmamalıdır.',
        'Oturum açmanız, gönderdiğiniz sorunun size ait bir hesapla ilişkilendirilmesi ve gerektiğinde sürecin sağlıklı yürütülmesi içindir.'
      ],
      points: [
        { title: 'Kişisel bilgi', text: 'Sorunun anlaşılması için zorunlu olmayan özel bilgileri yazmayın.' },
        { title: 'Üçüncü kişiler', text: 'Başka kişileri tanıtacak isim, adres, olay detayı veya mahrem bilgi paylaşmayın.' },
        { title: 'Hesap kullanımı', text: 'Hesap bilgisi arşiv okuma deneyimini değil, soru gönderim sürecini düzenli yürütmeyi destekler.' }
      ],
      actions: [
        { label: 'Soru Sorarken Dikkat Edin', href: `${PREVIEW_BASE}/soru-sor` },
        { label: 'Kullanım Koşulları', href: `${PREVIEW_BASE}/kullanim-kosullari`, secondary: true }
      ]
    },
    'kullanim-kosullari': {
      title: 'Kullanım Koşulları',
      kicker: 'Kullanım Koşulları',
      heading: 'Arşivden yararlanırken ve soru gönderirken geçerli temel kullanım ilkeleri.',
      copy: [
        'Bu arşiv; yayınlanmış soru-cevapları okumak, aramak, kategoriler üzerinden incelemek ve ilgili cevaplara ulaşmak için sunulur.',
        'Soru gönderimi, sorunun mutlaka yayınlanacağı veya belirli bir süre içinde cevaplanacağı anlamına gelmez. Gönderilen sorular uygunluk ve ihtiyaç durumuna göre değerlendirilir.'
      ],
      points: [
        { title: 'Okuma ve paylaşım', text: 'Cevapları okuyabilir ve bağlantılarını paylaşabilirsiniz; içerik bütünlüğü korunmalıdır.' },
        { title: 'Soru gönderimi', text: 'Gönderilen sorular açık, saygılı ve tek konuya odaklı olmalıdır.' },
        { title: 'Arşiv düzeni', text: 'Başlıklar, kategoriler ve bağlantılar okuyucunun cevaba daha kolay ulaşması için düzenlenebilir.' }
      ],
      actions: [
        { label: 'Arşivi Aç', href: `${PREVIEW_BASE}/arsiv` },
        { label: 'Gizlilik', href: `${PREVIEW_BASE}/gizlilik`, secondary: true }
      ]
    }
  };
  const page = pages[kind] || pages.hakkimizda;
  return renderShell({
    active: kind === 'iletisim' ? 'ask' : 'archive',
    title: page.title,
    description: page.heading,
    canonicalPath: `/${kind}`,
    content: `
      <main class="pa-main pa-narrow-main">
        <section class="pa-info-page">
          <p class="pa-kicker">${escapeHtml(page.kicker)}</p>
          <h1>${escapeHtml(page.heading)}</h1>
          <div class="pa-info-copy">
            ${page.copy.map(paragraph => `<p>${escapeHtml(paragraph)}</p>`).join('')}
          </div>
          ${guideList(page.points || [])}
          <div class="pa-empty-actions">
            ${(page.actions || []).map(action => `<a class="pa-button${action.secondary ? ' is-secondary' : ''}" href="${escapeHtml(action.href)}">${escapeHtml(action.label)}</a>`).join('')}
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
    description: 'Aradığınız içerik bulunamadı.',
    status: 404,
    content: `
      <main class="pa-main pa-narrow-main">
        <section class="pa-empty-state is-large">
          <p class="pa-kicker">404</p>
          <h1>Sayfa bulunamadı.</h1>
          <p>Aradığınız içerik şu anda görünmüyor. Arama yapabilir veya ana sayfaya dönebilirsiniz.</p>
          ${searchBox()}
          <div class="pa-empty-actions">
            <a class="pa-button" href="${publicArchiveHomeHref()}">Ana Sayfa</a>
            <a class="pa-button is-secondary" href="${PREVIEW_BASE}/arama">Arşivde Ara</a>
          </div>
        </section>
      </main>
    `
  });
}

function renderShell({ title, description, active, content, status = 200, questionSlug = '', canonicalPath = '', structuredData = [] }) {
  const safeTitle = pageTitle(title);
  const safeDescription = description || publicArchiveFixtures.brand.sentence;
  const publicAppName = publicArchiveFixtures.brand.name;
  const publicShortAppName = 'Dini Sorular';
  const canonicalHref = canonicalPath ? publicArchiveCanonicalUrl(canonicalPath) : '';
  const shareImageHref = publicArchiveAssetUrl(PUBLIC_SHARE_IMAGE_FILE);
  const structuredItems = [
    publicArchiveSiteStructuredData(),
    ...(Array.isArray(structuredData) ? structuredData : structuredData ? [structuredData] : [])
  ];
  return {
    status,
    html: `<!doctype html>
<html lang="tr" data-theme="light">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">
  <meta name="robots" content="${PUBLIC_ARCHIVE_NOINDEX ? 'noindex,nofollow' : 'index,follow'}">
  <meta name="description" content="${escapeHtml(safeDescription)}">
  <meta name="application-name" content="${escapeHtml(publicAppName)}">
  <meta name="mobile-web-app-capable" content="yes">
  <meta name="apple-mobile-web-app-capable" content="yes">
  <meta name="apple-mobile-web-app-status-bar-style" content="black-translucent">
  <meta name="apple-mobile-web-app-title" content="${escapeHtml(publicShortAppName)}">
  ${!PUBLIC_ARCHIVE_NOINDEX && canonicalHref ? `<link rel="canonical" href="${escapeHtml(canonicalHref)}">` : ''}
  <meta property="og:locale" content="tr_TR">
  <meta property="og:site_name" content="${escapeHtml(publicAppName)}">
  <meta property="og:title" content="${escapeHtml(safeTitle)}">
  <meta property="og:description" content="${escapeHtml(safeDescription)}">
  <meta property="og:type" content="${questionSlug ? 'article' : 'website'}">
  ${canonicalHref ? `<meta property="og:url" content="${escapeHtml(canonicalHref)}">` : ''}
  <meta property="og:image" content="${escapeHtml(shareImageHref)}">
  <meta property="og:image:width" content="1200">
  <meta property="og:image:height" content="630">
  <meta property="og:image:alt" content="${escapeHtml(publicAppName)}">
  <meta name="twitter:card" content="summary_large_image">
  <meta name="twitter:title" content="${escapeHtml(safeTitle)}">
  <meta name="twitter:description" content="${escapeHtml(safeDescription)}">
  <meta name="twitter:image" content="${escapeHtml(shareImageHref)}">
  <meta name="twitter:image:alt" content="${escapeHtml(publicAppName)}">
  <meta name="theme-color" content="#F7F3EA">
  <title>${escapeHtml(safeTitle)}</title>
  ${structuredItems.map(jsonLdScript).join('\n  ')}
  <link rel="icon" type="image/png" sizes="16x16" href="${publicArchiveAssetHref('favicon-16.png')}">
  <link rel="icon" type="image/png" sizes="32x32" href="${publicArchiveAssetHref('favicon-32.png')}">
  <link rel="icon" type="image/png" sizes="48x48" href="${publicArchiveAssetHref('favicon-48.png')}">
  <link rel="apple-touch-icon" sizes="180x180" href="${publicArchiveAssetHref('apple-touch-icon.png')}">
  <link rel="manifest" href="${publicArchiveAssetHref('site.webmanifest')}">
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
  <button class="pa-scroll-top" type="button" data-scroll-top aria-label="Yukarı çık" aria-hidden="true">
    ${iconSvg('arrow-up', 'pa-scroll-top-icon')}
  </button>
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
      function bindActiveStatsCounters() {
        var section = document.querySelector('[data-active-stats]');
        var counters = section ? Array.from(section.querySelectorAll('[data-count-up]')) : [];
        if (!section || !counters.length) return;
        var formatter = new Intl.NumberFormat('tr-TR');
        var reducedMotion = window.matchMedia && window.matchMedia('(prefers-reduced-motion: reduce)').matches;
        var started = false;
        function targetFor(node) {
          var target = Number(node.getAttribute('data-count-target') || '0');
          return Number.isFinite(target) && target > 0 ? Math.round(target) : 0;
        }
        function animateNode(node) {
          var target = targetFor(node);
          if (reducedMotion || target === 0) {
            node.textContent = formatter.format(target);
            return;
          }
          var duration = 2400;
          var startedAt = 0;
          node.textContent = '0';
          function tick(time) {
            if (!startedAt) startedAt = time;
            var progress = Math.min((time - startedAt) / duration, 1);
            var eased = 1 - Math.pow(1 - progress, 3);
            node.textContent = formatter.format(Math.round(target * eased));
            if (progress < 1) window.requestAnimationFrame(tick);
            else node.textContent = formatter.format(target);
          }
          window.requestAnimationFrame(tick);
        }
        function startCounters() {
          if (started) return;
          started = true;
          section.setAttribute('data-counted', 'true');
          counters.forEach(animateNode);
        }
        if ('IntersectionObserver' in window) {
          var observer = new IntersectionObserver(function(entries){
            if (entries.some(function(entry){ return entry.isIntersecting; })) {
              observer.disconnect();
              startCounters();
            }
          }, { threshold: 0.35, rootMargin: '0px 0px -8% 0px' });
          observer.observe(section);
        } else {
          window.setTimeout(startCounters, 300);
        }
      }
      function bindScrollTopControl() {
        var button = document.querySelector('[data-scroll-top]');
        if (!button) return;
        var ticking = false;
        function update() {
          var visible = window.scrollY > 420;
          button.setAttribute('data-visible', visible ? 'true' : 'false');
          button.setAttribute('aria-hidden', visible ? 'false' : 'true');
          ticking = false;
        }
        window.addEventListener('scroll', function(){
          if (ticking) return;
          ticking = true;
          window.requestAnimationFrame(update);
        }, { passive: true });
        window.addEventListener('resize', update, { passive: true });
        button.addEventListener('click', function(){
          window.scrollTo({ top: 0, behavior: 'smooth' });
          button.blur();
        });
        update();
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
      function publicArchiveClientId(storage, key) {
        try {
          var current = storage.getItem(key);
          if (current) return current;
          var next = (window.crypto && window.crypto.randomUUID)
            ? window.crypto.randomUUID()
            : String(Date.now()) + '-' + Math.random().toString(36).slice(2);
          storage.setItem(key, next);
          return next;
        } catch (error) {
          return String(Date.now()) + '-' + Math.random().toString(36).slice(2);
        }
      }
      function trackPublicVisit() {
        try {
          var params = new URLSearchParams(window.location.search || '');
          var payload = {
            visitorId: publicArchiveClientId(window.localStorage, 'dsca-visitor-id'),
            sessionId: publicArchiveClientId(window.sessionStorage, 'dsca-session-id'),
            path: window.location.pathname + window.location.search,
            referrer: document.referrer || '',
            utmSource: params.get('utm_source') || '',
            utmMedium: params.get('utm_medium') || '',
            utmCampaign: params.get('utm_campaign') || '',
            timezone: Intl.DateTimeFormat().resolvedOptions().timeZone || '',
            language: navigator.language || '',
            screenWidth: window.screen && window.screen.width,
            screenHeight: window.screen && window.screen.height
          };
          window.fetch('${PREVIEW_BASE}/api/public-analytics/visit', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
            body: JSON.stringify(payload),
            keepalive: true
          }).catch(function(){});
        } catch (error) {}
      }
      async function loadPublicSession() {
        try {
          var response = await fetch('${PREVIEW_BASE}/api/session', { headers: { Accept: 'application/json' } });
          return await response.json();
        } catch (error) {
          return { loggedIn: false, googleConfigured: false, emailConfigured: false };
        }
      }
      function escapeClientHtml(value) {
        return String(value || '')
          .replace(/&/g, '&amp;')
          .replace(/</g, '&lt;')
          .replace(/>/g, '&gt;')
          .replace(/"/g, '&quot;')
          .replace(/'/g, '&#39;');
      }
      function publicSubmissionStatusLabel(status) {
        return {
          new: 'Alındı',
          reviewing: 'İnceleniyor',
          answered: 'Cevabınız hazır',
          closed: 'Kapandı'
        }[status] || 'Alındı';
      }
      function publicSubmissionDate(value) {
        var date = value ? new Date(value) : null;
        if (!date || !Number.isFinite(date.getTime())) return '';
        return date.toLocaleDateString('tr-TR', { day: '2-digit', month: 'long', year: 'numeric' });
      }
      function publicSubmissionCardHtml(item) {
        var answered = Boolean(item && item.answer_text);
        var unseen = answered && !item.user_seen_at;
        var question = escapeClientHtml(item.question || 'Soru metni');
        var answer = escapeClientHtml(item.answer_text || '');
        var created = publicSubmissionDate(item.created_at);
        var answeredAt = publicSubmissionDate(item.answered_at);
        return [
          '<article class="pa-user-question-card' + (unseen ? ' has-new-answer' : '') + '">',
          '  <div class="pa-user-question-head">',
          '    <span class="pa-user-question-status">' + escapeClientHtml(publicSubmissionStatusLabel(item.status)) + '</span>',
          unseen ? '    <span class="pa-new-answer-badge">Yeni cevap</span>' : '',
          '  </div>',
          '  <h3>' + question + '</h3>',
          created ? '  <p class="pa-user-question-date">Gönderim: ' + escapeClientHtml(created) + '</p>' : '',
          answered ? [
            '  <div class="pa-user-answer">',
            answeredAt ? '    <span>Cevap tarihi: ' + escapeClientHtml(answeredAt) + '</span>' : '',
            '    <p>' + answer.replace(/\\n{2,}/g, '</p><p>').replace(/\\n/g, '<br>') + '</p>',
            '  </div>',
            unseen ? '  <button type="button" class="pa-mini-action" data-mark-question-seen="' + escapeClientHtml(item.id) + '">Okundu olarak işaretle</button>' : ''
          ].join('') : '  <p class="pa-user-question-wait">Sorunuz ekibe ulaştı. Cevap hazırlandığında bu alanda görünecek.</p>',
          '</article>'
        ].join('');
      }
      function setAccountNoticeDot(count) {
        document.querySelectorAll('[data-account-notice-dot]').forEach(function(dot){
          var active = Number(count || 0) > 0;
          dot.hidden = !active;
          dot.setAttribute('aria-hidden', active ? 'false' : 'true');
        });
      }
      async function loadPublicUserQuestions(session) {
        var section = document.querySelector('[data-user-questions]');
        var list = document.querySelector('[data-user-questions-list]');
        if (!session || !session.loggedIn) {
          setAccountNoticeDot(0);
          if (section) section.hidden = true;
          return;
        }
        try {
          var response = await fetch('${PREVIEW_BASE}/api/my-question-submissions', { headers: { Accept: 'application/json' } });
          var data = await response.json().catch(function(){ return {}; });
          if (!response.ok || data.available === false) {
            setAccountNoticeDot(0);
            if (section && list) {
              section.hidden = false;
              list.innerHTML = '<div class="pa-mini-empty">' + escapeClientHtml(data.error || 'Sorularınız şu anda alınamadı.') + '</div>';
            }
            return;
          }
          var items = Array.isArray(data.submissions) ? data.submissions : [];
          var unseenCount = Number(data.unseenAnsweredCount || 0);
          setAccountNoticeDot(unseenCount);
          if (!section || !list) return;
          section.hidden = false;
          list.innerHTML = items.length
            ? items.map(publicSubmissionCardHtml).join('')
            : '<div class="pa-mini-empty">Henüz gönderdiğiniz soru yok.</div>';
          list.querySelectorAll('[data-mark-question-seen]').forEach(function(button){
            button.addEventListener('click', async function(){
              var id = button.getAttribute('data-mark-question-seen');
              if (!id) return;
              button.disabled = true;
              try {
                await fetch('${PREVIEW_BASE}/api/my-question-submissions/' + encodeURIComponent(id) + '/seen', {
                  method: 'POST',
                  headers: { Accept: 'application/json' }
                });
                await loadPublicUserQuestions(session);
              } catch (error) {
                button.disabled = false;
              }
            });
          });
        } catch (error) {
          setAccountNoticeDot(0);
          if (section && list) {
            section.hidden = false;
            list.innerHTML = '<div class="pa-mini-empty">Sorularınız şu anda alınamadı.</div>';
          }
        }
      }
      function renderSessionUi(session) {
        var status = document.querySelector('[data-account-status]');
        var actions = document.querySelector('[data-account-actions]');
        var authPanel = document.querySelector('[data-public-auth]');
        var googleButton = document.querySelector('[data-google-auth-button]');
        var askSession = document.querySelector('[data-ask-session]');
        if (status) {
          if (session.loggedIn && session.user) status.textContent = 'Oturum açık: ' + (session.user.name || session.user.email);
          else if (session.googleConfigured || session.emailConfigured) status.textContent = 'Soru göndermek için Google veya e-posta ile giriş yapabilirsiniz.';
          else status.textContent = 'Soru gönderimi için hesap hazırlığı tamamlanıyor. Arşivi incelemeye devam edebilirsiniz.';
        }
        if (actions && session.loggedIn) {
          actions.innerHTML = '<button class="pa-button is-secondary" type="button" data-public-logout>Çıkış Yap</button><a class="pa-button" href="${PREVIEW_BASE}/soru-sor">Soru Sor</a>';
        }
        if (authPanel) {
          if (session.loggedIn) authPanel.setAttribute('hidden', '');
          else authPanel.removeAttribute('hidden');
        }
        if (googleButton && !session.googleConfigured) {
          googleButton.setAttribute('aria-disabled', 'true');
          googleButton.classList.add('is-disabled');
          var googleText = googleButton.querySelector('span:last-child');
          if (googleText) googleText.textContent = 'Google hazırlığı bekleniyor';
          googleButton.addEventListener('click', function(event){ event.preventDefault(); });
        }
        document.querySelectorAll('[data-email-login-form], [data-email-register-form]').forEach(function(form){
          var disabled = session.emailConfigured === false;
          form.querySelectorAll('input, button').forEach(function(input){ input.disabled = disabled; });
          if (disabled) form.setAttribute('data-disabled', 'true');
          else form.removeAttribute('data-disabled');
        });
        if (authPanel) {
          if (session.emailConfigured === false) authPanel.setAttribute('data-email-disabled', 'true');
          else authPanel.removeAttribute('data-email-disabled');
        }
        if (askSession) {
          if (session.loggedIn && session.user) askSession.textContent = 'Sorunuz ' + (session.user.name || session.user.email) + ' hesabıyla kaydedilecek.';
          else if (session.googleConfigured || session.emailConfigured) askSession.innerHTML = 'Soru göndermek için önce <a href="${PREVIEW_BASE}/hesabim">hesabınızla oturum açın</a>.';
          else askSession.textContent = 'Soru gönderimi için hesap hazırlığı tamamlanıyor. Arşivi incelemeye devam edebilirsiniz.';
        }
        document.querySelectorAll('[data-public-logout]').forEach(function(button){
          button.addEventListener('click', async function(){
            await fetch('${PREVIEW_BASE}/auth/logout', { method: 'POST', headers: { Accept: 'application/json' } });
            window.location.href = '${PREVIEW_BASE}/hesabim';
          });
        });
      }
      function bindShrinkingHeader() {
        var root = document.documentElement;
        var update = function(){
          if (window.scrollY > 16) root.setAttribute('data-pa-scrolled', 'true');
          else root.removeAttribute('data-pa-scrolled');
        };
        update();
        window.addEventListener('scroll', update, { passive: true });
      }
      function bindPublicAuthTabs() {
        var panel = document.querySelector('[data-public-auth]');
        if (!panel) return;
        var tabs = Array.prototype.slice.call(panel.querySelectorAll('[data-auth-tab]'));
        var forms = Array.prototype.slice.call(panel.querySelectorAll('[data-auth-form]'));
        var setMode = function(mode){
          panel.setAttribute('data-auth-mode', mode);
          tabs.forEach(function(tab){
            var active = tab.getAttribute('data-auth-tab') === mode;
            tab.classList.toggle('is-active', active);
            tab.setAttribute('aria-selected', active ? 'true' : 'false');
          });
          forms.forEach(function(form){
            form.classList.toggle('is-active', form.getAttribute('data-auth-form') === mode);
          });
          var status = document.querySelector('[data-email-auth-status]');
          if (status) status.textContent = '';
        };
        tabs.forEach(function(tab){
          tab.addEventListener('click', function(){ setMode(tab.getAttribute('data-auth-tab') || 'login'); });
        });
        setMode(panel.getAttribute('data-auth-mode') || 'login');
      }
      function bindPublicEmailAuth() {
        document.querySelectorAll('[data-email-login-form], [data-email-register-form]').forEach(function(form){
          if (form.dataset.bound === 'true') return;
          form.dataset.bound = 'true';
          form.addEventListener('submit', async function(event){
            event.preventDefault();
            var status = document.querySelector('[data-email-auth-status]');
            var button = form.querySelector('button[type="submit"]');
            var isRegister = form.hasAttribute('data-email-register-form');
            var payload = {
              email: form.elements.email && form.elements.email.value,
              password: form.elements.password && form.elements.password.value
            };
            if (isRegister) payload.name = form.elements.name && form.elements.name.value;
            if (button) button.disabled = true;
            if (status) status.textContent = isRegister ? 'Hesabınız oluşturuluyor...' : 'Giriş yapılıyor...';
            try {
              var endpoint = form.getAttribute('data-auth-endpoint') || '${PREVIEW_BASE}/api/auth/email/' + (isRegister ? 'register' : 'login');
              var response = await fetch(endpoint, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
                body: JSON.stringify(payload)
              });
              var data = await response.json().catch(function(){ return {}; });
              if (!response.ok) {
                if (status) status.textContent = data.error || 'İşlem tamamlanamadı.';
                return;
              }
              if (status) status.textContent = 'Oturum açıldı. Yönlendiriliyorsunuz...';
              window.location.href = '${PREVIEW_BASE}/hesabim';
            } catch (error) {
              if (status) status.textContent = 'Bağlantı kurulamadı. Lütfen tekrar deneyin.';
            } finally {
              if (button) button.disabled = false;
            }
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
            category: '',
            topic: '',
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
                if (status) status.innerHTML = 'Soru göndermek için önce <a href="${PREVIEW_BASE}/hesabim">hesabınızla oturum açın</a>.';
              } else if (status) status.textContent = data.error || 'Soru kaydedilemedi.';
              return;
            }
            form.reset();
            if (status) status.textContent = 'Sorunuz kaydedildi. Teşekkür ederiz.';
          } catch (error) {
            if (status) status.textContent = 'Bağlantı kurulamadı. Lütfen tekrar deneyin.';
          } finally {
            if (button) button.disabled = false;
          }
        });
      }
      function bindFastPublicNavigation() {
        var root = document.documentElement;
        var ttl = 2 * 60 * 1000;
        var cachePrefix = 'dsca-page-cache:v5:';
        var inflight = {};
        function cleanPath(pathname) {
          return String(pathname || '/').replace(/\\/+$/, '') || '/';
        }
        function isSafeRoute(url) {
          if (!url || url.origin !== window.location.origin) return false;
          var path = cleanPath(url.pathname);
          var base = '${PREVIEW_BASE}' || '';
          if (base && !path.startsWith(base)) return false;
          var relative = base ? cleanPath(path.slice(base.length) || '/') : path;
          if (relative.startsWith('/api') || relative.startsWith('/auth') || relative.startsWith('/assets')) return false;
          if (/\\.(png|jpe?g|webp|svg|ico|css|js|json|xml|txt)$/i.test(relative)) return false;
          return true;
        }
        function isFastLink(anchor) {
          if (!anchor || anchor.target || anchor.hasAttribute('download')) return false;
          if (anchor.closest('[data-no-fast-nav], [data-share], [data-copy-link]')) return false;
          try {
            var url = new URL(anchor.href, window.location.href);
            if (!isSafeRoute(url)) return false;
            if (url.pathname === window.location.pathname && url.search === window.location.search && url.hash) return false;
            return Boolean(anchor.closest('.pa-mobile-nav, .pa-desktop-nav, .pa-footer-links, .pa-logo, .pa-archive-cta, .pa-section-link') || anchor.classList.contains('pa-button') || anchor.classList.contains('pa-question-title') || anchor.classList.contains('pa-card-cta'));
          } catch (error) {
            return false;
          }
        }
        function cacheKey(url) {
          return cachePrefix + url.pathname + url.search;
        }
        function readCached(url) {
          try {
            var raw = window.sessionStorage.getItem(cacheKey(url));
            if (!raw) return '';
            var item = JSON.parse(raw);
            if (!item || !item.html || Date.now() - Number(item.time || 0) > ttl) {
              window.sessionStorage.removeItem(cacheKey(url));
              return '';
            }
            return String(item.html || '');
          } catch (error) {
            return '';
          }
        }
        function writeCached(url, html) {
          if (!html || !/<html[\\s>]/i.test(html)) return;
          try {
            window.sessionStorage.setItem(cacheKey(url), JSON.stringify({ time: Date.now(), html: html }));
          } catch (error) {}
        }
        function fetchPage(url) {
          var cached = readCached(url);
          if (cached) return Promise.resolve(cached);
          var key = cacheKey(url);
          if (inflight[key]) return inflight[key];
          inflight[key] = fetch(url.href, {
            credentials: 'same-origin',
            headers: { Accept: 'text/html', 'X-Public-Navigation': 'prefetch' }
          }).then(function(response){
            var type = response.headers.get('content-type') || '';
            if (!response.ok || !type.includes('text/html')) throw new Error('Sayfa alınamadı');
            return response.text();
          }).then(function(html){
            writeCached(url, html);
            return html;
          }).finally(function(){
            delete inflight[key];
          });
          return inflight[key];
        }
        function pageStack() {
          return window['his' + 'tory'];
        }
        function setPending(anchor, url) {
          root.setAttribute('data-pa-navigating', 'true');
          document.querySelectorAll('.pa-bottom-link, .pa-desktop-nav a').forEach(function(link){
            link.classList.remove('is-pending');
            try {
              var linkUrl = new URL(link.href, window.location.href);
              var active = cleanPath(linkUrl.pathname) === cleanPath(url.pathname);
              link.classList.toggle('is-active', active);
            } catch (error) {}
          });
          if (anchor) anchor.classList.add('is-pending');
        }
        function replaceDocument(url, html, mode) {
          if (!html || !/<html[\\s>]/i.test(html)) {
            window.location.href = url.href;
            return;
          }
          if (mode === 'push') pageStack().pushState({ paFast: true }, '', url.href);
          else if (mode === 'replace') pageStack().replaceState({ paFast: true }, '', url.href);
          document.open();
          document.write(html);
          document.close();
        }
        function prefetch(anchor) {
          if (!isFastLink(anchor)) return;
          try {
            var url = new URL(anchor.href, window.location.href);
            if (readCached(url)) return;
            fetchPage(url).catch(function(){});
          } catch (error) {}
        }
        function navigate(anchor, event) {
          if (!isFastLink(anchor)) return;
          if (event.metaKey || event.ctrlKey || event.shiftKey || event.altKey || event.button > 0) return;
          event.preventDefault();
          var url = new URL(anchor.href, window.location.href);
          setPending(anchor, url);
          fetchPage(url).then(function(html){
            replaceDocument(url, html, 'push');
          }).catch(function(){
            window.location.href = url.href;
          });
        }
        document.querySelectorAll('a[href]').forEach(function(anchor){
          if (!isFastLink(anchor)) return;
          anchor.addEventListener('pointerenter', function(){ prefetch(anchor); }, { passive: true });
          anchor.addEventListener('focus', function(){ prefetch(anchor); }, { passive: true });
          anchor.addEventListener('touchstart', function(){ prefetch(anchor); }, { passive: true });
          anchor.addEventListener('click', function(event){ navigate(anchor, event); });
        });
        var warm = function(){
          document.querySelectorAll('.pa-mobile-nav a[href], .pa-desktop-nav a[href]').forEach(prefetch);
        };
        if ('requestIdleCallback' in window) window.requestIdleCallback(warm, { timeout: 1200 });
        else window.setTimeout(warm, 700);
        try { pageStack().replaceState({ paFast: true }, '', window.location.href); } catch (error) {}
        window.addEventListener('popstate', function(){
          var url = new URL(window.location.href);
          if (!isSafeRoute(url)) return;
          root.setAttribute('data-pa-navigating', 'true');
          fetchPage(url).then(function(html){
            replaceDocument(url, html, 'none');
          }).catch(function(){
            window.location.reload();
          });
        });
      }
      loadReadCounts();
      trackQuestionRead();
      trackPublicVisit();
      bindConceptSliders();
      bindActiveStatsCounters();
      bindScrollTopControl();
      bindShrinkingHeader();
      bindPublicAuthTabs();
      bindPublicEmailAuth();
      bindFastPublicNavigation();
      loadPublicSession().then(function(session){
        renderSessionUi(session);
        loadPublicUserQuestions(session);
      });
      bindQuestionForm();
    })();
  </script>
</body>
</html>`
  };
}

function renderPublicArchivePreviewRoute(routePath, query = {}, archiveData = publicArchiveFixtures) {
  return withPublicArchiveData(archiveData, () => {
    const pathname = String(routePath || '').replace(/\/+$/, '') || publicArchiveHomeHref();
    if (pathname === publicArchiveHomeHref()) return renderHome();
    if (pathname === `${PREVIEW_BASE}/arsiv`) return renderArchive(query);
    if (pathname === `${PREVIEW_BASE}/arama`) return renderSearch(query.q || '');
    if (pathname === `${PREVIEW_BASE}/konular`) return renderTopicsIndex();
    if (pathname === `${PREVIEW_BASE}/kategoriler`) return renderCategoriesIndex();
    if (pathname === `${PREVIEW_BASE}/hesabim`) return renderAccount();
    if (pathname === `${PREVIEW_BASE}/soru-sor`) return renderAsk();
    if (pathname === `${PREVIEW_BASE}/hakkimizda`) return renderInfoPage('hakkimizda');
    if (pathname === `${PREVIEW_BASE}/nasil-kullanilir`) return renderInfoPage('nasil-kullanilir');
    if (pathname === `${PREVIEW_BASE}/iletisim`) return renderInfoPage('iletisim');
    if (pathname === `${PREVIEW_BASE}/gizlilik`) return renderInfoPage('gizlilik');
    if (pathname === `${PREVIEW_BASE}/kullanim-kosullari`) return renderInfoPage('kullanim-kosullari');
    const questionMatch = pathname.match(publicArchiveRoutePattern('soru'));
    if (questionMatch) return renderQuestion(questionMatch[1]);
    const topicMatch = pathname.match(publicArchiveRoutePattern('konu'));
    if (topicMatch) return renderTopic(topicMatch[1], query);
    const categoryMatch = pathname.match(publicArchiveRoutePattern('kategori'));
    if (categoryMatch) return renderCategory(categoryMatch[1], query);
    return renderNotFound();
  });
}

function sendRendered(res, rendered) {
  res.status(rendered.status || 200).type('html').send(rendered.html);
}

function createPublicArchivePreviewRouter(options = {}) {
  const router = express.Router();
  const basePath = normalizePublicArchiveBasePath(options.basePath ?? DEFAULT_PUBLIC_ARCHIVE_BASE);
  const noindex = options.noindex !== false;
  const cssFile = options.cssFile || path.join(__dirname, 'public-archive.css');
  const assetDir = options.assetDir || path.join(__dirname, 'public-archive-assets', 'assets');
  const loadArchiveData = typeof options.loadArchiveData === 'function'
    ? options.loadArchiveData
    : async () => publicArchiveFixtures;
  function routeFor(pathname = '') {
    const clean = String(pathname || '').replace(/^\/+|\/+$/g, '');
    return clean ? `${basePath}/${clean}` || `/${clean}` : (basePath || '/');
  }
  function dataRouteFor(pathname = '') {
    const clean = String(pathname || '').replace(/^\/+|\/+$/g, '');
    return clean ? `${DEFAULT_PUBLIC_ARCHIVE_BASE}/${clean}` : DEFAULT_PUBLIC_ARCHIVE_BASE;
  }
  async function sendRoute(req, res, next, routePath, query = {}) {
    try {
      const archiveData = await loadArchiveData(req, dataRouteFor(routePath), query);
      sendRendered(res, renderPublicArchivePreviewRoute(routeFor(routePath), query, {
        ...(archiveData || {}),
        basePath,
        noindex
      }));
    } catch (error) {
      next(error);
    }
  }
  router.use((req, res, next) => {
    if (noindex) {
      res.set('X-Robots-Tag', 'noindex, nofollow');
      res.set('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate');
    }
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
  router.get(['/', ''], (req, res, next) => sendRoute(req, res, next, ''));
  router.get('/arsiv', (req, res, next) => sendRoute(req, res, next, 'arsiv', {
    harf: req.query.harf || '',
    kategori: req.query.kategori || '',
    kategoriAra: req.query.kategoriAra || '',
    sayfa: req.query.sayfa || ''
  }));
  router.get('/arama', (req, res, next) => sendRoute(req, res, next, 'arama', { q: req.query.q || '' }));
  router.get('/konular', (req, res, next) => sendRoute(req, res, next, 'konular'));
  router.get('/kategoriler', (req, res, next) => sendRoute(req, res, next, 'kategoriler'));
  router.get('/hesabim', (req, res, next) => sendRoute(req, res, next, 'hesabim'));
  router.get('/soru-sor', (req, res, next) => sendRoute(req, res, next, 'soru-sor'));
  router.get('/hakkimizda', (req, res, next) => sendRoute(req, res, next, 'hakkimizda'));
  router.get('/nasil-kullanilir', (req, res, next) => sendRoute(req, res, next, 'nasil-kullanilir'));
  router.get('/iletisim', (req, res, next) => sendRoute(req, res, next, 'iletisim'));
  router.get('/gizlilik', (req, res, next) => sendRoute(req, res, next, 'gizlilik'));
  router.get('/kullanim-kosullari', (req, res, next) => sendRoute(req, res, next, 'kullanim-kosullari'));
  router.get('/soru/:slug', (req, res, next) => sendRoute(req, res, next, `soru/${req.params.slug}`));
  router.get('/konu/:slug', (req, res, next) => sendRoute(req, res, next, `konu/${req.params.slug}`, { sayfa: req.query.sayfa || '' }));
  router.get('/kategori/:slug', (req, res, next) => sendRoute(req, res, next, `kategori/${req.params.slug}`, { sayfa: req.query.sayfa || '' }));
  router.use((req, res, next) => sendRoute(req, res, next, 'bulunamadi'));
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
