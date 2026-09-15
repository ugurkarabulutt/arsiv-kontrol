const express = require('express');
const fs = require('fs');
const path = require('path');
const { publicArchiveFixtures } = require('./public-archive-fixtures');
const publicArchiveTopicArticles = require('./public-archive-topic-articles.json');

const DEFAULT_PUBLIC_ARCHIVE_BASE = '/public-preview';
let PREVIEW_BASE = DEFAULT_PUBLIC_ARCHIVE_BASE;
let CSS_PATH = `${PREVIEW_BASE}/public-archive.css`;
let ASSET_PATH = `${PREVIEW_BASE}/assets`;
let PUBLIC_ARCHIVE_NOINDEX = true;
const ICON_DIR = path.join(__dirname, 'public-archive-assets', 'icons');
const ARCHIVE_PAGE_SIZE = 30;
const PUBLIC_ARCHIVE_CANONICAL_ORIGIN = 'https://arsiv.ibrahimlive.ai';
const PUBLIC_ARCHIVE_HTML_CACHE = 'public, max-age=0, s-maxage=300, stale-while-revalidate=1800';
const PUBLIC_ARCHIVE_STATIC_CACHE = 'public, max-age=31536000, immutable';
const PUBLIC_SHARE_IMAGE_FILE = 'public-share-card-20260823-v3.png';
const PUBLIC_SHARE_IMAGE_VERSION = 'telegram-cache-refresh-20260823';
const PUBLIC_SHARE_UPDATED_TIME = '2026-08-23T14:42:53+03:00';
const PUBLIC_ARCHIVE_ASSET_VERSION = '20260915-popular-fast-nav-v1';
const PUBLIC_CATEGORY_INDEX_MIN_QUESTIONS = 5;
const PUBLIC_TOPIC_GUIDE_PATH = '/konu-rehberi';
const PUBLIC_ARCHIVE_SEO_TITLE_MAX = 76;
const PUBLIC_ARCHIVE_SEO_DESCRIPTION_MAX = 168;
const PUBLIC_ARCHIVE_CORE_TOPIC_NAMES = [
  'Hidayet',
  'Mürşid',
  'Zikir',
  'Takva',
  'Nefs tezkiyesi',
  'Allah’a ulaşmayı dilemek',
  'Teslimiyet',
  'Kur’ân ayetleri'
];
const PUBLIC_CATEGORY_SEO_SLUGS = new Set([
  'allaha-ulasmayi-dilemek',
  'mursid',
  'hidayet',
  'zikir',
  'takva',
  'tabiiyet',
  'nefs',
  'ruh',
  'teslimiyet'
]);

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

function publicTopicArticleBySlug(slug = '') {
  return publicArchiveTopicArticles[String(slug || '').trim()] || null;
}

function publicTopicArticlePath(article = {}) {
  const explicitPath = String(article.path || '').trim();
  if (explicitPath) return explicitPath.startsWith('/') ? explicitPath : `/${explicitPath}`;
  return `${PUBLIC_TOPIC_GUIDE_PATH}/${String(article.slug || '').trim()}`;
}

function publicArchiveAssetHref(filename) {
  return `${ASSET_PATH}/${filename}?v=${PUBLIC_ARCHIVE_ASSET_VERSION}`;
}

function publicArchiveAssetUrl(filename) {
  return publicArchiveCanonicalUrl(`/assets/${filename}`);
}

function publicArchiveShareImageUrl() {
  return `${publicArchiveAssetUrl(PUBLIC_SHARE_IMAGE_FILE)}?v=${PUBLIC_SHARE_IMAGE_VERSION}`;
}

function publicArchiveRoutePattern(section = '') {
  const escapedBase = PREVIEW_BASE.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  return new RegExp(`^${escapedBase}/${section}/([^/]+)$`);
}

function setPublicArchiveRuntime({ basePath = DEFAULT_PUBLIC_ARCHIVE_BASE, noindex = true } = {}) {
  PREVIEW_BASE = normalizePublicArchiveBasePath(basePath);
  CSS_PATH = `${publicArchivePath('public-archive.css')}?v=${PUBLIC_ARCHIVE_ASSET_VERSION}`;
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
    dataUnavailable: archiveData.dataUnavailable === true,
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
    dataUnavailable: publicArchiveFixtures.dataUnavailable,
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
  publicArchiveFixtures.dataUnavailable = next.dataUnavailable;
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
    publicArchiveFixtures.dataUnavailable = previous.dataUnavailable;
    setPublicArchiveRuntime({ basePath: previous.basePath, noindex: previous.noindex });
  }
}

const ROUTE_PATHS = [
  PREVIEW_BASE,
  `${PREVIEW_BASE}/arsiv`,
  `${PREVIEW_BASE}/one-cikan-sorular`,
  `${PREVIEW_BASE}/son-yayinlanan-sorular`,
  `${PREVIEW_BASE}/cok-okunan-cevaplar`,
  `${PREVIEW_BASE}/arama`,
  `${PREVIEW_BASE}${PUBLIC_TOPIC_GUIDE_PATH}/allaha-ulasmayi-dilemek`,
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

function publicArchiveComparable(value = '') {
  return String(value || '')
    .replace(/\u00A0/g, ' ')
    .replace(/[’‘`´]/g, "'")
    .replace(/[“”]/g, '"')
    .toLocaleLowerCase('tr-TR')
    .normalize('NFKD')
    .replace(/[\u0300-\u036f]/g, '')
    .replace(/[^\p{L}\p{N}]+/gu, ' ')
    .replace(/\s+/g, ' ')
    .trim();
}

function questionTextIdentity(entry = {}) {
  return publicArchiveComparable(entry.question || entry.title || '');
}

function asPublicCategory(item) {
  if (!item) return null;
  return {
    id: item.id || `category-${item.slug}`,
    slug: item.slug,
    name: item.name,
    description: item.description || `${item.name} hakkında dini soru ve cevaplar; ilgili ayet delilleri, kavram bağlantıları ve kaynak bağlamıyla birlikte okunur.`,
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
  return uniquePublicArchiveQuestionResults(publicArchiveFixtures.qa.filter(entry => (entry.topicSlugs || []).includes(slug)));
}

function entriesForCategory(slug) {
  return uniquePublicArchiveQuestionResults(publicArchiveFixtures.qa.filter(entry => categorySlugsFor(entry).includes(slug)));
}

function categoryQuestionCount(category) {
  const count = Number(category?.questionCount ?? category?.question_count);
  return Number.isFinite(count) && count > 0 ? Math.round(count) : entriesForCategory(category?.slug).length;
}

function publicCategorySeoIndexable(category, explicitCount = null) {
  const count = Number(explicitCount);
  const questionCount = Number.isFinite(count) && count >= 0 ? Math.round(count) : categoryQuestionCount(category);
  return questionCount >= PUBLIC_CATEGORY_INDEX_MIN_QUESTIONS || PUBLIC_CATEGORY_SEO_SLUGS.has(String(category?.slug || ''));
}

function relatedEntries(entry) {
  const currentQuestion = questionTextIdentity(entry);
  const seenQuestions = new Set([currentQuestion].filter(Boolean));
  return (entry.relatedSlugs || [])
    .map(slug => bySlug(publicArchiveFixtures.qa, slug))
    .filter(item => {
      if (!item || item.slug === entry.slug) return false;
      const identity = questionTextIdentity(item);
      if (identity && seenQuestions.has(identity)) return false;
      if (identity) seenQuestions.add(identity);
      return true;
    })
    .slice(0, 6);
}

function sideQuestionLink(item) {
  return `
    <a class="pa-side-question-link" href="${PREVIEW_BASE}/soru/${escapeHtml(item.slug)}">
      <strong class="pa-side-question-title">${escapeHtml(item.title)}</strong>
      <span class="pa-side-question-bottom">
        <span class="pa-side-question-meta">${readCountLabel(item.readCount || 0)}</span>
        <span class="pa-side-question-cta">Cevabı oku ${iconSvg('arrow-right', 'pa-cta-icon')}</span>
      </span>
    </a>
  `;
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
  const cleanTitle = compactSeoText(title, PUBLIC_ARCHIVE_SEO_TITLE_MAX);
  if (!cleanTitle || cleanTitle === 'Ana Sayfa' || cleanTitle === brand) return brand;
  const branded = `${cleanTitle} | ${brand}`;
  return branded.length <= PUBLIC_ARCHIVE_SEO_TITLE_MAX ? branded : cleanTitle;
}

function compactSeoText(value, maxLength = PUBLIC_ARCHIVE_SEO_DESCRIPTION_MAX) {
  const clean = plainText(value);
  const limit = Number(maxLength);
  if (!clean || !Number.isFinite(limit) || clean.length <= limit) return clean;
  const sliceLimit = Math.max(12, limit - 1);
  const clipped = clean.slice(0, sliceLimit);
  const breakpoints = ['? ', '. ', '! ', '; ', ': ', ', ', ' ']
    .map(token => clipped.lastIndexOf(token))
    .filter(index => index > Math.floor(limit * 0.55));
  const end = breakpoints.length ? Math.max(...breakpoints) + 1 : sliceLimit;
  return `${clipped.slice(0, end).replace(/[,:;.\s]+$/u, '')}…`;
}

function readableStructuredText(value) {
  if (Array.isArray(value)) return value.map(plainText).filter(Boolean).join('\n\n');
  return String(value || '')
    .replace(/\r\n/g, '\n')
    .replace(/[ \t]+/g, ' ')
    .replace(/\n{3,}/g, '\n\n')
    .trim();
}

function publicArchiveDateIso(value) {
  if (!value) return '';
  const date = new Date(value);
  return Number.isFinite(date.getTime()) ? date.toISOString() : '';
}

function publicArchivePublisher() {
  return {
    '@type': 'Organization',
    '@id': `${publicArchiveCanonicalUrl('/')}#organization`,
    name: publicArchiveFixtures.brand.name,
    url: publicArchiveCanonicalUrl('/'),
    knowsAbout: PUBLIC_ARCHIVE_CORE_TOPIC_NAMES.map(name => ({ '@type': 'Thing', name })),
    logo: {
      '@type': 'ImageObject',
      url: publicArchiveAssetUrl('app-icon-512.png'),
      width: 512,
      height: 512
    },
    image: publicArchiveShareImageUrl()
  };
}

function publicArchiveAnswerAuthor() {
  const name = publicArchiveFixtures.brand.authorName || publicArchiveFixtures.brand.answererLabel || '';
  return name
    ? {
        '@type': 'Person',
        '@id': `${publicArchiveCanonicalUrl('/')}#dr-abdulcabbar-boran`,
        name
      }
    : publicArchivePublisher();
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
      const openTag = '<svg class=\"' + className + '\" aria-hidden=\"true\" focusable=\"false\" width=\"1em\" height=\"1em\" ';
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

function previewActionNavIndex(active) {
  return Math.max(0, ['home', 'archive', 'search', 'ask'].indexOf(active));
}

function brandLogo() {
  const logoText = publicArchiveFixtures.brand.logoLines.map(line => `<span>${escapeHtml(line)}</span>`).join('');
  return `
    <img class="pa-logo-mark" src="${publicArchiveAssetHref('arsiv-logo-mark.png')}" alt="" aria-hidden="true" width="256" height="256" decoding="async">
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
        <a class="pa-account-button${active === 'account' ? ' is-active' : ''}" href="${PREVIEW_BASE}/hesabim" aria-label="Hesab\u0131m" data-account-button>
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
    <div class="pa-live-search" data-live-search>
      <form class="pa-search" action="${PREVIEW_BASE}/arama" method="get" role="search" id="arama" data-live-search-form data-live-search-url="${PREVIEW_BASE}/api/public-search">
        <label class="pa-sr-only" for="pa-search-input">${escapeHtml(label)}</label>
        <span class="pa-search-leading">${iconSvg('search')}</span>
        <input id="pa-search-input" name="q" value="${escapeHtml(value)}" placeholder="" autocomplete="off" inputmode="search" enterkeyhint="search" aria-label="Sorunuzu veya kategorinizi yazın" aria-controls="pa-live-search-results" aria-expanded="false">
        <span class="pa-search-typehint" data-live-search-hint aria-hidden="true">Soru veya kategori arayın...</span>
        <button type="submit" aria-label="Ara">
          <span class="pa-search-icon">${iconSvg('arrow-right')}</span>
        </button>
      </form>
      <div class="pa-live-search-panel" id="pa-live-search-results" data-live-search-panel hidden aria-live="polite"></div>
    </div>
  `;
}

function stillLife() {
  return `
    <div class="pa-still-life" aria-hidden="true">
      <picture class="pa-hero-asset pa-hero-asset-book">
        <img src="${publicArchiveAssetHref('hero-open-book-warm.jpg')}" alt="" width="1280" height="1024" loading="eager" fetchpriority="high" decoding="async">
      </picture>
    </div>
  `;
}

function sectionHeader(title, actionText, actionHref) {
  return `
    <div class="pa-section-head">
      <h2>${escapeHtml(title)}</h2>
      ${actionHref ? `<a href="${escapeHtml(actionHref)}" data-prefetch-priority="true">${escapeHtml(actionText || 'Tümünü Gör')} ${iconSvg('chevron-right', 'pa-inline-chevron')}</a>` : ''}
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

const HOME_READING_PATHS = [
  { title: 'Allah’a Ulaşmayı Dilemek', slug: 'allaha-ulasmayi-dilemek', articleSlug: 'allaha-ulasmayi-dilemek', text: 'Yolun başlangıcı, talep ve kalbin yönelişi.' },
  { title: 'Hidayet Nedir?', slug: 'hidayet', articleSlug: 'hidayet', text: 'Hidayetin anlamı, başlangıcı ve hayattaki karşılığı.' },
  { title: 'Mürşide Tâbiiyet', slug: 'tabiiyet', articleSlug: 'murside-tabiiyet', fallbackSlug: 'mursid', text: 'Tâbiiyet, mürşid ve irşad bağıyla ilgili cevaplar.' },
  { title: 'Zikir Nedir?', slug: 'zikir', articleSlug: 'zikir-ve-daimi-zikir', text: 'Zikrin sürekliliği ve kalbin diri tutulması.' },
  { title: 'Nefs Tezkiyesi', slug: 'nefs-tezkiyesi', fallbackSlug: 'nefs', text: 'Nefsin arınması ve manevi dönüşüm.' },
  { title: 'Ruhun Allah’a Ulaşması', slug: 'ruh', text: 'Ruhun teslimi ve Allah’a yöneliş merhaleleri.' },
  { title: 'Teslimiyet', slug: 'teslimiyet', text: 'Teslim, tevekkül ve irade başlıklarının birlikte okunması.' },
  { title: 'Takva', slug: 'takva', text: 'Korunma, sakınma ve Allah’a yakınlık arayışı.' },
  { title: 'Tövbe ve Günahlardan Kurtuluş', slug: 'tovbe', query: 'Tövbe günahlardan kurtuluş', text: 'Tövbe, arınma ve yeniden istikamet bulma soruları.' },
  { title: 'Dua ve Tevekkül', slug: 'dua', query: 'Dua tevekkül', text: 'Talep, teslim ve sonucu Allah’a bırakma dengesi.' },
  { title: 'Namaz ve İbadet Bilinci', slug: 'namaz', query: 'Namaz ibadet bilinci', text: 'İbadetin şuuruyla ilgili soru ve cevaplar.' },
  { title: 'Kur’ân’da Hidayet Ayetleri', slug: 'hidayet', query: 'Kur’ân hidayet ayetleri', text: 'Hidayet konusunun ayet atıflarıyla takip edilmesi.' }
];

function conceptSliderItems(isClone = false) {
  const disabled = publicArchiveFixtures.dataUnavailable === true;
  return HERO_CONCEPT_ITEMS.map(([label, slug]) => `
    ${disabled ? `<span class="pa-concept-pill"${isClone ? ' aria-hidden="true"' : ''}>` : `<a class="pa-concept-pill" href="${PREVIEW_BASE}/kategori/${escapeHtml(slug)}"${isClone ? ' tabindex="-1" aria-hidden="true"' : ''}>`}
      <span>${escapeHtml(label)}</span>
    ${disabled ? '</span>' : '</a>'}
  `).join('');
}

function heroConceptLane() {
  return `
    <div class="pa-hero-concepts" data-concept-slider aria-label="Öne çıkan kategoriler">
      <div class="pa-concept-head">
        <span>Öne çıkan kategoriler</span>
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

function categoryEvidenceReferences(entries = [], limit = 12) {
  const counts = new Map();
  for (const entry of entries || []) {
    for (const reference of extractQuranReferences(entry)) {
      const key = reference.label;
      const current = counts.get(key) || { ...reference, count: 0 };
      current.count += 1;
      counts.set(key, current);
    }
  }
  return [...counts.values()]
    .sort((a, b) => Number(b.count || 0) - Number(a.count || 0) || String(a.label).localeCompare(String(b.label), 'tr'))
    .slice(0, limit);
}

function categoryEvidencePanel(category, entries = []) {
  const references = categoryEvidenceReferences(entries, 12);
  if (!references.length) return '';
  return `
    <aside class="pa-source-box pa-category-evidence" aria-label="${escapeHtml(category?.name || 'Kategori')} delil atıfları">
      <h2>Bu sayfadaki delil atıfları</h2>
      <p>Bu sayfada listelenen cevaplarda açıkça adı geçen ayet atıfları:</p>
      <div class="pa-source-references">
        ${references.map(reference => {
          const href = `${PREVIEW_BASE}/arama?q=${encodeURIComponent(reference.label)}`;
          return `<a class="pa-source-reference" href="${escapeHtml(href)}">${escapeHtml(reference.label)}</a>`;
        }).join('')}
      </div>
    </aside>
  `;
}

function plainText(value) {
  if (Array.isArray(value)) return value.map(plainText).filter(Boolean).join('\n\n');
  return String(value || '').replace(/\s+/g, ' ').trim();
}

function inlineJson(data) {
  return JSON.stringify(data).replace(/</g, '\\u003c');
}

const LIVE_SEARCH_EXAMPLES = [
  'Mürşid farz mıdır?',
  'Hidayet nedir?',
  'Nefs tezkiyesi nasıl yapılır?',
  'Zikir nedir?',
  'Takva sahibi nasıl olunur?'
];

function publicArchiveLiveSearchSeed(entries = [], categories = [], options = {}) {
  const categoryMap = new Map();
  for (const category of categories || []) {
    if (!category?.slug || !category?.name) continue;
    categoryMap.set(category.slug, {
      slug: category.slug,
      title: category.name,
      subtitle: `${archiveCountLabel(categoryQuestionCount(category))} ilgili soru`,
      count: categoryQuestionCount(category),
      text: plainText([category.name, category.slug, category.description].join(' '))
    });
  }
  if (options.includeHeroConcepts === true) {
    for (const [title, slug] of HERO_CONCEPT_ITEMS) {
      if (!categoryMap.has(slug)) {
        categoryMap.set(slug, {
          slug,
          title,
          subtitle: 'Öne çıkan konu',
          count: 0,
          text: `${title} ${slug}`
        });
      }
    }
  }
  const seenQuestions = new Set();
  const questions = [];
  for (const entry of entries || []) {
    if (!entry?.slug) continue;
    const key = questionTextIdentity(entry);
    if (key && seenQuestions.has(key)) continue;
    if (key) seenQuestions.add(key);
    const categoryNames = categoriesFor(entry).map(category => category.name).filter(Boolean).join(' ');
    questions.push({
      slug: entry.slug,
      title: plainText(entry.title || entry.question).replace(/^\s*\d+\.\s*Soru:\s*/iu, '').slice(0, 180),
      subtitle: [categoryNames.split(' ').slice(0, 5).join(' '), readCountLabel(normalizedReadCount(entry))].filter(Boolean).join(' - '),
      count: normalizedReadCount(entry),
      text: plainText([entry.title, entry.question, categoryNames].join(' ')).slice(0, 900)
    });
    if (questions.length >= 90) break;
  }
  return {
    examples: LIVE_SEARCH_EXAMPLES,
    categories: [...categoryMap.values()]
      .sort((a, b) => Number(b.count || 0) - Number(a.count || 0) || String(a.title || '').localeCompare(String(b.title || ''), 'tr'))
      .slice(0, 140),
    questions
  };
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
    image: publicArchiveShareImageUrl(),
    publisher: { '@id': `${publicArchiveCanonicalUrl('/')}#organization` },
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

function publicArchiveOrganizationStructuredData() {
  return {
    '@context': 'https://schema.org',
    ...publicArchivePublisher()
  };
}

function publicArchiveReferenceStructuredData(label) {
  return {
    '@type': 'CreativeWork',
    name: label,
    isPartOf: {
      '@type': 'Book',
      name: 'Kur’an-ı Kerîm'
    }
  };
}

function collectionPageStructuredData({ canonicalPath, title, description, entries = [], category = null, total = 0, breadcrumbItems = [], references = [] } = {}) {
  const canonicalUrl = publicArchiveCanonicalUrl(canonicalPath || '/');
  const cleanTitle = compactSeoText(title, PUBLIC_ARCHIVE_SEO_TITLE_MAX);
  const cleanDescription = compactSeoText(description || publicArchiveFixtures.brand.sentence);
  const referenceMentions = seoList(references, 12).map(publicArchiveReferenceStructuredData);
  const itemListElement = (entries || [])
    .filter(entry => entry?.slug)
    .slice(0, 20)
    .map((entry, index) => ({
      '@type': 'ListItem',
      position: index + 1,
      url: publicArchiveCanonicalUrl(`/soru/${entry.slug}`),
      name: compactSeoText(entry.title || entry.question, 110)
    }));
  const graph = [
    {
      '@type': 'CollectionPage',
      '@id': `${canonicalUrl}#webpage`,
      url: canonicalUrl,
      name: cleanTitle,
      description: cleanDescription,
      inLanguage: 'tr',
      isPartOf: { '@id': `${publicArchiveCanonicalUrl('/')}#website` },
      publisher: { '@id': `${publicArchiveCanonicalUrl('/')}#organization` },
      about: category?.name ? { '@type': 'Thing', name: category.name } : undefined,
      mentions: [
        ...(category?.name ? [{ '@type': 'Thing', name: category.name }] : []),
        ...referenceMentions
      ],
      mainEntity: {
        '@type': 'ItemList',
        '@id': `${canonicalUrl}#itemlist`,
        name: cleanTitle,
        numberOfItems: Number(total || entries.length || itemListElement.length) || itemListElement.length,
        itemListElement
      }
    }
  ];
  const filteredBreadcrumbItems = (breadcrumbItems || []).filter(Boolean);
  if (filteredBreadcrumbItems.length) {
    graph.push({
      '@type': 'BreadcrumbList',
      '@id': `${canonicalUrl}#breadcrumb`,
      itemListElement: filteredBreadcrumbItems.map((item, index) => ({
        '@type': 'ListItem',
        position: index + 1,
        name: item.name,
        item: item.url
      }))
    });
  }
  return {
    '@context': 'https://schema.org',
    '@graph': graph
  };
}

function categoryIndexStructuredData({ categories = [], title = 'Dini Soru Kategorileri', description = '' } = {}) {
  const canonicalUrl = publicArchiveCanonicalUrl('/kategoriler');
  const cleanTitle = compactSeoText(title, PUBLIC_ARCHIVE_SEO_TITLE_MAX);
  const cleanDescription = compactSeoText(description || publicArchiveFixtures.brand.sentence);
  const itemListElement = (categories || [])
    .filter(category => category?.slug && category?.name)
    .slice(0, 60)
    .map((category, index) => ({
      '@type': 'ListItem',
      position: index + 1,
      url: publicArchiveCanonicalUrl(`/kategori/${category.slug}`),
      name: category.name,
      description: categorySeoDescription(category, categoryQuestionCount(category))
    }));
  return {
    '@context': 'https://schema.org',
    '@graph': [
      {
        '@type': 'CollectionPage',
        '@id': `${canonicalUrl}#webpage`,
        url: canonicalUrl,
        name: cleanTitle,
        description: cleanDescription,
        inLanguage: 'tr',
        isPartOf: { '@id': `${publicArchiveCanonicalUrl('/')}#website` },
        publisher: { '@id': `${publicArchiveCanonicalUrl('/')}#organization` },
        mainEntity: {
          '@type': 'ItemList',
          '@id': `${canonicalUrl}#itemlist`,
          name: cleanTitle,
          numberOfItems: categories.length,
          itemListElement
        }
      },
      {
        '@type': 'BreadcrumbList',
        '@id': `${canonicalUrl}#breadcrumb`,
        itemListElement: [
          { '@type': 'ListItem', position: 1, name: 'Ana Sayfa', item: publicArchiveCanonicalUrl('/') },
          { '@type': 'ListItem', position: 2, name: 'Kategoriler', item: canonicalUrl }
        ]
      }
    ]
  };
}

function questionSeoTitle(entry = {}) {
  const source = entry.question || entry.title || '';
  return compactSeoText(String(source || '').replace(/^\s*\d+\.\s*Soru:\s*/iu, ''), PUBLIC_ARCHIVE_SEO_TITLE_MAX);
}

function seoList(items = [], limit = 3) {
  return [...new Set((items || []).map(plainText).filter(Boolean))].slice(0, limit);
}

function quranReferenceLabels(entry = {}, limit = 3) {
  return extractQuranReferences(entry).map(reference => reference.label).slice(0, limit);
}

function questionSeoDescription(entry = {}) {
  const question = plainText(entry.question || entry.title);
  const answer = plainText(entry.answer || entry.answerText || entry.answer_text || entry.fullAnswer || entry.body);
  const categories = seoList(categoriesFor(entry).map(category => category.name), 3);
  const references = quranReferenceLabels(entry, 3);
  const context = [
    categories.length ? `${categories.join(', ')} başlığında dini soru-cevap.` : '',
    references.length ? `Ayet atıfları: ${references.join(', ')}.` : ''
  ].filter(Boolean).join(' ');
  const answerLead = answer ? `Cevap: ${answer}` : '';
  const source = [context, question, answerLead].filter(Boolean).join(' ');
  return compactSeoText(source, PUBLIC_ARCHIVE_SEO_DESCRIPTION_MAX);
}

function categorySeoTitle(category = {}) {
  const name = plainText(category.name || 'Kategori');
  return `${name} Soruları ve Cevapları`;
}

function categorySeoDescription(category = {}, questionCount = 0, entries = []) {
  const name = plainText(category.name || 'Bu kategori');
  const count = Number(questionCount);
  const countText = Number.isFinite(count) && count > 0
    ? `${archiveCountLabel(count)} dini soru-cevap`
    : 'dini soru ve cevaplar';
  const references = categoryEvidenceReferences(entries, 3).map(reference => reference.label);
  const referenceText = references.length ? ` Öne çıkan ayet atıfları: ${references.join(', ')}.` : '';
  return compactSeoText(`${name} hakkında ${countText}; cevapları, ilgili kavramları ve kaynak bağlamını birlikte okuyun.${referenceText}`, PUBLIC_ARCHIVE_SEO_DESCRIPTION_MAX);
}

function archiveSeoDescription(questionCount = 0) {
  const count = Number(questionCount);
  const countText = Number.isFinite(count) && count > 0 ? `${archiveCountLabel(count)} yayınlanmış soru-cevap` : 'yayınlanmış dini soru-cevaplar';
  return `${countText}; hidayet, mürşid, zikir, takva, nefs ve teslimiyet gibi konularda kategorili ve kaynak bağlamlı arşiv.`;
}

function categoriesIndexSeoDescription(categoryCount = 0, questionCount = 0) {
  const categories = Number(categoryCount);
  const questions = Number(questionCount);
  const categoryText = Number.isFinite(categories) && categories > 0 ? `${archiveCountLabel(categories)} kategori` : 'ana kategoriler';
  const questionText = Number.isFinite(questions) && questions > 0 ? `${archiveCountLabel(questions)} soru-cevap` : 'yayınlanmış soru-cevaplar';
  return `${categoryText} altında ${questionText}: dini soruları hidayet, zikir, takva, nefs ve ilgili başlıklarla inceleyin.`;
}

function questionPageStructuredData(entry, category) {
  const canonicalUrl = publicArchiveCanonicalUrl(`/soru/${entry.slug}`);
  const categoryNames = categoriesFor(entry).map(item => item.name).filter(Boolean);
  const references = extractQuranReferences(entry).map(reference => reference.label);
  const answerText = readableStructuredText(entry.answer || entry.answerText || entry.answer_text || entry.fullAnswer || entry.body);
  const description = questionSeoDescription(entry);
  const answerAuthor = publicArchiveAnswerAuthor();
  const question = plainText(entry.question || entry.title);
  const datePublished = publicArchiveDateIso(entry.publishedAt);
  const dateModified = publicArchiveDateIso(entry.updatedAt || entry.publishedAt);
  const pageId = `${canonicalUrl}#webpage`;
  const articleId = `${canonicalUrl}#article`;
  const questionId = `${canonicalUrl}#question`;
  const answerId = `${canonicalUrl}#accepted-answer`;
  const breadcrumbId = `${canonicalUrl}#breadcrumb`;
  const breadcrumbItems = [
    { name: 'Ana Sayfa', url: publicArchiveCanonicalUrl('/') },
    { name: 'Arşiv', url: publicArchiveCanonicalUrl('/arsiv') },
    category ? { name: category.name, url: publicArchiveCanonicalUrl(`/kategori/${category.slug}`) } : null,
    { name: entry.title, url: canonicalUrl }
  ].filter(Boolean);

  return {
    '@context': 'https://schema.org',
    '@graph': [
      {
        '@type': 'WebPage',
        '@id': pageId,
        url: canonicalUrl,
        name: entry.title,
        description,
        inLanguage: 'tr',
        isPartOf: { '@id': `${publicArchiveCanonicalUrl('/')}#website` },
        primaryImageOfPage: {
          '@type': 'ImageObject',
          url: publicArchiveShareImageUrl(),
          width: 1200,
          height: 630
        },
        breadcrumb: { '@id': breadcrumbId },
        mainEntity: { '@id': questionId },
        datePublished: datePublished || undefined,
        dateModified: dateModified || undefined
      },
      {
        '@type': 'Article',
        '@id': articleId,
        url: canonicalUrl,
        mainEntityOfPage: {
          '@id': pageId
        },
        headline: entry.title,
        name: entry.title,
        description,
        inLanguage: 'tr',
        articleSection: categoryNames,
        about: categoryNames.map(name => ({ '@type': 'Thing', name })),
        keywords: categoryNames.join(', '),
        articleBody: answerText,
        datePublished: datePublished || undefined,
        dateModified: dateModified || undefined,
        author: answerAuthor,
        publisher: { '@id': `${publicArchiveCanonicalUrl('/')}#organization` },
        citation: references.length ? references.map(publicArchiveReferenceStructuredData) : undefined
      },
      {
        '@type': 'Question',
        '@id': questionId,
        name: entry.title,
        text: question,
        url: canonicalUrl,
        inLanguage: 'tr',
        answerCount: answerText ? 1 : 0,
        acceptedAnswer: answerText
          ? {
              '@type': 'Answer',
              '@id': answerId,
              text: answerText,
              url: `${canonicalUrl}#cevap`,
              inLanguage: 'tr',
              author: answerAuthor,
              dateCreated: datePublished || undefined,
              dateModified: dateModified || undefined
            }
          : undefined
      },
    {
      '@type': 'BreadcrumbList',
      '@id': breadcrumbId,
      itemListElement: breadcrumbItems.map((item, index) => ({
        '@type': 'ListItem',
        position: index + 1,
        name: item.name,
        item: item.url
      }))
    }
    ]
  };
}

function cleanTopicArticleText(value = '') {
  return String(value || '').replace(/\s*\[\d+\]/g, '');
}

function topicArticleInlineHtml(value = '') {
  return escapeHtml(cleanTopicArticleText(value));
}

function topicArticleHeadingAnchor(text = '', index = 0) {
  const normalized = publicArchiveComparable(text).replace(/\s+/g, '-').replace(/^-+|-+$/g, '').slice(0, 58);
  return `bolum-${index + 1}${normalized ? `-${normalized}` : ''}`;
}

function annotatedTopicArticleBlocks(article = {}) {
  let headingIndex = 0;
  const visibleBlocks = [];
  let skipInternalNotes = false;
  for (const block of article.blocks || []) {
    const isHeading = block?.type === 'heading';
    const isInternalNoteHeading = isHeading && ['Kaynaklar ve metin notu', 'Ayet ve metin notu']
      .some(label => publicArchiveComparable(block.text) === publicArchiveComparable(label));
    if (isInternalNoteHeading) {
      skipInternalNotes = true;
      continue;
    }
    if (skipInternalNotes && !isHeading) continue;
    if (skipInternalNotes && isHeading) skipInternalNotes = false;
    if (!isHeading) {
      visibleBlocks.push(block);
      continue;
    }
    const id = topicArticleHeadingAnchor(block.text, headingIndex);
    headingIndex += 1;
    visibleBlocks.push({ ...block, id });
  }
  return visibleBlocks;
}

function topicArticleBodyText(article = {}) {
  return readableStructuredText(annotatedTopicArticleBlocks(article)
    .map(block => {
      if (block.type === 'heading') return cleanTopicArticleText(block.text);
      if (block.type === 'evidence') return cleanTopicArticleText(`${block.reference} - ${block.note}\n${block.text}`);
      return cleanTopicArticleText(block.text);
    })
    .filter(Boolean)
    .join('\n\n'));
}

function topicArticleStructuredData(article = {}, relatedQuestions = []) {
  const canonicalPath = publicTopicArticlePath(article);
  const canonicalUrl = publicArchiveCanonicalUrl(canonicalPath);
  const cleanDescription = compactSeoText(article.description || article.summary || publicArchiveFixtures.brand.sentence, PUBLIC_ARCHIVE_SEO_DESCRIPTION_MAX);
  const cleanTitle = compactSeoText(article.title, PUBLIC_ARCHIVE_SEO_TITLE_MAX);
  const articleId = `${canonicalUrl}#article`;
  const pageId = `${canonicalUrl}#webpage`;
  const breadcrumbId = `${canonicalUrl}#breadcrumb`;
  const quranMentions = (article.quranReferences || []).map(reference => {
    return publicArchiveReferenceStructuredData(reference.label);
  });
  const relatedItemList = (relatedQuestions || [])
    .filter(entry => entry?.slug)
    .slice(0, 12)
    .map((entry, index) => ({
      '@type': 'ListItem',
      position: index + 1,
      url: publicArchiveCanonicalUrl(`/soru/${entry.slug}`),
      name: compactSeoText(entry.title || entry.question, 120)
    }));
  const graph = [
    {
      '@type': 'WebPage',
      '@id': pageId,
      url: canonicalUrl,
      name: cleanTitle,
      description: cleanDescription,
      inLanguage: 'tr',
      isPartOf: { '@id': `${publicArchiveCanonicalUrl('/')}#website` },
      breadcrumb: { '@id': breadcrumbId },
      mainEntity: { '@id': articleId },
      datePublished: article.publishedAt,
      dateModified: article.updatedAt || article.publishedAt,
      primaryImageOfPage: {
        '@type': 'ImageObject',
        url: publicArchiveShareImageUrl(),
        width: 1200,
        height: 630
      }
    },
    {
      '@type': 'BlogPosting',
      '@id': articleId,
      url: canonicalUrl,
      mainEntityOfPage: { '@id': pageId },
      headline: cleanTitle,
      alternativeHeadline: article.subtitle || undefined,
      description: cleanDescription,
      inLanguage: 'tr',
      articleSection: 'Konu Rehberi',
      articleBody: topicArticleBodyText(article),
      keywords: (article.keywords || []).join(', '),
      about: (article.keywords || []).slice(0, 8).map(name => ({ '@type': 'Thing', name })),
      mentions: quranMentions,
      author: publicArchiveAnswerAuthor(),
      publisher: { '@id': `${publicArchiveCanonicalUrl('/')}#organization` },
      datePublished: article.publishedAt,
      dateModified: article.updatedAt || article.publishedAt
    },
    {
      '@type': 'BreadcrumbList',
      '@id': breadcrumbId,
      itemListElement: [
        { '@type': 'ListItem', position: 1, name: 'Ana Sayfa', item: publicArchiveCanonicalUrl('/') },
        { '@type': 'ListItem', position: 2, name: 'Konu Rehberleri', item: publicArchiveCanonicalUrl('/#konu-rehberleri') },
        { '@type': 'ListItem', position: 3, name: article.title, item: canonicalUrl }
      ]
    }
  ];
  if (relatedItemList.length) {
    graph.push({
      '@type': 'ItemList',
      '@id': `${canonicalUrl}#related-questions`,
      name: `${article.title} ile ilgili sorular`,
      numberOfItems: relatedItemList.length,
      itemListElement: relatedItemList
    });
  }
  return {
    '@context': 'https://schema.org',
    '@graph': graph
  };
}

function topicArticleRelatedQuestions(article = {}, limit = 8) {
  const terms = (article.relatedTerms || article.keywords || [article.title]).map(publicArchiveComparable).filter(Boolean);
  const preferredCategory = String(article.categorySlug || '').trim();
  const scored = uniquePublicArchiveQuestionResults(publicArchiveFixtures.qa)
    .map(entry => {
      const categorySlugs = categorySlugsFor(entry);
      const categoryNames = categoriesFor(entry).map(category => category.name).join(' ');
      const references = quranReferenceLabels(entry, 8).join(' ');
      const titleText = publicArchiveComparable(entry.title || entry.question || '');
      const fullText = publicArchiveComparable([entry.title, entry.question, entry.summary, plainText(entry.answer || entry.answerText || entry.answer_text), categoryNames, references].join(' '));
      let score = categorySlugs.includes(preferredCategory) ? 110 : 0;
      for (const term of terms) {
        if (!term) continue;
        if (titleText.includes(term)) score += 42;
        else if (fullText.includes(term)) score += 22;
      }
      if (references) score += 8;
      return { entry, score };
    })
    .filter(item => item.score > 0)
    .sort((a, b) => b.score - a.score || normalizedReadCount(b.entry) - normalizedReadCount(a.entry) || entryPublishedTime(b.entry) - entryPublishedTime(a.entry));
  return scored.slice(0, limit).map(item => item.entry);
}

function renderTopicArticleBlock(block = {}, article = {}) {
  if (block.type === 'heading') {
    return `<h2 id="${escapeHtml(block.id || '')}">${escapeHtml(block.text)}</h2>`;
  }
  if (block.type === 'evidence') {
    return `
      <aside class="pa-topic-evidence">
        <div class="pa-topic-evidence-head">
          <strong>${escapeHtml(block.reference)}</strong>
          <span>${escapeHtml(block.note)}</span>
        </div>
        <p>${topicArticleInlineHtml(block.text, article)}</p>
      </aside>
    `;
  }
  return `<p>${topicArticleInlineHtml(block.text || '', article)}</p>`;
}

function topicArticleTocHtml(blocks = []) {
  const headings = blocks.filter(block => block.type === 'heading');
  if (!headings.length) return '';
  return `
    <section class="pa-topic-article-toc-block" aria-label="Makale içindekiler">
      <nav class="pa-topic-toc" aria-label="İçindekiler">
        <strong>İçindekiler</strong>
        ${headings.map(block => `<a href="#${escapeHtml(block.id)}">${escapeHtml(block.text)}</a>`).join('')}
      </nav>
    </section>
  `;
}

function topicArticleGuideLinksHtml(article = {}) {
  const currentSlug = String(article.slug || '').trim();
  const articles = Object.values(publicArchiveTopicArticles || {})
    .filter(item => item?.slug && item?.path && item.slug !== currentSlug)
    .slice(0, 5);
  if (!articles.length) return '';
  return `
        <section class="pa-topic-proof-card pa-topic-next-card">
          <strong>Okumaya devam edin</strong>
          <ul class="pa-topic-next-list">
            ${articles.map(item => `
              <li>
                <a href="${escapeHtml(publicArchivePath(item.path))}">
                  <strong>${escapeHtml(item.title)}</strong>
                </a>
              </li>
            `).join('')}
          </ul>
        </section>
  `;
}

function topicArticleFooterLinksHtml(article = {}) {
  return `
    <section class="pa-topic-article-support" aria-label="Makale sonu bağlantıları">
      ${(article.quranReferences || []).length ? `
        <section class="pa-topic-proof-card">
          <strong>Bu yazıda geçen ayetler</strong>
          <div>
            ${(article.quranReferences || []).map(reference => {
              const hrefValue = `${PREVIEW_BASE}/arama?q=${encodeURIComponent(reference.label)}`;
              return `<a href="${escapeHtml(hrefValue)}">${escapeHtml(reference.label)}</a>`;
            }).join('')}
          </div>
        </section>
      ` : ''}
      ${topicArticleGuideLinksHtml(article)}
    </section>
  `;
}

function renderTopicGuideArticle(slug) {
  const article = publicTopicArticleBySlug(slug);
  if (!article) return renderNotFound();
  const annotatedBlocks = annotatedTopicArticleBlocks(article);
  const relatedQuestions = topicArticleRelatedQuestions(article, 8);
  const canonicalPath = publicTopicArticlePath(article);
  const description = compactSeoText(article.description || article.summary || publicArchiveFixtures.brand.sentence, PUBLIC_ARCHIVE_SEO_DESCRIPTION_MAX);
  const categorySlug = article.categorySlug || 'allaha-ulasmayi-dilemek';
  const category = publicCategoryBySlug(categorySlug);
  const questionTopicTitle = category?.name || String(article.title || '').replace(/\s+Nedir\?\s*$/i, '').trim() || article.title || 'Bu konu';
  const articleSeoTitle = /[?？]\s*$/.test(String(article.title || ''))
    ? article.title
    : `${article.title} Nedir?`;
  return renderShell({
    active: 'archive',
    title: articleSeoTitle,
    description,
    canonicalPath,
    structuredData: topicArticleStructuredData(article, relatedQuestions),
    headMeta: {
      contentType: 'article',
      authorName: publicArchiveFixtures.brand.authorName,
      publishedTime: article.publishedAt,
      modifiedTime: article.updatedAt || article.publishedAt,
      section: 'Konu Rehberi',
      tags: article.keywords || []
    },
    searchSeedEntries: relatedQuestions,
    searchSeedCategories: [publicCategoryBySlug(article.categorySlug)].filter(Boolean),
    content: `
      <main class="pa-main pa-topic-article-main">
        ${breadcrumb([{ label: 'Konu Rehberleri', href: `${PREVIEW_BASE}/#konu-rehberleri` }, { label: article.title }])}
        <header class="pa-topic-article-hero">
          <p class="pa-kicker">${escapeHtml(article.series || 'Konu Rehberi')}</p>
          <h1>${escapeHtml(article.title)}</h1>
          <p class="pa-topic-article-subtitle">${escapeHtml(article.subtitle || article.description || '')}</p>
          <div class="pa-collection-meta">
            ${article.readTime ? `<span>${escapeHtml(article.readTime)} dk okuma</span>` : ''}
            <span>${escapeHtml(String((article.quranReferences || []).length))} ayet atfı</span>
          </div>
        </header>
        ${topicArticleTocHtml(annotatedBlocks)}
        <div class="pa-topic-article-layout">
          <article class="pa-topic-article-body" id="makale">
            ${annotatedBlocks.map(block => renderTopicArticleBlock(block, article)).join('')}
          </article>
        </div>
        ${topicArticleFooterLinksHtml(article)}
        ${relatedQuestions.length ? `
          <section class="pa-section pa-topic-article-related" id="ilgili-sorular">
            ${sectionHeader(`${questionTopicTitle} ile ilgili sorular`, 'Tümünü Gör', `${PREVIEW_BASE}/kategori/${categorySlug}`)}
            <div class="pa-list">${relatedQuestions.map(entry => questionCard(entry, true)).join('')}</div>
          </section>
        ` : ''}
      </main>
    `
  });
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

function publicArchiveQuestionResultIdentity(entry = {}) {
  const question = questionTextIdentity(entry);
  if (question) return question;
  const answer = publicArchiveComparable(plainText(entry.answer || entry.answerText || entry.answer_text || entry.fullAnswer || entry.body || ''));
  return answer || String(entry.slug || entry.id || '');
}

function homeQuestionIdentity(entry = {}) {
  return publicArchiveQuestionResultIdentity(entry);
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

function uniquePublicArchiveQuestionResults(entries = []) {
  const byIdentity = new Map();
  for (const entry of entries || []) {
    if (!entry?.slug) continue;
    const key = publicArchiveQuestionResultIdentity(entry);
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

function hourlyQuestionPick(entries = [], count = 3, hour = homeRotationHour(), slot = 'featured') {
  if (!entries.length) return [];
  return entries
    .map(entry => ({ entry, score: hashString(`${slot}:${hour}:${entry.slug || ''}:${entry.title || ''}`) }))
    .sort((a, b) => b.score - a.score)
    .slice(0, count)
    .map(item => item.entry);
}

function homeQuestionSets(entries = []) {
  const unique = uniqueHomeQuestions(entries);
  const hour = homeRotationHour();
  const featuredPool = unique
    .map(entry => ({ entry, score: weightedHomeScore(entry, hour, 'featured') }))
    .sort((a, b) => b.score - a.score)
    .slice(0, 18)
    .map(item => item.entry);
  const featured = hourlyQuestionPick(featuredPool, 3, hour, 'featured');
  const used = new Set(featured.map(homeQuestionIdentity));
  const latestPool = unique
    .filter(entry => !used.has(homeQuestionIdentity(entry)))
    .sort((a, b) => entryPublishedTime(b) - entryPublishedTime(a))
    .slice(0, 24);
  const latest = hourlyQuestionPick(rotateByHour(latestPool, hour), 3, hour, 'latest');
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

function homeLatestEntries(entries = [], limit = 6) {
  return uniqueHomeQuestions(entries)
    .sort((a, b) => entryPublishedTime(b) - entryPublishedTime(a) || String(a.title || '').localeCompare(String(b.title || ''), 'tr'))
    .slice(0, limit);
}

function homePopularEntries(entries = [], limit = 6) {
  return uniqueHomeQuestions(entries)
    .sort((a, b) => normalizedReadCount(b) - normalizedReadCount(a) || entryPublishedTime(b) - entryPublishedTime(a))
    .slice(0, limit);
}

function homeFeaturedEntries(entries = [], limit = 6) {
  const hour = homeRotationHour();
  return uniqueHomeQuestions(entries)
    .map(entry => ({ entry, score: weightedHomeScore(entry, hour, 'featured-list') }))
    .sort((a, b) => b.score - a.score || entryPublishedTime(b.entry) - entryPublishedTime(a.entry))
    .slice(0, limit)
    .map(item => item.entry);
}

function homeCollectionEntries(kind = 'featured', entries = publicArchiveFixtures.qa, limit = 36) {
  if (kind === 'latest') return homeLatestEntries(entries, limit);
  if (kind === 'popular') return homePopularEntries(entries, limit);
  return homeFeaturedEntries(entries, limit);
}

function homeReadingPathHref(item = {}) {
  const article = item.articleSlug ? publicTopicArticleBySlug(item.articleSlug) : null;
  if (article?.slug) return `${PREVIEW_BASE}${publicTopicArticlePath(article)}`;
  const category = publicCategoryBySlug(item.slug) || publicCategoryBySlug(item.fallbackSlug);
  if (category?.slug) return `${PREVIEW_BASE}/kategori/${escapeHtml(category.slug)}`;
  const query = item.query || item.title || '';
  return `${PREVIEW_BASE}/arama?q=${encodeURIComponent(query)}`;
}

function homeReadingPathItems() {
  return HOME_READING_PATHS.map(item => {
    const article = item.articleSlug ? publicTopicArticleBySlug(item.articleSlug) : null;
    const isArticle = Boolean(article?.slug);
    return `
      <a class="pa-reading-card" href="${escapeHtml(homeReadingPathHref(item))}"${isArticle ? ' data-topic-article-link="true"' : ''}>
        <span class="pa-reading-mark">${iconSvg('topics')}</span>
        <strong>${escapeHtml(item.title)}</strong>
        <span class="pa-reading-copy">${escapeHtml(item.text)}</span>
        <span class="pa-reading-action">${isArticle ? 'Rehbere Başla' : 'Soruları gör'} ${iconSvg('chevron-right', 'pa-inline-chevron')}</span>
      </a>
    `;
  }).join('');
}

function quranEvidenceEntries(entries = [], limit = 4) {
  return uniqueHomeQuestions(entries)
    .map(entry => ({ entry, references: extractQuranReferences(entry).slice(0, 4) }))
    .filter(item => item.references.length)
    .sort((a, b) => b.references.length - a.references.length || normalizedReadCount(b.entry) - normalizedReadCount(a.entry) || entryPublishedTime(b.entry) - entryPublishedTime(a.entry))
    .slice(0, limit);
}

function homeQuranEvidenceSection(items = []) {
  if (!items.length) return '';
  return `
    <section class="pa-section pa-quran-evidence" aria-labelledby="pa-quran-evidence-title">
      <div class="pa-section-head">
        <div>
          <p class="pa-kicker">Delilli okuma</p>
          <h2 id="pa-quran-evidence-title">Ayet atıflarıyla öne çıkan cevaplar</h2>
        </div>
        <a href="${PREVIEW_BASE}/arama?q=${encodeURIComponent('Kur’ân ayetleri')}">Ayetli cevapları ara ${iconSvg('chevron-right', 'pa-inline-chevron')}</a>
      </div>
      <div class="pa-evidence-grid">
        ${items.map(item => {
          const entry = item.entry;
          return `
            <article class="pa-evidence-card" data-card-href="${PREVIEW_BASE}/soru/${escapeHtml(entry.slug)}" role="link" tabindex="0" aria-label="${escapeHtml(entry.title)}">
              <div class="pa-evidence-top">
                <span>${iconSvg('tevhid')}</span>
                <div class="pa-evidence-refs">
                  ${item.references.map(reference => `<a href="${PREVIEW_BASE}/arama?q=${encodeURIComponent(reference.label)}">${escapeHtml(reference.label)}</a>`).join('')}
                </div>
              </div>
              <a class="pa-question-title" href="${PREVIEW_BASE}/soru/${escapeHtml(entry.slug)}">${escapeHtml(entry.title)}</a>
              <p>${escapeHtml(plainText(entry.summary || entry.excerpt || answerTextForReferences(entry)).slice(0, 150))}</p>
            </article>
          `;
        }).join('')}
      </div>
    </section>
  `;
}

function homeReadingPathSection() {
  return `
    <section class="pa-section pa-topic-path" id="konu-rehberleri" aria-labelledby="pa-reading-path-title">
      <div class="pa-topic-path-head">
        <p class="pa-kicker">Konu rehberleri</p>
        <h2 id="pa-reading-path-title">Temel konuları sırayla takip edin.</h2>
        <p>Her başlık, aynı kavram etrafındaki soru-cevapları bir araya getirir ve okumayı daha derli toplu ilerletir.</p>
      </div>
      <div class="pa-reading-track" aria-label="Konu rehberleri">
        <div class="pa-reading-rail">
          <div class="pa-reading-set">
            ${homeReadingPathItems()}
          </div>
        </div>
      </div>
    </section>
  `;
}

function homeDiscoveryMapSection(entries = []) {
  const counts = new Map();
  for (const entry of entries || []) {
    for (const slug of categorySlugsFor(entry)) {
      if (!slug) continue;
      counts.set(slug, (counts.get(slug) || 0) + 1);
    }
  }
  const categories = publicCategories()
    .map(category => ({ category, count: counts.get(category.slug) || categoryQuestionCount(category) }))
    .filter(item => item.count > 0)
    .sort((a, b) => Number(b.count || 0) - Number(a.count || 0) || String(a.category.name || '').localeCompare(String(b.category.name || ''), 'tr'))
    .slice(0, 14);
  if (!categories.length) return '';
  return `
    <section class="pa-section pa-discovery-map" aria-labelledby="pa-discovery-map-title">
      <div>
        <p class="pa-kicker">Kavram akışı</p>
        <h2 id="pa-discovery-map-title">Bir cevaptan diğerine konu bağıyla geçin.</h2>
      </div>
      <div class="pa-discovery-cloud">
        ${categories.map((item, index) => `
          <a class="pa-discovery-pill" href="${PREVIEW_BASE}/kategori/${escapeHtml(item.category.slug)}" style="--pa-pill-rank:${index % 5}">
            <strong>${escapeHtml(item.category.name)}</strong>
            <span>${archiveCountLabel(item.count)} soru</span>
          </a>
        `).join('')}
      </div>
    </section>
  `;
}

function renderCollectionIntro(kind, pageState) {
  const latest = kind === 'latest';
  const popular = kind === 'popular';
  return {
    canonicalPath: popular ? '/cok-okunan-cevaplar' : latest ? '/son-yayinlanan-sorular' : '/one-cikan-sorular',
    title: popular ? 'Çok Okunan Cevaplar' : latest ? 'Son Yayınlanan Sorular' : 'Öne Çıkan Sorular',
    kicker: popular ? 'Çok okunanlar' : latest ? 'Son yayınlananlar' : 'Öne çıkanlar',
    description: popular
      ? `Arşivde en çok okunan ${archiveCountLabel(pageState.total)} dini soru-cevap kaydı okunma sırasına göre listelenir.`
      : latest
      ? `Arşive en son eklenen ${archiveCountLabel(pageState.total)} dini soru-cevap kaydı yayın sırasına göre listelenir.`
      : `Okunma, güncellik ve konu dağılımı dikkate alınarak öne çıkan ${archiveCountLabel(pageState.total)} dini soru-cevap kaydı.`,
    emptyTitle: popular ? 'Henüz çok okunan cevap görünmüyor.' : latest ? 'Henüz son yayın listesi görünmüyor.' : 'Henüz öne çıkan soru görünmüyor.'
  };
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
      <div class="pa-cta-copy">
        <span class="pa-cta-symbol">${iconSvg('ask-question')}</span>
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
  const dataUnavailable = publicArchiveFixtures.dataUnavailable === true;
  const { featured, latest } = homeQuestionSets(publicArchiveFixtures.qa);
  const featuredList = homeCollectionEntries('featured', publicArchiveFixtures.qa, 6);
  const latestList = homeCollectionEntries('latest', publicArchiveFixtures.qa, 5);
  const popularList = homeCollectionEntries('popular', publicArchiveFixtures.qa, 5);
  const quranEvidenceList = quranEvidenceEntries(publicArchiveFixtures.qa, 4);
  const homeSearchSeedEntries = [...featuredList, ...latestList, ...popularList, ...featured, ...latest];
  return renderShell({
    active: 'home',
    title: 'Ana Sayfa',
    description: 'Dini sorulara Dr. Abdulcabbar Boran’ın cevaplarını; Kur’ân ayetleri, kaynak bağlamı ve ilgili kategorilerle birlikte okuyun.',
    canonicalPath: '/',
    searchSeedEntries: homeSearchSeedEntries,
    searchSeedCategories: publicCategories(),
    includeHeroSearchSeed: true,
    content: `
      <main class="pa-main">
        <section class="pa-hero">
          <div class="pa-hero-copy">
            <h1>Sorularınıza, kaynaklarıyla birlikte cevap bulun.</h1>
            <p>Hidayet, mürşid, zikir ve teslimiyet gibi temel kategorilerden başlayın; ilgili soruları, cevapları ve delilleri bir arada okuyun.</p>
            ${searchBox()}
            ${heroConceptLane()}
          </div>
          ${stillLife()}
        </section>

        ${archiveShortcutBand()}

        ${!dataUnavailable && featured.length ? `<section class="pa-section">
          ${sectionHeader('Öne Çıkan Sorular', 'Öne çıkanları gör', `${PREVIEW_BASE}/one-cikan-sorular`)}
          <div class="pa-question-grid">${featured.map(entry => questionCard(entry, { showMeta: false, strongCta: true })).join('')}</div>
        </section>` : ''}

        ${!dataUnavailable ? activeArchiveStatsBand(publicArchiveFixtures.qa) : ''}

        ${!dataUnavailable && latestList.length ? `<section class="pa-section">
          ${sectionHeader('Son Yayınlanan Sorular', 'Son yayınlananları gör', `${PREVIEW_BASE}/son-yayinlanan-sorular`)}
          <div class="pa-list">${latestList.slice(0, 4).map(entry => questionCard(entry, true)).join('')}</div>
        </section>` : ''}

        ${!dataUnavailable && popularList.length ? `<section class="pa-section pa-home-popular">
          ${sectionHeader('Çok Okunan Cevaplar', 'Arşivde devam et', `${PREVIEW_BASE}/cok-okunan-cevaplar`)}
          <div class="pa-question-grid">${popularList.slice(0, 5).map(entry => questionCard(entry, { compact: true })).join('')}</div>
        </section>` : ''}

        ${!dataUnavailable ? homeQuranEvidenceSection(quranEvidenceList) : ''}
        ${!dataUnavailable ? homeReadingPathSection() : ''}
        ${!dataUnavailable ? homeDiscoveryMapSection(publicArchiveFixtures.qa) : ''}
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
  const entries = uniquePublicArchiveQuestionResults(publicArchiveFixtures.qa);
  if (preFiltered && normalized === preFilteredQuery) return entries;
  if (!normalized) return entries;
  return entries.filter(entry => {
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
const ARCHIVE_LETTER_ALIASES = {
  'Â': 'A',
  'Ê': 'E',
  'Î': 'İ',
  'Ô': 'O',
  'Û': 'U'
};

function sortedCategories() {
  return publicCategories().sort((a, b) => trCollator.compare(a.name || '', b.name || ''));
}

function normalizeArchiveLetter(value = '', fallback = '') {
  const rawValue = String(value || '').trim();
  if (rawValue === '#') return '#';
  const firstLetter = Array.from(rawValue).find(char => /\p{L}/u.test(char));
  if (!firstLetter) return fallback;
  const upper = firstLetter.toLocaleUpperCase('tr-TR');
  return ARCHIVE_LETTER_ALIASES[upper] || upper;
}

function categoryInitial(category) {
  return normalizeArchiveLetter(category?.name || '', '#');
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
    <nav class="pa-pagination" aria-label="Arşiv sayfaları" data-load-more-shell>
      <span class="pa-pagination-status">${archiveCountLabel(state.start)}-${archiveCountLabel(state.end)} / ${archiveCountLabel(state.total)} soru gösteriliyor</span>
      ${nextHref
        ? `<a class="pa-load-more" href="${escapeHtml(nextHref)}" data-load-more>Daha Fazla Göster ${iconSvg('arrow-right', 'pa-cta-icon')}</a>`
        : `<span class="pa-load-complete">${iconSvg('check', 'pa-cta-icon')} Tüm kayıtlar gösterildi</span>`}
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
  const queryLetter = normalizeArchiveLetter(query.harf || '');
  const defaultLetter = letters.find(letter => letter !== '#') || letters[0] || '';
  const activeLetter = selectedCategory
    ? categoryInitial(selectedCategory)
    : queryLetter && letters.includes(queryLetter)
      ? queryLetter
      : defaultLetter;
  const letterCategories = categoriesByLetter.get(activeLetter) || [];
  const categorySearch = String(query.kategoriAra || '').trim();
  const normalizedCategorySearch = normalizeSearchText(categorySearch);
  const visibleCategories = selectedCategory
    ? [selectedCategory]
    : normalizedCategorySearch
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
      <div class="pa-alpha-index" data-alpha-index aria-label="Alfabetik kategori dizini">
        <div class="pa-alpha-shell">
          <button class="pa-alpha-nav" type="button" data-alpha-scroll="prev" aria-label="Önceki harfleri göster">${iconSvg('arrow-left')}</button>
          <div class="pa-alpha-track" data-alpha-track role="list" aria-label="Kategori harfleri">
            ${state.letters.map(letter => `
              <a class="pa-alpha-letter${letter === state.activeLetter ? ' is-active' : ''}" href="${escapeHtml(archiveQueryUrl({ harf: letter }))}"${letter === state.activeLetter ? ' aria-current="true"' : ''} role="listitem">${escapeHtml(letter)}</a>
            `).join('')}
          </div>
          <button class="pa-alpha-nav" type="button" data-alpha-scroll="next" aria-label="Sonraki harfleri göster">${iconSvg('arrow-right')}</button>
        </div>
        <div class="pa-letter-panel">
          <div class="pa-letter-head">
            <span class="pa-letter-badge">${escapeHtml(state.activeLetter)}</span>
            <strong>${escapeHtml(state.selectedCategory ? `${state.selectedCategory.name} seçildi` : `${state.activeLetter} harfiyle başlayan kategoriler`)}</strong>
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
  const dataUnavailable = publicArchiveFixtures.dataUnavailable === true;
  const serverPagination = publicArchiveFixtures.pagination?.scope === 'archive'
    ? publicArchiveFixtures.pagination
    : null;
  const entries = uniquePublicArchiveQuestionResults(publicArchiveFixtures.qa).sort((a, b) => String(b.publishedAt).localeCompare(String(a.publishedAt)));
  const answeredCount = archiveStatCount('answerCount', entries.filter(entry => Array.isArray(entry.answer) && entry.answer.length).length || entries.length);
  const categoryIndex = archiveCategoryIndex(query);
  const visibleEntries = serverPagination?.prePaginated
    ? entries
    : categoryIndex.selectedCategory
    ? entries.filter(entry => categorySlugsFor(entry).includes(categoryIndex.selectedCategory.slug))
    : entries;
  const pageState = archivePaginationState(visibleEntries, query.sayfa, serverPagination);
  const archiveDescription = archiveSeoDescription(answeredCount);
  const paginationParams = {
    harf: (query.harf || categoryIndex.selectedCategory || categoryIndex.categorySearch) ? categoryIndex.activeLetter : '',
    kategori: categoryIndex.selectedCategory?.slug || '',
    kategoriAra: categoryIndex.categorySearch || ''
  };
  const listTitle = categoryIndex.selectedCategory ? `${categoryIndex.selectedCategory.name} soruları` : 'Tüm Sorular';
  return renderShell({
    active: 'archive',
    title: 'Dini Soru Cevap Arşivi',
    description: archiveDescription,
    canonicalPath: '/arsiv',
    structuredData: collectionPageStructuredData({
      canonicalPath: '/arsiv',
      title: 'Dini Sorular ve Cevaplar Arşivi',
      description: archiveDescription,
      entries: pageState.pageEntries,
      total: pageState.total,
      breadcrumbItems: [
        { name: 'Ana Sayfa', url: publicArchiveCanonicalUrl('/') },
        { name: 'Arşiv', url: publicArchiveCanonicalUrl('/arsiv') }
      ]
    }),
    searchSeedEntries: pageState.pageEntries,
    searchSeedCategories: categoryIndex.visibleCategories,
    content: `
      <main class="pa-main pa-narrow-main">
        <section class="pa-archive-hero">
          <p class="pa-kicker">Arşiv</p>
          <h1>Merak ettiğiniz konunun cevaplarına ulaşın.</h1>
          <p>Soru ve cevapları kategorilerine göre inceleyebilir, aradığınız konuyu alfabetik olarak kolayca bulabilirsiniz.</p>
          ${!dataUnavailable ? `<div class="pa-collection-meta">
            <span>${archiveCountLabel(answeredCount)} soru cevap</span>
          </div>` : ''}
          ${!dataUnavailable ? categoryIndex.html : ''}
        </section>
        ${!dataUnavailable ? `<section class="pa-section" id="sorular">
          ${sectionHeader(listTitle, categoryIndex.selectedCategory ? 'Tümünü göster' : '', categoryIndex.selectedCategory ? archiveQueryUrl({ harf: categoryIndex.activeLetter, hash: 'sorular' }) : '')}
          ${visibleEntries.length
            ? `<div class="pa-list" data-archive-results>${pageState.pageEntries.map(entry => questionCard(entry, true)).join('')}</div>${archivePagination(`${PREVIEW_BASE}/arsiv`, paginationParams, pageState)}`
            : `<div class="pa-empty-state"><h2>Bu kategoride soru görünmüyor.</h2><p>Arşivdeki diğer kategorileri inceleyebilirsiniz.</p></div>`}
        </section>` : ''}
      </main>
    `
  });
}

function renderQuestionCollection(kind = 'featured', query = {}) {
  const serverPagination = publicArchiveFixtures.pagination?.scope === 'collection' && publicArchiveFixtures.pagination?.kind === kind
    ? publicArchiveFixtures.pagination
    : null;
  const entries = serverPagination?.prePaginated
    ? uniquePublicArchiveQuestionResults(publicArchiveFixtures.qa)
    : homeCollectionEntries(kind, publicArchiveFixtures.qa, kind === 'popular' ? 20 : 90);
  const pageState = archivePaginationState(entries, query.sayfa, serverPagination);
  const intro = renderCollectionIntro(kind, pageState);
  return renderShell({
    active: 'archive',
    title: intro.title,
    description: intro.description,
    canonicalPath: intro.canonicalPath,
    structuredData: collectionPageStructuredData({
      canonicalPath: intro.canonicalPath,
      title: intro.title,
      description: intro.description,
      entries: pageState.pageEntries,
      total: pageState.total,
      breadcrumbItems: [
        { name: 'Ana Sayfa', url: publicArchiveCanonicalUrl('/') },
        { name: intro.title, url: publicArchiveCanonicalUrl(intro.canonicalPath) }
      ]
    }),
    searchSeedEntries: pageState.pageEntries,
    searchSeedCategories: publicCategories(),
    content: `
      <main class="pa-main pa-narrow-main">
        ${breadcrumb([{ label: intro.title }])}
        <section class="pa-collection-hero pa-curated-hero">
          <p class="pa-kicker">${escapeHtml(intro.kicker)}</p>
          <h1>${escapeHtml(intro.title)}</h1>
          <p>${escapeHtml(intro.description)}</p>
          <div class="pa-collection-meta">
            <span>${archiveCountLabel(pageState.total)} soru cevap</span>
          </div>
        </section>
        <section class="pa-section" id="sorular">
          ${sectionHeader(kind === 'latest' ? 'Yayın sırasına göre' : 'Okuma önceliğine göre')}
          ${entries.length
            ? `<div class="pa-list" data-archive-results>${pageState.pageEntries.map(entry => questionCard(entry, true)).join('')}</div>${archivePagination(`${PREVIEW_BASE}${intro.canonicalPath}`, {}, pageState)}`
            : `<div class="pa-empty-state"><h2>${escapeHtml(intro.emptyTitle)}</h2><p>Arşivin tamamından okumaya devam edebilirsiniz.</p></div>`}
        </section>
      </main>
    `
  });
}

function renderSearch(query = '') {
  const cleanQuery = String(query || '').trim();
  const results = searchResults(cleanQuery);
  const directCategories = searchDirectCategoryMatches();
  return renderShell({
    active: 'search',
    title: cleanQuery ? `"${cleanQuery}" için arama` : 'Arama',
    description: 'Dini soru-cevap arşivinde soru, cevap metni ve kategori başlıkları içinde arama yapın.',
    canonicalPath: '/arama',
    pageNoindex: true,
    searchSeedEntries: results,
    searchSeedCategories: Array.isArray(publicArchiveFixtures.search?.categoryMatches)
      ? publicArchiveFixtures.search.categoryMatches.map(item => publicCategoryBySlug(item.slug)).filter(Boolean)
      : [],
    content: `
      <main class="pa-main pa-narrow-main">
        <section class="pa-search-page">
          <p class="pa-kicker">Arşivde ara</p>
          <h1>Aradığınız cevaba en kısa yoldan ulaşın.</h1>
          <p class="pa-page-intro">Soru başlıkları, cevap metinleri ve kategoriler içinde sade bir arama yapabilirsiniz.</p>
          ${searchBox(cleanQuery)}
          ${directCategories}
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

function searchDirectCategoryMatches() {
  const matches = Array.isArray(publicArchiveFixtures.search?.categoryMatches)
    ? publicArchiveFixtures.search.categoryMatches.filter(item => item?.slug && item?.name).slice(0, 3)
    : [];
  if (!matches.length) return '';
  return `
    <div class="pa-search-direct" aria-label="Doğrudan kategori eşleşmeleri">
      ${matches.map(item => `
        <a class="pa-search-direct-card" href="${PREVIEW_BASE}/kategori/${escapeHtml(item.slug)}">
          <span>
            <strong>${escapeHtml(item.name)}</strong>
            <small>${archiveCountLabel(item.questionCount || 0)} ilgili soru</small>
          </span>
          ${iconSvg('arrow-right', 'pa-search-direct-icon')}
        </a>
      `).join('')}
    </div>
  `;
}

function renderTopicsIndex() {
  return renderCategoriesIndex();
}

function renderCategoriesIndex() {
  const categories = sortedCategories();
  const questionCount = archiveStatCount('questionCount', publicArchiveFixtures.qa.length);
  const categoriesDescription = categoriesIndexSeoDescription(categories.length, questionCount);
  return renderShell({
    active: 'categories',
    title: 'Dini Soru Kategorileri',
    description: categoriesDescription,
    canonicalPath: '/kategoriler',
    structuredData: categoryIndexStructuredData({
      categories,
      title: 'Dini Soru Kategorileri',
      description: categoriesDescription
    }),
    content: `
      <main class="pa-main pa-narrow-main">
        <section class="pa-collection-hero">
          <p class="pa-kicker">Kategoriler</p>
          <h1>Soruları ana başlıklarına göre inceleyin.</h1>
          <p>${escapeHtml(categoriesDescription)}</p>
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
  const blockedPopular = new Set([entry.slug, ...related.map(item => item.slug)]);
  const currentQuestion = questionTextIdentity(entry);
  const seenPopularQuestions = new Set([currentQuestion, ...related.map(questionTextIdentity)].filter(Boolean));
  const popular = publicArchiveFixtures.qa
    .filter(item => item?.isDetailPopular)
    .filter(item => {
      if (!item || blockedPopular.has(item.slug)) return false;
      const identity = questionTextIdentity(item);
      if (identity && seenPopularQuestions.has(identity)) return false;
      if (identity) seenPopularQuestions.add(identity);
      return true;
    })
    .sort((a, b) => normalizedReadCount(b) - normalizedReadCount(a) || String(a.title || '').localeCompare(String(b.title || ''), 'tr'))
    .slice(0, 5);
  return renderShell({
    active: 'archive',
    title: questionSeoTitle(entry),
    description: questionSeoDescription(entry),
    canonicalPath: `/soru/${entry.slug}`,
    structuredData: questionPageStructuredData(entry, category),
    questionSlug: entry.slug,
    headMeta: {
      authorName: publicArchiveFixtures.brand.authorName,
      publishedTime: entry.publishedAt,
      modifiedTime: entry.updatedAt || entry.publishedAt,
      section: category?.name || '',
      tags: categoriesFor(entry).map(item => item.name).filter(Boolean)
    },
    searchSeedEntries: [entry, ...related, ...popular],
    searchSeedCategories: categoriesFor(entry),
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
            <section class="pa-reading-block" id="cevap">
              <h2>Cevap</h2>
              ${entry.answer.map(paragraph => `<p>${escapeHtml(paragraph)}</p>`).join('')}
            </section>
            ${detailInfoPanel(entry)}
            ${sourceReferencesPanel(entry)}
            <div class="pa-tool-row" aria-label="Sayfa araçları">
              <button type="button" class="pa-detail-action pa-detail-action-share" data-share aria-label="Bu soru ve cevabın bağlantısını paylaş">
                <span class="pa-detail-action-icon" data-action-icon>${iconSvg('share-2')}</span>
                <span class="pa-tool-label" data-action-label>Paylaş</span>
              </button>
              <button type="button" class="pa-detail-action pa-detail-action-copy" data-copy-answer aria-label="Cevap metnini kopyala">
                <span class="pa-detail-action-icon" data-action-icon>${iconSvg('copy')}</span>
                <span class="pa-tool-label" data-action-label>Cevabı Kopyala</span>
              </button>
              <span class="pa-sr-only" data-tool-status aria-live="polite"></span>
            </div>
          </div>
          <aside class="pa-answer-aside">
            ${related.length ? `
              <section>
                <h2>İlgili Sorular</h2>
                <div class="pa-side-list">${related.map(sideQuestionLink).join('')}</div>
              </section>
            ` : ''}
            ${popular.length ? `
              <section>
                <h2>En Çok Okunanlar</h2>
                <div class="pa-side-list">${popular.map(sideQuestionLink).join('')}</div>
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
  const entries = serverPagination?.prePaginated ? uniquePublicArchiveQuestionResults(publicArchiveFixtures.qa) : entriesForCategory(category.slug);
  const pageState = archivePaginationState(entries, query.sayfa, serverPagination);
  const pageNoindex = !publicCategorySeoIndexable(category, pageState.total);
  const categoryTitle = categorySeoTitle(category);
  const categoryDescription = categorySeoDescription(category, pageState.total, pageState.pageEntries);
  const evidenceReferences = categoryEvidenceReferences(pageState.pageEntries, 12).map(reference => reference.label);
  return renderShell({
    active: 'categories',
    title: categoryTitle,
    description: categoryDescription,
    canonicalPath: `/kategori/${category.slug}`,
    pageNoindex,
    structuredData: pageNoindex ? [] : collectionPageStructuredData({
      canonicalPath: `/kategori/${category.slug}`,
      title: categoryTitle,
      description: categoryDescription,
      entries: pageState.pageEntries,
      category,
      total: pageState.total,
      references: evidenceReferences,
      breadcrumbItems: [
        { name: 'Ana Sayfa', url: publicArchiveCanonicalUrl('/') },
        { name: 'Kategoriler', url: publicArchiveCanonicalUrl('/kategoriler') },
        { name: category.name, url: publicArchiveCanonicalUrl(`/kategori/${category.slug}`) }
      ]
    }),
    searchSeedEntries: pageState.pageEntries,
    searchSeedCategories: [category],
    content: `
      <main class="pa-main pa-narrow-main">
        ${breadcrumb([{ label: 'Kategoriler', href: `${PREVIEW_BASE}/kategoriler` }, { label: category.name }])}
        <section class="pa-collection-hero">
          <p class="pa-kicker">Kategori</p>
          <h1>${escapeHtml(category.name)}</h1>
          <p>${escapeHtml(categoryDescription)}</p>
          <div class="pa-collection-meta">
            <span>${archiveCountLabel(pageState.total)} ilgili soru</span>
          </div>
        </section>
        ${categoryEvidencePanel(category, pageState.pageEntries)}
        <section class="pa-section" id="sorular">
          ${sectionHeader('Bu Kategorideki Sorular')}
          <div class="pa-list" data-archive-results>${pageState.pageEntries.map(entry => questionCard(entry, true)).join('')}</div>
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
    pageNoindex: true,
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
    pageNoindex: true,
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
        <section class="pa-account-questions pa-ask-questions" data-user-questions hidden>
          <div class="pa-section-heading">
            <div>
              <p class="pa-kicker">Sorularım</p>
              <h2>Gönderdiğiniz sorular</h2>
              <p>Sorduğunuz sorular, inceleme durumu ve gelen cevaplar bu alanda görünür.</p>
            </div>
            <a class="pa-section-link" href="${PREVIEW_BASE}/hesabim">Hesabım</a>
          </div>
          <div class="pa-user-question-list" data-user-questions-list>
            <div class="pa-mini-empty">Sorularınız yükleniyor...</div>
          </div>
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
    pageNoindex: kind === 'gizlilik' || kind === 'kullanim-kosullari',
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

function publicArchiveUnavailableData(archiveData = {}) {
  return {
    ...(archiveData || {}),
    categories: [],
    topics: [],
    qa: [],
    stats: null,
    pagination: null,
    search: null,
    dataUnavailable: true,
    noindex: true
  };
}

function renderPublicArchiveUnavailableRoute(routePath = publicArchiveHomeHref(), query = {}, archiveData = {}) {
  return renderPublicArchivePreviewRoute(routePath, query, publicArchiveUnavailableData(archiveData));
}

function renderShell({ title, description, active, content, status = 200, questionSlug = '', canonicalPath = '', structuredData = [], pageNoindex = false, headMeta = {}, searchSeedEntries = [], searchSeedCategories = [], includeHeroSearchSeed = false }) {
  const safeTitle = pageTitle(title);
  const safeDescription = compactSeoText(description || publicArchiveFixtures.brand.sentence, PUBLIC_ARCHIVE_SEO_DESCRIPTION_MAX);
  const publicAppName = publicArchiveFixtures.brand.name;
  const publicShortAppName = 'Dini Sorular';
  const canonicalHref = canonicalPath ? publicArchiveCanonicalUrl(canonicalPath) : '';
  const robotsContent = PUBLIC_ARCHIVE_NOINDEX ? 'noindex,nofollow' : pageNoindex ? 'noindex,follow' : 'index,follow';
  const shouldExposeCanonical = robotsContent === 'index,follow' && canonicalHref;
  const shareImageHref = publicArchiveShareImageUrl();
  const publishedTime = publicArchiveDateIso(headMeta.publishedTime);
  const modifiedTime = publicArchiveDateIso(headMeta.modifiedTime) || publishedTime;
  const openGraphUpdatedTime = modifiedTime || PUBLIC_SHARE_UPDATED_TIME;
  const articleTags = [...new Set((Array.isArray(headMeta.tags) ? headMeta.tags : []).map(plainText).filter(Boolean))].slice(0, 12);
  const articleSection = plainText(headMeta.section || '');
  const authorName = plainText(headMeta.authorName || '');
  const isArticlePage = Boolean(questionSlug || headMeta.contentType === 'article');
  const structuredItems = [
    publicArchiveOrganizationStructuredData(),
    publicArchiveSiteStructuredData(),
    ...(Array.isArray(structuredData) ? structuredData : structuredData ? [structuredData] : [])
  ];
  const liveSearchSeedJson = inlineJson(publicArchiveLiveSearchSeed(searchSeedEntries, searchSeedCategories, { includeHeroConcepts: includeHeroSearchSeed }));
  const themeBootScript = `(function(){try{var saved=localStorage.getItem('dsca-theme');var theme=saved==='dark'||saved==='light'?saved:'dark';var root=document.documentElement;var bg=theme==='dark'?'#0D1412':'#F7F3EA';root.setAttribute('data-theme',theme);root.style.backgroundColor=bg;root.style.colorScheme=theme;var meta=document.querySelector('meta[name="theme-color"]');if(meta)meta.setAttribute('content',bg);}catch(error){document.documentElement.style.backgroundColor='#0D1412';}})();`;
  return {
    status,
    html: `<!doctype html>
<html lang="tr" data-theme="dark" style="background-color:#0D1412;color-scheme:dark">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">
  <meta name="robots" content="${robotsContent}">
  <meta name="googlebot" content="${robotsContent}">
  <meta name="description" content="${escapeHtml(safeDescription)}">
  ${isArticlePage && authorName ? `<meta name="author" content="${escapeHtml(authorName)}">` : ''}
  <meta name="application-name" content="${escapeHtml(publicAppName)}">
  <meta name="mobile-web-app-capable" content="yes">
  <meta name="apple-mobile-web-app-capable" content="yes">
  <meta name="apple-mobile-web-app-status-bar-style" content="default">
  <meta name="apple-mobile-web-app-title" content="${escapeHtml(publicShortAppName)}">
  ${shouldExposeCanonical ? `<link rel="canonical" href="${escapeHtml(canonicalHref)}">` : ''}
  <link rel="sitemap" type="application/xml" title="Sitemap" href="${PUBLIC_ARCHIVE_CANONICAL_ORIGIN}/sitemap.xml">
  <link rel="alternate" type="text/plain" title="LLMs.txt" href="${PUBLIC_ARCHIVE_CANONICAL_ORIGIN}/llms.txt">
  <meta property="og:locale" content="tr_TR">
  <meta property="og:site_name" content="${escapeHtml(publicAppName)}">
  <meta property="og:title" content="${escapeHtml(safeTitle)}">
  <meta property="og:description" content="${escapeHtml(safeDescription)}">
  <meta property="og:type" content="${isArticlePage ? 'article' : 'website'}">
  ${canonicalHref ? `<meta property="og:url" content="${escapeHtml(canonicalHref)}">` : ''}
  <meta property="og:updated_time" content="${escapeHtml(openGraphUpdatedTime)}">
  ${isArticlePage && publishedTime ? `<meta property="article:published_time" content="${escapeHtml(publishedTime)}">` : ''}
  ${isArticlePage && modifiedTime ? `<meta property="article:modified_time" content="${escapeHtml(modifiedTime)}">` : ''}
  ${isArticlePage && articleSection ? `<meta property="article:section" content="${escapeHtml(articleSection)}">` : ''}
  ${isArticlePage ? articleTags.map(tag => `<meta property="article:tag" content="${escapeHtml(tag)}">`).join('\n  ') : ''}
  <meta property="og:image" content="${escapeHtml(shareImageHref)}">
  <meta property="og:image:secure_url" content="${escapeHtml(shareImageHref)}">
  <meta property="og:image:type" content="image/png">
  <meta property="og:image:width" content="1200">
  <meta property="og:image:height" content="630">
  <meta property="og:image:alt" content="${escapeHtml(publicAppName)}">
  <meta name="twitter:card" content="summary_large_image">
  <meta name="twitter:title" content="${escapeHtml(safeTitle)}">
  <meta name="twitter:description" content="${escapeHtml(safeDescription)}">
  <meta name="twitter:image" content="${escapeHtml(shareImageHref)}">
  <meta name="twitter:image:alt" content="${escapeHtml(publicAppName)}">
  <meta name="theme-color" content="#0D1412">
  <script data-pa-theme-boot>${themeBootScript}</script>
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
        var theme = saved === 'dark' || saved === 'light' ? saved : 'dark';
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
  <nav class="pa-mobile-nav" aria-label="Mobil alt gezinme" data-active-index="${previewActionNavIndex(active)}">
    ${previewActionNav(active)}
  </nav>
  <button class="pa-scroll-top" type="button" data-scroll-top aria-label="Yukarı çık" aria-hidden="true" tabindex="-1">
    ${iconSvg('arrow-up', 'pa-scroll-top-icon')}
  </button>
  <script>
    (function(){
      var pageCleanups = [];
      function addPageCleanup(cleanup) {
        if (typeof cleanup === 'function') pageCleanups.push(cleanup);
      }
      function cleanupPublicArchivePage() {
        while (pageCleanups.length) {
          var cleanup = pageCleanups.pop();
          try { cleanup(); } catch (error) {}
        }
      }
      function applyTheme(theme) {
        document.documentElement.setAttribute('data-theme', theme);
        var meta = document.querySelector('meta[name="theme-color"]');
        if (meta) meta.setAttribute('content', theme === 'dark' ? '#0D1412' : '#F7F3EA');
        document.querySelectorAll('[data-theme-toggle]').forEach(function(button){
          button.setAttribute('aria-label', theme === 'dark' ? 'Açık temaya geç' : 'Koyu temaya geç');
        });
      }
      function bindThemeControls() {
        document.querySelectorAll('[data-theme-toggle]').forEach(function(button){
          if (button.dataset.themeBound === 'true') return;
          button.dataset.themeBound = 'true';
          button.addEventListener('click', function(){
            var next = document.documentElement.getAttribute('data-theme') === 'dark' ? 'light' : 'dark';
            try { localStorage.setItem('dsca-theme', next); } catch (error) {}
            applyTheme(next);
          });
        });
      }
      async function copyPublicText(value) {
        if (navigator.clipboard && typeof navigator.clipboard.writeText === 'function') {
          await navigator.clipboard.writeText(value);
          return;
        }
        var textarea = document.createElement('textarea');
        textarea.value = value;
        textarea.setAttribute('readonly', '');
        textarea.style.position = 'fixed';
        textarea.style.opacity = '0';
        textarea.style.pointerEvents = 'none';
        document.body.appendChild(textarea);
        textarea.select();
        var copied = document.execCommand('copy');
        textarea.remove();
        if (!copied) throw new Error('COPY_UNAVAILABLE');
      }
      function openPublicArchiveHref(href) {
        if (!href) return;
        if (typeof window.__publicArchiveNavigateTo === 'function') {
          window.__publicArchiveNavigateTo(href);
          return;
        }
        window.location.href = href;
      }
      function setDetailActionState(button, label, icon, message) {
        var labelNode = button.querySelector('[data-action-label]');
        var iconNode = button.querySelector('[data-action-icon]');
        if (labelNode) labelNode.textContent = label;
        if (iconNode) iconNode.innerHTML = icon;
        button.classList.add('is-complete');
        var status = document.querySelector('[data-tool-status]');
        if (status) status.textContent = message || label;
      }
      function resetDetailActionState(button, label, icon, ariaLabel) {
        var labelNode = button.querySelector('[data-action-label]');
        var iconNode = button.querySelector('[data-action-icon]');
        if (labelNode) labelNode.textContent = label;
        if (iconNode) iconNode.innerHTML = icon;
        button.classList.remove('is-complete');
        button.removeAttribute('aria-busy');
        if (ariaLabel) button.setAttribute('aria-label', ariaLabel);
      }
      function answerTextForCopy() {
        var sections = Array.from(document.querySelectorAll('.pa-answer-primary .pa-reading-block'));
        var answer = sections.find(function(section){
          var heading = section.querySelector('h2');
          return heading && heading.textContent.trim() === 'Cevap';
        });
        if (!answer) return '';
        return Array.from(answer.querySelectorAll('p')).map(function(paragraph){
          return paragraph.textContent.trim();
        }).filter(Boolean).join('\\n\\n');
      }
      function bindCopyControls() {
        document.querySelectorAll('[data-copy-answer]').forEach(function(button){
          if (button.dataset.copyBound === 'true') return;
          button.dataset.copyBound = 'true';
          button.addEventListener('click', async function(){
            var defaultIcon = ${JSON.stringify(iconSvg('copy'))};
            var doneIcon = ${JSON.stringify(iconSvg('check'))};
            var answer = answerTextForCopy();
            button.setAttribute('aria-busy', 'true');
            try {
              if (!answer) throw new Error('ANSWER_NOT_FOUND');
              await copyPublicText(answer);
              setDetailActionState(button, 'Cevap kopyalandı', doneIcon, 'Cevap metni panoya kopyalandı.');
            } catch (error) {
              setDetailActionState(button, 'Kopyalanamadı', defaultIcon, 'Cevap kopyalanamadı.');
            }
            button.removeAttribute('aria-busy');
            setTimeout(function(){ resetDetailActionState(button, 'Cevabı Kopyala', defaultIcon, 'Cevap metnini kopyala'); }, 1800);
          });
        });
      }
      function bindShareControls() {
        document.querySelectorAll('[data-share]').forEach(function(button){
          if (button.dataset.shareBound === 'true') return;
          button.dataset.shareBound = 'true';
          button.addEventListener('click', async function(){
            var defaultIcon = ${JSON.stringify(iconSvg('share-2'))};
            var doneIcon = ${JSON.stringify(iconSvg('check'))};
            var question = document.querySelector('.pa-answer-primary .pa-reading-block p');
            var shareData = { title: document.title, text: question ? question.textContent.trim() : document.title, url: window.location.href };
            if (navigator.share) {
              try {
                await navigator.share(shareData);
                setDetailActionState(button, 'Paylaşıldı', doneIcon, 'Paylaşım tamamlandı.');
                setTimeout(function(){ resetDetailActionState(button, 'Paylaş', defaultIcon, 'Bu soru ve cevabın bağlantısını paylaş'); }, 1800);
              } catch (error) {
                if (!error || error.name !== 'AbortError') {
                  try {
                    await copyPublicText(window.location.href);
                    setDetailActionState(button, 'Bağlantı kopyalandı', doneIcon, 'Paylaşım bağlantısı panoya kopyalandı.');
                    setTimeout(function(){ resetDetailActionState(button, 'Paylaş', defaultIcon, 'Bu soru ve cevabın bağlantısını paylaş'); }, 1800);
                  } catch (copyError) {}
                }
              }
            } else {
              try {
                await copyPublicText(window.location.href);
                setDetailActionState(button, 'Bağlantı kopyalandı', doneIcon, 'Paylaşım bağlantısı panoya kopyalandı.');
                setTimeout(function(){ resetDetailActionState(button, 'Paylaş', defaultIcon, 'Bu soru ve cevabın bağlantısını paylaş'); }, 1800);
              } catch (error) {}
            }
          });
        });
      }
      function bindCardLinks() {
        document.querySelectorAll('[data-card-href]').forEach(function(card){
          if (card.dataset.cardBound === 'true') return;
          card.dataset.cardBound = 'true';
          function openCard(event) {
            if (event.target && event.target.closest && event.target.closest('a, button, input, select, textarea')) return;
            var href = card.getAttribute('data-card-href');
            openPublicArchiveHref(href);
          }
          card.addEventListener('click', openCard);
          card.addEventListener('keydown', function(event){
            if (event.key !== 'Enter' && event.key !== ' ') return;
            event.preventDefault();
            var href = card.getAttribute('data-card-href');
            openPublicArchiveHref(href);
          });
        });
      }
      function bindArchiveAlphaIndexes() {
        document.querySelectorAll('[data-alpha-index]').forEach(function(index){
          if (index.dataset.alphaBound === 'true') return;
          index.dataset.alphaBound = 'true';
          var track = index.querySelector('[data-alpha-track]');
          var previous = index.querySelector('[data-alpha-scroll="prev"]');
          var next = index.querySelector('[data-alpha-scroll="next"]');
          if (!track) return;
          var scrollTimer = 0;
          function maxScroll() {
            return Math.max(0, track.scrollWidth - track.clientWidth);
          }
          function updateButtons() {
            var max = maxScroll();
            if (previous) previous.disabled = track.scrollLeft <= 2;
            if (next) next.disabled = track.scrollLeft >= max - 2;
          }
          function scrollDirection(direction) {
            var amount = Math.min(340, Math.max(180, Math.round(track.clientWidth * 0.42)));
            var target = Math.min(maxScroll(), Math.max(0, track.scrollLeft + direction * amount));
            track.scrollLeft = target;
            window.clearTimeout(scrollTimer);
            scrollTimer = window.setTimeout(updateButtons, 320);
          }
          function onScroll() {
            window.clearTimeout(scrollTimer);
            scrollTimer = window.setTimeout(updateButtons, 80);
          }
          function onResize() {
            updateButtons();
          }
          function centerActiveLetter() {
            var active = track.querySelector('.pa-alpha-letter.is-active');
            if (!active) return updateButtons();
            try { active.scrollIntoView({ block: 'nearest', inline: 'center' }); } catch (error) {}
            window.setTimeout(updateButtons, 120);
          }
          function onPreviousClick(event) {
            event.preventDefault();
            scrollDirection(-1);
          }
          function onNextClick(event) {
            event.preventDefault();
            scrollDirection(1);
          }
          if (previous) previous.addEventListener('click', onPreviousClick);
          if (next) next.addEventListener('click', onNextClick);
          track.addEventListener('scroll', onScroll, { passive: true });
          window.addEventListener('resize', onResize, { passive: true });
          updateButtons();
          if (typeof window.requestAnimationFrame === 'function') {
            window.requestAnimationFrame(centerActiveLetter);
          } else {
            window.setTimeout(centerActiveLetter, 0);
          }
          addPageCleanup(function(){
            window.clearTimeout(scrollTimer);
            if (previous) previous.removeEventListener('click', onPreviousClick);
            if (next) next.removeEventListener('click', onNextClick);
            track.removeEventListener('scroll', onScroll);
            window.removeEventListener('resize', onResize);
          });
        });
      }
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
          var running = true;
          var measureTimer = 0;
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
            if (!running) return;
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
          measureTimer = window.setTimeout(measure, 250);
          rafId = window.requestAnimationFrame(loop);
          var pageHideHandler = function(){ if (rafId) window.cancelAnimationFrame(rafId); };
          window.addEventListener('pagehide', pageHideHandler, { once: true });
          addPageCleanup(function(){
            running = false;
            window.clearTimeout(resumeTimer);
            window.clearTimeout(measureTimer);
            if (rafId) window.cancelAnimationFrame(rafId);
            window.removeEventListener('resize', measure);
            window.removeEventListener('load', measure);
            window.removeEventListener('pagehide', pageHideHandler);
          });
        });
      }
      var liveSearchSeed = ${liveSearchSeedJson};
      function normalizeClientSearch(value) {
        return String(value || '')
          .toLocaleLowerCase('tr-TR')
          .normalize('NFD')
          .replace(/[\\u0300-\\u036f]/g, '')
          .replace(/[’'\\\`´]/g, '')
          .replace(/[^\\p{L}\\p{N}\\s]/gu, ' ')
          .replace(/\\s+/g, ' ')
          .trim();
      }
      function clientSearchTokens(value) {
        var normalized = normalizeClientSearch(value);
        if (!normalized) return [];
        var tokens = normalized.split(' ').filter(function(token){ return token.length >= 2; });
        return Array.from(new Set([normalized].concat(tokens)));
      }
      var clientSearchFillerWords = new Set(['acaba', 'anlat', 'anlatir', 'anlatır', 'ara', 'bir', 'bize', 'bu', 'cevap', 'eder', 'ermek', 'etmek', 'gibi', 'gidilir', 'icin', 'için', 'ile', 'mi', 'mı', 'mu', 'mü', 'midir', 'mıdır', 'mudur', 'müdür', 'nasıl', 'nasil', 'ne', 'nedir', 'niye', 'olmak', 'olunur', 'olur', 'sahibi', 'sahip', 'soru', 'var', 've', 'ya', 'yapilir', 'yapılır']);
      function clientSearchIntentTokens(value) {
        var normalized = normalizeClientSearch(value);
        if (!normalized) return [];
        var tokens = normalized.split(' ').filter(function(token){ return token.length >= 2; });
        var intentTokens = tokens.filter(function(token){ return !clientSearchFillerWords.has(token); });
        return intentTokens.length ? intentTokens : tokens;
      }
      function clientSearchTokenForms(token) {
        var value = normalizeClientSearch(token);
        if (!value) return [];
        var forms = [value];
        var suffixes = ['lerinden', 'larından', 'lerden', 'lardan', 'nin', 'nın', 'nun', 'nün', 'in', 'ın', 'un', 'ün', 'den', 'dan', 'ten', 'tan', 'ye', 'ya', 'yi', 'yı', 'yu', 'yü', 'de', 'da', 'te', 'ta', 'ne', 'na', 'ni', 'nı', 'nu', 'nü', 'e', 'a', 'i', 'ı', 'u', 'ü'];
        suffixes.forEach(function(suffix){
          if (value.length > suffix.length + 3 && value.endsWith(suffix)) forms.push(value.slice(0, -suffix.length));
        });
        return Array.from(new Set(forms.filter(function(form){ return form.length >= 3; })));
      }
      function clientSearchTokenMatches(haystack, token) {
        return clientSearchTokenForms(token).some(function(form){ return haystack.includes(form); });
      }
      function localSearchRank(value, query) {
        var haystack = normalizeClientSearch(value);
        var needle = normalizeClientSearch(query);
        if (!haystack || !needle) return 0;
        if (haystack === needle) return 120;
        if (haystack.startsWith(needle)) return 96;
        if (haystack.includes(needle)) return 80;
        var tokens = clientSearchIntentTokens(query);
        if (!tokens.length) return 0;
        var rank = 0;
        tokens.forEach(function(token, index){
          if (!clientSearchTokenMatches(haystack, token)) return;
          rank += 28;
          if (index === 0) rank += 24;
          if (token.length >= 5) rank += 8;
        });
        if (!rank) return 0;
        return Math.min(78, rank);
      }
      function bindLiveSearchControls() {
        document.querySelectorAll('[data-live-search]').forEach(function(shell){
          if (shell.dataset.liveSearchBound === 'true') return;
          shell.dataset.liveSearchBound = 'true';
          var form = shell.querySelector('[data-live-search-form]');
          var input = form ? form.querySelector('input[name="q"]') : null;
          var hint = form ? form.querySelector('[data-live-search-hint]') : null;
          var submitButton = form ? form.querySelector('button[type="submit"]') : null;
          var panel = shell.querySelector('[data-live-search-panel]');
          if (!form || !input || !panel) return;
          var endpoint = form.getAttribute('data-live-search-url') || '${PREVIEW_BASE}/api/public-search';
          var cache = new Map();
          var timer = 0;
          var loadingTimer = 0;
          var hintTimer = 0;
          var requestId = 0;
          var controller = null;
          function routeHref(type, slug) {
            return '${PREVIEW_BASE}/' + (type === 'category' ? 'kategori/' : 'soru/') + encodeURIComponent(slug || '');
          }
          function updateInputState() {
            if (input.value.trim()) form.classList.add('has-value');
            else form.classList.remove('has-value');
          }
          function closePanel() {
            panel.hidden = true;
            input.setAttribute('aria-expanded', 'false');
          }
          function fitPanelToViewport() {
            if (panel.hidden) return;
            if (!window.matchMedia || !window.matchMedia('(max-width: 520px)').matches) {
              panel.style.maxHeight = '';
              return;
            }
            var viewportHeight = window.visualViewport && window.visualViewport.height ? window.visualViewport.height : window.innerHeight;
            var panelTop = panel.getBoundingClientRect().top;
            var bottomLimit = viewportHeight - 16;
            var mobileNav = document.querySelector('.pa-mobile-nav');
            if (mobileNav) {
              var navRect = mobileNav.getBoundingClientRect();
              if (navRect.top > 0 && navRect.top < viewportHeight) bottomLimit = Math.min(bottomLimit, navRect.top - 12);
            }
            var available = Math.floor(bottomLimit - panelTop);
            var maxHeight = Math.max(156, Math.min(360, available));
            panel.style.maxHeight = maxHeight + 'px';
          }
          function openPanel() {
            panel.hidden = false;
            input.setAttribute('aria-expanded', 'true');
            fitPanelToViewport();
          }
          function renderStatus(message) {
            panel.innerHTML = '<p class="pa-live-search-status">' + escapeClientHtml(message) + '</p>';
            openPanel();
          }
          function resultCard(item) {
            var title = escapeClientHtml(item.title || item.name || 'Sonuç');
            var subtitle = escapeClientHtml(item.subtitle || item.snippet || '');
            var pill = escapeClientHtml(item.pill || 'Aç');
            var href = escapeClientHtml(item.href || '#');
            return [
              '<a class="pa-live-search-card" href="' + href + '">',
              '  <span><strong>' + title + '</strong>' + (subtitle ? '<small>' + subtitle + '</small>' : '') + '</span>',
              '  <span class="pa-live-search-pill">' + pill + '</span>',
              '</a>'
            ].join('');
          }
          function renderGroup(title, items) {
            if (!Array.isArray(items) || !items.length) return '';
            return [
              '<div class="pa-live-search-group">',
              '  <p class="pa-live-search-heading">' + escapeClientHtml(title) + '</p>',
              items.map(resultCard).join(''),
              '</div>'
            ].join('');
          }
          function renderResults(data) {
            var groups = data && data.groups ? data.groups : {};
            var html = [
              renderGroup('Konular', groups.categories),
              renderGroup('En uygun sorular', groups.questions),
              renderGroup('Cevaplarda geçenler', groups.answers)
            ].filter(Boolean).join('');
            if (!html) {
              renderStatus('Bu aramada henüz güçlü bir eşleşme görünmüyor. Enter ile detaylı arama yapabilirsiniz.');
              return;
            }
            panel.innerHTML = html;
            openPanel();
          }
          function localResults(query) {
            var categoryItems = (liveSearchSeed.categories || [])
              .map(function(item){
                return {
                  item: item,
                  rank: localSearchRank(item.text || item.title || item.slug, query)
                };
              })
              .filter(function(result){ return result.rank > 0; })
              .sort(function(a, b){ return b.rank - a.rank || Number(b.item.count || 0) - Number(a.item.count || 0) || String(a.item.title || '').localeCompare(String(b.item.title || ''), 'tr'); })
              .slice(0, 5)
              .map(function(result){
                return {
                  href: routeHref('category', result.item.slug),
                  title: result.item.title,
                  subtitle: result.item.subtitle,
                  pill: 'Konu'
                };
              });
            var questionItems = (liveSearchSeed.questions || [])
              .map(function(item){
                return {
                  item: item,
                  rank: localSearchRank(item.text || item.title || item.slug, query)
                };
              })
              .filter(function(result){ return result.rank > 0; })
              .sort(function(a, b){ return b.rank - a.rank || Number(b.item.count || 0) - Number(a.item.count || 0) || String(a.item.title || '').localeCompare(String(b.item.title || ''), 'tr'); })
              .slice(0, 5)
              .map(function(result){
                return {
                  href: routeHref('question', result.item.slug),
                  title: result.item.title,
                  subtitle: result.item.subtitle,
                  pill: 'Oku'
                };
              });
            return {
              available: true,
              query: query,
              groups: {
                categories: categoryItems,
                questions: questionItems,
                answers: []
              }
            };
          }
          function renderInstantResults(query) {
            var data = localResults(query);
            var total = (data.groups.categories || []).length + (data.groups.questions || []).length;
            if (!total) return false;
            renderResults(data);
            return true;
          }
          async function runSearch() {
            var query = input.value.trim();
            if (query.length < 2) {
              closePanel();
              return;
            }
            var key = normalizeClientSearch(query);
            if (cache.has(key)) {
              renderResults(cache.get(key));
              return;
            }
            if (controller) controller.abort();
            var currentRequest = ++requestId;
            controller = new AbortController();
            window.clearTimeout(loadingTimer);
            loadingTimer = window.setTimeout(function(){
              if (panel.querySelector('.pa-live-search-card')) return;
              renderStatus('Aranıyor...');
            }, 260);
            try {
              var url = endpoint + (endpoint.indexOf('?') === -1 ? '?' : '&') + 'q=' + encodeURIComponent(query);
              var response = await fetch(url, {
                signal: controller.signal,
                headers: { Accept: 'application/json' }
              });
              var data = await response.json().catch(function(){ return {}; });
              if (!response.ok || data.available === false) throw new Error(data.error || 'Arama alınamadı.');
              if (currentRequest !== requestId) return;
              window.clearTimeout(loadingTimer);
              cache.set(key, data);
              renderResults(data);
            } catch (error) {
              if (error && error.name === 'AbortError') return;
              window.clearTimeout(loadingTimer);
              if (panel.querySelector('.pa-live-search-card')) return;
              renderStatus('Arama şu anda alınamadı. Enter ile arama sayfasını açabilirsiniz.');
            }
          }
          function scheduleSearch() {
            window.clearTimeout(timer);
            window.clearTimeout(loadingTimer);
            updateInputState();
            var query = input.value.trim();
            if (query.length < 2) {
              closePanel();
              return;
            }
            var hasInstantResults = renderInstantResults(query);
            timer = window.setTimeout(runSearch, hasInstantResults ? 60 : 120);
          }
          function searchPageUrl(query) {
            var url = new URL(form.getAttribute('action') || '${PREVIEW_BASE}/arama', window.location.href);
            url.searchParams.set('q', query);
            return url;
          }
          function goToSearchPage(query) {
            var url = searchPageUrl(query);
            closePanel();
            if (controller) controller.abort();
            if (typeof window.__publicArchiveNavigateTo === 'function') {
              window.__publicArchiveNavigateTo(url.href);
              return;
            }
            window.location.href = url.href;
          }
          function submitLiveSearch(event) {
            if (event) event.preventDefault();
            updateInputState();
            var query = input.value.trim();
            if (query.length < 2) {
              input.focus();
              closePanel();
              return;
            }
            renderInstantResults(query);
            goToSearchPage(query);
          }
          function bindAnimatedHint() {
            if (!hint) return;
            var examples = Array.isArray(liveSearchSeed.examples) && liveSearchSeed.examples.length ? liveSearchSeed.examples : ['Soru veya kategori arayın...'];
            var reducedMotion = window.matchMedia && window.matchMedia('(prefers-reduced-motion: reduce)').matches;
            if (reducedMotion) {
              hint.textContent = 'Soru veya kategori arayın...';
              return;
            }
            var exampleIndex = 0;
            var charIndex = 0;
            var deleting = false;
            function tick() {
              updateInputState();
              if (input.value.trim()) {
                hint.textContent = '';
                hintTimer = window.setTimeout(tick, 450);
                return;
              }
              var example = examples[exampleIndex % examples.length];
              hint.textContent = example.slice(0, charIndex);
              var delay = deleting ? 34 : 72;
              if (!deleting && charIndex < example.length) {
                charIndex += 1;
              } else if (!deleting) {
                deleting = true;
                delay = 1400;
              } else if (charIndex > 0) {
                charIndex -= 1;
              } else {
                deleting = false;
                exampleIndex += 1;
                delay = 260;
              }
              hintTimer = window.setTimeout(tick, delay);
            }
            tick();
          }
          updateInputState();
          bindAnimatedHint();
          form.addEventListener('click', function(event){
            if (submitButton && submitButton.contains(event.target)) return;
            input.focus();
          });
          form.addEventListener('submit', submitLiveSearch);
          input.addEventListener('input', scheduleSearch);
          input.addEventListener('focus', function(){
            updateInputState();
            if (input.value.trim().length >= 2) scheduleSearch();
          });
          input.addEventListener('blur', updateInputState);
          input.addEventListener('keydown', function(event){
            if (event.key === 'Escape') closePanel();
            if (event.key === 'Enter') {
              event.preventDefault();
              submitLiveSearch(event);
            }
          });
          window.addEventListener('resize', fitPanelToViewport, { passive: true });
          if (window.visualViewport) window.visualViewport.addEventListener('resize', fitPanelToViewport, { passive: true });
          function onDocumentClick(event) {
            if (!shell.contains(event.target)) closePanel();
          }
          document.addEventListener('click', onDocumentClick);
          addPageCleanup(function(){
            window.clearTimeout(timer);
            window.clearTimeout(loadingTimer);
            window.clearTimeout(hintTimer);
            if (controller) controller.abort();
            window.removeEventListener('resize', fitPanelToViewport);
            if (window.visualViewport) window.visualViewport.removeEventListener('resize', fitPanelToViewport);
            document.removeEventListener('click', onDocumentClick);
          });
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
        var observer = null;
        var fallbackTimer = 0;
        if ('IntersectionObserver' in window) {
          observer = new IntersectionObserver(function(entries){
            if (entries.some(function(entry){ return entry.isIntersecting; })) {
              observer.disconnect();
              startCounters();
            }
          }, { threshold: 0.35, rootMargin: '0px 0px -8% 0px' });
          observer.observe(section);
        } else {
          fallbackTimer = window.setTimeout(startCounters, 300);
        }
        addPageCleanup(function(){
          if (observer) observer.disconnect();
          window.clearTimeout(fallbackTimer);
        });
      }
      function bindScrollTopControl() {
        var button = document.querySelector('[data-scroll-top]');
        if (!button) return;
        var ticking = false;
        function update() {
          var visible = window.scrollY > 420;
          button.setAttribute('data-visible', visible ? 'true' : 'false');
          button.setAttribute('aria-hidden', visible ? 'false' : 'true');
          button.tabIndex = visible ? 0 : -1;
          ticking = false;
        }
        function onScroll() {
          if (ticking) return;
          ticking = true;
          window.requestAnimationFrame(update);
        }
        function onClick() {
          window.scrollTo({ top: 0, behavior: 'smooth' });
          button.blur();
        }
        window.addEventListener('scroll', onScroll, { passive: true });
        window.addEventListener('resize', update, { passive: true });
        button.addEventListener('click', onClick);
        update();
        addPageCleanup(function(){
          window.removeEventListener('scroll', onScroll);
          window.removeEventListener('resize', update);
          button.removeEventListener('click', onClick);
        });
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
      function linkifyPublicSubmissionAnswer(value) {
        var escaped = escapeClientHtml(value || '');
        return escaped.replace(/https?:\\/\\/[^\\s<>"']+/g, function(url) {
          var cleanUrl = url;
          var trailing = '';
          while (/[.,;:!?)]$/.test(cleanUrl)) {
            trailing = cleanUrl.slice(-1) + trailing;
            cleanUrl = cleanUrl.slice(0, -1);
          }
          return '<a class="pa-user-answer-link" href="' + cleanUrl + '" target="_blank" rel="noopener noreferrer">' + cleanUrl + '</a>' + trailing;
        });
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
        var answer = linkifyPublicSubmissionAnswer(item.answer_text || '');
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
        var unseen = Math.max(0, Number(count || 0));
        var active = unseen > 0;
        document.querySelectorAll('[data-account-notice-dot]').forEach(function(dot){
          dot.hidden = !active;
          dot.dataset.count = String(unseen);
          dot.setAttribute('aria-hidden', active ? 'false' : 'true');
        });
        document.querySelectorAll('[data-account-button]').forEach(function(button){
          button.setAttribute('aria-label', active ? 'Hesabım, ' + unseen + ' yeni cevap' : 'Hesabım');
          button.toggleAttribute('data-has-notice', active);
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
        addPageCleanup(function(){
          window.removeEventListener('scroll', update);
        });
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
            if (status) status.textContent = 'Sorunuz kaydedildi. Gönderdiğiniz sorular bölümünde görünecek.';
            if (window.__publicArchiveSession) await loadPublicUserQuestions(window.__publicArchiveSession);
            var questionsSection = document.querySelector('[data-user-questions]');
            if (questionsSection) {
              questionsSection.hidden = false;
              window.setTimeout(function(){
                try { questionsSection.scrollIntoView({ behavior: 'smooth', block: 'start' }); } catch (error) {}
              }, 120);
            }
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
        var navigationFallbackMs = 900;
        var maxCachedHtmlLength = 240000;
        var cachePrefix = 'dsca-page-cache:v13:';
        var inflight = {};
        function cleanPath(pathname) {
          return String(pathname || '/').replace(/\\/+$/, '') || '/';
        }
        function relativePath(url) {
          var path = cleanPath(url.pathname);
          var base = '${PREVIEW_BASE}' || '';
          return base ? cleanPath(path.slice(base.length) || '/') : path;
        }
        function isSafeRoute(url) {
          if (!url || url.origin !== window.location.origin) return false;
          var base = '${PREVIEW_BASE}' || '';
          if (base && !cleanPath(url.pathname).startsWith(base)) return false;
          var relative = relativePath(url);
          if (relative.startsWith('/api') || relative.startsWith('/auth') || relative.startsWith('/assets')) return false;
          if (/\\.(png|jpe?g|webp|svg|ico|css|js|json|xml|txt)$/i.test(relative)) return false;
          return true;
        }
        function isCacheableRoute(url) {
          return isSafeRoute(url);
        }
        function isFastLink(anchor) {
          if (!anchor || anchor.target || anchor.hasAttribute('download')) return false;
          if (anchor.closest('[data-no-fast-nav], [data-share], [data-copy-answer]')) return false;
          try {
            var url = new URL(anchor.href, window.location.href);
            if (!isSafeRoute(url)) return false;
            if (url.pathname === window.location.pathname && url.search === window.location.search && url.hash) return false;
            return Boolean(anchor.closest('.pa-page, .pa-mobile-nav'));
          } catch (error) {
            return false;
          }
        }
        function cacheKey(url) {
          return cachePrefix + url.pathname + url.search;
        }
        function readCached(url) {
          if (!isCacheableRoute(url)) return '';
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
          if (!isCacheableRoute(url)) return;
          if (!html || !/<html[\\s>]/i.test(html)) return;
          if (String(html).length > maxCachedHtmlLength) return;
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
        function freezeRouteBackground() {
          try {
            var styles = window.getComputedStyle(document.documentElement);
            var bg = (styles && styles.getPropertyValue('--pa-bg') || '').trim();
            if (!bg) bg = document.documentElement.getAttribute('data-theme') === 'dark' ? '#0D1412' : '#F7F3EA';
            document.documentElement.style.backgroundColor = bg;
            if (document.body) document.body.style.backgroundColor = bg;
          } catch (error) {}
        }
        function setPending(anchor, url) {
          freezeRouteBackground();
          root.setAttribute('data-pa-navigating', 'true');
          function setMobileNavIndex(mobileNav, nextIndex) {
            if (!mobileNav) return;
            var value = String(Math.max(0, nextIndex));
            var current = mobileNav.getAttribute('data-active-index');
            mobileNav.setAttribute('data-active-index', value);
            if (current && current !== value) {
              mobileNav.classList.remove('is-gliding');
              void mobileNav.offsetWidth;
              mobileNav.classList.add('is-gliding');
              window.clearTimeout(mobileNav.__paGlideTimer);
              mobileNav.__paGlideTimer = window.setTimeout(function(){
                mobileNav.classList.remove('is-gliding');
              }, 740);
            }
          }
          document.querySelectorAll('.pa-bottom-link, .pa-desktop-nav a').forEach(function(link){
            link.classList.remove('is-pending');
            try {
              var linkUrl = new URL(link.href, window.location.href);
              var active = cleanPath(linkUrl.pathname) === cleanPath(url.pathname);
              link.classList.toggle('is-active', active);
              var mobileNav = link.closest('.pa-mobile-nav');
              if (mobileNav && active) {
                var links = Array.from(mobileNav.querySelectorAll('.pa-bottom-link'));
                setMobileNavIndex(mobileNav, links.indexOf(link));
              }
            } catch (error) {}
          });
          if (anchor) anchor.classList.add('is-pending');
        }
        function syncHead(nextDoc) {
          var nextTitle = nextDoc.querySelector('title');
          if (nextTitle) document.title = nextTitle.textContent || document.title;
          var canonicalSelector = 'link[rel="' + 'canonical"]';
          var managedSelector = [
            'meta[name="robots"]',
            'meta[name="description"]',
            canonicalSelector,
            'meta[property^="og:"]',
            'meta[name^="twitter:"]',
            'script[type="application/ld+json"]'
          ].join(',');
          document.head.querySelectorAll(managedSelector).forEach(function(node){ node.remove(); });
          var beforeNode = document.head.querySelector('link[rel="icon"], link[rel="apple-touch-icon"], link[rel="manifest"], link[rel="preconnect"], link[rel="stylesheet"], script:not([data-pa-theme-boot])');
          nextDoc.head.querySelectorAll(managedSelector).forEach(function(node){
            document.head.insertBefore(document.importNode(node, true), beforeNode || null);
          });
        }
        function syncBodyState(nextDoc) {
          var nextQuestionSlug = nextDoc.body ? nextDoc.body.getAttribute('data-question-slug') : '';
          if (nextQuestionSlug) document.body.setAttribute('data-question-slug', nextQuestionSlug);
          else document.body.removeAttribute('data-question-slug');
        }
        function replaceNode(selector, nextDoc) {
          var current = document.querySelector(selector);
          var next = nextDoc.querySelector(selector);
          if (!current || !next) return false;
          current.replaceWith(document.importNode(next, true));
          return true;
        }
        function scrollToRouteTarget(url) {
          var hash = decodeURIComponent(String(url.hash || '').replace(/^#/, ''));
          if (hash) {
            var target = document.getElementById(hash);
            if (target) {
              window.requestAnimationFrame(function(){ target.scrollIntoView({ block: 'start' }); });
              return;
            }
          }
          try { window.scrollTo({ top: 0, left: 0, behavior: 'auto' }); } catch (error) { window.scrollTo(0, 0); }
        }
        function replacePublicArchiveShell(url, html, mode) {
          if (!html || !/<html[\\s>]/i.test(html)) {
            window.location.href = url.href;
            return;
          }
          var nextDoc = new DOMParser().parseFromString(html, 'text/html');
          if (!nextDoc || !nextDoc.querySelector('.pa-page') || !nextDoc.querySelector('.pa-mobile-nav')) {
            window.location.href = url.href;
            return;
          }
          if (mode === 'push') pageStack().pushState({ paFast: true }, '', url.href);
          else if (mode === 'replace') pageStack().replaceState({ paFast: true }, '', url.href);
          freezeRouteBackground();
          cleanupPublicArchivePage();
          syncHead(nextDoc);
          syncBodyState(nextDoc);
          if (!replaceNode('.pa-page', nextDoc) || !replaceNode('.pa-mobile-nav', nextDoc) || !replaceNode('[data-scroll-top]', nextDoc)) {
            window.location.href = url.href;
            return;
          }
          root.removeAttribute('data-pa-navigating');
          scrollToRouteTarget(url);
          initializePublicArchivePage();
        }
        function prefetchUrl(url) {
          if (!isSafeRoute(url)) return;
          if (readCached(url)) return;
          fetchPage(url).catch(function(){});
        }
        function prefetchHref(href) {
          if (!href) return;
          try {
            prefetchUrl(new URL(href, window.location.href));
          } catch (error) {}
        }
        function prefetch(anchor) {
          if (!isFastLink(anchor)) return;
          try {
            prefetchUrl(new URL(anchor.href, window.location.href));
          } catch (error) {}
        }
        function prefetchCard(card) {
          if (!card) return;
          prefetchHref(card.getAttribute('data-card-href'));
        }
        function loadMoreArchive(anchor, event) {
          if (!anchor || !anchor.hasAttribute('data-load-more')) return false;
          if (event.metaKey || event.ctrlKey || event.shiftKey || event.altKey || event.button > 0) return false;
          event.preventDefault();
          var list = document.querySelector('[data-archive-results]');
          var shell = document.querySelector('[data-load-more-shell]');
          if (!list || !shell) {
            navigate(anchor, event);
            return true;
          }
          var url = new URL(anchor.href, window.location.href);
          anchor.setAttribute('aria-busy', 'true');
          anchor.classList.add('is-loading');
          fetchPage(url).then(function(html){
            var nextDoc = new DOMParser().parseFromString(html, 'text/html');
            var nextList = nextDoc.querySelector('[data-archive-results]');
            var nextShell = nextDoc.querySelector('[data-load-more-shell]');
            if (!nextList) throw new Error('Yeni kayıt listesi bulunamadı');
            nextList.querySelectorAll('.pa-question-card').forEach(function(card){
              list.appendChild(document.importNode(card, true));
            });
            if (nextShell && shell.parentNode) shell.replaceWith(document.importNode(nextShell, true));
            else shell.remove();
            try { pageStack().replaceState({ paFast: true }, '', url.href); } catch (error) {}
            bindCardLinks();
            loadReadCounts();
          }).catch(function(){
            window.location.href = url.href;
          }).finally(function(){
            anchor.removeAttribute('aria-busy');
            anchor.classList.remove('is-loading');
          });
          return true;
        }
        function navigate(anchor, event) {
          if (!isFastLink(anchor)) return;
          if (event.metaKey || event.ctrlKey || event.shiftKey || event.altKey || event.button > 0) return;
          var url = new URL(anchor.href, window.location.href);
          event.preventDefault();
          var cachedHtml = readCached(url);
          var fromMobileNav = Boolean(anchor.closest && anchor.closest('.pa-mobile-nav'));
          var startedAt = Date.now();
          setPending(anchor, url);
          if (!cachedHtml) {
            var fallbackTimer = window.setTimeout(function(){
              window.location.href = url.href;
            }, navigationFallbackMs);
            fetchPage(url).then(function(html){
              window.clearTimeout(fallbackTimer);
              var elapsed = Date.now() - startedAt;
              var wait = fromMobileNav ? Math.max(0, 260 - elapsed) : 0;
              window.setTimeout(function(){
                try {
                  replacePublicArchiveShell(url, html, 'push');
                } catch (error) {
                  window.location.href = url.href;
                }
              }, wait);
            }).catch(function(){
              window.clearTimeout(fallbackTimer);
              window.location.href = url.href;
            });
            return;
          }
          var elapsed = Date.now() - startedAt;
          var wait = fromMobileNav ? Math.max(0, 260 - elapsed) : 0;
          window.setTimeout(function(){
            try {
              replacePublicArchiveShell(url, cachedHtml, 'push');
            } catch (error) {
              window.location.href = url.href;
            }
          }, wait);
        }
        window.__publicArchiveNavigateTo = function(href) {
          try {
            var url = new URL(href, window.location.href);
            if (!isSafeRoute(url)) {
              window.location.href = url.href;
              return;
            }
            setPending(null, url);
            var cachedHtml = readCached(url);
            if (cachedHtml) {
              try {
                replacePublicArchiveShell(url, cachedHtml, 'push');
              } catch (error) {
                window.location.href = url.href;
              }
              return;
            }
            var fallbackTimer = window.setTimeout(function(){
              window.location.href = url.href;
            }, navigationFallbackMs);
            fetchPage(url).then(function(html){
              window.clearTimeout(fallbackTimer);
              try {
                replacePublicArchiveShell(url, html, 'push');
              } catch (error) {
                window.location.href = url.href;
              }
            }).catch(function(){
              window.clearTimeout(fallbackTimer);
              window.location.href = url.href;
            });
          } catch (error) {
            window.location.href = href;
          }
        };
        function eventAnchor(event) {
          return event && event.target && event.target.closest ? event.target.closest('a[href]') : null;
        }
        function eventCard(event) {
          if (!event || !event.target || !event.target.closest) return null;
          if (event.target.closest('a, button, input, select, textarea')) return null;
          return event.target.closest('[data-card-href]');
        }
        var warm = function(){
          var seen = {};
          var candidates = [];
          function addCandidate(href) {
            if (!href || seen[href]) return;
            seen[href] = true;
            candidates.push(href);
          }
          function addSelector(selector) {
            Array.prototype.slice.call(document.querySelectorAll(selector)).forEach(function(element){
              if (element.matches && element.matches('a[href]')) {
                if (isFastLink(element)) addCandidate(element.href);
                return;
              }
              var href = element.getAttribute && element.getAttribute('data-card-href');
              if (href) {
                try {
                  addCandidate(new URL(href, window.location.href).href);
                } catch (error) {}
              }
            });
          }
          addSelector('[data-prefetch-priority]');
          addSelector('.pa-archive-shortcut, .pa-reading-card');
          addSelector('.pa-question-card[data-card-href], .pa-evidence-card[data-card-href]');
          addSelector('.pa-mobile-nav a[href]');
          addSelector('.pa-page a[href], .pa-mobile-nav a[href]');
          candidates.slice(0, 22).forEach(prefetchHref);
        };
        function observePrefetchCandidates() {
          if (!('IntersectionObserver' in window)) return;
          var observer = new IntersectionObserver(function(entries){
            entries.forEach(function(entry){
              if (!entry.isIntersecting && entry.intersectionRatio <= 0) return;
              var element = entry.target;
              if (element.matches && element.matches('a[href]')) prefetch(element);
              else prefetchCard(element);
              observer.unobserve(element);
            });
          }, { rootMargin: '1200px 0px 1200px 0px', threshold: 0.01 });
          Array.prototype.slice.call(document.querySelectorAll('[data-prefetch-priority], .pa-archive-shortcut, .pa-reading-card, .pa-question-card[data-card-href], .pa-evidence-card[data-card-href]'))
            .forEach(function(element){ observer.observe(element); });
        }
        if (!window.__publicArchiveFastNavBound) {
          window.__publicArchiveFastNavBound = true;
          document.addEventListener('pointerover', function(event){
            var anchor = eventAnchor(event);
            if (anchor) prefetch(anchor);
            else prefetchCard(eventCard(event));
          }, { passive: true });
          document.addEventListener('focusin', function(event){
            var anchor = eventAnchor(event);
            if (anchor) prefetch(anchor);
            else prefetchCard(eventCard(event));
          }, { passive: true });
          document.addEventListener('touchstart', function(event){
            var anchor = eventAnchor(event);
            if (anchor) {
              prefetch(anchor);
              if (anchor.closest && anchor.closest('.pa-mobile-nav') && isFastLink(anchor)) {
                try {
                  setPending(anchor, new URL(anchor.href, window.location.href));
                } catch (error) {}
              }
            } else {
              prefetchCard(eventCard(event));
            }
          }, { passive: true });
          document.addEventListener('click', function(event){
            var anchor = eventAnchor(event);
            if (anchor && loadMoreArchive(anchor, event)) return;
            if (anchor) navigate(anchor, event);
          });
          try { pageStack().replaceState({ paFast: true }, '', window.location.href); } catch (error) {}
          window.addEventListener('popstate', function(){
            var url = new URL(window.location.href);
            if (!isSafeRoute(url)) return;
            root.setAttribute('data-pa-navigating', 'true');
            fetchPage(url).then(function(html){
              replacePublicArchiveShell(url, html, 'none');
            }).catch(function(){
              window.location.reload();
            });
          });
        }
        window.setTimeout(warm, 180);
        observePrefetchCandidates();
        if ('requestIdleCallback' in window) window.requestIdleCallback(warm, { timeout: 700 });
        else window.setTimeout(warm, 700);
      }
      function initializePublicArchivePage() {
        applyTheme(document.documentElement.getAttribute('data-theme') || 'dark');
        bindThemeControls();
        bindCopyControls();
        bindShareControls();
        bindCardLinks();
        loadReadCounts();
        trackQuestionRead();
        trackPublicVisit();
        bindArchiveAlphaIndexes();
        bindConceptSliders();
        bindLiveSearchControls();
        bindActiveStatsCounters();
        bindScrollTopControl();
        bindShrinkingHeader();
        bindPublicAuthTabs();
        bindPublicEmailAuth();
        bindFastPublicNavigation();
        loadPublicSession().then(function(session){
          window.__publicArchiveSession = session;
          renderSessionUi(session);
          loadPublicUserQuestions(session);
        });
        bindQuestionForm();
      }
      initializePublicArchivePage();
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
    if (pathname === `${PREVIEW_BASE}/one-cikan-sorular`) return renderQuestionCollection('featured', query);
    if (pathname === `${PREVIEW_BASE}/son-yayinlanan-sorular`) return renderQuestionCollection('latest', query);
    if (pathname === `${PREVIEW_BASE}/cok-okunan-cevaplar`) return renderQuestionCollection('popular', query);
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
    const topicArticleMatch = pathname.match(publicArchiveRoutePattern('konu-rehberi'));
    if (topicArticleMatch) return renderTopicGuideArticle(topicArticleMatch[1]);
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
      const cleanRoutePath = String(routePath || '').replace(/^\/+/, '');
      if (!noindex && cleanRoutePath.startsWith('soru/')) {
        res.set('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate');
      }
      sendRendered(res, renderPublicArchivePreviewRoute(routeFor(routePath), query, {
        ...(archiveData || {}),
        basePath,
        noindex
      }));
    } catch (error) {
      if (error?.code === 'PUBLIC_ARCHIVE_DATA_UNAVAILABLE') {
        res.set('X-Robots-Tag', 'noindex, nofollow');
        res.set('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate');
        sendRendered(res, renderPublicArchiveUnavailableRoute(routeFor(routePath), query, { basePath }));
        return;
      }
      next(error);
    }
  }
  router.use((req, res, next) => {
    if (noindex) {
      res.set('X-Robots-Tag', 'noindex, nofollow');
      res.set('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate');
    } else if (req.method === 'GET' || req.method === 'HEAD') {
      res.set('Cache-Control', PUBLIC_ARCHIVE_HTML_CACHE);
    }
    next();
  });
  router.use('/assets', express.static(assetDir, {
    etag: true,
    immutable: !noindex,
    index: false,
    maxAge: noindex ? 0 : '1y',
    setHeaders(res) {
      res.setHeader('Cache-Control', noindex ? 'no-store, no-cache, must-revalidate, proxy-revalidate' : PUBLIC_ARCHIVE_STATIC_CACHE);
    }
  }));
  router.get('/public-archive.css', (req, res) => {
    res.set('Cache-Control', noindex ? 'no-store, no-cache, must-revalidate, proxy-revalidate' : PUBLIC_ARCHIVE_STATIC_CACHE);
    res.type('text/css').sendFile(cssFile);
  });
  router.get(['/', ''], (req, res, next) => sendRoute(req, res, next, ''));
  router.get('/arsiv', (req, res, next) => sendRoute(req, res, next, 'arsiv', {
    harf: req.query.harf || '',
    kategori: req.query.kategori || '',
    kategoriAra: req.query.kategoriAra || '',
    sayfa: req.query.sayfa || ''
  }));
  router.get('/one-cikan-sorular', (req, res, next) => sendRoute(req, res, next, 'one-cikan-sorular', { sayfa: req.query.sayfa || '' }));
  router.get('/son-yayinlanan-sorular', (req, res, next) => sendRoute(req, res, next, 'son-yayinlanan-sorular', { sayfa: req.query.sayfa || '' }));
  router.get('/cok-okunan-cevaplar', (req, res, next) => sendRoute(req, res, next, 'cok-okunan-cevaplar', { sayfa: req.query.sayfa || '' }));
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
  router.get('/konu-rehberi/:slug', (req, res, next) => sendRoute(req, res, next, `konu-rehberi/${req.params.slug}`));
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
  renderPublicArchiveUnavailableRoute,
  renderPublicArchivePreviewRoute,
  publicArchiveFixtures
};
