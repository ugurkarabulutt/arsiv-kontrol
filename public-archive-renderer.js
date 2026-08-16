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
    ['Ara', PREVIEW_BASE + '/arama#arama', 'search'],
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
      <input id="pa-search-input" name="q" value="${escapeHtml(value)}" placeholder="Soru veya kavram arayın..." autocomplete="off" inputmode="search" enterkeyhint="search" aria-label="Sorunuzu veya kavramınızı yazın">
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
        <span>Öne çıkan kavramlar</span>
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
        <span>Tüm soru ve cevapları tek sayfada inceleyin.</span>
      </div>
      <span class="pa-archive-shortcut-link">Arşive Git ${iconSvg('arrow-right', 'pa-cta-icon')}</span>
    </a>
  `;
}

function archiveCountLabel(count) {
  return Number(count || 0).toLocaleString('tr-TR');
}

function activeArchiveStatsBand(entries = []) {
  const questionCount = entries.length;
  const answerCount = entries.filter(entry => Array.isArray(entry.answer)
    ? entry.answer.some(paragraph => String(paragraph || '').trim())
    : String(entry.answer || entry.answerText || entry.answer_text || '').trim()).length;
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
      <p>Cevap metninde atıf yapılan ayetler:</p>
      <div class="pa-source-references">
        ${references.map(reference => {
          const href = `${PREVIEW_BASE}/arama?q=${encodeURIComponent(reference.label)}`;
          return `<a class="pa-source-reference" href="${escapeHtml(href)}" data-source-reference="${escapeHtml(reference.label)}">${escapeHtml(reference.label)}</a>`;
        }).join('')}
      </div>
    </aside>
  `;
}

function questionCard(entry, options = {}) {
  const cardOptions = typeof options === 'boolean' ? { compact: options } : options;
  const compact = Boolean(cardOptions.compact);
  const showMeta = cardOptions.showMeta !== false;
  const strongCta = Boolean(cardOptions.strongCta);
  const category = categoryFor(entry);
  const topics = topicsFor(entry);
  const visibleTopics = topics.filter(topic => !category || topic.slug !== category.slug);
  const countNode = readCountNode(entry);
  const href = `${PREVIEW_BASE}/soru/${escapeHtml(entry.slug)}`;
  return `
    <article class="pa-question-card${compact ? ' is-compact' : ''}${strongCta ? ' has-strong-cta' : ''}" data-card-href="${href}" role="link" tabindex="0" aria-label="${escapeHtml(entry.title)}">
      <span class="pa-card-icon">${iconSvg(questionIconName(entry, category, topics))}</span>
      <a class="pa-question-title" href="${href}">${escapeHtml(entry.title)}</a>
      ${showMeta ? `<div class="pa-card-meta">
        ${category ? chip(category.name, `${PREVIEW_BASE}/kategori/${category.slug}`) : ''}
        ${visibleTopics.slice(0, 2).map(topic => chip(topic.name, `${PREVIEW_BASE}/konu/${topic.slug}`)).join('')}
      </div>` : ''}
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
        <p>Her cevap, ilgili kavramlarla birlikte anlam kazanır. Sorularınız Dr. Abdulcabbar Boran tarafından Kur’an ve Hadis-i Şerif ışığında cevaplandırılır; her cevap, ilgili konu ve kavramlarla birlikte arşivlenir. Böylece yalnızca aradığınız sorunun cevabına değil; sorularınızla ilgili bağlantılı kavramlara ve bu kavramlarla ilgili diğer sorulara da kolayca ulaşabilirsiniz.</p>
      </div>
      ${stillLife()}
    </section>
  `;
}

function renderHome() {
  const featured = publicArchiveFixtures.qa.filter(entry => entry.isFeatured).slice(0, 3);
  const latest = [...publicArchiveFixtures.qa].sort((a, b) => String(b.publishedAt).localeCompare(String(a.publishedAt))).slice(0, 3);
  return renderShell({
    active: 'home',
    title: 'Ana Sayfa',
    description: 'Dini Sorular ve Cevaplar Arşivi içinde soru, cevap ve kavramları birlikte okuyun.',
    content: `
      <main class="pa-main">
        <section class="pa-hero">
          <div class="pa-hero-copy">
            <p class="pa-kicker">${escapeHtml(publicArchiveFixtures.brand.sentence)}</p>
            <h1>Sorularınıza, kaynaklarıyla birlikte cevap bulun.</h1>
            <p>Hidayet, mürşid, zikir ve teslimiyet gibi temel kavramlardan başlayın; ilgili soruları, cevapları ve delilleri bir arada okuyun.</p>
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
  return [...publicArchiveFixtures.categories].sort((a, b) => trCollator.compare(a.name || '', b.name || ''));
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
  const search = new URLSearchParams();
  if (params.harf) search.set('harf', params.harf);
  if (params.kategori) search.set('kategori', params.kategori);
  if (params.kategoriAra) search.set('kategoriAra', params.kategoriAra);
  const query = search.toString();
  return `${PREVIEW_BASE}/arsiv${query ? `?${query}` : ''}${params.hash ? `#${params.hash}` : ''}`;
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
                  <span>${entriesForCategory(category.slug).length} soru</span>
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
  const entries = [...publicArchiveFixtures.qa].sort((a, b) => String(b.publishedAt).localeCompare(String(a.publishedAt)));
  const answeredCount = entries.filter(entry => Array.isArray(entry.answer) && entry.answer.length).length || entries.length;
  const categoryIndex = archiveCategoryIndex(query);
  const visibleEntries = categoryIndex.selectedCategory
    ? entries.filter(entry => entry.categorySlug === categoryIndex.selectedCategory.slug)
    : entries;
  const listTitle = categoryIndex.selectedCategory ? `${categoryIndex.selectedCategory.name} soruları` : 'Tüm Sorular';
  return renderShell({
    active: 'archive',
    title: 'Arşiv',
    description: 'Merak ettiğiniz konunun cevaplarına ulaşın.',
    content: `
      <main class="pa-main pa-narrow-main">
        <section class="pa-archive-hero">
          <p class="pa-kicker">Arşiv</p>
          <h1>Merak ettiğiniz konunun cevaplarına ulaşın.</h1>
          <p>Soru ve cevapları kategorilerine göre inceleyebilir, aradığınız konuyu alfabetik olarak kolayca bulabilirsiniz.</p>
          <div class="pa-collection-meta">
            <span>${answeredCount} soru cevap</span>
          </div>
          ${categoryIndex.html}
        </section>
        <section class="pa-section" id="sorular">
          ${sectionHeader(listTitle, categoryIndex.selectedCategory ? 'Tümünü göster' : '', categoryIndex.selectedCategory ? archiveQueryUrl({ harf: categoryIndex.activeLetter, hash: 'sorular' }) : '')}
          ${visibleEntries.length
            ? `<div class="pa-list">${visibleEntries.map(entry => questionCard(entry, true)).join('')}</div>`
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
    description: 'Arşivdeki kavram ve konu başlıkları.',
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
    description: 'Arşivdeki soru-cevap kategorileri.',
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
          category ? { label: category.name, href: `${PREVIEW_BASE}/kategori/${category.slug}` } : { label: 'Soru' }
        ])}
        <article class="pa-answer-layout">
          <div class="pa-answer-primary">
            <h1>${escapeHtml(entry.title)}</h1>
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
    description: 'Soru gönderimi için hesap sayfası.',
    content: `
      <main class="pa-main pa-narrow-main">
        <section class="pa-account-page" data-account-panel>
          <p class="pa-kicker">Hesabım</p>
          <h1>Hesabınızla soru gönderimini takip edin.</h1>
          <p>Google ile devam ettiğinizde gönderdiğiniz sorular size bağlanır. Böylece ileride sorularınızı aynı hesaptan takip edebilirsiniz.</p>
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
    description: 'Arşive soru göndermek için sade form.',
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
                text: 'Benzer cevaplar varsa arama ve kavram sayfaları sizi hızlıca ilgili kayda götürür.'
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
              <small class="pa-field-help">Kategori veya kavram seçmeniz gerekmez; soru arşive alınırken ilgili başlıklarla bağlanır.</small>
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
      heading: 'Soruları kavramlarıyla birlikte okumak için hazırlanmış bir arşiv.',
      copy: [
        'Dini Sorular ve Cevaplar Arşivi, yayınlanan soru ve cevapları ana başlıklar ve kavramlarla birlikte okunur hâle getirir.',
        `${publicArchiveFixtures.brand.authorLine} Sayfalar, okuyucunun aradığı cevaba daha kolay ulaşması için düzenlenir.`
      ],
      points: [
        { title: 'Arama', text: 'Soru başlıkları, cevap metinleri ve kavramlar birlikte aranır.' },
        { title: 'Kavram bağı', text: 'Bir cevap tek başına bırakılmaz; ilgili kavram ve ana başlıklarla birlikte gösterilir.' },
        { title: 'Okuma rahatlığı', text: 'Uzun cevaplar mobil ve masaüstünde sakin bir okuma düzeniyle sunulur.' }
      ]
    },
    'nasil-kullanilir': {
      title: 'Nasıl Kullanılır',
      kicker: 'Nasıl Kullanılır',
      heading: 'Aradığınız cevaba birkaç sade adımla ulaşabilirsiniz.',
      copy: [
        'Önce arama kutusuna merak ettiğiniz soruyu veya kavramı yazın. Sonra ilgili soru kartını açarak cevabı okuyun.',
        'Cevabın yanında görünen kavramlar, aynı konudaki başka sorulara geçmenize yardımcı olur.'
      ],
      points: [
        { title: 'Arayın', text: 'Soru, kavram veya ana başlık yazarak başlayın.' },
        { title: 'Cevabı okuyun', text: 'Soru detayında cevabı, yayın tarihini ve ilgili kavramları birlikte görün.' },
        { title: 'Devam edin', text: 'İlgili sorular ve kavramlar üzerinden okumayı derinleştirin.' }
      ]
    },
    iletisim: {
      title: 'İletişim',
      kicker: 'İletişim',
      heading: 'Arşivle ilgili notlarınızı sade şekilde iletebilirsiniz.',
      copy: [
        'Arşivde bir eksik, yazım hatası veya iletmek istediğiniz bir not fark ederseniz bize bildirebilirsiniz.',
        'Yeni bir dini soru göndermek için Soru Sor sayfasını kullanmanız yeterlidir.'
      ],
      points: [
        { title: 'Arşiv notu', text: 'Sayfa, bağlantı veya yazım hatasıyla ilgili notlarınızı kısa şekilde iletin.' },
        { title: 'Yeni soru', text: 'Dini sorular için Soru Sor sayfasındaki formu kullanın.' },
        { title: 'Mahremiyet', text: 'İletişim veya soru metninde kişisel bilgi paylaşmayın.' }
      ]
    },
    gizlilik: {
      title: 'Gizlilik',
      kicker: 'Gizlilik',
      heading: 'Soru gönderirken mahremiyeti korumak esastır.',
      copy: [
        'Soru gönderirken ad, telefon, adres, özel sağlık bilgisi veya üçüncü kişilere ait mahrem ayrıntılar yazmayın.',
        'Google ile devam etmeniz, gönderdiğiniz soruyu kendi hesabınızla ilişkilendirmek içindir.'
      ],
      points: [
        { title: 'Az bilgi', text: 'Soruyu anlamaya yetmeyen kişisel ayrıntıları yazmayın.' },
        { title: 'Mahremiyet', text: 'Kendinize veya başkasına ait özel bilgileri paylaşmayın.' },
        { title: 'Hesap bağı', text: 'Hesap bilgisi, gönderdiğiniz soruyu takip edebilmeniz için kullanılır.' }
      ]
    },
    'kullanim-kosullari': {
      title: 'Kullanım Koşulları',
      kicker: 'Kullanım',
      heading: 'Arşiv okuma ve soru gönderimi için sade kullanım ilkeleri.',
      copy: [
        'Arşiv; soru-cevap içeriklerini okumak, aramak ve kavramlar üzerinden keşfetmek için sunulur.',
        'Soru gönderimi, cevabın hemen yayınlanacağı veya belirli bir sürede yanıtlanacağı anlamına gelmez.'
      ],
      points: [
        { title: 'Okuma', text: 'Cevapları arşiv sayfalarından okuyabilir, bağlantılarını paylaşabilirsiniz.' },
        { title: 'Soru gönderimi', text: 'Gönderilen sorular içerik ve ihtiyaç durumuna göre ele alınır.' },
        { title: 'Düzen', text: 'Arşivdeki başlıklar ve kavramlar okuyucunun kolay ulaşması için düzenlenir.' }
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
        <section class="pa-info-page">
          <p class="pa-kicker">${escapeHtml(page.kicker)}</p>
          <h1>${escapeHtml(page.heading)}</h1>
          <div class="pa-info-copy">
            ${page.copy.map(paragraph => `<p>${escapeHtml(paragraph)}</p>`).join('')}
          </div>
          ${guideList(page.points || [])}
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
          else if (session.googleConfigured) status.textContent = 'Soru göndermek için Google ile devam edebilirsiniz.';
          else status.textContent = 'Soru gönderimi şu anda açık değil. Arşivi incelemeye devam edebilirsiniz.';
        }
        if (actions && session.loggedIn) {
          actions.innerHTML = '<button class="pa-button is-secondary" type="button" data-public-logout>Çıkış Yap</button><a class="pa-button" href="${PREVIEW_BASE}/soru-sor">Soru Sor</a>';
        }
        if (askSession) {
          if (session.loggedIn && session.user) askSession.textContent = 'Sorunuz ' + (session.user.name || session.user.email) + ' hesabıyla kaydedilecek.';
          else if (session.googleConfigured) askSession.innerHTML = 'Soru göndermek için önce <a href="${PREVIEW_BASE}/auth/google?returnTo=${encodeURIComponent(PREVIEW_BASE + '/soru-sor')}">Google ile oturum açın</a>.';
          else askSession.textContent = 'Soru gönderimi şu anda açık değil. Arşivi incelemeye devam edebilirsiniz.';
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
                if (status) status.innerHTML = 'Soru göndermek için önce <a href="${PREVIEW_BASE}/auth/google?returnTo=${encodeURIComponent(PREVIEW_BASE + '/soru-sor')}">Google ile oturum açın</a>.';
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
      loadReadCounts();
      trackQuestionRead();
      bindConceptSliders();
      bindActiveStatsCounters();
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
  router.get('/arsiv', (req, res, next) => sendRoute(req, res, next, `${PREVIEW_BASE}/arsiv`, {
    harf: req.query.harf || '',
    kategori: req.query.kategori || '',
    kategoriAra: req.query.kategoriAra || ''
  }));
  router.get('/arama', (req, res, next) => sendRoute(req, res, next, `${PREVIEW_BASE}/arama`, { q: req.query.q || '' }));
  router.get('/konular', (req, res, next) => sendRoute(req, res, next, `${PREVIEW_BASE}/konular`));
  router.get('/kategoriler', (req, res, next) => sendRoute(req, res, next, `${PREVIEW_BASE}/kategoriler`));
  router.get('/hesabim', (req, res, next) => sendRoute(req, res, next, `${PREVIEW_BASE}/hesabim`));
  router.get('/soru-sor', (req, res, next) => sendRoute(req, res, next, `${PREVIEW_BASE}/soru-sor`));
  router.get('/hakkimizda', (req, res, next) => sendRoute(req, res, next, `${PREVIEW_BASE}/hakkimizda`));
  router.get('/nasil-kullanilir', (req, res, next) => sendRoute(req, res, next, `${PREVIEW_BASE}/nasil-kullanilir`));
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
