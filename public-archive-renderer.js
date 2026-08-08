const express = require('express');
const path = require('path');
const { publicArchiveFixtures } = require('./public-archive-fixtures');

const PREVIEW_BASE = '/public-preview';
const CSS_PATH = `${PREVIEW_BASE}/public-archive.css`;

const ROUTE_PATHS = [
  PREVIEW_BASE,
  `${PREVIEW_BASE}/arama`,
  `${PREVIEW_BASE}/soru/ornek-soru`,
  `${PREVIEW_BASE}/konu/ornek-kavram`,
  `${PREVIEW_BASE}/kategori/ornek-kategori`,
  `${PREVIEW_BASE}/soru-sor`,
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

function previewActionNav(active) {
  const items = [
    ['Ana Sayfa', PREVIEW_BASE, 'home'],
    ['Arşiv', `${PREVIEW_BASE}/arama`, 'archive'],
    ['Ara', `${PREVIEW_BASE}/arama#arama`, 'search'],
    ['Konular', `${PREVIEW_BASE}/konu/ornek-kavram`, 'topics'],
    ['Soru Sor', `${PREVIEW_BASE}/soru-sor`, 'ask']
  ];
  return items.map(([label, url, key]) => `
    <a class="pa-bottom-link${active === key ? ' is-active' : ''}" href="${escapeHtml(url)}">
      <span class="pa-bottom-icon pa-icon-${escapeHtml(key)}" aria-hidden="true"></span>
      <span>${escapeHtml(label)}</span>
    </a>
  `).join('');
}

function header(active) {
  const nav = [
    ['Ana Sayfa', PREVIEW_BASE, 'home'],
    ['Arşiv', `${PREVIEW_BASE}/arama`, 'archive'],
    ['Konular', `${PREVIEW_BASE}/konu/ornek-kavram`, 'topics'],
    ['Soru Sor', `${PREVIEW_BASE}/soru-sor`, 'ask']
  ];
  const logo = publicArchiveFixtures.brand.logoLines.map(line => `<span>${escapeHtml(line)}</span>`).join('');
  return `
    <header class="pa-header">
      <a class="pa-logo" href="${PREVIEW_BASE}" aria-label="${escapeHtml(publicArchiveFixtures.brand.name)}">${logo}</a>
      <nav class="pa-desktop-nav" aria-label="Ana gezinme">
        ${nav.map(([label, url, key]) => `<a class="${active === key || (active === 'search' && key === 'archive') ? 'is-active' : ''}" href="${escapeHtml(url)}">${escapeHtml(label)}</a>`).join('')}
      </nav>
      <button class="pa-theme-toggle" type="button" data-theme-toggle aria-label="Tema değiştir">
        <span class="pa-theme-toggle-icon" aria-hidden="true"></span>
      </button>
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
        <a href="${PREVIEW_BASE}#baglam">Hakkımızda</a>
        <a href="${PREVIEW_BASE}#iletisim">İletişim</a>
        <a href="${PREVIEW_BASE}/soru-sor#gizlilik">Gizlilik</a>
        <a href="${PREVIEW_BASE}/soru-sor#kullanim">Kullanım Koşulları</a>
      </nav>
      <p class="pa-copyright">© 2026 Dini Sorular ve Cevaplar Arşivi. Tüm hakları saklıdır.</p>
    </footer>
  `;
}

function searchBox(value = '', label = 'Arşivde ara') {
  return `
    <form class="pa-search" action="${PREVIEW_BASE}/arama" method="get" role="search" id="arama">
      <label class="pa-sr-only" for="pa-search-input">${escapeHtml(label)}</label>
      <input id="pa-search-input" name="q" value="${escapeHtml(value)}" placeholder="Sorunuzu yazın veya konu arayın..." autocomplete="off">
      <button type="submit" aria-label="Ara">
        <span class="pa-search-icon" aria-hidden="true"></span>
      </button>
    </form>
  `;
}

function stillLife() {
  return `
    <div class="pa-still-life" aria-hidden="true">
      <div class="pa-branch"><span></span><span></span><span></span><span></span></div>
      <div class="pa-vase"></div>
      <div class="pa-books"><span></span><span></span><span></span><span></span></div>
    </div>
  `;
}

function sectionHeader(title, actionText, actionHref) {
  return `
    <div class="pa-section-head">
      <h2>${escapeHtml(title)}</h2>
      ${actionHref ? `<a href="${escapeHtml(actionHref)}">${escapeHtml(actionText || 'Tümünü Gör')} <span aria-hidden="true">›</span></a>` : ''}
    </div>
  `;
}

function chip(label, hrefValue) {
  const content = `<span class="pa-chip">${escapeHtml(label)}</span>`;
  if (!hrefValue) return content;
  return `<a class="pa-chip" href="${escapeHtml(hrefValue)}">${escapeHtml(label)}</a>`;
}

function questionCard(entry, compact = false) {
  const category = categoryFor(entry);
  const topics = topicsFor(entry);
  const meta = [
    entry.updatedAt ? `Güncellendi: ${formatDate(entry.updatedAt)}` : '',
    entry.readTime ? `${entry.readTime} dk okuma` : ''
  ].filter(Boolean).join(' · ');
  return `
    <article class="pa-question-card${compact ? ' is-compact' : ''}">
      <a class="pa-question-title" href="${PREVIEW_BASE}/soru/${escapeHtml(entry.slug)}">${escapeHtml(entry.title)}</a>
      <p>${escapeHtml(entry.excerpt || entry.summary)}</p>
      <div class="pa-card-meta">
        ${category ? chip(category.name, `${PREVIEW_BASE}/kategori/${category.slug}`) : ''}
        ${topics.slice(0, 2).map(topic => chip(topic.name, `${PREVIEW_BASE}/konu/${topic.slug}`)).join('')}
      </div>
      ${meta ? `<p class="pa-card-foot">${escapeHtml(meta)}</p>` : ''}
    </article>
  `;
}

function topicCard(topic) {
  return `
    <a class="pa-topic-card" href="${PREVIEW_BASE}/konu/${escapeHtml(topic.slug)}">
      <span class="pa-topic-mark" aria-hidden="true"></span>
      <strong>${escapeHtml(topic.name)}</strong>
      <span>${entriesForTopic(topic.slug).length} soru</span>
    </a>
  `;
}

function categoryCard(category) {
  return `
    <a class="pa-category-card" href="${PREVIEW_BASE}/kategori/${escapeHtml(category.slug)}">
      <strong>${escapeHtml(category.name)}</strong>
      <span>${entriesForCategory(category.slug).length} soru</span>
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
      <div>
        <h2>Aklınızda bir soru mu var?</h2>
        <p>Aradığınız cevabı bulamadığınızda soru ekranını inceleyebilirsiniz.</p>
      </div>
      <a class="pa-button" href="${PREVIEW_BASE}/soru-sor">Soru Sor</a>
    </section>
  `;
}

function trustBand() {
  return `
    <section class="pa-context-band" id="baglam">
      <div>
        <p class="pa-kicker">Güvenilir kaynak, sade anlatım</p>
        <h2>Arşiv, kısa cevap ile derin okuma arasında sakin bir yol sunar.</h2>
        <p>${escapeHtml(publicArchiveFixtures.brand.sentence)} ${escapeHtml(publicArchiveFixtures.brand.authorLine)} Bu ekranda kayıt alınmıyor; yalnızca arayüz davranışı gösteriliyor.</p>
                <p>Cevaplar; soru, kavram ve kategori bağlantılarıyla birlikte okunacak şekilde düzenlenir. Amaç, doğru bilgiye sade ve huzurlu bir okuma deneyimiyle ulaşmaktır.</p>
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
    description: 'Dini Sorular ve Cevaplar Arşivi içinde sakin ve okunabilir soru-cevap deneyimi.',
    content: `
      <main class="pa-main">
        <section class="pa-hero">
          <div class="pa-hero-copy">
            <p class="pa-kicker">${escapeHtml(publicArchiveFixtures.brand.sentence)}</p>
            <h1>Merak ettiğiniz sorunun cevabını bulun.</h1>
            <p>Dini konulardaki sorular için sade, güvenilir ve okuma odaklı bir arşiv deneyimi.</p>
            ${searchBox()}
          </div>
          ${stillLife()}
        </section>

        <section class="pa-section">
          ${sectionHeader('Öne Çıkan Sorular', 'Tümünü Gör', `${PREVIEW_BASE}/arama`)}
          <div class="pa-question-grid">${featured.map(entry => questionCard(entry)).join('')}</div>
        </section>

        <section class="pa-section">
          ${sectionHeader('Kavramlar', 'Tümünü Gör', `${PREVIEW_BASE}/konu/ornek-kavram`)}
          <div class="pa-topic-grid">${topics.map(topicCard).join('')}</div>
        </section>

        <section class="pa-section">
          ${sectionHeader('Kategoriler', 'Tümünü Gör', `${PREVIEW_BASE}/kategori/ornek-kategori`)}
          <div class="pa-category-grid">${categories.map(categoryCard).join('')}</div>
        </section>

        <section class="pa-section">
          ${sectionHeader('Son Yayınlanan Sorular', 'Arşive Git', `${PREVIEW_BASE}/arama`)}
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

function renderSearch(query = '') {
  const cleanQuery = String(query || '').trim();
  const results = searchResults(cleanQuery);
  return renderShell({
    active: 'search',
    title: cleanQuery ? `"${cleanQuery}" için arama` : 'Arama',
    description: 'Arşivde soru, konu ve kategori arayın.',
    content: `
      <main class="pa-main pa-narrow-main">
        ${breadcrumb([{ label: 'Arama' }])}
        <section class="pa-search-page">
          <p class="pa-kicker">Arşivde ara</p>
          <h1>Aradığınız cevaba en kısa yoldan ulaşın.</h1>
          ${searchBox(cleanQuery)}
        </section>
        <section class="pa-section">
          ${sectionHeader(cleanQuery ? `"${cleanQuery}" araması` : 'Arşivdeki Sorular')}
          ${results.length
            ? `<div class="pa-list">${results.map(entry => questionCard(entry, true)).join('')}</div>`
            : renderNoResults(cleanQuery)}
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
        <a class="pa-button is-secondary" href="${PREVIEW_BASE}/arama">Arşive Dön</a>
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
    content: `
      <main class="pa-main pa-detail-main">
        ${breadcrumb([
          { label: 'Arşiv', href: `${PREVIEW_BASE}/arama` },
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
              ${publicArchiveFixtures.brand.answererLabel ? `<span>${escapeHtml(publicArchiveFixtures.brand.answererLabel)}</span>` : ''}
            </div>
            <section class="pa-reading-block">
              <h2>Orijinal Soru</h2>
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
        ${breadcrumb([{ label: 'Konular', href: `${PREVIEW_BASE}/konu/ornek-kavram` }, { label: topic.name }])}
        <section class="pa-collection-hero">
          <p class="pa-kicker">Kavram</p>
          <h1>${escapeHtml(topic.name)}</h1>
          <p>${escapeHtml(topic.description)}</p>
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
    active: 'archive',
    title: category.name,
    description: category.description,
    content: `
      <main class="pa-main pa-narrow-main">
        ${breadcrumb([{ label: 'Kategoriler', href: `${PREVIEW_BASE}/kategori/ornek-kategori` }, { label: category.name }])}
        <section class="pa-collection-hero">
          <p class="pa-kicker">Kategori</p>
          <h1>${escapeHtml(category.name)}</h1>
          <p>${escapeHtml(category.description)}</p>
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

function renderAsk() {
  return renderShell({
    active: 'ask',
    title: 'Soru Sor',
    description: 'Soru sorma ekranı için statik ön izleme.',
    content: `
      <main class="pa-main pa-form-main">
        ${breadcrumb([{ label: 'Soru Sor' }])}
        <section class="pa-form-layout">
          <div class="pa-form-copy">
            <p class="pa-kicker">Soru Sor</p>
            <h1>Sorunuzu kısa ve açık yazın.</h1>
            <p>${escapeHtml(publicArchiveFixtures.brand.sentence)} ${escapeHtml(publicArchiveFixtures.brand.authorLine)} Bu ekranda kayıt alınmıyor; yalnızca arayüz davranışı gösteriliyor.</p>
            <div class="pa-note-box" id="gizlilik">
              <strong>Gizlilik notu</strong>
              <p>Kişisel bilgi, özel sağlık bilgisi veya üçüncü kişilere ait mahrem ayrıntılar paylaşmayın.</p>
            </div>
          </div>
          <form class="pa-ask-form" data-static-question-form>
            <label>
              <span>Soru metni</span>
              <textarea rows="7" maxlength="500" placeholder="Sorunuzu yazın..."></textarea>
            </label>
            <label>
              <span>İsteğe bağlı kategori veya konu</span>
              <select>
                <option>Kategori seçin</option>
                ${publicArchiveFixtures.categories.map(category => `<option>${escapeHtml(category.name)}</option>`).join('')}
              </select>
            </label>
            <label class="pa-check-row" id="kullanim">
              <input type="checkbox">
              <span>Kişisel bilgi paylaşmadığımı anladım.</span>
            </label>
            <button class="pa-button" type="submit" disabled>Bu ekranda kayıt alınmaz</button>
          </form>
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

function renderShell({ title, description, active, content, status = 200 }) {
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
  <meta name="theme-color" content="#FFFFFF">
  <title>${escapeHtml(safeTitle)}</title>
  <link rel="stylesheet" href="${CSS_PATH}">
  <script>
    (function(){
      try {
        var saved = localStorage.getItem('dsca-theme');
        var preferred = window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light';
        var theme = saved === 'dark' || saved === 'light' ? saved : preferred;
        document.documentElement.setAttribute('data-theme', theme);
        document.querySelector('meta[name="theme-color"]').setAttribute('content', theme === 'dark' ? '#0D0F12' : '#FFFFFF');
      } catch (error) {}
    })();
  </script>
</head>
<body>
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
        if (meta) meta.setAttribute('content', theme === 'dark' ? '#0D0F12' : '#FFFFFF');
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
      var form = document.querySelector('[data-static-question-form]');
      if (form) form.addEventListener('submit', function(event){ event.preventDefault(); });
    })();
  </script>
</body>
</html>`
  };
}

function renderPublicArchivePreviewRoute(routePath, query = {}) {
  const pathname = routePath.replace(/\/+$/, '') || PREVIEW_BASE;
  if (pathname === PREVIEW_BASE) return renderHome();
  if (pathname === `${PREVIEW_BASE}/arama`) return renderSearch(query.q || '');
  if (pathname === `${PREVIEW_BASE}/soru-sor`) return renderAsk();
  const questionMatch = pathname.match(/^\/public-preview\/soru\/([^/]+)$/);
  if (questionMatch) return renderQuestion(questionMatch[1]);
  const topicMatch = pathname.match(/^\/public-preview\/konu\/([^/]+)$/);
  if (topicMatch) return renderTopic(topicMatch[1]);
  const categoryMatch = pathname.match(/^\/public-preview\/kategori\/([^/]+)$/);
  if (categoryMatch) return renderCategory(categoryMatch[1]);
  return renderNotFound();
}

function sendRendered(res, rendered) {
  res.status(rendered.status || 200).type('html').send(rendered.html);
}

function createPublicArchivePreviewRouter(options = {}) {
  const router = express.Router();
  const cssFile = options.cssFile || path.join(__dirname, 'public-archive.css');
  router.use((req, res, next) => {
    res.set('X-Robots-Tag', 'noindex, nofollow');
    res.set('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate');
    next();
  });
  router.get('/public-archive.css', (req, res) => {
    res.type('text/css').sendFile(cssFile);
  });
  router.get(['/', ''], (req, res) => sendRendered(res, renderHome()));
  router.get('/arama', (req, res) => sendRendered(res, renderSearch(req.query.q || '')));
  router.get('/soru-sor', (req, res) => sendRendered(res, renderAsk()));
  router.get('/soru/:slug', (req, res) => sendRendered(res, renderQuestion(req.params.slug)));
  router.get('/konu/:slug', (req, res) => sendRendered(res, renderTopic(req.params.slug)));
  router.get('/kategori/:slug', (req, res) => sendRendered(res, renderCategory(req.params.slug)));
  router.use((req, res) => sendRendered(res, renderNotFound()));
  return router;
}

module.exports = {
  PREVIEW_BASE,
  ROUTE_PATHS,
  createPublicArchivePreviewRouter,
  renderPublicArchivePreviewRoute,
  publicArchiveFixtures
};
