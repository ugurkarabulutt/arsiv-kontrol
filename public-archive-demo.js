const express = require('express');
const path = require('path');
const { qaEntries, categoryNames, slugify } = require('./data/qa-seed');

const SITE_TITLE = 'İbrahimLive Soru Cevap Arşivi';
const SITE_DESCRIPTION = 'Merak ettiğiniz konu, kavram veya soruyu arşivde arayın.';

function esc(value = '') {
  return String(value)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

function normalizeSearch(value = '') {
  return String(value)
    .toLocaleLowerCase('tr-TR')
    .normalize('NFD')
    .replace(/[\u0300-\u036f]/g, '')
    .replace(/[’'`´]/g, '')
    .replace(/ı/g, 'i')
    .replace(/ğ/g, 'g')
    .replace(/ü/g, 'u')
    .replace(/ş/g, 's')
    .replace(/ö/g, 'o')
    .replace(/ç/g, 'c')
    .replace(/â/g, 'a')
    .replace(/î/g, 'i')
    .replace(/û/g, 'u')
    .replace(/[^a-z0-9\s-]/g, ' ')
    .replace(/\s+/g, ' ')
    .trim();
}

function absoluteUrl(req, route = '/') {
  if (process.env.PUBLIC_ARCHIVE_BASE_URL) {
    const base = process.env.PUBLIC_ARCHIVE_BASE_URL.replace(/\/+$/, '');
    const cleanRoute = route.startsWith('/') ? route : `/${route}`;
    return `${base}${cleanRoute}`;
  }
  const host = req.get('host') || 'localhost:3000';
  const protocol = req.protocol || 'http';
  return `${protocol}://${host}${route}`;
}

function pageMeta(title, description) {
  return {
    title: title ? `${title} | ${SITE_TITLE}` : SITE_TITLE,
    description: description || SITE_DESCRIPTION
  };
}

function dateLabel(value) {
  return new Intl.DateTimeFormat('tr-TR', {
    day: '2-digit',
    month: 'long',
    year: 'numeric'
  }).format(new Date(value));
}

function categorySlug(name) {
  return slugify(name);
}

function topicSlug(name) {
  return slugify(name);
}

function categoryCounts() {
  return categoryNames.map(name => ({
    name,
    slug: categorySlug(name),
    count: qaEntries.filter(entry => entry.category === name).length
  }));
}

function allTopics() {
  const counts = new Map();
  qaEntries.forEach(entry => {
    entry.topics.forEach(topic => counts.set(topic, (counts.get(topic) || 0) + 1));
  });
  return [...counts.entries()]
    .map(([name, count]) => ({ name, slug: topicSlug(name), count }))
    .sort((a, b) => b.count - a.count || a.name.localeCompare(b.name, 'tr-TR'));
}

function searchEntries(query) {
  const needle = normalizeSearch(query);
  if (!needle) return [];
  const terms = needle.split(' ').filter(Boolean);
  return qaEntries
    .map(entry => {
      const haystack = normalizeSearch([
        entry.title,
        entry.question,
        entry.summary,
        entry.answer,
        entry.category,
        entry.topics.join(' ')
      ].join(' '));
      const score = terms.reduce((sum, term) => sum + (haystack.includes(term) ? 1 : 0), 0);
      const titleBoost = normalizeSearch(entry.title).includes(needle) ? 4 : 0;
      return { entry, score: score + titleBoost };
    })
    .filter(item => item.score > 0)
    .sort((a, b) => b.score - a.score || new Date(b.entry.updatedAt) - new Date(a.entry.updatedAt))
    .map(item => item.entry);
}

function relatedEntries(entry, limit = 4) {
  const topicSet = new Set(entry.topics.map(normalizeSearch));
  return qaEntries
    .filter(item => item.id !== entry.id)
    .map(item => {
      const sameCategory = item.category === entry.category ? 2 : 0;
      const topicScore = item.topics.reduce((sum, topic) => sum + (topicSet.has(normalizeSearch(topic)) ? 1 : 0), 0);
      return { item, score: sameCategory + topicScore };
    })
    .filter(item => item.score > 0)
    .sort((a, b) => b.score - a.score || new Date(b.item.updatedAt) - new Date(a.item.updatedAt))
    .slice(0, limit)
    .map(item => item.item);
}

function renderJsonLd(items) {
  return items
    .filter(Boolean)
    .map(item => `<script type="application/ld+json">${JSON.stringify(item).replace(/</g, '\\u003c')}</script>`)
    .join('\n');
}

function layout(req, meta, content, jsonLd = []) {
  const canonical = absoluteUrl(req, req.originalUrl.split('?')[0] || '/');
  return `<!doctype html>
<html lang="tr">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>${esc(meta.title)}</title>
  <meta name="description" content="${esc(meta.description)}">
  <link rel="canonical" href="${esc(canonical)}">
  <link rel="stylesheet" href="/archive-public.css">
  ${renderJsonLd(jsonLd)}
</head>
<body>
  <header class="site-header">
    <a class="brand" href="/" aria-label="İbrahimLive arşiv ana sayfa">
      <span class="brand-mark">İ</span>
      <span>İbrahimLive</span>
    </a>
    <nav class="top-nav" aria-label="Ana gezinme">
      <a href="/arama">Arama</a>
      <a href="/kategori/${categorySlug('Hidayet')}">Kategoriler</a>
      <a href="/konu/${topicSlug('zikir')}">Konular</a>
    </nav>
  </header>
  <main>${content}</main>
  <footer class="site-footer">
    <div>
      <strong>İbrahimLive Soru Cevap Arşivi</strong>
      <p>Konular, kavramlar ve soru-cevaplar arasında düzenli arama için hazırlanmış bilgi merkezi.</p>
    </div>
    <a href="/" class="footer-link">Arşive dön</a>
  </footer>
  <script>
    function copyCurrentUrl(){
      navigator.clipboard && navigator.clipboard.writeText(location.href);
      const note = document.querySelector('[data-copy-note]');
      if(note){ note.textContent = 'Bağlantı kopyalandı.'; setTimeout(function(){ note.textContent = ''; }, 1800); }
    }
    function shareCurrentPage(){
      if(navigator.share){ navigator.share({ title: document.title, url: location.href }); }
      else { copyCurrentUrl(); }
    }
  </script>
</body>
</html>`;
}

function searchForm(value = '') {
  return `<form class="search-panel" action="/arama" method="get">
    <label class="sr-only" for="archiveSearch">Arşivde ara</label>
    <input id="archiveSearch" name="q" value="${esc(value)}" placeholder="Konu, kavram veya soru arayın..." autocomplete="off">
    <button type="submit">Ara</button>
  </form>`;
}

function entryCard(entry) {
  return `<article class="qa-card">
    <div class="card-meta">
      <a href="/kategori/${categorySlug(entry.category)}">${esc(entry.category)}</a>
      <span>${entry.readTime} dk okuma</span>
    </div>
    <h3><a href="/soru/${entry.slug}">${esc(entry.title)}</a></h3>
    <p>${esc(entry.summary)}</p>
    <div class="topic-row">${entry.topics.slice(0, 4).map(topic => `<a href="/konu/${topicSlug(topic)}">${esc(topic)}</a>`).join('')}</div>
    <a class="read-link" href="/soru/${entry.slug}">Cevabı oku</a>
  </article>`;
}

function collectionGrid(items) {
  return `<div class="qa-grid">${items.map(entryCard).join('')}</div>`;
}

function homeJsonLd(req) {
  return [
    {
      '@context': 'https://schema.org',
      '@type': 'WebSite',
      name: SITE_TITLE,
      url: absoluteUrl(req, '/'),
      potentialAction: {
        '@type': 'SearchAction',
        target: `${absoluteUrl(req, '/arama')}?q={search_term_string}`,
        'query-input': 'required name=search_term_string'
      }
    },
    {
      '@context': 'https://schema.org',
      '@type': 'Organization',
      name: 'İbrahimLive',
      url: absoluteUrl(req, '/')
    }
  ];
}

function renderHome(req, res) {
  const featured = qaEntries.filter((_, index) => [3, 12, 24, 37].includes(index));
  const latest = [...qaEntries].sort((a, b) => new Date(b.updatedAt) - new Date(a.updatedAt)).slice(0, 6);
  const topics = allTopics().slice(0, 12);
  const categories = categoryCounts().slice(0, 8);
  const content = `
    <section class="hero">
      <div class="hero-inner">
        <div class="hero-copy">
          <p class="eyebrow">Delilli Soru Cevap Arşivi</p>
          <h1>${SITE_TITLE}</h1>
          <p class="hero-text">${SITE_DESCRIPTION}</p>
          ${searchForm('')}
          <div class="hero-stats">
            <span><strong>${qaEntries.length}</strong> soru-cevap</span>
            <span><strong>${categoryNames.length}</strong> kategori</span>
            <span><strong>${allTopics().length}</strong> konu</span>
          </div>
        </div>
        <aside class="hero-panel" aria-label="Öne çıkan arşiv başlıkları">
          <div class="panel-title"><strong>Öne çıkan başlıklar</strong><span>Güncel arşiv</span></div>
          <div class="feature-list">
            ${featured.map(entry => `<a href="/soru/${entry.slug}"><small>${esc(entry.category)}</small><span>${esc(entry.title)}</span></a>`).join('')}
          </div>
        </aside>
      </div>
    </section>
    <section class="section section-frame">
      <div class="section-head">
        <div><p class="eyebrow">Hızlı başlangıç</p><h2>Popüler konular</h2><p>Sık aranan kavramlardan başlayın.</p></div>
        <a href="/arama" class="plain-link">Tüm arşivde ara</a>
      </div>
      <div class="pill-cloud">${topics.map(topic => `<a href="/konu/${topic.slug}">${esc(topic.name)} <span>${topic.count}</span></a>`).join('')}</div>
    </section>
    <section class="section section-frame">
      <div class="section-head"><div><p class="eyebrow">Seçili içerikler</p><h2>Öne çıkan soru-cevaplar</h2><p>Arşiv detay sayfasını göstermek için seçilmiş kayıtlar.</p></div></div>
      ${collectionGrid(featured)}
    </section>
    <section class="section split-section">
      <div class="section-frame">
        <div class="section-head"><div><p class="eyebrow">Kategoriler</p><h2>Kavram alanları</h2></div></div>
        <div class="category-list">${categories.map(cat => `<a href="/kategori/${cat.slug}"><span>${esc(cat.name)}</span><strong>${cat.count}</strong></a>`).join('')}</div>
      </div>
      <div class="section-frame">
        <div class="section-head"><div><p class="eyebrow">Yeni eklenenler</p><h2>Son soru-cevaplar</h2></div></div>
        <div class="latest-list">${latest.map(entry => `<a href="/soru/${entry.slug}"><span>${esc(entry.title)}</span><small>${dateLabel(entry.updatedAt)}</small></a>`).join('')}</div>
      </div>
    </section>`;
  res.send(layout(req, pageMeta('', SITE_DESCRIPTION), content, homeJsonLd(req)));
}

function renderSearch(req, res) {
  const q = String(req.query.q || '').trim();
  const results = q ? searchEntries(q) : [];
  const meta = pageMeta(q ? `"${q}" arama sonuçları` : 'Arama', 'Arşivde konu, kavram veya soru arayın.');
  const content = `
    <section class="page-hero compact">
      <p class="eyebrow">Arama</p>
      <h1>Arşivde arama yapın</h1>
      ${searchForm(q)}
    </section>
    <section class="section section-frame">
      ${q ? `<p class="result-count">${results.length} sonuç bulundu: <strong>${esc(q)}</strong></p>` : '<div class="empty-state"><h2>Aramaya başlayın</h2><p>Konu, kavram veya soru yazarak arşivdeki kayıtları listeleyebilirsiniz.</p></div>'}
      ${q && results.length ? collectionGrid(results) : ''}
      ${q && !results.length ? `<div class="empty-state"><h2>Sonuç bulunamadı</h2><p>Farklı bir kavram, daha kısa bir ifade veya kategori adıyla tekrar arayın.</p></div>` : ''}
    </section>`;
  const jsonLd = [{
    '@context': 'https://schema.org',
    '@type': 'WebPage',
    name: meta.title,
    description: meta.description,
    url: absoluteUrl(req, req.originalUrl)
  }];
  res.send(layout(req, meta, content, jsonLd));
}

function articleJsonLd(req, entry) {
  return [
    {
      '@context': 'https://schema.org',
      '@type': 'WebPage',
      name: entry.title,
      description: entry.summary,
      url: absoluteUrl(req, `/soru/${entry.slug}`)
    },
    {
      '@context': 'https://schema.org',
      '@type': 'Article',
      headline: entry.title,
      description: entry.summary,
      datePublished: entry.createdAt,
      dateModified: entry.updatedAt,
      articleSection: entry.category,
      keywords: entry.topics.join(', '),
      author: { '@type': 'Organization', name: 'İbrahimLive' }
    },
    breadcrumbJsonLd(req, [
      ['Ana sayfa', '/'],
      [entry.category, `/kategori/${categorySlug(entry.category)}`],
      [entry.title, `/soru/${entry.slug}`]
    ])
  ];
}

function breadcrumbJsonLd(req, items) {
  return {
    '@context': 'https://schema.org',
    '@type': 'BreadcrumbList',
    itemListElement: items.map(([name, item], index) => ({
      '@type': 'ListItem',
      position: index + 1,
      name,
      item: absoluteUrl(req, item)
    }))
  };
}

function renderQuestion(req, res) {
  const entry = qaEntries.find(item => item.slug === req.params.slug);
  if (!entry) return renderNotFound(req, res);
  const related = relatedEntries(entry, 4);
  const content = `
    <article class="article-shell">
      <nav class="breadcrumb"><a href="/">Ana sayfa</a><span>/</span><a href="/kategori/${categorySlug(entry.category)}">${esc(entry.category)}</a></nav>
      <header class="article-head">
        <div class="card-meta"><a href="/kategori/${categorySlug(entry.category)}">${esc(entry.category)}</a><span>${entry.readTime} dk okuma</span></div>
        <h1>${esc(entry.title)}</h1>
        <p>${esc(entry.summary)}</p>
      </header>
      <section class="answer-block">
        <h2>Soru</h2>
        <p class="question-text">${esc(entry.question)}</p>
        <h2>Cevap</h2>
        ${entry.answer.split('\n\n').map(part => `<p>${esc(part)}</p>`).join('')}
      </section>
      <aside class="article-side">
        <div class="topic-row">${entry.topics.map(topic => `<a href="/konu/${topicSlug(topic)}">${esc(topic)}</a>`).join('')}</div>
        <div class="action-row">
          <button type="button" onclick="shareCurrentPage()">Paylaş</button>
          <button type="button" onclick="copyCurrentUrl()">Bağlantıyı kopyala</button>
          <button type="button" onclick="window.print()">Yazdır</button>
        </div>
        <p class="copy-note" data-copy-note></p>
        <p class="updated">Son güncelleme: ${dateLabel(entry.updatedAt)}</p>
      </aside>
    </article>
    <section class="section section-frame">
      <div class="section-head"><div><p class="eyebrow">Devamı</p><h2>Benzer soru-cevaplar</h2></div></div>
      ${collectionGrid(related)}
    </section>`;
  res.send(layout(req, pageMeta(entry.title, entry.summary), content, articleJsonLd(req, entry)));
}

function collectionJsonLd(req, title, description, route, items) {
  return [
    {
      '@context': 'https://schema.org',
      '@type': 'CollectionPage',
      name: title,
      description,
      url: absoluteUrl(req, route)
    },
    {
      '@context': 'https://schema.org',
      '@type': 'ItemList',
      itemListElement: items.slice(0, 20).map((entry, index) => ({
        '@type': 'ListItem',
        position: index + 1,
        url: absoluteUrl(req, `/soru/${entry.slug}`),
        name: entry.title
      }))
    },
    breadcrumbJsonLd(req, [['Ana sayfa', '/'], [title, route]])
  ];
}

function renderTopic(req, res) {
  const topic = allTopics().find(item => item.slug === req.params.slug);
  if (!topic) return renderNotFound(req, res);
  const items = qaEntries.filter(entry => entry.topics.some(value => topicSlug(value) === topic.slug));
  const title = topic.name;
  const description = `${title} konusunda arşivde yer alan soru-cevaplar.`;
  const content = `
    <section class="page-hero compact">
      <p class="eyebrow">Konu</p>
      <h1>${esc(title)}</h1>
      <p>${esc(description)}</p>
      ${searchForm(title)}
    </section>
    <section class="section section-frame">
      <p class="result-count">${items.length} soru-cevap listeleniyor.</p>
      ${collectionGrid(items)}
    </section>`;
  res.send(layout(req, pageMeta(title, description), content, collectionJsonLd(req, title, description, `/konu/${topic.slug}`, items)));
}

function renderCategory(req, res) {
  const category = categoryCounts().find(item => item.slug === req.params.slug);
  if (!category) return renderNotFound(req, res);
  const items = qaEntries.filter(entry => entry.category === category.name);
  const title = category.name;
  const description = `${title} kategorisindeki soru-cevap kayıtları.`;
  const content = `
    <section class="page-hero compact">
      <p class="eyebrow">Kategori</p>
      <h1>${esc(title)}</h1>
      <p>${esc(description)}</p>
      ${searchForm(title)}
    </section>
    <section class="section section-frame">
      <p class="result-count">${items.length} soru-cevap listeleniyor.</p>
      ${collectionGrid(items)}
    </section>`;
  res.send(layout(req, pageMeta(title, description), content, collectionJsonLd(req, title, description, `/kategori/${category.slug}`, items)));
}

function renderNotFound(req, res) {
  const content = `<section class="page-hero compact">
    <p class="eyebrow">Bulunamadı</p>
    <h1>Aradığınız kayıt bulunamadı</h1>
    <p>Arama yaparak benzer konuları inceleyebilirsiniz.</p>
    ${searchForm('')}
  </section>`;
  res.status(404).send(layout(req, pageMeta('Kayıt bulunamadı', 'Aradığınız kayıt bulunamadı.'), content));
}

function createPublicArchiveRouter(options = {}) {
  const router = express.Router();
  const cssFile = options.cssFile || path.join(__dirname, 'archive-public.css');
  const adminFile = options.adminFile || path.join(__dirname, 'index.html');

  router.get('/archive-public.css', (req, res) => res.sendFile(cssFile));
  router.get('/', renderHome);
  router.get('/arama', renderSearch);
  router.get('/soru/:slug', renderQuestion);
  router.get('/konu/:slug', renderTopic);
  router.get('/kategori/:slug', renderCategory);
  router.get('/admin', (req, res) => res.sendFile(adminFile));

  return router;
}

module.exports = {
  createPublicArchiveRouter,
  normalizeSearch,
  searchEntries
};
