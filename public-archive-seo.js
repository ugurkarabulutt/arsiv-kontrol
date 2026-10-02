'use strict';

function publicSeoSlug(value = '') {
  const ascii = String(value || '')
    .toLocaleLowerCase('tr-TR')
    .replace(/ğ/g, 'g').replace(/ü/g, 'u').replace(/ş/g, 's')
    .replace(/ı/g, 'i').replace(/i̇/g, 'i').replace(/ö/g, 'o').replace(/ç/g, 'c')
    .replace(/[âÂ]/g, 'a').replace(/[îÎ]/g, 'i').replace(/[ûÛ]/g, 'u')
    .replace(/[’'`´]/g, '')
    .normalize('NFD')
    .replace(/[\u0300-\u036f]/g, '')
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-+|-+$/g, '')
    .slice(0, 96)
    .replace(/-+$/g, '');
  return ascii || 'soru';
}

function stripPublicQuestionAddress(value = '') {
  const source = String(value || '').trim();
  if (!source) return '';
  const slugLike = /^[a-z0-9-]+$/i.test(source);
  if (slugLike) {
    const cleaned = source
      .replace(/^(?:(?:soru-\d+|\d+-soru)-)?muhterem-hocam(?:izin|iz|in)?(?:-+|(?=[a-z]))/i, '')
      .replace(/^(?:soru-\d+|\d+-soru)-+/i, '')
      .replace(/^\d+-(?:sual-de|suali|sual)-+/i, '')
      .replace(/^-+|-+$/g, '');
    return cleaned || source;
  }
  const cleaned = source
    .replace(/^\s*(?:[“"'‘’]\s*)?(?:(?:Soru\s+\d+|\d+\s*[.)-]?\s*Soru)\s*[:.)-]?\s*)?/iu, '')
    .replace(/^\s*Muhterem\s+Hocam(?:ızın|ız|ın)?\s*[,;:–—-]?\s*/iu, '')
    .replace(/^\s*(?:Soru\s+\d+|\d+\s*[.)-]?\s*Soru|\d+\s*[.)-]?\s*Sual(?:i|ı|de)?)\s*[:.,)-]?\s*/iu, '')
    .trim();
  return cleaned || source;
}

function publicQuestionSlug(value = '') {
  return publicSeoSlug(stripPublicQuestionAddress(value));
}

function uniquePublicQuestionSlug(value, usedSlugs, fallback = 'soru') {
  const used = usedSlugs instanceof Set ? usedSlugs : new Set();
  const base = publicQuestionSlug(value || fallback);
  let candidate = base;
  let index = 2;
  while (used.has(candidate)) {
    const suffix = `-${index}`;
    const stem = base.slice(0, Math.max(1, 96 - suffix.length)).replace(/-+$/g, '') || fallback;
    candidate = `${stem}${suffix}`;
    index += 1;
  }
  used.add(candidate);
  return candidate;
}

function buildPublicQuestionSlugMigrationPlan(rows = [], options = {}) {
  const records = (rows || [])
    .filter(row => row?.slug)
    .map(row => ({ ...row, slug: String(row.slug).trim() }))
    .sort((a, b) => a.slug.localeCompare(b.slug, 'tr'));
  const used = new Set([
    ...records.map(row => row.slug),
    ...(Array.isArray(options.reservedSlugs) ? options.reservedSlugs.map(String) : [])
  ]);
  const plan = [];
  for (const row of records) {
    const cleanBase = publicQuestionSlug(row.slug);
    if (!cleanBase || cleanBase === row.slug) continue;
    const newSlug = uniquePublicQuestionSlug(cleanBase, used, 'soru');
    plan.push({
      oldSlug: row.slug,
      newSlug,
      sourceHistoryId: row.source_history_id || null,
      collisionResolved: newSlug !== cleanBase
    });
  }
  return plan;
}

function dedupePublicSitemapRows(rows = []) {
  const bySlug = new Map();
  for (const row of rows || []) {
    const slug = String(row?.slug || '').trim();
    if (!slug || bySlug.has(slug)) continue;
    bySlug.set(slug, { ...row, slug });
  }
  return [...bySlug.values()];
}

function collectPublicSitemapTaxonomy(rows = []) {
  const taxonomy = new Map();
  for (const row of rows || []) {
    const perQuestion = new Map();
    if (row?.category_slug) perQuestion.set(String(row.category_slug), new Set(['main']));
    for (const slug of Array.isArray(row?.topic_slugs) ? row.topic_slugs : []) {
      if (!slug) continue;
      const cleanSlug = String(slug);
      if (!perQuestion.has(cleanSlug)) perQuestion.set(cleanSlug, new Set());
      perQuestion.get(cleanSlug).add('topic');
    }
    for (const [slug, roles] of perQuestion) {
      const current = taxonomy.get(slug) || { slug, count: 0, lastmod: '', roles: new Set() };
      current.count += 1;
      current.lastmod = [current.lastmod, row.updated_at || row.published_at || '']
        .filter(Boolean)
        .sort((a, b) => new Date(b).getTime() - new Date(a).getTime())[0] || '';
      for (const role of roles) current.roles.add(role);
      taxonomy.set(slug, current);
    }
  }
  return [...taxonomy.values()]
    .map(item => ({ ...item, roles: [...item.roles].sort() }))
    .sort((a, b) => a.slug.localeCompare(b.slug, 'tr'));
}

module.exports = {
  buildPublicQuestionSlugMigrationPlan,
  collectPublicSitemapTaxonomy,
  dedupePublicSitemapRows,
  publicQuestionSlug,
  publicSeoSlug,
  stripPublicQuestionAddress,
  uniquePublicQuestionSlug
};
