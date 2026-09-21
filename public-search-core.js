'use strict';

const crypto = require('crypto');

const PUBLIC_SEARCH_EMBEDDING_MODEL = 'text-embedding-3-small';
const PUBLIC_SEARCH_EMBEDDING_DIMENSIONS = 1024;
const PUBLIC_SEARCH_ANSWER_CHUNK_CHARS = 1800;
const PUBLIC_SEARCH_ANSWER_CHUNK_OVERLAP_CHARS = 220;
const PUBLIC_SEARCH_MAX_ANSWER_CHUNKS = 32;

function cleanSearchDocumentText(value = '', max = 120000) {
  return String(value || '')
    .replace(/\r\n?/g, '\n')
    .replace(/[ \t]+\n/g, '\n')
    .replace(/\n{3,}/g, '\n\n')
    .replace(/[ \t]{2,}/g, ' ')
    .trim()
    .slice(0, max);
}

function normalizeSearchText(value = '') {
  return String(value || '')
    .toLocaleLowerCase('tr-TR')
    .replace(/ç/g, 'c').replace(/ğ/g, 'g').replace(/ı/g, 'i')
    .replace(/ö/g, 'o').replace(/ş/g, 's').replace(/ü/g, 'u')
    .replace(/â/g, 'a').replace(/î/g, 'i').replace(/û/g, 'u')
    .normalize('NFD')
    .replace(/[\u0300-\u036f]/g, '')
    .replace(/[^a-z0-9]+/g, ' ')
    .replace(/\s+/g, ' ')
    .trim();
}

function searchDocumentHash(value = '') {
  return crypto.createHash('sha256').update(String(value || ''), 'utf8').digest('hex');
}

function splitOversizedSearchParagraph(value = '', maxChars = PUBLIC_SEARCH_ANSWER_CHUNK_CHARS) {
  const source = cleanSearchDocumentText(value);
  if (!source) return [];
  if (source.length <= maxChars) return [source];

  const pieces = [];
  let remaining = source;
  while (remaining.length > maxChars) {
    const window = remaining.slice(0, maxChars + 1);
    const sentenceBreak = Math.max(window.lastIndexOf('. '), window.lastIndexOf('? '), window.lastIndexOf('! '));
    const wordBreak = window.lastIndexOf(' ');
    const cutAt = sentenceBreak >= Math.round(maxChars * 0.55)
      ? sentenceBreak + 1
      : wordBreak >= Math.round(maxChars * 0.55)
        ? wordBreak
        : maxChars;
    pieces.push(remaining.slice(0, cutAt).trim());
    remaining = remaining.slice(cutAt).trim();
  }
  if (remaining) pieces.push(remaining);
  return pieces.filter(Boolean);
}

function chunkSearchDocumentText(value = '', options = {}) {
  const maxChars = Math.max(800, Number(options.maxChars) || PUBLIC_SEARCH_ANSWER_CHUNK_CHARS);
  const overlapChars = Math.max(0, Math.min(maxChars / 3, Number(options.overlapChars) || PUBLIC_SEARCH_ANSWER_CHUNK_OVERLAP_CHARS));
  const maxChunks = Math.max(1, Number(options.maxChunks) || PUBLIC_SEARCH_MAX_ANSWER_CHUNKS);
  const paragraphs = cleanSearchDocumentText(value)
    .split(/\n{2,}/)
    .flatMap(paragraph => splitOversizedSearchParagraph(paragraph, maxChars))
    .filter(Boolean);
  if (!paragraphs.length) return [];

  const chunks = [];
  let current = '';
  for (const paragraph of paragraphs) {
    const candidate = current ? `${current}\n\n${paragraph}` : paragraph;
    if (candidate.length <= maxChars) {
      current = candidate;
      continue;
    }
    if (current) chunks.push(current.trim());
    if (chunks.length >= maxChunks) break;
    const overlap = current && overlapChars
      ? current.slice(Math.max(0, current.length - overlapChars)).replace(/^\S*\s+/, '').trim()
      : '';
    current = overlap ? `${overlap}\n\n${paragraph}` : paragraph;
    if (current.length > maxChars) current = current.slice(0, maxChars).trim();
  }
  if (current && chunks.length < maxChunks) chunks.push(current.trim());
  return chunks.filter(Boolean).slice(0, maxChunks);
}

function rowsBySlug(rows = []) {
  return new Map((rows || []).filter(row => row?.slug).map(row => [row.slug, row]));
}

function uniqueStrings(values = []) {
  return [...new Set((values || []).map(value => String(value || '').trim()).filter(Boolean))];
}

function publicQaTopicSlugs(row = {}) {
  const topicSlugs = Array.isArray(row.topic_slugs) ? row.topic_slugs : [];
  return uniqueStrings([row.category_slug, ...topicSlugs]);
}

function publicQaSearchLabels(row = {}, categoryMap = new Map(), topicMap = new Map()) {
  const slugs = publicQaTopicSlugs(row);
  return uniqueStrings(slugs.map(slug => topicMap.get(slug)?.name || categoryMap.get(slug)?.name || slug.replace(/-/g, ' ')));
}

function relatedCategorySlugsFromSearchRows(rows = [], limit = 4) {
  const scores = new Map();
  const candidates = (rows || []).filter(Boolean).slice(0, 8);
  candidates.forEach((row, index) => {
    const weight = candidates.length - index;
    for (const slug of publicQaTopicSlugs(row)) {
      const current = scores.get(slug) || { slug, occurrences: 0, weight: 0, firstRank: index };
      current.occurrences += 1;
      current.weight += weight;
      current.firstRank = Math.min(current.firstRank, index);
      scores.set(slug, current);
    }
  });
  return [...scores.values()]
    .sort((a, b) => b.occurrences - a.occurrences
      || b.weight - a.weight
      || a.firstRank - b.firstRank
      || a.slug.localeCompare(b.slug, 'tr'))
    .slice(0, Math.max(0, Number(limit) || 0))
    .map(item => item.slug);
}

function createSearchDocument(row, documentKey, documentKind, content, metadata = {}) {
  const cleanContent = cleanSearchDocumentText(content, 16000);
  return {
    qa_slug: row.slug,
    document_key: documentKey,
    document_kind: documentKind,
    content: cleanContent,
    search_text: normalizeSearchText(cleanContent),
    content_hash: searchDocumentHash(cleanContent),
    metadata
  };
}

function buildPublicQaSearchDocuments(row = {}, context = {}) {
  if (!row?.slug || row.status && row.status !== 'published') return [];
  const categoryMap = context.categoryMap || rowsBySlug(context.categories);
  const topicMap = context.topicMap || rowsBySlug(context.topics);
  const labels = publicQaSearchLabels(row, categoryMap, topicMap);
  const title = cleanSearchDocumentText(row.title || row.question || 'Soru', 600);
  const question = cleanSearchDocumentText(row.question || row.title || '', 2400);
  const summary = cleanSearchDocumentText(row.summary || row.excerpt || '', 1800);
  const sharedMetadata = {
    title,
    categorySlug: row.category_slug || '',
    topicSlugs: publicQaTopicSlugs(row)
  };
  const questionDocument = [
    title ? `Başlık: ${title}` : '',
    question ? `Soru: ${question}` : '',
    summary ? `Kısa açıklama: ${summary}` : '',
    labels.length ? `İlgili konular: ${labels.join(', ')}` : ''
  ].filter(Boolean).join('\n');
  const documents = [createSearchDocument(row, 'question:0', 'question', questionDocument, sharedMetadata)];
  const answerChunks = chunkSearchDocumentText(row.answer_text || '');
  answerChunks.forEach((chunk, index) => {
    const content = [
      question ? `Soru: ${question}` : '',
      labels.length ? `İlgili konular: ${labels.join(', ')}` : '',
      `Cevap bölümü: ${chunk}`
    ].filter(Boolean).join('\n');
    documents.push(createSearchDocument(row, `answer:${index}`, 'answer', content, {
      ...sharedMetadata,
      chunkIndex: index
    }));
  });
  return documents.filter(document => document.content);
}

function semanticSearchBoost(similarity = 0) {
  const score = Number(similarity || 0);
  if (!Number.isFinite(score) || score <= 0) return 0;
  return Math.round(Math.min(1, score) * 700);
}

module.exports = {
  PUBLIC_SEARCH_EMBEDDING_DIMENSIONS,
  PUBLIC_SEARCH_EMBEDDING_MODEL,
  buildPublicQaSearchDocuments,
  chunkSearchDocumentText,
  cleanSearchDocumentText,
  normalizeSearchText,
  publicQaSearchLabels,
  publicQaTopicSlugs,
  relatedCategorySlugsFromSearchRows,
  rowsBySlug,
  searchDocumentHash,
  semanticSearchBoost
};
