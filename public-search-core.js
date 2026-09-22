'use strict';

const crypto = require('crypto');

const PUBLIC_SEARCH_EMBEDDING_MODEL = 'text-embedding-3-small';
const PUBLIC_SEARCH_EMBEDDING_DIMENSIONS = 1024;
const PUBLIC_SEARCH_ANSWER_CHUNK_CHARS = 1800;
const PUBLIC_SEARCH_ANSWER_CHUNK_OVERLAP_CHARS = 220;
const PUBLIC_SEARCH_MAX_ANSWER_CHUNKS = 32;
const PUBLIC_SEARCH_KEYWORD_TERM_LIMIT = 5;
const PUBLIC_SEARCH_QUERY_FILLERS = new Set([
  'acaba', 'acikla', 'aciklar', 'anlat', 'anlatir', 'ara', 'bir', 'bize', 'bu',
  'cevap', 'eder', 'etmek', 'gibi', 'halinde', 'hocam', 'icin', 'ile', 'mi',
  'insan', 'insanin', 'kisi', 'kisinin', 'midir', 'misiniz', 'muhterem', 'mu',
  'mudur', 'nasil', 'ne', 'nedir', 'sahip', 'sirasinda', 'soru', 'var', 've', 'ya'
]);

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

function canonicalSearchTerm(value = '') {
  const token = normalizeSearchText(value).replace(/\s+/g, '');
  if (!token) return '';
  if (/^uyku/.test(token) || /^uyu(?:r|du|dug|yan|mak)/.test(token)) return 'uyku';
  if (/^vucu(?:t|d)/.test(token)) return 'vucut';
  if (/^ayril/.test(token)) return 'ayril';
  if (/^beden/.test(token)) return 'beden';
  if (/^nefs/.test(token)) return 'nefs';
  if (/^ruh/.test(token)) return 'ruh';
  if (/^cik/.test(token)) return 'cik';
  if (/^ulas/.test(token)) return 'ulas';
  if (/^yonel/.test(token)) return 'yonel';
  if (/^hidayet/.test(token)) return 'hidayet';
  if (/^zikir/.test(token)) return 'zikir';

  const suffixes = [
    'larindan', 'lerinden', 'larina', 'lerine', 'larinin', 'lerinin',
    'undan', 'unden', 'indan', 'inden', 'dan', 'den', 'tan', 'ten',
    'lar', 'ler', 'dir', 'dur', 'tir', 'tur', 'nin', 'nun', 'lik', 'luk'
  ];
  for (const suffix of suffixes) {
    if (token.length > suffix.length + 3 && token.endsWith(suffix)) {
      return token.slice(0, -suffix.length);
    }
  }
  return token;
}

function keywordSearchTerms(value = '', limit = PUBLIC_SEARCH_KEYWORD_TERM_LIMIT) {
  const normalized = normalizeSearchText(value);
  const sourceTokens = normalized.split(' ').filter(token => token.length >= 3);
  const usefulTokens = sourceTokens.filter(token => !PUBLIC_SEARCH_QUERY_FILLERS.has(token));
  const selectedTokens = usefulTokens.length ? usefulTokens : sourceTokens;
  const terms = [];
  for (const token of selectedTokens) {
    const canonical = canonicalSearchTerm(token);
    if (canonical.length < 3 || terms.includes(canonical)) continue;
    terms.push(canonical);
  }
  return terms.slice(0, Math.max(1, Number(limit) || PUBLIC_SEARCH_KEYWORD_TERM_LIMIT));
}

function searchTextTermPositions(searchText = '', terms = []) {
  return terms
    .map(term => ({ term, index: searchText.indexOf(term) }))
    .filter(item => item.index >= 0);
}

function buildSearchMatchExcerpt(value = '', terms = [], maxChars = 240) {
  const source = cleanSearchDocumentText(value, 16000)
    .replace(/^Soru:\s*[^\n]*\n?/iu, '')
    .replace(/^İlgili konular:\s*[^\n]*\n?/iu, '')
    .replace(/^Cevap bölümü:\s*/iu, '')
    .trim();
  if (!source) return '';
  const sentences = source.split(/(?<=[.!?])\s+|\n+/u).map(item => item.trim()).filter(Boolean);
  const candidates = sentences.length ? sentences : [source];
  let best = candidates[0];
  let bestScore = -1;
  for (const sentence of candidates) {
    const normalized = normalizeSearchText(sentence);
    const matches = terms.filter(term => normalized.includes(term));
    const positions = searchTextTermPositions(normalized, matches).map(item => item.index);
    const span = positions.length > 1 ? Math.max(...positions) - Math.min(...positions) : 9999;
    const score = (matches.length * 1000) + (positions.length > 1 ? Math.max(0, 320 - span) : 0);
    if (score > bestScore) {
      best = sentence;
      bestScore = score;
    }
  }
  if (best.length <= maxChars) return best;
  const normalizedBest = normalizeSearchText(best);
  const firstMatch = searchTextTermPositions(normalizedBest, terms)
    .sort((a, b) => a.index - b.index)[0];
  const start = firstMatch ? Math.max(0, firstMatch.index - Math.floor(maxChars * 0.28)) : 0;
  const clipped = best.slice(start, start + maxChars).trim();
  return `${start > 0 ? '...' : ''}${clipped}${best.length > start + clipped.length ? '...' : ''}`;
}

function scoreKeywordSearchDocument(document = {}, query = '', terms = keywordSearchTerms(query)) {
  const searchText = normalizeSearchText(document.search_text || document.content || '');
  if (!searchText || !terms.length) return null;
  const matches = searchTextTermPositions(searchText, terms);
  if (!matches.length) return null;
  const matchedTerms = matches.map(item => item.term);
  const coverage = matchedTerms.length / terms.length;
  const indexes = matches.map(item => item.index);
  const span = indexes.length > 1 ? Math.max(...indexes) - Math.min(...indexes) : 9999;
  const exactQuery = normalizeSearchText(query);
  const exactBonus = exactQuery && searchText.includes(exactQuery) ? 1200 : 0;
  const coverageBonus = Math.round(coverage * 1600);
  const allTermsBonus = matchedTerms.length === terms.length ? 620 : 0;
  const proximityBonus = indexes.length > 1 ? Math.max(0, 420 - Math.min(span, 420)) : 0;
  const kindBonus = document.document_kind === 'question' ? 140 : 80;
  return {
    slug: document.qa_slug,
    score: exactBonus + coverageBonus + allTermsBonus + proximityBonus + (matchedTerms.length * 240) + kindBonus,
    matchedTerms,
    matchedCount: matchedTerms.length,
    coverage,
    documentKind: document.document_kind || '',
    excerpt: buildSearchMatchExcerpt(document.content || '', matchedTerms)
  };
}

function rankKeywordSearchDocuments(documents = [], query = '', options = {}) {
  const terms = keywordSearchTerms(query, options.termLimit);
  const bestBySlug = new Map();
  for (const document of documents || []) {
    if (!document?.qa_slug) continue;
    const candidate = scoreKeywordSearchDocument(document, query, terms);
    if (!candidate) continue;
    const current = bestBySlug.get(candidate.slug);
    if (!current || candidate.score > current.score) bestBySlug.set(candidate.slug, candidate);
  }
  return [...bestBySlug.values()]
    .sort((a, b) => b.score - a.score
      || b.coverage - a.coverage
      || b.matchedCount - a.matchedCount
      || a.slug.localeCompare(b.slug, 'tr'))
    .slice(0, Math.max(1, Number(options.limit) || 60));
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
  buildSearchMatchExcerpt,
  canonicalSearchTerm,
  chunkSearchDocumentText,
  cleanSearchDocumentText,
  keywordSearchTerms,
  normalizeSearchText,
  publicQaSearchLabels,
  publicQaTopicSlugs,
  relatedCategorySlugsFromSearchRows,
  rowsBySlug,
  rankKeywordSearchDocuments,
  searchDocumentHash,
  scoreKeywordSearchDocument,
  semanticSearchBoost
};
