'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const {
  PUBLIC_SEARCH_EMBEDDING_DIMENSIONS,
  buildPublicQaSearchDocuments,
  chunkSearchDocumentText,
  normalizeSearchText,
  relatedCategorySlugsFromSearchRows,
  semanticSearchBoost
} = require('../public-search-core');

test('search answer chunks stay bounded and retain neighboring context', () => {
  const paragraphs = Array.from({ length: 12 }, (_, index) => `Bölüm ${index + 1}. ${'Açıklama '.repeat(80)}`);
  const chunks = chunkSearchDocumentText(paragraphs.join('\n\n'), {
    maxChars: 1000,
    overlapChars: 120,
    maxChunks: 6
  });

  assert.ok(chunks.length > 1);
  assert.ok(chunks.length <= 6);
  assert.ok(chunks.every(chunk => chunk.length <= 1000));
  assert.match(chunks[0], /Bölüm 1/);
  assert.match(chunks[1], /Açıklama/);
});

test('search documents include the question, answer, and approved concept labels', () => {
  const documents = buildPublicQaSearchDocuments({
    slug: 'uykuda-nefs',
    title: 'Uyku halinde nefs',
    question: 'Uyku halinde vücuttan ayrılan nedir?',
    summary: 'Uyku, nefs ve beden ilişkisi açıklanıyor.',
    answer_text: 'Her gece nefsimiz vücudumuzdan ayrılır. Ruh ile nefs aynı kavram değildir.',
    category_slug: 'nefs',
    topic_slugs: ['uyku-ve-ruya'],
    status: 'published'
  }, {
    categories: [{ slug: 'nefs', name: 'Nefs' }],
    topics: [{ slug: 'uyku-ve-ruya', name: 'Uyku ve Rüya' }]
  });

  assert.equal(documents[0].document_key, 'question:0');
  assert.match(documents[0].content, /İlgili konular: Nefs, Uyku ve Rüya/);
  assert.ok(documents.some(document => document.document_kind === 'answer'));
  assert.match(documents.find(document => document.document_kind === 'answer').content, /nefsimiz vücudumuzdan ayrılır/);
  assert.match(documents.find(document => document.document_kind === 'answer').search_text, /nefsimiz vucudumuzdan ayrilir/);
  assert.equal(documents[0].content_hash.length, 64);
});

test('search normalization keeps Turkish intent terms comparable', () => {
  assert.equal(
    normalizeSearchText('Uyku hâlinde vücuttan ayrılan nefstir.'),
    'uyku halinde vucuttan ayrilan nefstir'
  );
});

test('semantic boost admits meaning matches without outranking exact titles', () => {
  assert.equal(PUBLIC_SEARCH_EMBEDDING_DIMENSIONS, 1024);
  assert.equal(semanticSearchBoost(0), 0);
  assert.equal(semanticSearchBoost(0.75), 525);
  assert.equal(semanticSearchBoost(2), 700);
});

test('related categories come from concepts repeated in the strongest search results', () => {
  const slugs = relatedCategorySlugsFromSearchRows([
    { category_slug: 'olum', topic_slugs: ['uyku', 'nefs'] },
    { category_slug: 'ruh', topic_slugs: ['nefs', 'fizik-vucut'] },
    { category_slug: 'ruh', topic_slugs: ['nefs'] },
    { category_slug: 'can', topic_slugs: ['ruh', 'nefs'] }
  ], 4);

  assert.deepEqual(slugs, ['nefs', 'ruh', 'olum', 'uyku']);
});
