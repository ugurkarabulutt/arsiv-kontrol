'use strict';

const {
  PUBLIC_SEARCH_EMBEDDING_DIMENSIONS,
  PUBLIC_SEARCH_EMBEDDING_MODEL,
  buildPublicQaSearchDocuments,
  rowsBySlug
} = require('./public-search-core');

function chunkArray(items = [], size = 100) {
  const chunks = [];
  for (let index = 0; index < items.length; index += size) chunks.push(items.slice(index, index + size));
  return chunks;
}

async function loadExistingSearchDocuments(supabase, slugs = []) {
  const rows = [];
  for (const batch of chunkArray([...new Set(slugs.filter(Boolean))], 100)) {
    if (!batch.length) continue;
    const { data, error } = await supabase
      .from('public_qa_search_documents')
      .select('qa_slug,document_key,content_hash,embedding_model,search_text')
      .in('qa_slug', batch);
    if (error) throw new Error(error.message);
    rows.push(...(data || []));
  }
  return rows;
}

async function upsertSearchDocuments(supabase, rows = []) {
  for (const batch of chunkArray(rows, 100)) {
    if (!batch.length) continue;
    const { error } = await supabase
      .from('public_qa_search_documents')
      .upsert(batch, { onConflict: 'qa_slug,document_key' });
    if (error) throw new Error(error.message);
  }
}

async function deleteStaleSearchDocuments(supabase, staleRows = []) {
  const bySlug = new Map();
  for (const row of staleRows) {
    if (!row?.qa_slug || !row?.document_key) continue;
    if (!bySlug.has(row.qa_slug)) bySlug.set(row.qa_slug, []);
    bySlug.get(row.qa_slug).push(row.document_key);
  }
  for (const [slug, keys] of bySlug) {
    for (const batch of chunkArray(keys, 100)) {
      const { error } = await supabase
        .from('public_qa_search_documents')
        .delete()
        .eq('qa_slug', slug)
        .in('document_key', batch);
      if (error) throw new Error(error.message);
    }
  }
}

async function indexPublicQaSearchRows(options = {}) {
  const {
    supabase,
    rows = [],
    categories = [],
    topics = [],
    embedTexts,
    embeddingModel = PUBLIC_SEARCH_EMBEDDING_MODEL,
    embeddingDimensions = PUBLIC_SEARCH_EMBEDDING_DIMENSIONS,
    embeddingBatchSize = 48,
    now = new Date().toISOString()
  } = options;
  if (!supabase) throw new Error('Supabase istemcisi gerekli.');
  if (typeof embedTexts !== 'function') throw new Error('Embedding üreticisi gerekli.');

  const activeRows = (rows || []).filter(row => row?.slug && (!row.status || row.status === 'published'));
  const slugs = activeRows.map(row => row.slug);
  if (!slugs.length) return { indexedRecords: 0, indexedDocuments: 0, skippedDocuments: 0, deletedDocuments: 0 };

  const categoryMap = rowsBySlug(categories);
  const topicMap = rowsBySlug(topics);
  const documents = activeRows.flatMap(row => buildPublicQaSearchDocuments(row, { categoryMap, topicMap }));
  const existingRows = await loadExistingSearchDocuments(supabase, slugs);
  const existingMap = new Map(existingRows.map(row => [`${row.qa_slug}:${row.document_key}`, row]));
  const wantedKeys = new Set(documents.map(row => `${row.qa_slug}:${row.document_key}`));
  const staleRows = existingRows.filter(row => !wantedKeys.has(`${row.qa_slug}:${row.document_key}`));
  const pending = documents.filter(row => {
    const existing = existingMap.get(`${row.qa_slug}:${row.document_key}`);
    return !existing
      || existing.content_hash !== row.content_hash
      || existing.embedding_model !== embeddingModel
      || existing.search_text !== row.search_text;
  });

  const embeddedRows = [];
  for (const batch of chunkArray(pending, Math.max(1, Number(embeddingBatchSize) || 48))) {
    const vectors = await embedTexts(batch.map(row => row.content), {
      model: embeddingModel,
      dimensions: embeddingDimensions
    });
    if (!Array.isArray(vectors) || vectors.length !== batch.length) {
      throw new Error('Embedding servisi beklenen sayıda sonuç döndürmedi.');
    }
    batch.forEach((row, index) => {
      if (!Array.isArray(vectors[index]) || vectors[index].length !== embeddingDimensions) {
        throw new Error(`Embedding boyutu ${embeddingDimensions} olmalı.`);
      }
      embeddedRows.push({
        ...row,
        embedding: vectors[index],
        embedding_model: embeddingModel,
        updated_at: now
      });
    });
  }

  await upsertSearchDocuments(supabase, embeddedRows);
  await deleteStaleSearchDocuments(supabase, staleRows);
  return {
    indexedRecords: new Set(embeddedRows.map(row => row.qa_slug)).size,
    indexedDocuments: embeddedRows.length,
    skippedDocuments: documents.length - pending.length,
    deletedDocuments: staleRows.length,
    totalDocuments: documents.length
  };
}

module.exports = {
  indexPublicQaSearchRows,
  loadExistingSearchDocuments
};
