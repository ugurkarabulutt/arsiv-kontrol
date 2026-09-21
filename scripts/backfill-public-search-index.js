'use strict';

require('dotenv').config({ path: process.env.ENV_FILE || '.env' });

const { createClient } = require('@supabase/supabase-js');
const {
  PUBLIC_SEARCH_EMBEDDING_DIMENSIONS,
  PUBLIC_SEARCH_EMBEDDING_MODEL,
  buildPublicQaSearchDocuments,
  rowsBySlug
} = require('../public-search-core');
const { indexPublicQaSearchRows } = require('../public-search-indexer');

const OPENAI_EMBEDDINGS_URL = 'https://api.openai.com/v1/embeddings';
const args = new Set(process.argv.slice(2));
const apply = args.has('--apply');
const requestedSlug = process.argv.find(value => value.startsWith('--slug='))?.slice('--slug='.length).trim() || '';
const requestedLimit = Number(process.argv.find(value => value.startsWith('--limit='))?.slice('--limit='.length) || 0);
const recordBatchSize = Math.max(1, Math.min(50, Number(process.argv.find(value => value.startsWith('--batch='))?.slice('--batch='.length) || 20)));

function requiredEnv(name) {
  const value = String(process.env[name] || '').trim();
  if (!value) throw new Error(`${name} tanımlı değil.`);
  return value;
}

function sleep(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

async function fetchAllPages(buildQuery, pageSize = 1000) {
  const rows = [];
  for (let from = 0; ; from += pageSize) {
    const { data, error } = await buildQuery().range(from, from + pageSize - 1);
    if (error) throw new Error(error.message);
    rows.push(...(data || []));
    if (!data || data.length < pageSize) return rows;
  }
}

async function fetchOpenAIEmbeddings(inputs = [], options = {}) {
  if (!inputs.length) return [];
  const apiKey = requiredEnv('OPENAI_API_KEY');
  let lastError = null;
  for (let attempt = 0; attempt < 3; attempt += 1) {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 30000);
    try {
      const response = await fetch(OPENAI_EMBEDDINGS_URL, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${apiKey}`
        },
        body: JSON.stringify({
          model: options.model || PUBLIC_SEARCH_EMBEDDING_MODEL,
          dimensions: options.dimensions || PUBLIC_SEARCH_EMBEDDING_DIMENSIONS,
          input: inputs,
          encoding_format: 'float'
        }),
        signal: controller.signal
      });
      clearTimeout(timeout);
      const payload = await response.json().catch(() => ({}));
      if (!response.ok) throw new Error(payload?.error?.message || `OpenAI embeddings HTTP ${response.status}`);
      return (payload.data || []).sort((a, b) => a.index - b.index).map(item => item.embedding);
    } catch (error) {
      clearTimeout(timeout);
      lastError = error;
      if (attempt < 2) await sleep(800 * (attempt + 1));
    }
  }
  throw lastError || new Error('Embedding üretilemedi.');
}

async function main() {
  const supabase = createClient(requiredEnv('SUPABASE_URL'), requiredEnv('SUPABASE_KEY'), {
    auth: { persistSession: false, autoRefreshToken: false }
  });
  const [categories, topics] = await Promise.all([
    fetchAllPages(() => supabase.from('public_categories').select('slug,name,description')),
    fetchAllPages(() => supabase.from('public_topics').select('slug,name,description,category_slug,related_topic_slugs'))
  ]);
  let rows = await fetchAllPages(() => {
    let query = supabase
      .from('public_qa')
      .select('slug,title,question,summary,excerpt,answer_text,category_slug,topic_slugs,status,updated_at')
      .eq('status', 'published')
      .order('slug', { ascending: true });
    if (requestedSlug) query = query.eq('slug', requestedSlug);
    return query;
  });
  if (Number.isFinite(requestedLimit) && requestedLimit > 0) rows = rows.slice(0, requestedLimit);

  const categoryMap = rowsBySlug(categories);
  const topicMap = rowsBySlug(topics);
  const documentCount = rows.reduce((total, row) => total + buildPublicQaSearchDocuments(row, { categoryMap, topicMap }).length, 0);
  console.log(JSON.stringify({
    mode: apply ? 'apply' : 'dry-run',
    records: rows.length,
    estimatedDocuments: documentCount,
    model: PUBLIC_SEARCH_EMBEDDING_MODEL,
    dimensions: PUBLIC_SEARCH_EMBEDDING_DIMENSIONS
  }));
  if (!apply || !rows.length) return;

  const total = { indexedRecords: 0, indexedDocuments: 0, skippedDocuments: 0, deletedDocuments: 0 };
  for (let index = 0; index < rows.length; index += recordBatchSize) {
    const batch = rows.slice(index, index + recordBatchSize);
    const result = await indexPublicQaSearchRows({
      supabase,
      rows: batch,
      categories,
      topics,
      embedTexts: fetchOpenAIEmbeddings
    });
    for (const key of Object.keys(total)) total[key] += Number(result[key] || 0);
    console.log(JSON.stringify({ progress: Math.min(rows.length, index + batch.length), total: rows.length, ...result }));
  }

  const indexedRows = await fetchAllPages(() => supabase.from('public_qa_search_documents').select('qa_slug'));
  const indexedSlugs = new Set(indexedRows.map(row => row.qa_slug).filter(Boolean));
  const missingSlugs = rows.map(row => row.slug).filter(slug => !indexedSlugs.has(slug));
  console.log(JSON.stringify({
    complete: missingSlugs.length === 0,
    indexedQaCount: indexedSlugs.size,
    checkedQaCount: rows.length,
    missingCount: missingSlugs.length,
    ...total
  }));
  if (missingSlugs.length) process.exitCode = 2;
}

main().catch(error => {
  console.error(`Public arama indeksi hazırlanamadı: ${error.message}`);
  process.exitCode = 1;
});
