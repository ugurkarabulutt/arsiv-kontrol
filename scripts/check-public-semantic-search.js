'use strict';

require('dotenv').config({ path: process.env.ENV_FILE || '.env' });

const { createClient } = require('@supabase/supabase-js');
const {
  PUBLIC_SEARCH_EMBEDDING_DIMENSIONS,
  PUBLIC_SEARCH_EMBEDDING_MODEL
} = require('../public-search-core');

const OPENAI_EMBEDDINGS_URL = 'https://api.openai.com/v1/embeddings';
const query = process.argv.find(value => value.startsWith('--query='))?.slice('--query='.length).trim()
  || 'Uyku halinde vücuttan ayrılan nefstir';
const displayLimit = Math.max(1, Math.min(30, Number(process.argv.find(value => value.startsWith('--limit='))?.slice('--limit='.length) || 10)));
const poolLimit = Math.max(displayLimit, Math.min(120, Number(process.argv.find(value => value.startsWith('--pool='))?.slice('--pool='.length) || 48)));
const expectedSlug = process.argv.find(value => value.startsWith('--expect-slug='))?.slice('--expect-slug='.length).trim() || '';
const rawQuery = process.argv.includes('--raw-query');

function queryTerms(value = '') {
  const suffixes = ['dir', 'dır', 'dur', 'dür', 'tir', 'tır', 'tur', 'tür', 'den', 'dan', 'ten', 'tan', 'an', 'en', 'de', 'da', 'te', 'ta'];
  const terms = new Set();
  const tokens = String(value || '').toLocaleLowerCase('tr-TR')
    .replace(/ç/g, 'c').replace(/ğ/g, 'g').replace(/ı/g, 'i')
    .replace(/ö/g, 'o').replace(/ş/g, 's').replace(/ü/g, 'u')
    .replace(/â/g, 'a').replace(/î/g, 'i').replace(/û/g, 'u')
    .replace(/[^a-z0-9]+/g, ' ').trim().split(/\s+/).filter(token => token.length >= 3);
  for (const token of tokens) {
    const forms = [token];
    for (const suffix of suffixes) {
      if (token.length > suffix.length + 3 && token.endsWith(suffix)) forms.push(token.slice(0, -suffix.length));
    }
    forms.sort((a, b) => a.length - b.length || a.localeCompare(b));
    terms.add(forms[0]);
  }
  return [...terms].slice(0, 24);
}

function requiredEnv(name) {
  const value = String(process.env[name] || '').trim();
  if (!value) throw new Error(`${name} tanımlı değil.`);
  return value;
}

async function embedQuery(value) {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 30000);
  try {
    const response = await fetch(OPENAI_EMBEDDINGS_URL, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${requiredEnv('OPENAI_API_KEY')}`
      },
      body: JSON.stringify({
        model: PUBLIC_SEARCH_EMBEDDING_MODEL,
        dimensions: PUBLIC_SEARCH_EMBEDDING_DIMENSIONS,
        input: [rawQuery ? value : `Dini soru-cevap arşivinde aranan konu: ${value}`],
        encoding_format: 'float'
      }),
      signal: controller.signal
    });
    const payload = await response.json().catch(() => ({}));
    if (!response.ok) throw new Error(payload?.error?.message || `OpenAI embeddings HTTP ${response.status}`);
    const embedding = payload?.data?.[0]?.embedding;
    if (!Array.isArray(embedding) || embedding.length !== PUBLIC_SEARCH_EMBEDDING_DIMENSIONS) {
      throw new Error('Sorgu embedding boyutu geçersiz.');
    }
    return embedding;
  } finally {
    clearTimeout(timeout);
  }
}

async function main() {
  const startedAt = Date.now();
  const supabase = createClient(requiredEnv('SUPABASE_URL'), requiredEnv('SUPABASE_KEY'), {
    auth: { persistSession: false, autoRefreshToken: false }
  });
  const embedding = await embedQuery(query);
  const { data: matches, error } = await supabase.rpc('match_public_qa_hybrid_search', {
    p_query_embedding: embedding,
    p_query_terms: queryTerms(query),
    p_match_threshold: 0.35,
    p_match_count: poolLimit
  });
  if (error) throw new Error(error.message);
  const slugs = (matches || []).map(match => match.qa_slug).filter(Boolean);
  const { data: rows, error: rowsError } = slugs.length
    ? await supabase.from('public_qa').select('slug,title,question').in('slug', slugs)
    : { data: [], error: null };
  if (rowsError) throw new Error(rowsError.message);
  const rowMap = new Map((rows || []).map(row => [row.slug, row]));
  const formattedMatches = (matches || []).map((match, index) => ({
    rank: index + 1,
    similarity: Number(Number(match.similarity || 0).toFixed(4)),
    lexicalMatches: Number(match.lexical_matches || 0),
    hybridScore: Number(Number(match.hybrid_score || 0).toFixed(4)),
    kind: match.document_kind,
    slug: match.qa_slug,
    title: rowMap.get(match.qa_slug)?.title || rowMap.get(match.qa_slug)?.question || '',
    preview: String(match.matched_text || '').replace(/\s+/g, ' ').trim().slice(0, 280)
  }));
  const expected = expectedSlug
    ? formattedMatches.find(match => match.slug === expectedSlug) || null
    : undefined;
  console.log(JSON.stringify({
    query,
    elapsedMs: Date.now() - startedAt,
    poolSize: formattedMatches.length,
    expected,
    matches: formattedMatches.slice(0, displayLimit)
  }, null, 2));
}

main().catch(error => {
  console.error(`Public anlam araması doğrulanamadı: ${error.message}`);
  process.exitCode = 1;
});
