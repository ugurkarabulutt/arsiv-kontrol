const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');

const migrationPath = path.join(
  __dirname,
  '../supabase/migrations/20261027171035_repair_search_read_and_analysis_metadata.sql'
);
const migration = fs.readFileSync(migrationPath, 'utf8');
const schema = fs.readFileSync(path.join(__dirname, '../schema.sql'), 'utf8');

test('analysis provenance columns are restored idempotently', () => {
  assert.match(migration, /add column if not exists prompt_version text/i);
  assert.match(migration, /add column if not exists rules_hash text/i);
});

test('read counter is unambiguous, atomic and backend-only', () => {
  for (const sql of [migration, schema]) {
    const start = sql.indexOf('create or replace function public.increment_public_question_read');
    assert.notEqual(start, -1);
    const end = sql.indexOf('-- public_categories', start);
    const body = sql.slice(start, end === -1 ? start + 2500 : end);
    assert.match(body, /security invoker/i);
    assert.match(body, /set search_path = ''/i);
    assert.match(body, /on conflict on constraint public_question_stats_pkey/i);
    assert.doesNotMatch(body, /on conflict \(slug\)/i);
    assert.match(body, /revoke all[\s\S]*from public, anon, authenticated/i);
    assert.match(body, /grant execute[\s\S]*to service_role/i);
  }
});

test('hybrid search narrows indexed lexical candidates before vector scoring', () => {
  for (const sql of [migration, schema]) {
    assert.match(sql, /public_qa_search_documents_search_vector_idx/i);
    assert.match(sql, /to_tsvector\('simple'::regconfig, search_text\)/i);
    const occurrences = sql.indexOf('lexical_occurrences as materialized');
    const hits = sql.indexOf('lexical_hits as materialized', occurrences);
    const candidates = sql.indexOf('lexical_candidates as materialized', hits);
    const vectorScore = sql.indexOf('document.embedding operator(extensions.<=>) p_query_embedding', candidates);
    assert.ok(occurrences > -1 && hits > occurrences && candidates > hits && vectorScore > candidates);
    assert.match(sql.slice(occurrences, candidates), /to_tsquery\('simple'::regconfig, terms\.term \|\| ':\*'\)/i);
    assert.match(sql.slice(hits, candidates), /limit least\(greatest\(p_match_count, 1\) \* 8, 384\)/i);
  }
});
