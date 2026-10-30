'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');

const migration = fs.readFileSync(path.join(
  __dirname,
  '../supabase/migrations/20261030230541_admin_review_search_index.sql'
), 'utf8');

test('review search migration is indexed, normalized and private', () => {
  assert.match(migration, /generated always as/i);
  assert.match(migration, /normalize_review_search_text/i);
  assert.match(migration, /history_review_search_text_trgm_idx/i);
  assert.match(migration, /extensions\.gin_trgm_ops/i);
  assert.match(migration, /with \(security_invoker = true\)/i);
  assert.match(migration, /revoke all on public\.review_history_queue from public, anon, authenticated/i);
  assert.match(migration, /grant select on public\.review_history_queue to service_role/i);
});
