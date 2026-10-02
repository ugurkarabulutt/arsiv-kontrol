const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');
const { PGlite } = require('@electric-sql/pglite');

test('question slug migration moves dependent data and keeps a permanent redirect', async () => {
  const db = new PGlite();
  await db.exec(`
    create role anon;
    create role authenticated;
    create role service_role;
    create table public.history (id uuid primary key);
    create table public.public_qa (
      slug text primary key,
      source_history_id uuid references public.history(id),
      related_slugs jsonb not null default '[]'::jsonb,
      updated_at timestamptz not null default now()
    );
    create table public.public_qa_topics (
      qa_slug text references public.public_qa(slug) on delete cascade,
      topic_slug text not null,
      primary key (qa_slug, topic_slug)
    );
    create table public.public_qa_search_documents (
      qa_slug text references public.public_qa(slug) on delete cascade,
      document_key text not null,
      primary key (qa_slug, document_key)
    );
    create table public.public_question_stats (
      slug text primary key,
      read_count integer not null default 0,
      updated_at timestamptz not null default now()
    );
    create table public.public_visit_events (
      id uuid primary key,
      question_slug text
    );
    create table public.public_question_redirects (
      from_slug text primary key,
      to_slug text not null,
      history_id uuid not null references public.history(id),
      created_at timestamptz not null default now(),
      check (from_slug <> to_slug)
    );
  `);
  const migration = fs.readFileSync(
    path.join(__dirname, '../supabase/migrations/20261002110000_public_question_slug_cleanup.sql'),
    'utf8'
  );
  await db.exec(migration);
  const historyId = '00000000-0000-4000-8000-000000000001';
  const otherHistoryId = '00000000-0000-4000-8000-000000000002';
  await db.query('insert into public.history(id) values ($1), ($2)', [historyId, otherHistoryId]);
  await db.query(`
    insert into public.public_qa(slug, source_history_id, related_slugs) values
      ('muhterem-hocam-cennete-kimler-girer', $1, '[]'::jsonb),
      ('cennete-kimler-girer', $2, '["muhterem-hocam-cennete-kimler-girer"]'::jsonb)
  `, [historyId, otherHistoryId]);
  await db.query("insert into public.public_qa_topics(qa_slug,topic_slug) values ('muhterem-hocam-cennete-kimler-girer','ahiret')");
  await db.query("insert into public.public_qa_search_documents(qa_slug,document_key) values ('muhterem-hocam-cennete-kimler-girer','question:0')");
  await db.query("insert into public.public_question_stats(slug,read_count) values ('muhterem-hocam-cennete-kimler-girer',7)");
  await db.query("insert into public.public_visit_events(id,question_slug) values ('00000000-0000-4000-8000-000000000003','muhterem-hocam-cennete-kimler-girer')");

  const payload = [{
    oldSlug: 'muhterem-hocam-cennete-kimler-girer',
    newSlug: 'cennete-kimler-girer-2'
  }];
  const result = await db.query('select public.apply_public_question_slug_migration($1::jsonb) as result', [JSON.stringify(payload)]);
  assert.equal(result.rows[0].result.moved, 1);
  assert.equal((await db.query("select count(*)::int as count from public.public_qa where slug='cennete-kimler-girer-2'")).rows[0].count, 1);
  assert.equal((await db.query('select qa_slug from public.public_qa_topics')).rows[0].qa_slug, 'cennete-kimler-girer-2');
  assert.equal((await db.query('select qa_slug from public.public_qa_search_documents')).rows[0].qa_slug, 'cennete-kimler-girer-2');
  assert.equal((await db.query("select read_count from public.public_question_stats where slug='cennete-kimler-girer-2'")).rows[0].read_count, 7);
  assert.equal((await db.query('select question_slug from public.public_visit_events')).rows[0].question_slug, 'cennete-kimler-girer-2');
  assert.deepEqual((await db.query("select related_slugs from public.public_qa where slug='cennete-kimler-girer'")).rows[0].related_slugs, ['cennete-kimler-girer-2']);
  assert.deepEqual((await db.query('select from_slug,to_slug,redirect_type from public.public_question_redirects')).rows[0], {
    from_slug: 'muhterem-hocam-cennete-kimler-girer',
    to_slug: 'cennete-kimler-girer-2',
    redirect_type: 'slug_cleanup'
  });
  await db.close();
});
