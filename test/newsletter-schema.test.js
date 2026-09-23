const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { PGlite } = require('@electric-sql/pglite');

test('newsletter admin migration preserves subscribers and keeps new tables service-role only', async () => {
  const db = new PGlite();
  await db.exec(`
    create role anon;
    create role authenticated;
    create role service_role;
    create table public.users (id uuid primary key default gen_random_uuid());
    create table public.public_newsletter_subscriptions (
      id uuid primary key default gen_random_uuid(),
      email text not null unique,
      status text not null default 'active' check (status in ('active', 'unsubscribed')),
      source text not null default 'footer',
      consent_version text not null,
      consented_at timestamptz not null default now(),
      unsubscribed_at timestamptz,
      unsubscribe_token uuid not null default gen_random_uuid() unique,
      created_at timestamptz not null default now(),
      updated_at timestamptz not null default now(),
      constraint public_newsletter_email_normalized check (email = lower(btrim(email)))
    );
    insert into public.public_newsletter_subscriptions (email, consent_version)
    values ('existing@example.com', 'v1');
  `);
  const migration = fs.readFileSync(path.join(__dirname, '..', 'supabase', 'migrations', '20260923213000_newsletter_admin_center.sql'), 'utf8');
  await db.exec(migration);

  const subscriber = await db.query("select email, status, resend_sync_status from public.public_newsletter_subscriptions where email='existing@example.com'");
  assert.deepEqual(subscriber.rows[0], { email: 'existing@example.com', status: 'active', resend_sync_status: 'pending' });
  await db.exec("update public.public_newsletter_subscriptions set status='suppressed' where email='existing@example.com'");
  await assert.rejects(() => db.exec("update public.public_newsletter_subscriptions set status='invalid' where email='existing@example.com'"));

  const tables = await db.query("select tablename, rowsecurity from pg_tables where schemaname='public' and tablename in ('newsletter_campaigns','newsletter_delivery_events') order by tablename");
  assert.deepEqual(tables.rows, [
    { tablename: 'newsletter_campaigns', rowsecurity: true },
    { tablename: 'newsletter_delivery_events', rowsecurity: true }
  ]);
  await db.close();
});

test('question newsletter consent migration keeps old questions opted out', async () => {
  const db = new PGlite();
  await db.exec(`
    create table public.public_question_submissions (
      id uuid primary key default gen_random_uuid(),
      question text not null
    );
    insert into public.public_question_submissions (question) values ('Mevcut soru kaydı');
  `);
  const migration = fs.readFileSync(path.join(__dirname, '..', 'supabase', 'migrations', '20260923233000_question_newsletter_consent.sql'), 'utf8');
  await db.exec(migration);

  const result = await db.query('select newsletter_consent, newsletter_consent_version, newsletter_consented_at from public.public_question_submissions');
  assert.deepEqual(result.rows[0], {
    newsletter_consent: false,
    newsletter_consent_version: null,
    newsletter_consented_at: null
  });
  await db.close();
});
