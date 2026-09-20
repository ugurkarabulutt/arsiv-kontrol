create table if not exists public.public_newsletter_subscriptions (
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

alter table public.public_newsletter_subscriptions enable row level security;

revoke all on public.public_newsletter_subscriptions from public, anon, authenticated;
grant select, insert, update, delete on public.public_newsletter_subscriptions to service_role;

create index if not exists public_newsletter_status_created_idx
  on public.public_newsletter_subscriptions (status, created_at desc);
