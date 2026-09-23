alter table public.public_newsletter_subscriptions
  drop constraint if exists public_newsletter_subscriptions_status_check;

alter table public.public_newsletter_subscriptions
  add constraint public_newsletter_subscriptions_status_check
  check (status in ('active', 'unsubscribed', 'suppressed'));

alter table public.public_newsletter_subscriptions
  add column if not exists status_reason text,
  add column if not exists resend_contact_id text,
  add column if not exists resend_sync_status text not null default 'pending',
  add column if not exists resend_synced_at timestamptz,
  add column if not exists resend_error text,
  add column if not exists last_provider_event_at timestamptz;

alter table public.public_newsletter_subscriptions
  drop constraint if exists public_newsletter_subscriptions_resend_sync_status_check;

alter table public.public_newsletter_subscriptions
  add constraint public_newsletter_subscriptions_resend_sync_status_check
  check (resend_sync_status in ('pending', 'synced', 'failed'));

create index if not exists public_newsletter_sync_status_idx
  on public.public_newsletter_subscriptions (resend_sync_status, updated_at desc);

create table if not exists public.newsletter_campaigns (
  id uuid primary key default gen_random_uuid(),
  name text not null,
  subject text not null,
  preview_text text,
  heading text not null,
  body_text text not null,
  cta_label text,
  cta_url text,
  status text not null default 'draft'
    check (status in ('draft', 'ready', 'scheduled', 'sending', 'sent', 'canceled', 'failed')),
  resend_segment_id text,
  resend_broadcast_id text unique,
  recipient_count integer not null default 0,
  prepared_at timestamptz,
  scheduled_at timestamptz,
  sent_at timestamptz,
  last_error text,
  created_by uuid references public.users(id) on delete set null,
  updated_by uuid references public.users(id) on delete set null,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

alter table public.newsletter_campaigns enable row level security;
revoke all on public.newsletter_campaigns from public, anon, authenticated;
grant select, insert, update, delete on public.newsletter_campaigns to service_role;
create index if not exists newsletter_campaigns_status_updated_idx
  on public.newsletter_campaigns (status, updated_at desc);
create index if not exists newsletter_campaigns_created_by_idx
  on public.newsletter_campaigns (created_by);
create index if not exists newsletter_campaigns_updated_by_idx
  on public.newsletter_campaigns (updated_by);

create table if not exists public.newsletter_delivery_events (
  provider_event_id text primary key,
  campaign_id uuid references public.newsletter_campaigns(id) on delete set null,
  resend_broadcast_id text,
  resend_email_id text,
  event_type text not null,
  recipient_email text,
  event_at timestamptz not null,
  payload jsonb not null default '{}'::jsonb,
  created_at timestamptz not null default now()
);

alter table public.newsletter_delivery_events enable row level security;
revoke all on public.newsletter_delivery_events from public, anon, authenticated;
grant select, insert, update, delete on public.newsletter_delivery_events to service_role;
create index if not exists newsletter_delivery_campaign_event_idx
  on public.newsletter_delivery_events (campaign_id, event_type, event_at desc);
create index if not exists newsletter_delivery_broadcast_idx
  on public.newsletter_delivery_events (resend_broadcast_id, event_at desc);
create index if not exists newsletter_delivery_email_idx
  on public.newsletter_delivery_events (recipient_email, event_at desc);
