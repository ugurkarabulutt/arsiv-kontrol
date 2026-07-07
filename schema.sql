-- Arşiv Kontrol AI — Supabase şeması
-- Supabase Dashboard → SQL Editor'de bir kez çalıştırın.

create extension if not exists "pgcrypto";

-- ── users ──────────────────────────────────────────────────────────────────
create table if not exists public.users (
  id         uuid primary key default gen_random_uuid(),
  username   text unique not null,
  password   text not null,            -- bcrypt hash
  name       text not null,
  role       text not null default 'user',
  active      boolean not null default true,
  created_at timestamptz not null default now()
);

-- Yalnızca "admin" kullanıcı adı süper admin olabilir.
update public.users set role = 'admin' where role = 'super_admin' and username <> 'admin';
update public.users set role = 'super_admin' where username = 'admin';

-- ── history ────────────────────────────────────────────────────────────────
create table if not exists public.history (
  id             uuid primary key default gen_random_uuid(),
  user_id        uuid references public.users(id) on delete set null,
  username       text,
  name           text,
  filename       text,
  score          integer default 0,
  total_errors   integer default 0,
  cat_counts     jsonb   default '{}'::jsonb,
  summary        text,
  original_text  text,
  corrected_text text,
  status         text default 'bekliyor',
  approved_by    text,
  approved_at    timestamptz,
  text_hash      text,                    -- tekrar-gönderim kontrolü (normalize metnin SHA-256 özeti)
  prompt_version text,
  rules_hash     text,
  created_at     timestamptz not null default now()
);
create index if not exists history_created_at_idx on public.history (created_at desc);
create index if not exists history_user_id_idx    on public.history (user_id);
create index if not exists history_text_hash_idx  on public.history (user_id, text_hash);

-- Mevcut bir veritabanına sonradan eklemek için (history zaten varsa):
alter table public.history add column if not exists text_hash text;
alter table public.history add column if not exists original_text text;
alter table public.history add column if not exists prompt_version text;
alter table public.history add column if not exists rules_hash text;

-- Kullanıcı son aktiflik takibi:
alter table public.users add column if not exists last_seen_at timestamptz;
create index if not exists users_last_seen_at_idx on public.users (last_seen_at desc);
create index if not exists history_text_hash_idx on public.history (user_id, text_hash);

-- ── alerts ─────────────────────────────────────────────────────────────────
create table if not exists public.alerts (
  id         uuid primary key default gen_random_uuid(),
  type       text,
  message    text,
  user_id    uuid references public.users(id) on delete set null,
  history_id uuid references public.history(id) on delete cascade,
  score      integer,
  feedback_status text default 'open',
  resolved_at timestamptz,
  resolved_by text,
  resolution_group text,
  resolution_note text,
  read       boolean not null default false,
  created_at timestamptz not null default now()
);
create index if not exists alerts_created_at_idx on public.alerts (created_at desc);
create index if not exists alerts_feedback_status_idx on public.alerts (type, feedback_status);

-- issue_resolution_log
create table if not exists public.issue_resolution_log (
  id uuid primary key default gen_random_uuid(),
  resolution_group text unique,
  title text not null,
  summary text,
  status text not null default 'resolved',
  feedback_count integer not null default 0,
  user_count integer not null default 0,
  created_by text,
  created_at timestamptz not null default now()
);
create index if not exists issue_resolution_log_created_at_idx on public.issue_resolution_log (created_at desc);

-- ai_reports
create table if not exists public.ai_reports (
  id uuid primary key default gen_random_uuid(),
  period text not null,
  period_start timestamptz,
  period_end timestamptz,
  title text,
  content jsonb not null default '{}'::jsonb,
  metrics jsonb not null default '{}'::jsonb,
  model text,
  created_by text,
  created_at timestamptz not null default now()
);
create index if not exists ai_reports_created_at_idx on public.ai_reports (created_at desc);
create index if not exists ai_reports_period_idx on public.ai_reports (period, created_at desc);
create unique index if not exists ai_reports_period_range_idx on public.ai_reports (period, period_start, period_end);

-- Mevcut bir veritabanına sonradan eklemek için (alerts zaten varsa):
alter table public.alerts add column if not exists feedback_status text default 'open';
alter table public.alerts add column if not exists resolved_at timestamptz;
alter table public.alerts add column if not exists resolved_by text;
alter table public.alerts add column if not exists resolution_group text;
alter table public.alerts add column if not exists resolution_note text;
create index if not exists alerts_feedback_status_idx on public.alerts (type, feedback_status);

-- ── settings (kurallar vb.) ─────────────────────────────────────────────────
create table if not exists public.settings (
  key   text primary key,
  value text
);

-- NOT: Sunucu service_role anahtarı ile bağlanır ve RLS'i bypass eder.
-- Bu tablolara yalnızca backend erişir; istemci tarafı doğrudan erişim yoktur.
