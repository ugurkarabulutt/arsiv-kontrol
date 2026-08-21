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
  question_text  text,
  status         text default 'bekliyor',
  approved_by    text,
  approved_at    timestamptz,
  text_hash      text,                    -- tekrar-gönderim kontrolü (normalize metnin SHA-256 özeti)
  prompt_version text,
  rules_hash     text,
  tags           jsonb not null default '[]'::jsonb,
  created_at     timestamptz not null default now()
);
create index if not exists history_created_at_idx on public.history (created_at desc);
create index if not exists history_user_id_idx    on public.history (user_id);
create index if not exists history_text_hash_idx  on public.history (user_id, text_hash);
create index if not exists history_tags_idx       on public.history using gin (tags);

-- Mevcut bir veritabanına sonradan eklemek için (history zaten varsa):
alter table public.history add column if not exists text_hash text;
alter table public.history add column if not exists original_text text;
alter table public.history add column if not exists question_text text;
alter table public.history add column if not exists prompt_version text;
alter table public.history add column if not exists rules_hash text;
alter table public.history add column if not exists tags jsonb not null default '[]'::jsonb;
create index if not exists history_public_approved_idx on public.history (approved_at desc) where status = 'onaylandi';
create index if not exists history_tags_idx on public.history using gin (tags);

-- Excel/e-tablo etiket aktarimi icin guvenli onizleme kayitlari.
-- Bu tablolar dogrudan history guncellemez; once eslesme onizlemesi uretir.
create table if not exists public.history_tag_import_batches (
  id              uuid primary key default gen_random_uuid(),
  filename        text,
  sheet_name      text,
  total_rows      integer not null default 0,
  usable_rows     integer not null default 0,
  history_count   integer not null default 0,
  ready_count     integer not null default 0,
  review_count    integer not null default 0,
  unmatched_count integer not null default 0,
  applied_count   integer not null default 0,
  skipped_count   integer not null default 0,
  status          text not null default 'preview',
  note            text,
  created_by      text,
  created_at      timestamptz not null default now(),
  updated_at      timestamptz not null default now()
);

create table if not exists public.history_tag_import_matches (
  id             uuid primary key default gen_random_uuid(),
  batch_id       uuid references public.history_tag_import_batches(id) on delete cascade,
  history_id     uuid references public.history(id) on delete set null,
  excel_row      integer,
  excel_question text,
  answer_preview text,
  tags           jsonb not null default '[]'::jsonb,
  confidence     numeric not null default 0,
  match_status   text not null default 'review',
  match_reason   text,
  current_tags   jsonb not null default '[]'::jsonb,
  applied_at     timestamptz,
  applied_by     text,
  created_at     timestamptz not null default now()
);

create index if not exists history_tag_import_batches_status_idx on public.history_tag_import_batches (status, updated_at desc);
create index if not exists history_tag_import_matches_batch_idx on public.history_tag_import_matches (batch_id, match_status, confidence desc);
create index if not exists history_tag_import_matches_history_idx on public.history_tag_import_matches (history_id);

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

-- content_correction_log
create table if not exists public.content_correction_log (
  id uuid primary key default gen_random_uuid(),
  package_id text not null,
  history_id uuid references public.history(id) on delete cascade,
  field_name text not null,
  old_value text,
  new_value text,
  old_hash text,
  new_hash text,
  status text not null default 'applied',
  created_by text,
  created_at timestamptz not null default now()
);
create index if not exists content_correction_log_package_idx on public.content_correction_log (package_id, created_at desc);
create index if not exists content_correction_log_history_idx on public.content_correction_log (history_id);

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

-- archive_sources
create table if not exists public.archive_sources (
  id text primary key,
  title text not null,
  source_type text not null default 'dokuman',
  status text not null default 'kaynak',
  category text,
  source_date timestamptz,
  source_url text,
  tags jsonb not null default '[]'::jsonb,
  note text,
  source_text text not null,
  text_preview text,
  text_length integer not null default 0,
  source_text_hash text,
  title_key text,
  source_url_key text,
  search_blob text,
  created_by text,
  updated_by text,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  conflict_accepted_at timestamptz,
  conflict_accepted_by text,
  conflict_accepted_conflicts jsonb not null default '[]'::jsonb
);
create index if not exists archive_sources_updated_at_idx on public.archive_sources (updated_at desc);
create index if not exists archive_sources_type_status_idx on public.archive_sources (source_type, status);
create index if not exists archive_sources_text_hash_idx on public.archive_sources (source_text_hash);
create index if not exists archive_sources_url_key_idx on public.archive_sources (source_url_key);
create index if not exists archive_sources_title_type_idx on public.archive_sources (title_key, source_type);

alter table public.archive_sources add column if not exists text_preview text;
alter table public.archive_sources add column if not exists text_length integer not null default 0;
alter table public.archive_sources add column if not exists search_blob text;
alter table public.archive_sources add column if not exists conflict_accepted_at timestamptz;
alter table public.archive_sources add column if not exists conflict_accepted_by text;
alter table public.archive_sources add column if not exists conflict_accepted_conflicts jsonb not null default '[]'::jsonb;

-- archive_source_versions
create table if not exists public.archive_source_versions (
  id uuid primary key default gen_random_uuid(),
  source_id text references public.archive_sources(id) on delete cascade,
  version_no integer not null,
  event_type text not null default 'update',
  snapshot jsonb not null default '{}'::jsonb,
  previous_snapshot jsonb,
  change_keys jsonb not null default '[]'::jsonb,
  created_by text,
  created_at timestamptz not null default now()
);
create unique index if not exists archive_source_versions_source_version_idx on public.archive_source_versions (source_id, version_no);
create index if not exists archive_source_versions_source_idx on public.archive_source_versions (source_id, created_at desc);

-- archive_source_events
create table if not exists public.archive_source_events (
  id uuid primary key default gen_random_uuid(),
  source_id text references public.archive_sources(id) on delete set null,
  event_type text not null,
  actor text,
  summary text,
  metadata jsonb not null default '{}'::jsonb,
  created_at timestamptz not null default now()
);
create index if not exists archive_source_events_source_idx on public.archive_source_events (source_id, created_at desc);
create index if not exists archive_source_events_created_at_idx on public.archive_source_events (created_at desc);

-- archive_import_batches
create table if not exists public.archive_import_batches (
  id text primary key,
  title text not null,
  status text not null default 'open',
  note text,
  created_by text,
  updated_by text,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);
create index if not exists archive_import_batches_status_idx on public.archive_import_batches (status, updated_at desc);
create index if not exists archive_import_batches_updated_at_idx on public.archive_import_batches (updated_at desc);

-- archive_import_items
create table if not exists public.archive_import_items (
  id text primary key,
  batch_id text references public.archive_import_batches(id) on delete cascade,
  file_name text not null,
  file_extension text,
  file_size bigint not null default 0,
  source_type text not null default 'dokuman',
  status text not null default 'extracted',
  title text,
  category text,
  tags jsonb not null default '[]'::jsonb,
  note text,
  extracted_text text not null default '',
  text_preview text,
  text_length integer not null default 0,
  text_hash text,
  source_id text references public.archive_sources(id) on delete set null,
  error_message text,
  created_by text,
  updated_by text,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);
create index if not exists archive_import_items_batch_idx on public.archive_import_items (batch_id, updated_at desc);
create index if not exists archive_import_items_status_idx on public.archive_import_items (status, updated_at desc);
create index if not exists archive_import_items_text_hash_idx on public.archive_import_items (text_hash);

-- archive_work_items
create table if not exists public.archive_work_items (
  id text primary key,
  title text not null,
  status text not null default 'taslak',
  priority text not null default 'normal',
  assigned_to text,
  due_date timestamptz,
  source_id text references public.archive_sources(id) on delete set null,
  source_title text,
  category text,
  topics jsonb not null default '[]'::jsonb,
  question text,
  answer_draft text,
  note text,
  text_preview text,
  text_length integer not null default 0,
  search_blob text,
  created_by text,
  updated_by text,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);
create index if not exists archive_work_items_status_idx on public.archive_work_items (status, updated_at desc);
create index if not exists archive_work_items_priority_idx on public.archive_work_items (priority, updated_at desc);
create index if not exists archive_work_items_source_idx on public.archive_work_items (source_id, updated_at desc);
create index if not exists archive_work_items_updated_at_idx on public.archive_work_items (updated_at desc);

-- archive_publish_tasks
create table if not exists public.archive_publish_tasks (
  id text primary key,
  title text not null,
  status text not null default 'planlandi',
  priority text not null default 'normal',
  assigned_to text,
  due_date timestamptz,
  publish_date timestamptz,
  publication_url text,
  platform text,
  source_id text references public.archive_sources(id) on delete set null,
  source_title text,
  work_item_id text references public.archive_work_items(id) on delete set null,
  work_item_title text,
  category text,
  topics jsonb not null default '[]'::jsonb,
  description text,
  note text,
  text_preview text,
  text_length integer not null default 0,
  search_blob text,
  created_by text,
  updated_by text,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);
create index if not exists archive_publish_tasks_status_idx on public.archive_publish_tasks (status, updated_at desc);
create index if not exists archive_publish_tasks_priority_idx on public.archive_publish_tasks (priority, updated_at desc);
create index if not exists archive_publish_tasks_source_idx on public.archive_publish_tasks (source_id, updated_at desc);
create index if not exists archive_publish_tasks_work_idx on public.archive_publish_tasks (work_item_id, updated_at desc);
create index if not exists archive_publish_tasks_updated_at_idx on public.archive_publish_tasks (updated_at desc);

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

-- public_users
-- Public arşiv Google oturumları admin users tablosundan ayrı tutulur.
-- RLS açık kalır; public/anon doğrudan tablo okuyamaz. Erişim yalnız server API üzerinden yapılır.
create table if not exists public.public_users (
  id uuid primary key default gen_random_uuid(),
  google_sub text unique,
  email text not null,
  name text not null,
  avatar_url text,
  password_hash text,
  auth_provider text not null default 'google',
  email_verified boolean not null default false,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  last_login_at timestamptz
);
alter table public.public_users alter column google_sub drop not null;
alter table public.public_users add column if not exists password_hash text;
alter table public.public_users add column if not exists auth_provider text not null default 'google';
alter table public.public_users enable row level security;
create index if not exists public_users_email_idx on public.public_users (email);
create unique index if not exists public_users_email_unique_idx on public.public_users (lower(email));
create index if not exists public_users_last_login_idx on public.public_users (last_login_at desc);

-- public_question_submissions
-- Public "Soru Sor" akışından gelen sorular admin panelinde izlenir.
-- RLS açık kalır; doğrudan istemci erişimi yoktur.
create table if not exists public.public_question_submissions (
  id uuid primary key default gen_random_uuid(),
  public_user_id uuid references public.public_users(id) on delete set null,
  submitter_name text,
  submitter_email text,
  question text not null,
  category text,
  topic text,
  privacy_accepted boolean not null default false,
  status text not null default 'new',
  source text not null default 'public-preview',
  user_agent text,
  admin_note text,
  answer_text text,
  answered_by text,
  answered_at timestamptz,
  user_notified_at timestamptz,
  user_seen_at timestamptz,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);
alter table public.public_question_submissions add column if not exists answer_text text;
alter table public.public_question_submissions add column if not exists answered_by text;
alter table public.public_question_submissions add column if not exists answered_at timestamptz;
alter table public.public_question_submissions add column if not exists user_notified_at timestamptz;
alter table public.public_question_submissions add column if not exists user_seen_at timestamptz;
alter table public.public_question_submissions enable row level security;
create index if not exists public_question_submissions_created_idx on public.public_question_submissions (created_at desc);
create index if not exists public_question_submissions_status_idx on public.public_question_submissions (status, created_at desc);
create index if not exists public_question_submissions_user_idx on public.public_question_submissions (public_user_id, created_at desc);
create index if not exists public_question_submissions_answered_idx on public.public_question_submissions (answered_at desc);

-- public_question_stats
-- Public soru kartları ve detay sayfaları için kişisel veri tutmayan okunma sayacı.
-- RLS açık kalır; sayaç güncellemesi server API/service role üzerinden yapılır.
create table if not exists public.public_question_stats (
  slug text primary key,
  read_count integer not null default 0,
  updated_at timestamptz not null default now()
);
alter table public.public_question_stats enable row level security;
create index if not exists public_question_stats_updated_idx on public.public_question_stats (updated_at desc);

-- public_visit_events
-- Public site ziyaret istatistikleri. Ham IP saklanmaz; sunucu yalnız gizli hash tutar.
-- RLS açık kalır; kayıt ve okuma server API/service role üzerinden yapılır.
create table if not exists public.public_visit_events (
  id uuid primary key default gen_random_uuid(),
  created_at timestamptz not null default now(),
  site_area text not null default 'public-root',
  visitor_id text,
  session_id text,
  path text not null,
  route_type text,
  question_slug text,
  referrer text,
  referrer_host text,
  source_type text,
  utm_source text,
  utm_medium text,
  utm_campaign text,
  country text,
  region text,
  city text,
  timezone text,
  language text,
  device_type text,
  browser_name text,
  os_name text,
  screen_width integer,
  screen_height integer,
  ip_hash text,
  user_agent text,
  is_bot boolean not null default false
);
alter table public.public_visit_events enable row level security;
create index if not exists public_visit_events_created_idx on public.public_visit_events (created_at desc);
create index if not exists public_visit_events_source_idx on public.public_visit_events (source_type, created_at desc);
create index if not exists public_visit_events_location_idx on public.public_visit_events (country, city, created_at desc);
create index if not exists public_visit_events_visitor_idx on public.public_visit_events (visitor_id, created_at desc);
create index if not exists public_visit_events_question_idx on public.public_visit_events (question_slug, created_at desc);

create or replace function public.increment_public_question_read(p_slug text)
returns table(slug text, read_count integer, updated_at timestamptz)
language plpgsql
security definer
set search_path = public
as $$
begin
  insert into public.public_question_stats as stats (slug, read_count, updated_at)
  values (p_slug, 1, now())
  on conflict (slug)
  do update set
    read_count = stats.read_count + 1,
    updated_at = now();

  return query
    select s.slug, s.read_count, s.updated_at
    from public.public_question_stats s
    where s.slug = p_slug;
end;
$$;
revoke all on function public.increment_public_question_read(text) from public;

-- public_categories / public_topics / public_qa
-- Public arşivin okuma modeli. Admin iç bilgileri, denetim puanları, kullanıcı kimliği
-- ve prompt/AI süreç bilgileri bu tablolara taşınmaz.
create table if not exists public.public_categories (
  slug text primary key,
  name text not null,
  description text,
  topic_slugs jsonb not null default '[]'::jsonb,
  featured boolean not null default true,
  sort_order integer not null default 0,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);
alter table public.public_categories enable row level security;
create index if not exists public_categories_sort_idx on public.public_categories (sort_order, name);

create table if not exists public.public_topics (
  slug text primary key,
  name text not null,
  description text,
  category_slug text references public.public_categories(slug) on delete set null,
  related_topic_slugs jsonb not null default '[]'::jsonb,
  featured boolean not null default true,
  sort_order integer not null default 0,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);
alter table public.public_topics enable row level security;
create index if not exists public_topics_category_idx on public.public_topics (category_slug, sort_order);
create index if not exists public_topics_sort_idx on public.public_topics (sort_order, name);

create table if not exists public.public_qa (
  slug text primary key,
  source_history_id uuid unique references public.history(id) on delete set null,
  title text not null,
  question text not null,
  answer_text text not null,
  answer_paragraphs jsonb not null default '[]'::jsonb,
  summary text,
  excerpt text,
  category_slug text references public.public_categories(slug) on delete set null,
  topic_slugs jsonb not null default '[]'::jsonb,
  related_slugs jsonb not null default '[]'::jsonb,
  source_context_title text,
  source_context_text text,
  published_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  read_time integer not null default 1,
  is_featured boolean not null default false,
  status text not null default 'published',
  created_at timestamptz not null default now()
);
alter table public.public_qa enable row level security;
create index if not exists public_qa_status_published_idx on public.public_qa (status, published_at desc);
create index if not exists public_qa_category_idx on public.public_qa (category_slug, published_at desc);
create index if not exists public_qa_source_history_idx on public.public_qa (source_history_id);

create table if not exists public.public_qa_topics (
  qa_slug text references public.public_qa(slug) on delete cascade,
  topic_slug text references public.public_topics(slug) on delete cascade,
  updated_at timestamptz not null default now(),
  primary key (qa_slug, topic_slug)
);
alter table public.public_qa_topics enable row level security;
create index if not exists public_qa_topics_topic_idx on public.public_qa_topics (topic_slug);

-- NOT: Sunucu service_role anahtarı ile bağlanır ve RLS'i bypass eder.
-- Bu tablolara yalnızca backend erişir; istemci tarafı doğrudan erişim yoktur.
