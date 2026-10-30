-- Normalize Turkish review content once so question and answer searches are
-- insensitive to circumflexes, punctuation, whitespace and word order.
create extension if not exists pg_trgm with schema extensions;

create or replace function public.normalize_review_search_text(p_value text)
returns text
language sql
immutable
parallel safe
set search_path = ''
as $$
  select trim(regexp_replace(
    lower(translate(
      coalesce(p_value, ''),
      'ÇĞİIÖŞÜÂÎÛçğıiöşüâîû',
      'CGIIOSUAIUcgiiosuaiu'
    )),
    '[^a-z0-9]+',
    ' ',
    'g'
  ));
$$;

revoke all on function public.normalize_review_search_text(text)
  from public, anon, authenticated;
grant execute on function public.normalize_review_search_text(text)
  to service_role;

alter table public.history
  add column if not exists review_search_text text
  generated always as (
    public.normalize_review_search_text(
      coalesce(question_text, '') || ' ' ||
      coalesce(corrected_text, '') || ' ' ||
      coalesce(summary, '') || ' ' ||
      coalesce(submission_note, '') || ' ' ||
      coalesce(name, '') || ' ' ||
      coalesce(username, '') || ' ' ||
      coalesce(filename, '')
    )
  ) stored;

create index if not exists history_review_search_text_trgm_idx
  on public.history
  using gin (review_search_text extensions.gin_trgm_ops);

-- Preserve the existing queue column order and append the search-only column.
-- The view stays security-invoker and remains unreadable to browser roles.
create or replace view public.review_history_queue
with (security_invoker = true) as
select
  h.id,
  h.user_id,
  h.username,
  h.name,
  h.filename,
  h.score,
  h.total_errors,
  h.cat_counts,
  h.summary,
  h.corrected_text,
  h.status,
  h.approved_by,
  h.approved_at,
  h.created_at,
  h.text_hash,
  h.original_text,
  h.tags,
  h.question_text,
  h.submission_note,
  h.version,
  h.updated_at,
  h.assignee_id,
  h.workflow_meta,
  submitted.created_at as submitted_at,
  submitted.actor_id as submitted_by,
  coalesce(submitted.created_at, h.created_at) as approval_sort_at,
  status_event.created_at as status_changed_at,
  status_event.actor_id as status_changed_by,
  case
    when h.status = 'bekliyor' then coalesce(submitted.created_at, h.created_at)
    else greatest(
      status_event.created_at,
      case when h.status = 'onaylandi' then h.approved_at end,
      h.updated_at,
      h.created_at
    )
  end as queue_sort_at,
  h.review_search_text
from public.history h
left join lateral (
  select event.created_at, event.actor_id
  from (
    (select r.created_at, r.actor_id, 0 as priority
     from public.history_revisions r
     where r.history_id = h.id and r.action = 'submit'
     order by r.created_at desc, r.version desc limit 1)
    union all
    (select l.created_at, l.actor_user_id as actor_id, 1 as priority
     from public.admin_action_log l
     where l.target_type = 'history' and l.target_id = h.id::text
       and l.action in ('approval.submitted', 'review.submit')
     order by l.created_at desc, l.id desc limit 1)
  ) event
  order by event.created_at desc, event.priority
  limit 1
) submitted on true
left join lateral (
  select event.created_at, event.actor_id
  from (
    (select r.created_at, r.actor_id, 0 as priority
     from public.history_revisions r
     where r.history_id = h.id
       and r.after_data->>'status' = h.status
       and (r.before_data->>'status') is distinct from (r.after_data->>'status')
     order by r.created_at desc, r.version desc limit 1)
    union all
    (select l.created_at, l.actor_user_id as actor_id, 1 as priority
     from public.admin_action_log l
     where l.target_type = 'history' and l.target_id = h.id::text
       and l.target_status_after = h.status
       and l.target_status_before is distinct from l.target_status_after
     order by l.created_at desc, l.id desc limit 1)
  ) event
  order by event.created_at desc, event.priority
  limit 1
) status_event on true
where h.status not in ('chunk_draft','submitted_part')
  and coalesce(h.filename,'') !~ ' - Parça [0-9]+/[0-9]+$';

revoke all on public.review_history_queue from public, anon, authenticated;
revoke all on public.review_history_queue from service_role;
grant select on public.review_history_queue to service_role;

comment on column public.history.review_search_text is
  'Indexed Turkish-normalized private review search text for question, answer and ownership fields.';
comment on view public.review_history_queue is
  'Private read-only review queue with indexed normalized search. Pending uses latest submission; every other status uses latest workflow activity.';

notify pgrst, 'reload schema';
