-- Derive submission time from audit evidence without rewriting history records.
create index if not exists history_revisions_submission_idx
  on public.history_revisions (history_id, created_at desc, version desc)
  where action = 'submit';

create index if not exists admin_action_log_submission_idx
  on public.admin_action_log (target_id, created_at desc, id desc)
  where target_type = 'history' and action in ('approval.submitted', 'review.submit');

create or replace view public.review_history_queue
with (security_invoker = true) as
select h.*, submitted.created_at as submitted_at, submitted.actor_id as submitted_by,
  coalesce(submitted.created_at, h.created_at) as approval_sort_at
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
) submitted on true;

revoke all on public.review_history_queue from public, anon, authenticated;
revoke all on public.review_history_queue from service_role;
grant select on public.review_history_queue to service_role;

comment on view public.review_history_queue is
  'Private read-only approval queue. Latest actual submission, with creation-time fallback only when no submission evidence exists.';

notify pgrst, 'reload schema';
