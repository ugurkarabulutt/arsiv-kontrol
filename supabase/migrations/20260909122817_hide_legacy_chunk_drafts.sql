-- Keep legacy long-text split chunks out of member/management work queues.
-- Detail views already reject these technical rows; the queue view must match.
create or replace view public.review_history_queue
with (security_invoker = true) as
select h.*,
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
  end as queue_sort_at
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

comment on view public.review_history_queue is
  'Private read-only review queue. Pending uses latest submission; every other status uses latest workflow activity with preserved historical fallbacks. Legacy long-text split chunks are hidden from work queues.';

notify pgrst, 'reload schema';
