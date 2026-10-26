-- PostgreSQL can use a partial expression index only when its predicate is
-- explicit in the query. Repeat the non-empty branch conditions so both hash
-- indexes are selected on production data.
create or replace function public.review_find_existing_analysis(
  p_actor uuid,
  p_text text,
  p_hashes text[] default '{}'
) returns jsonb
language sql stable security invoker set search_path = '' as $$
  with needle as materialized (
    select
      public.review_text_key(p_text) as text_key,
      public.review_text_key_hash(p_text) as text_key_hash
  ), candidates as (
    select h.id,h.status,h.user_id,h.assignee_id,h.created_at
    from public.history h
    cross join needle n
    where n.text_key<>''
      and (h.user_id=p_actor or h.assignee_id=p_actor)
      and h.status not in ('copte','chunk_draft','submitted_part')
      and coalesce(h.filename,'') !~ ' - Parça [0-9]+/[0-9]+$'
      and public.review_text_key(h.original_text)<>''
      and public.review_text_key_hash(h.original_text)=n.text_key_hash
      and public.review_text_key(h.original_text)=n.text_key

    union

    select h.id,h.status,h.user_id,h.assignee_id,h.created_at
    from public.history h
    cross join needle n
    where n.text_key<>''
      and (h.user_id=p_actor or h.assignee_id=p_actor)
      and h.status not in ('copte','chunk_draft','submitted_part')
      and coalesce(h.filename,'') !~ ' - Parça [0-9]+/[0-9]+$'
      and public.review_text_key(h.corrected_text)<>''
      and public.review_text_key_hash(h.corrected_text)=n.text_key_hash
      and public.review_text_key(h.corrected_text)=n.text_key
  )
  select jsonb_build_object(
    'id',c.id,
    'status',c.status,
    'user_id',c.user_id,
    'assignee_id',c.assignee_id
  )
  from candidates c
  order by (c.status<>'taslak') desc, c.created_at, c.id
  limit 1;
$$;

revoke all on function public.review_find_existing_analysis(uuid,text,text[])
  from public,anon,authenticated;
grant execute on function public.review_find_existing_analysis(uuid,text,text[])
  to service_role;
