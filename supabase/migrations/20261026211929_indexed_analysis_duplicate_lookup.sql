-- Replace the O(n) full-text normalization scan used before every analysis with
-- collision-safe, indexed candidate lookups. The MD5 value is only a compact
-- index bucket; normalized text equality below remains the source of truth.
create or replace function public.review_text_key_hash(value text) returns text
language sql immutable security invoker set search_path = '' as $$
  select md5(public.review_text_key(value));
$$;

create index if not exists history_original_text_key_hash_idx
  on public.history (public.review_text_key_hash(original_text))
  include (id, user_id, assignee_id, status, created_at)
  where status not in ('copte','chunk_draft','submitted_part')
    and coalesce(filename,'') !~ ' - Parça [0-9]+/[0-9]+$'
    and public.review_text_key(original_text)<>'';

create index if not exists history_corrected_text_key_hash_idx
  on public.history (public.review_text_key_hash(corrected_text))
  include (id, user_id, assignee_id, status, created_at)
  where status not in ('copte','chunk_draft','submitted_part')
    and coalesce(filename,'') !~ ' - Parça [0-9]+/[0-9]+$'
    and public.review_text_key(corrected_text)<>'';

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

comment on function public.review_text_key_hash(text) is
  'Index bucket for review_text_key; exact normalized equality must still be checked.';

revoke all on function public.review_text_key_hash(text),
  public.review_find_existing_analysis(uuid,text,text[]) from public,anon,authenticated;
grant execute on function public.review_text_key_hash(text),
  public.review_find_existing_analysis(uuid,text,text[]) to service_role;
