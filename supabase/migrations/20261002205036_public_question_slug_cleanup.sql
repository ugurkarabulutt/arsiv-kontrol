alter table public.public_question_redirects
  alter column history_id drop not null;

alter table public.public_question_redirects
  add column if not exists redirect_type text not null default 'duplicate';

alter table public.public_qa_topics
  drop constraint if exists public_qa_topics_qa_slug_fkey;
alter table public.public_qa_topics
  add constraint public_qa_topics_qa_slug_fkey
  foreign key (qa_slug) references public.public_qa(slug)
  on update cascade on delete cascade;

alter table public.public_qa_search_documents
  drop constraint if exists public_qa_search_documents_qa_slug_fkey;
alter table public.public_qa_search_documents
  add constraint public_qa_search_documents_qa_slug_fkey
  foreign key (qa_slug) references public.public_qa(slug)
  on update cascade on delete cascade;

create or replace function public.apply_public_question_slug_migration(p_pairs jsonb)
returns jsonb
language plpgsql
security definer
set search_path = ''
as $$
declare
  pair_count integer := 0;
  moved_count integer := 0;
begin
  if jsonb_typeof(p_pairs) <> 'array' then
    raise exception 'INVALID_SLUG_MIGRATION_PAYLOAD';
  end if;

  create temporary table question_slug_map (
    old_slug text primary key,
    new_slug text not null unique,
    history_id uuid
  ) on commit drop;

  insert into question_slug_map(old_slug, new_slug)
  select
    trim(pair->>'oldSlug'),
    trim(pair->>'newSlug')
  from jsonb_array_elements(p_pairs) as pair;

  select count(*) into pair_count from question_slug_map;
  if pair_count = 0 then
    return jsonb_build_object('moved', 0, 'redirects', 0);
  end if;

  if exists (
    select 1 from question_slug_map
    where old_slug = new_slug
      or old_slug !~ '^[a-z0-9-]{2,140}$'
      or new_slug !~ '^[a-z0-9-]{2,96}$'
      or new_slug ~ '^(?:(?:soru-[0-9]+|[0-9]+-soru)-)?muhterem-hocam(?:iz)?-'
  ) then
    raise exception 'INVALID_SLUG_MIGRATION_PAIR';
  end if;

  if exists (
    select 1 from question_slug_map map
    left join public.public_qa qa on qa.slug = map.old_slug
    where qa.slug is null
  ) then
    raise exception 'SOURCE_SLUG_NOT_FOUND';
  end if;

  if exists (
    select 1
    from question_slug_map map
    join public.public_qa qa on qa.slug = map.new_slug
    where not exists (select 1 from question_slug_map source where source.old_slug = qa.slug)
  ) then
    raise exception 'TARGET_SLUG_CONFLICT';
  end if;

  if exists (
    select 1
    from question_slug_map map
    join public.public_question_redirects redirect on redirect.from_slug = map.new_slug
    where not exists (select 1 from question_slug_map source where source.old_slug = redirect.from_slug)
  ) then
    raise exception 'TARGET_REDIRECT_CONFLICT';
  end if;

  update question_slug_map map
  set history_id = qa.source_history_id
  from public.public_qa qa
  where qa.slug = map.old_slug;

  insert into public.public_question_stats as target (slug, read_count, updated_at)
  select map.new_slug, sum(stats.read_count)::integer, max(stats.updated_at)
  from question_slug_map map
  join public.public_question_stats stats on stats.slug = map.old_slug
  group by map.new_slug
  on conflict (slug) do update set
    read_count = target.read_count + excluded.read_count,
    updated_at = greatest(target.updated_at, excluded.updated_at);

  delete from public.public_question_stats stats
  using question_slug_map map
  where stats.slug = map.old_slug;

  update public.public_visit_events event
  set question_slug = map.new_slug
  from question_slug_map map
  where event.question_slug = map.old_slug;

  update public.public_question_redirects redirect
  set to_slug = map.new_slug
  from question_slug_map map
  where redirect.to_slug = map.old_slug
    and redirect.from_slug <> map.new_slug;

  update public.public_qa qa
  set slug = map.new_slug,
      updated_at = now()
  from question_slug_map map
  where qa.slug = map.old_slug;
  get diagnostics moved_count = row_count;

  update public.public_qa qa
  set related_slugs = coalesce((
    select jsonb_agg(coalesce(map.new_slug, related.value) order by related.ordinality)
    from jsonb_array_elements_text(qa.related_slugs) with ordinality as related(value, ordinality)
    left join question_slug_map map on map.old_slug = related.value
  ), '[]'::jsonb)
  where exists (
    select 1
    from jsonb_array_elements_text(qa.related_slugs) as related(value)
    join question_slug_map map on map.old_slug = related.value
  );

  insert into public.public_question_redirects(from_slug, to_slug, history_id, redirect_type)
  select old_slug, new_slug, history_id, 'slug_cleanup'
  from question_slug_map
  on conflict(from_slug) do update set
    to_slug = excluded.to_slug,
    history_id = excluded.history_id,
    redirect_type = 'slug_cleanup';

  return jsonb_build_object(
    'moved', moved_count,
    'redirects', pair_count
  );
end;
$$;

revoke all on function public.apply_public_question_slug_migration(jsonb) from public, anon, authenticated;
grant execute on function public.apply_public_question_slug_migration(jsonb) to service_role;
