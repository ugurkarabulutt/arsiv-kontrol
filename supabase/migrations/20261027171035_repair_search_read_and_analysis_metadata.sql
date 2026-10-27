-- Restore analysis provenance that is already part of the application contract.
alter table public.history
  add column if not exists prompt_version text,
  add column if not exists rules_hash text;

-- Read counts are written by the backend only. Using the named primary-key
-- constraint avoids the output-column/target-column ambiguity in PL/pgSQL.
create or replace function public.increment_public_question_read(p_slug text)
returns table(slug text, read_count integer, updated_at timestamptz)
language plpgsql
security invoker
set search_path = ''
as $$
begin
  insert into public.public_question_stats as stats (slug, read_count, updated_at)
  values (p_slug, 1, now())
  on conflict on constraint public_question_stats_pkey
  do update set
    read_count = stats.read_count + 1,
    updated_at = now();

  return query
    select stats.slug, stats.read_count, stats.updated_at
    from public.public_question_stats as stats
    where stats.slug = p_slug;
end;
$$;

revoke all on function public.increment_public_question_read(text)
  from public, anon, authenticated;
grant execute on function public.increment_public_question_read(text)
  to service_role;

-- Prefix token lookup keeps the Turkish-normalized lexical branch indexed.
-- The vector distance is calculated only after lexical candidates are capped.
create index if not exists public_qa_search_documents_search_vector_idx
  on public.public_qa_search_documents
  using gin (to_tsvector('simple'::regconfig, search_text));

create or replace function public.match_public_qa_hybrid_search(
  p_query_embedding extensions.vector(1024),
  p_query_terms text[] default '{}'::text[],
  p_match_threshold double precision default 0.52,
  p_match_count integer default 48
)
returns table (
  qa_slug text,
  document_kind text,
  matched_text text,
  similarity double precision,
  lexical_matches integer,
  hybrid_score double precision
)
language sql
stable
security invoker
set search_path = ''
as $$
  with terms as materialized (
    select distinct trim(term) as term
    from unnest(coalesce(p_query_terms, '{}'::text[])) as term
    where char_length(trim(term)) >= 3
      and trim(term) ~ '^[a-z0-9]+$'
    limit 24
  ), semantic_candidates as materialized (
    select
      document.qa_slug,
      document.document_key,
      document.document_kind,
      document.content as matched_text,
      1 - (document.embedding operator(extensions.<=>) p_query_embedding) as similarity,
      (
        select count(*)::integer
        from terms
        where document.search_text like ('%' || terms.term || '%')
      ) as lexical_matches
    from public.public_qa_search_documents as document
    join public.public_qa as qa
      on qa.slug = document.qa_slug
     and qa.status = 'published'
    order by document.embedding operator(extensions.<=>) p_query_embedding
    limit least(greatest(p_match_count, 1) * 4, 240)
  ), lexical_occurrences as materialized (
    select hit.qa_slug, hit.document_key, terms.term
    from terms
    cross join lateral (
      select document.qa_slug, document.document_key
      from public.public_qa_search_documents as document
      join public.public_qa as qa
        on qa.slug = document.qa_slug
       and qa.status = 'published'
      where to_tsvector('simple'::regconfig, document.search_text)
        @@ to_tsquery('simple'::regconfig, terms.term || ':*')
    ) as hit
  ), lexical_hits as materialized (
    select
      lexical_occurrences.qa_slug,
      lexical_occurrences.document_key,
      count(*)::integer as lexical_matches
    from lexical_occurrences
    group by lexical_occurrences.qa_slug, lexical_occurrences.document_key
    order by count(*) desc
    limit least(greatest(p_match_count, 1) * 8, 384)
  ), lexical_candidates as materialized (
    select
      document.qa_slug,
      document.document_key,
      document.document_kind,
      document.content as matched_text,
      1 - (document.embedding operator(extensions.<=>) p_query_embedding) as similarity,
      lexical_hits.lexical_matches
    from lexical_hits
    join public.public_qa_search_documents as document
      on document.qa_slug = lexical_hits.qa_slug
     and document.document_key = lexical_hits.document_key
  ), combined as (
    select * from semantic_candidates
    union all
    select * from lexical_candidates
  ), documents as (
    select distinct on (combined.qa_slug, combined.document_key)
      combined.qa_slug,
      combined.document_key,
      combined.document_kind,
      combined.matched_text,
      combined.similarity,
      combined.lexical_matches,
      combined.similarity + least(combined.lexical_matches, 8) * 0.18 as hybrid_score
    from combined
    where combined.lexical_matches > 0
       or combined.similarity >= greatest(-1, least(1, p_match_threshold))
    order by combined.qa_slug, combined.document_key,
      (combined.similarity + least(combined.lexical_matches, 8) * 0.18) desc
  ), records as (
    select distinct on (documents.qa_slug)
      documents.qa_slug,
      documents.document_kind,
      documents.matched_text,
      documents.similarity,
      documents.lexical_matches,
      documents.hybrid_score
    from documents
    order by documents.qa_slug, documents.hybrid_score desc
  )
  select
    records.qa_slug,
    records.document_kind,
    records.matched_text,
    records.similarity,
    records.lexical_matches,
    records.hybrid_score
  from records
  order by records.hybrid_score desc
  limit least(greatest(p_match_count, 1), 120);
$$;

revoke all on function public.match_public_qa_hybrid_search(extensions.vector, text[], double precision, integer)
  from public, anon, authenticated;
grant execute on function public.match_public_qa_hybrid_search(extensions.vector, text[], double precision, integer)
  to service_role;

comment on function public.match_public_qa_hybrid_search(extensions.vector, text[], double precision, integer) is
  'Combines indexed prefix-token coverage with capped semantic candidates for published archive search.';
