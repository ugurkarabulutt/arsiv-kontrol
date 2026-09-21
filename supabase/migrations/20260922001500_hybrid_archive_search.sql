create extension if not exists pg_trgm with schema extensions;

alter table public.public_qa_search_documents
  add column if not exists search_text text not null default '';

update public.public_qa_search_documents
set search_text = trim(regexp_replace(
  translate(lower(content), 'çğıöşüâîû', 'cgiosuaiu'),
  '[^a-z0-9]+',
  ' ',
  'g'
))
where search_text = '';

create index if not exists public_qa_search_documents_text_trgm_idx
  on public.public_qa_search_documents
  using gin (search_text extensions.gin_trgm_ops);

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
    where exists (
      select 1
      from public.public_qa as qa
      where qa.slug = document.qa_slug
        and qa.status = 'published'
    )
    order by document.embedding operator(extensions.<=>) p_query_embedding
    limit least(greatest(p_match_count, 1) * 4, 240)
  ), lexical_candidates as materialized (
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
    where exists (
      select 1
      from public.public_qa as qa
      where qa.slug = document.qa_slug
        and qa.status = 'published'
    )
      and exists (
        select 1
        from terms
        where document.search_text like ('%' || terms.term || '%')
      )
    order by lexical_matches desc, similarity desc
    limit least(greatest(p_match_count, 1) * 10, 600)
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
  'Combines semantic similarity with normalized Turkish term coverage for published archive search.';
