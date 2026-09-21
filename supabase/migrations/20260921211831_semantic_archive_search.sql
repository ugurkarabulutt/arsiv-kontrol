create extension if not exists vector with schema extensions;

create table if not exists public.public_qa_search_documents (
  qa_slug text not null references public.public_qa(slug) on delete cascade,
  document_key text not null,
  document_kind text not null check (document_kind in ('question', 'answer', 'concept')),
  content text not null,
  content_hash text not null,
  embedding extensions.vector(1024) not null,
  embedding_model text not null,
  metadata jsonb not null default '{}'::jsonb,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  primary key (qa_slug, document_key)
);

alter table public.public_qa_search_documents enable row level security;

revoke all on table public.public_qa_search_documents from anon, authenticated;
grant select, insert, update, delete on table public.public_qa_search_documents to service_role;

create index if not exists public_qa_search_documents_kind_idx
  on public.public_qa_search_documents (document_kind, qa_slug);

create index if not exists public_qa_search_documents_embedding_hnsw_idx
  on public.public_qa_search_documents
  using hnsw (embedding vector_cosine_ops);

create or replace function public.match_public_qa_search(
  p_query_embedding extensions.vector(1024),
  p_match_threshold double precision default 0.52,
  p_match_count integer default 40
)
returns table (
  qa_slug text,
  document_kind text,
  matched_text text,
  similarity double precision
)
language sql
stable
security invoker
set search_path = ''
as $$
  with nearest as materialized (
    select
      document.qa_slug,
      document.document_kind,
      document.content as matched_text,
      1 - (document.embedding operator(extensions.<=>) p_query_embedding) as similarity
    from public.public_qa_search_documents as document
    where exists (
      select 1
      from public.public_qa as qa
      where qa.slug = document.qa_slug
        and qa.status = 'published'
    )
    order by document.embedding operator(extensions.<=>) p_query_embedding
    limit least(greatest(p_match_count, 1) * 4, 200)
  ), deduplicated as (
    select distinct on (nearest.qa_slug)
      nearest.qa_slug,
      nearest.document_kind,
      nearest.matched_text,
      nearest.similarity
    from nearest
    order by nearest.qa_slug, nearest.similarity desc
  )
  select
    deduplicated.qa_slug,
    deduplicated.document_kind,
    deduplicated.matched_text,
    deduplicated.similarity
  from deduplicated
  where deduplicated.similarity >= greatest(-1, least(1, p_match_threshold))
  order by deduplicated.similarity desc
  limit least(greatest(p_match_count, 1), 120);
$$;

revoke all on function public.match_public_qa_search(extensions.vector, double precision, integer) from public, anon, authenticated;
grant execute on function public.match_public_qa_search(extensions.vector, double precision, integer) to service_role;

comment on table public.public_qa_search_documents is
  'Published archive search index. Contains only public question, answer, and approved concept text.';

comment on function public.match_public_qa_search(extensions.vector, double precision, integer) is
  'Returns semantically related published public_qa records for server-side hybrid search.';
