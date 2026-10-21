-- Route full question+answer matches against the live archive to a human review queue.
-- This migration changes workflow behavior only; existing rows are not moved automatically.

create or replace function public.review_duplicate_key(value text) returns text
language sql immutable security invoker set search_path = '' as $$
  select trim(regexp_replace(
    regexp_replace(
      regexp_replace(
        translate(
          lower(translate(coalesce(value, ''), 'Iİ', 'ıi')),
          'âáàäãåçğéèëîíìïñöóòõşûúùü',
          'aaaaaacgeeeiiiinoooosuuuu'
        ),
        $apostrophe$[’'`´]$apostrophe$,
        '',
        'g'
      ),
      '[^a-z0-9ı[:space:]]',
      ' ',
      'g'
    ),
    '[[:space:]]+',
    ' ',
    'g'
  ));
$$;

create index if not exists public_qa_duplicate_review_idx
  on public.public_qa (
    md5(public.review_duplicate_key(question)),
    md5(public.review_duplicate_key(answer_text)),
    published_at,
    slug
  )
  where status = 'published' and source_history_id is not null;

create or replace function public.review_history_change(
  p_id uuid, p_actor uuid, p_version integer, p_workspace text, p_action text,
  p_payload jsonb default '{}'::jsonb
) returns jsonb language plpgsql security invoker set search_path = '' as $$
declare
  h public.history%rowtype;
  old_h public.history%rowtype;
  actor public.users%rowtype;
  target public.history%rowtype;
  manager boolean;
  worker boolean;
  note text := trim(coalesce(p_payload->>'note',''));
  label text;
  target_slug text;
  duplicate_id uuid;
  duplicate_match_key text;
begin
  select * into actor from public.users where id=p_actor and active=true;
  if not found then raise exception 'FORBIDDEN'; end if;
  manager := actor.role in ('admin','super_admin') and p_workspace='management';
  select * into h from public.history where id=p_id for update;
  if not found or h.status in ('chunk_draft','submitted_part') or h.filename ~ ' - Parça [0-9]+/[0-9]+$' then
    raise exception 'NOT_FOUND';
  end if;
  old_h := h;
  worker := coalesce(h.assignee_id,h.user_id)=p_actor and p_workspace='member';
  if not manager and not worker then raise exception 'FORBIDDEN'; end if;
  if p_version is null or p_version<>h.version then raise exception 'VERSION_CONFLICT'; end if;
  if h.status='copte' and p_action<>'restore' then raise exception 'INVALID_STATUS'; end if;
  if length(note)>1200 then raise exception 'NOTE_TOO_LONG'; end if;

  if p_action in ('save','submit','reanalyze','approve') then
    if p_payload ? 'questionText' then h.question_text := p_payload->>'questionText'; end if;
    if p_payload ? 'correctedText' then h.corrected_text := p_payload->>'correctedText'; end if;
    if p_payload ? 'tags' then h.tags := p_payload->'tags'; end if;
    if p_payload ? 'submissionNote' then h.submission_note := p_payload->>'submissionNote'; end if;
    h.tags := coalesce(h.tags,'[]'::jsonb);
    if jsonb_typeof(h.tags)<>'array' then raise exception 'INVALID_TAGS'; end if;
    if exists(select 1 from jsonb_array_elements(h.tags) t where jsonb_typeof(t)<>'string' or trim(t#>>'{}')='') then raise exception 'INVALID_TAGS'; end if;
    if length(coalesce(h.question_text,''))>20000 or length(coalesce(h.corrected_text,''))>200000 or
       length(coalesce(h.submission_note,''))>1200 or jsonb_array_length(h.tags)>100 then raise exception 'CONTENT_TOO_LONG'; end if;
  end if;

  if p_action in ('save','submit','reanalyze') then
    if p_action='submit' and not worker then raise exception 'MEMBER_WORKSPACE_REQUIRED'; end if;
    if not (worker and h.status in ('taslak','geri_gonderildi')) and
       not (manager and p_action='save' and h.status in ('bekliyor','teyit_bekliyor','geri_gonderildi','dergah_sorulari','konferanslar')) then
      raise exception 'INVALID_STATUS';
    end if;
    if coalesce(h.workflow_meta->>'disputed','false')='true' then raise exception 'OWNERSHIP_REVIEW_REQUIRED'; end if;
    if p_action='reanalyze' then
      h.score := (p_payload->>'score')::integer;
      h.total_errors := (p_payload->>'totalErrors')::integer;
      h.cat_counts := p_payload->'catCounts';
      h.summary := p_payload->>'summary';
      h.workflow_meta := h.workflow_meta || jsonb_build_object('analysisInput',p_payload->>'analysisInput');
    end if;
    if p_action='submit' then
      h.status := 'bekliyor';
      h.approved_at := null; h.approved_by := null;
      h.workflow_meta := h.workflow_meta - 'returnNote' - 'returnReason';
    end if;
  elsif p_action='withdraw' then
    if not worker or h.status<>'bekliyor' then raise exception 'INVALID_STATUS'; end if;
    h.status := case when public.review_history_is_protected(h.id) then 'geri_gonderildi' else 'taslak' end;
    h.approved_at := null; h.approved_by := null;
    if h.status='geri_gonderildi' then
      h.workflow_meta := h.workflow_meta || jsonb_build_object('returnNote',
        coalesce(h.workflow_meta->>'lastReturnNote',h.workflow_meta->>'returnNote','İncelemeden geri çekildi; düzeltme görevi devam ediyor.'));
    end if;
  elsif p_action='revise_rejected' then
    if not worker or h.status<>'reddedildi' then raise exception 'INVALID_STATUS'; end if;
    if coalesce(h.workflow_meta->>'disputed','false')='true' then raise exception 'OWNERSHIP_REVIEW_REQUIRED'; end if;
    h.status := 'geri_gonderildi'; h.approved_at := null; h.approved_by := null;
    h.workflow_meta := h.workflow_meta || jsonb_build_object(
      'returnNote','Reddedilen kayıt ekip üyesi tarafından yeniden düzenlemeye alındı.',
      'reopenedRejectedBy',p_actor,'reopenedRejectedAt',now());
  elsif p_action='delete_draft' then
    if not worker or h.user_id<>p_actor then raise exception 'FORBIDDEN'; end if;
    if h.status<>'taslak' then raise exception 'DRAFT_ONLY'; end if;
    if public.review_history_is_protected(h.id) then raise exception 'DRAFT_PROTECTED'; end if;
    note := 'Kullanıcı kendi taslağını sildi.';
    h.workflow_meta := h.workflow_meta || jsonb_build_object('trashNote',note,'statusBeforeTrash',h.status,'trashedBy',actor.name,'trashedAt',now());
    h.status := 'copte';
  elsif p_action='close_duplicate' then
    if not worker then raise exception 'FORBIDDEN'; end if;
    if h.status not in ('taslak','geri_gonderildi') then raise exception 'INVALID_STATUS'; end if;
    if coalesce(h.workflow_meta->>'disputed','false')='true' then raise exception 'OWNERSHIP_REVIEW_REQUIRED'; end if;
    if coalesce(h.submission_note,'') !~* 'm[üu]kerrer' and note !~* 'm[üu]kerrer' then raise exception 'DUPLICATE_NOTE_REQUIRED'; end if;
    note := coalesce(nullif(note,''),'Kullanıcı kaydı mükerrer olarak kapattı.');
    h.workflow_meta := h.workflow_meta || jsonb_build_object('trashNote',note,'trashReason','duplicate','trashReasonLabel','Mükerrer','statusBeforeTrash',h.status,'trashedBy',actor.name,'trashedAt',now(),'memberClosedDuplicate',true,'memberClosedDuplicateAt',now());
    h.status := 'copte';
  elsif p_action='dispute' then
    if not worker or h.status<>'geri_gonderildi' then raise exception 'INVALID_STATUS'; end if;
    if note='' then raise exception 'NOTE_REQUIRED'; end if;
    h.workflow_meta := h.workflow_meta || jsonb_build_object('disputed',true,'disputeNote',note,'disputedBy',p_actor,'disputedAt',now());
  elsif p_action='resolve_dispute' then
    if not manager or coalesce(h.workflow_meta->>'disputed','false')<>'true' then raise exception 'INVALID_STATUS'; end if;
    if note='' then raise exception 'NOTE_REQUIRED'; end if;
    if nullif(p_payload->>'assigneeId','') is not null then
      if not exists(select 1 from public.users where id=(p_payload->>'assigneeId')::uuid and active=true) then raise exception 'INVALID_ASSIGNEE'; end if;
      h.assignee_id := (p_payload->>'assigneeId')::uuid;
    end if;
    h.workflow_meta := h.workflow_meta || jsonb_build_object('disputed',false,'ownershipResolution',note,'ownershipResolvedBy',p_actor,'ownershipResolvedAt',now());
  elsif p_action in ('approve','reject','review','dergah','conference','pending','return','archive','trash','confirm_duplicate','duplicate_clear','restore') then
    if not manager then raise exception 'MANAGEMENT_WORKSPACE_REQUIRED'; end if;
    if p_action='approve' then
      if h.status not in ('bekliyor','teyit_bekliyor','geri_gonderildi','dergah_sorulari','konferanslar') then raise exception 'INVALID_STATUS'; end if;
      if coalesce(h.workflow_meta->>'disputed','false')='true' then raise exception 'OWNERSHIP_REVIEW_REQUIRED'; end if;
      duplicate_match_key := jsonb_build_array(md5(public.review_duplicate_key(h.question_text)),md5(public.review_duplicate_key(h.corrected_text)))::text;
      duplicate_id := null; target_slug := null;
      select q.source_history_id,q.slug into duplicate_id,target_slug
      from public.public_qa q
      where q.status='published' and q.source_history_id is not null and q.source_history_id<>h.id
        and md5(public.review_duplicate_key(q.question))=md5(public.review_duplicate_key(h.question_text))
        and md5(public.review_duplicate_key(q.answer_text))=md5(public.review_duplicate_key(h.corrected_text))
        and public.review_duplicate_key(q.question)=public.review_duplicate_key(h.question_text)
        and public.review_duplicate_key(q.answer_text)=public.review_duplicate_key(h.corrected_text)
      order by q.published_at,q.slug
      limit 1 for update;
      if duplicate_id is not null then
        h.status := 'mukerrer_inceleme'; h.approved_at := null; h.approved_by := null;
        h.workflow_meta := h.workflow_meta || jsonb_build_object(
          'duplicateCandidateId',duplicate_id,'duplicateCandidateSlug',target_slug,
          'duplicateDetectedAt',now(),'duplicateDetectionMethod','normalized_full_question_and_answer',
          'duplicateMatchKey',duplicate_match_key
        );
      else
        h.status := 'onaylandi'; h.approved_at := now(); h.approved_by := actor.name;
        h.workflow_meta := h.workflow_meta - 'duplicateCandidateId' - 'duplicateCandidateSlug' - 'duplicateDetectedAt' - 'duplicateDetectionMethod' - 'duplicateMatchKey';
      end if;
    elsif p_action='duplicate_clear' then
      if h.status<>'mukerrer_inceleme' then raise exception 'INVALID_STATUS'; end if;
      if note='' then raise exception 'NOTE_REQUIRED'; end if;
      h.status := 'onaylandi'; h.approved_at := now(); h.approved_by := actor.name;
      h.workflow_meta := (h.workflow_meta || jsonb_build_object(
        'duplicateClearedCandidateId',h.workflow_meta->>'duplicateCandidateId',
        'duplicateClearedReason',note,'duplicateClearedBy',actor.name,'duplicateClearedAt',now()
      )) - 'duplicateCandidateId' - 'duplicateCandidateSlug' - 'duplicateDetectedAt' - 'duplicateDetectionMethod' - 'duplicateMatchKey';
    elsif p_action='confirm_duplicate' then
      if h.status<>'mukerrer_inceleme' then raise exception 'INVALID_STATUS'; end if;
      if note='' then raise exception 'NOTE_REQUIRED'; end if;
      if nullif(p_payload->>'duplicateId','') is null then raise exception 'DUPLICATE_SELECTION_REQUIRED'; end if;
      duplicate_id := (p_payload->>'duplicateId')::uuid;
      select * into target from public.history where id=duplicate_id and id<>h.id for update;
      if not found then raise exception 'NOT_EXACT_DUPLICATE'; end if;
      select q.slug into target_slug from public.public_qa q
      where q.source_history_id=target.id and q.status='published'
        and md5(public.review_duplicate_key(q.question))=md5(public.review_duplicate_key(h.question_text))
        and md5(public.review_duplicate_key(q.answer_text))=md5(public.review_duplicate_key(h.corrected_text))
        and public.review_duplicate_key(q.question)=public.review_duplicate_key(h.question_text)
        and public.review_duplicate_key(q.answer_text)=public.review_duplicate_key(h.corrected_text)
      order by q.published_at,q.slug limit 1 for update;
      if target_slug is null then raise exception 'NOT_EXACT_DUPLICATE'; end if;
      h.workflow_meta := h.workflow_meta || jsonb_build_object(
        'trashNote',note,'trashReason','duplicate','trashReasonLabel','Mükerrer','statusBeforeTrash',h.status,
        'trashedBy',actor.name,'trashedAt',now(),'duplicateId',duplicate_id,'duplicateSlug',target_slug,
        'duplicateConfirmedBy',actor.name,'duplicateConfirmedAt',now()
      );
      h.status := 'copte'; h.approved_at := null; h.approved_by := null;
      update public.public_question_redirects set to_slug=target_slug
        where to_slug in (select slug from public.public_qa where source_history_id=h.id) and from_slug<>target_slug;
      insert into public.public_question_redirects(from_slug,to_slug,history_id)
        select slug,target_slug,h.id from public.public_qa where source_history_id=h.id
        on conflict(from_slug) do update set to_slug=excluded.to_slug;
    elsif p_action='return' then
      if h.status not in ('bekliyor','teyit_bekliyor','dergah_sorulari','konferanslar','onaylandi') then raise exception 'INVALID_STATUS'; end if;
      if note='' then raise exception 'NOTE_REQUIRED'; end if;
      h.status := 'geri_gonderildi'; h.approved_at := null; h.approved_by := null;
      h.workflow_meta := h.workflow_meta || jsonb_build_object('returnNote',note,'returnReason',coalesce(p_payload->>'reason','other'),'returnedBy',actor.name,'returnedAt',now());
    elsif p_action='trash' then
      if note='' then raise exception 'NOTE_REQUIRED'; end if;
      h.workflow_meta := h.workflow_meta || jsonb_build_object('trashNote',note,'trashReason',case when nullif(p_payload->>'duplicateId','') is null then 'other' else 'duplicate' end,'trashReasonLabel',case when nullif(p_payload->>'duplicateId','') is null then 'Diğer' else 'Mükerrer' end,'statusBeforeTrash',h.status,'trashedBy',actor.name,'trashedAt',now());
      h.status := 'copte';
      if nullif(p_payload->>'duplicateId','') is not null then
        duplicate_id := (p_payload->>'duplicateId')::uuid;
        select * into target from public.history where id=duplicate_id and id<>h.id for update;
        if not found then raise exception 'NOT_EXACT_DUPLICATE'; end if;
        select q.slug into target_slug from public.public_qa q
        where q.source_history_id=target.id and q.status='published'
          and md5(public.review_duplicate_key(q.question))=md5(public.review_duplicate_key(h.question_text))
          and md5(public.review_duplicate_key(q.answer_text))=md5(public.review_duplicate_key(h.corrected_text))
          and public.review_duplicate_key(q.question)=public.review_duplicate_key(h.question_text)
          and public.review_duplicate_key(q.answer_text)=public.review_duplicate_key(h.corrected_text)
        order by q.published_at,q.slug limit 1 for update;
        if target_slug is null then raise exception 'NOT_EXACT_DUPLICATE'; end if;
        h.workflow_meta := h.workflow_meta || jsonb_build_object('duplicateId',duplicate_id,'duplicateSlug',target_slug,'duplicateConfirmedBy',actor.name,'duplicateConfirmedAt',now());
        update public.public_question_redirects set to_slug=target_slug
          where to_slug in (select slug from public.public_qa where source_history_id=h.id) and from_slug<>target_slug;
        insert into public.public_question_redirects(from_slug,to_slug,history_id)
          select slug,target_slug,h.id from public.public_qa where source_history_id=h.id
          on conflict(from_slug) do update set to_slug=excluded.to_slug;
      end if;
    elsif p_action='restore' then
      if h.status<>'copte' or note='' then raise exception 'INVALID_STATUS'; end if;
      h.status := case when h.workflow_meta->>'statusBeforeTrash'='taslak' then 'taslak'
        when h.workflow_meta->>'statusBeforeTrash'='mukerrer_inceleme' then 'mukerrer_inceleme' else 'geri_gonderildi' end;
      h.approved_at := null; h.approved_by := null;
      h.workflow_meta := h.workflow_meta || jsonb_build_object('returnNote',note,'restoredBy',actor.name,'restoredAt',now());
      delete from public.public_question_redirects where history_id=h.id;
    else
      if h.status='taslak' then raise exception 'INVALID_STATUS'; end if;
      if coalesce(h.workflow_meta->>'disputed','false')='true' then raise exception 'OWNERSHIP_REVIEW_REQUIRED'; end if;
      if p_action in ('reject','review','dergah','conference') and note='' then raise exception 'NOTE_REQUIRED'; end if;
      h.status := case p_action when 'reject' then 'reddedildi' when 'review' then 'teyit_bekliyor'
        when 'dergah' then 'dergah_sorulari' when 'conference' then 'konferanslar'
        when 'pending' then 'bekliyor' when 'archive' then 'arsivlendi' end;
      h.approved_at := null; h.approved_by := null;
      h.workflow_meta := h.workflow_meta || jsonb_build_object('decisionNote',note);
    end if;
  else raise exception 'INVALID_ACTION';
  end if;

  if p_action in ('submit','approve') then
    if public.review_duplicate_key(h.question_text)='' or public.review_duplicate_key(h.corrected_text)='' or jsonb_array_length(h.tags)=0 then raise exception 'REQUIRED_FIELDS'; end if;
  end if;
  if p_action='submit' or (p_action='approve' and h.status='onaylandi') then
    perform pg_advisory_xact_lock(hashtextextended(jsonb_build_array(public.review_duplicate_key(h.question_text),public.review_duplicate_key(h.corrected_text))::text,0));
    duplicate_id := null;
    select id into duplicate_id from public.history other where other.id<>h.id
      and ((p_action='submit' and other.status in ('bekliyor','onaylandi','teyit_bekliyor','dergah_sorulari','konferanslar'))
        or (p_action='approve' and other.status='onaylandi'))
      and public.review_duplicate_key(other.question_text)=public.review_duplicate_key(h.question_text)
      and public.review_duplicate_key(other.corrected_text)=public.review_duplicate_key(h.corrected_text)
      order by (other.user_id=p_actor or other.assignee_id=p_actor) desc,other.created_at,other.id limit 1;
    if duplicate_id is not null then raise exception 'EXACT_DUPLICATE' using detail=jsonb_build_object('duplicateId',duplicate_id)::text; end if;
  end if;

  perform set_config('app.review_actor',p_actor::text,true);
  perform set_config('app.review_action',p_action,true);
  update public.history set question_text=h.question_text,corrected_text=h.corrected_text,tags=h.tags,submission_note=h.submission_note,
    status=h.status,approved_at=h.approved_at,approved_by=h.approved_by,workflow_meta=h.workflow_meta,assignee_id=h.assignee_id,
    score=h.score,total_errors=h.total_errors,cat_counts=h.cat_counts,summary=h.summary where id=h.id returning * into h;
  if p_action in ('return','reject','review','dergah','conference','pending','archive','trash','confirm_duplicate','close_duplicate','dispute','restore','revise_rejected') then
    update public.public_qa set status=case when p_action in ('trash','confirm_duplicate','close_duplicate') then 'trash_hidden' when p_action='archive' then 'archived_hidden' else 'content_review_hidden' end,updated_at=now()
      where source_history_id=h.id and (status='published' or p_action in ('trash','confirm_duplicate','close_duplicate','restore','revise_rejected'));
  end if;
  if p_action in ('return','restore','resolve_dispute') then
    insert into public.alerts(type,user_id,history_id,message,read)
    values('approval_return',coalesce(h.assignee_id,h.user_id),h.id,
      'Kaydınız düzenleme için hazır. Soru: ' || coalesce(h.question_text,h.filename,'Denetim kaydı') || ' | Not: ' || note,false);
  end if;
  label := case p_action when 'save' then 'Kaydı düzenledi' when 'submit' then 'Onaya gönderdi'
    when 'approve' then case when h.status='mukerrer_inceleme' then 'Mükerrer incelemeye aldı' else 'Kaydı onayladı' end
    when 'revise_rejected' then 'Reddedilen kaydı düzenlemeye aldı'
    when 'delete_draft' then 'Taslağını sildi' when 'close_duplicate' then 'Mükerrer olarak kapattı'
    when 'confirm_duplicate' then 'Mükerrer olarak çöpe taşıdı' when 'duplicate_clear' then 'Mükerrer olmadığını doğruladı'
    when 'return' then 'Düzeltmeye gönderdi' when 'trash' then 'Çöpe taşıdı' when 'restore' then 'Çöpten geri aldı'
    when 'dergah' then 'Dergah sorularına aldı' when 'conference' then 'Konferanslara aldı'
    when 'dispute' then 'Sahiplik itirazı bildirdi' when 'resolve_dispute' then 'Sahiplik itirazını sonuçlandırdı'
    when 'reanalyze' then 'Aynı kaydı yeniden denetledi' when 'withdraw' then 'Onaydan geri çekti' else 'İnceleme kararı verdi' end;
  insert into public.admin_action_log(actor_user_id,actor_username,actor_name,actor_role,action,action_label,target_type,target_id,target_label,target_status_before,target_status_after,summary,metadata)
  values(actor.id,actor.username,actor.name,actor.role,'review.'||p_action,label,'history',h.id::text,h.question_text,old_h.status,h.status,label,
    jsonb_build_object('version',h.version,'workspace',p_workspace,'note',note,'ownerId',h.user_id,'assigneeId',h.assignee_id,'duplicateId',duplicate_id,'duplicateSlug',target_slug));
  perform set_config('app.review_actor','',true);
  perform set_config('app.review_action','',true);
  return to_jsonb(h);
end;
$$;

drop function if exists public.review_duplicate_candidates(uuid);
create function public.review_duplicate_candidates(p_id uuid)
returns table(
  id uuid,
  name text,
  slug text,
  question text,
  answer_text text,
  published_at timestamptz,
  updated_at timestamptz,
  match_type text
)
language sql stable security invoker set search_path='' as $$
  select q.source_history_id,coalesce(other.name,'Canlı arşiv'),q.slug,q.question,q.answer_text,
    q.published_at,q.updated_at,'normalized_full_question_and_answer'::text
  from public.history source
  join public.public_qa q on q.status='published' and q.source_history_id is not null and q.source_history_id<>source.id
    and md5(public.review_duplicate_key(q.question))=md5(public.review_duplicate_key(source.question_text))
    and md5(public.review_duplicate_key(q.answer_text))=md5(public.review_duplicate_key(source.corrected_text))
    and public.review_duplicate_key(q.question)=public.review_duplicate_key(source.question_text)
    and public.review_duplicate_key(q.answer_text)=public.review_duplicate_key(source.corrected_text)
  left join public.history other on other.id=q.source_history_id
  where source.id=p_id
  order by q.published_at,q.slug
  limit 30;
$$;

revoke all on function public.review_duplicate_key(text),
  public.review_history_change(uuid,uuid,integer,text,text,jsonb),
  public.review_duplicate_candidates(uuid) from public,anon,authenticated;
grant execute on function public.review_duplicate_key(text),
  public.review_history_change(uuid,uuid,integer,text,text,jsonb),
  public.review_duplicate_candidates(uuid) to service_role;

notify pgrst, 'reload schema';
