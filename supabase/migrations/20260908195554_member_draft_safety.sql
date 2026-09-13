-- No historical content/status updates. Permissions are checked again under the row lock.
create or replace function public.review_history_is_protected(p_id uuid) returns boolean
language sql stable security invoker set search_path = '' as $$
  select coalesce((select
    h.status='geri_gonderildi' or h.assignee_id is not null
    or coalesce(h.workflow_meta->>'memberDeleteProtected','false')='true'
    or h.workflow_meta ? 'returnedAt'
    or exists(select 1 from public.public_qa p where p.source_history_id=h.id)
    or exists(select 1 from public.history_revisions r where r.history_id=h.id
      and (r.before_data->>'status'='geri_gonderildi' or r.after_data->>'status'='geri_gonderildi'))
    or exists(select 1 from public.admin_action_log l where l.target_type='history' and l.target_id=h.id::text
      and (l.target_status_before='geri_gonderildi' or l.target_status_after='geri_gonderildi'))
    from public.history h where h.id=p_id),true);
$$;

create or replace function public.review_draft_protections(p_ids uuid[])
returns table(id uuid, member_delete_protected boolean)
language sql stable security invoker set search_path = '' as $$
  select h.id, public.review_history_is_protected(h.id)
  from public.history h where h.id=any(p_ids) and h.status='taslak';
$$;

create or replace function public.history_workflow_stamp() returns trigger
language plpgsql security invoker set search_path = '' as $$
begin
  if new.user_id is distinct from old.user_id then raise exception 'OWNER_IMMUTABLE'; end if;
  if old.status='copte' and new.status is distinct from old.status and coalesce(current_setting('app.review_action',true),'')<>'restore' then
    raise exception 'RESTORE_REQUIRED';
  end if;
  if old.status='geri_gonderildi' or new.status='geri_gonderildi'
    or coalesce(old.workflow_meta->>'memberDeleteProtected','false')='true' then
    new.workflow_meta := coalesce(new.workflow_meta,'{}') || jsonb_build_object('memberDeleteProtected',true);
    if old.status='geri_gonderildi' and old.workflow_meta ? 'returnNote' then
      new.workflow_meta := new.workflow_meta || jsonb_build_object('lastReturnNote',old.workflow_meta->>'returnNote');
    end if;
  end if;
  new.version := old.version + 1;
  new.updated_at := now();
  return new;
end;
$$;

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
       not (manager and p_action='save' and h.status in ('bekliyor','teyit_bekliyor','geri_gonderildi')) then
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
  elsif p_action='delete_draft' then
    if not worker or h.user_id<>p_actor then raise exception 'FORBIDDEN'; end if;
    if h.status<>'taslak' then raise exception 'DRAFT_ONLY'; end if;
    if public.review_history_is_protected(h.id) then raise exception 'DRAFT_PROTECTED'; end if;
    note := 'Kullanıcı kendi taslağını sildi.';
    h.workflow_meta := h.workflow_meta || jsonb_build_object('trashNote',note,'statusBeforeTrash',h.status,'trashedBy',actor.name,'trashedAt',now());
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
  elsif p_action in ('approve','reject','review','pending','return','archive','trash','restore') then
    if not manager then raise exception 'MANAGEMENT_WORKSPACE_REQUIRED'; end if;
    if p_action='approve' then
      if p_actor=h.user_id or p_actor=h.assignee_id then raise exception 'SELF_APPROVAL_FORBIDDEN'; end if;
      if h.status not in ('bekliyor','teyit_bekliyor') then raise exception 'INVALID_STATUS'; end if;
      if coalesce(h.workflow_meta->>'disputed','false')='true' then raise exception 'OWNERSHIP_REVIEW_REQUIRED'; end if;
      h.status := 'onaylandi'; h.approved_at := now(); h.approved_by := actor.name;
    elsif p_action='return' then
      if h.status not in ('bekliyor','teyit_bekliyor','onaylandi') then raise exception 'INVALID_STATUS'; end if;
      if p_actor=coalesce(h.assignee_id,h.user_id) then raise exception 'SELF_RETURN_FORBIDDEN'; end if;
      if note='' then raise exception 'NOTE_REQUIRED'; end if;
      h.status := 'geri_gonderildi'; h.approved_at := null; h.approved_by := null;
      h.workflow_meta := h.workflow_meta || jsonb_build_object('returnNote',note,'returnReason',coalesce(p_payload->>'reason','other'),'returnedBy',actor.name,'returnedAt',now());
    elsif p_action='trash' then
      if note='' then raise exception 'NOTE_REQUIRED'; end if;
      h.workflow_meta := h.workflow_meta || jsonb_build_object('trashNote',note,'statusBeforeTrash',h.status,'trashedBy',actor.name,'trashedAt',now());
      h.status := 'copte';
      if nullif(p_payload->>'duplicateId','') is not null then
        select * into target from public.history where id=(p_payload->>'duplicateId')::uuid and id<>h.id for update;
        if not found or target.status<>'onaylandi' or public.review_text_key(target.question_text)<>public.review_text_key(h.question_text)
          or public.review_text_key(target.corrected_text)<>public.review_text_key(h.corrected_text) then raise exception 'NOT_EXACT_DUPLICATE'; end if;
        select slug into target_slug from public.public_qa where source_history_id=target.id and status='published' for update;
        if target_slug is null then raise exception 'DUPLICATE_NOT_PUBLISHED'; end if;
        update public.public_question_redirects set to_slug=target_slug
          where to_slug in (select slug from public.public_qa where source_history_id=h.id) and from_slug<>target_slug;
        insert into public.public_question_redirects(from_slug,to_slug,history_id)
          select slug,target_slug,h.id from public.public_qa where source_history_id=h.id
          on conflict(from_slug) do update set to_slug=excluded.to_slug;
      end if;
    elsif p_action='restore' then
      if h.status<>'copte' or note='' then raise exception 'INVALID_STATUS'; end if;
      h.status := case when h.workflow_meta->>'statusBeforeTrash'='taslak' then 'taslak' else 'geri_gonderildi' end;
      h.approved_at := null; h.approved_by := null;
      h.workflow_meta := h.workflow_meta || jsonb_build_object('returnNote',note,'restoredBy',actor.name,'restoredAt',now());
      delete from public.public_question_redirects where history_id=h.id;
    else
      if h.status='taslak' then raise exception 'INVALID_STATUS'; end if;
      if coalesce(h.workflow_meta->>'disputed','false')='true' then raise exception 'OWNERSHIP_REVIEW_REQUIRED'; end if;
      if p_action in ('reject','review') and note='' then raise exception 'NOTE_REQUIRED'; end if;
      h.status := case p_action when 'reject' then 'reddedildi' when 'review' then 'teyit_bekliyor'
        when 'pending' then 'bekliyor' when 'archive' then 'arsivlendi' end;
      h.approved_at := null; h.approved_by := null;
      h.workflow_meta := h.workflow_meta || jsonb_build_object('decisionNote',note);
    end if;
  else raise exception 'INVALID_ACTION';
  end if;

  if p_action in ('submit','approve') then
    if public.review_text_key(h.question_text)='' or public.review_text_key(h.corrected_text)='' or jsonb_array_length(h.tags)=0 then raise exception 'REQUIRED_FIELDS'; end if;
    -- Serialize identical Q+A submissions across users. Similar wording is not a duplicate.
    perform pg_advisory_xact_lock(hashtextextended(jsonb_build_array(public.review_text_key(h.question_text),public.review_text_key(h.corrected_text))::text,0));
    select id into duplicate_id from public.history other where other.id<>h.id and other.status in ('bekliyor','onaylandi','teyit_bekliyor')
      and public.review_text_key(other.question_text)=public.review_text_key(h.question_text)
      and public.review_text_key(other.corrected_text)=public.review_text_key(h.corrected_text)
      order by (other.user_id=p_actor or other.assignee_id=p_actor) desc, other.created_at, other.id limit 1;
    if duplicate_id is not null then raise exception 'EXACT_DUPLICATE' using detail=jsonb_build_object('duplicateId',duplicate_id)::text; end if;
  end if;

  perform set_config('app.review_actor',p_actor::text,true);
  perform set_config('app.review_action',p_action,true);
  update public.history set question_text=h.question_text,corrected_text=h.corrected_text,tags=h.tags,submission_note=h.submission_note,
    status=h.status,approved_at=h.approved_at,approved_by=h.approved_by,workflow_meta=h.workflow_meta,assignee_id=h.assignee_id,
    score=h.score,total_errors=h.total_errors,cat_counts=h.cat_counts,summary=h.summary where id=h.id returning * into h;
  if p_action in ('return','reject','review','pending','archive','trash','dispute','restore') then
    update public.public_qa set status=case when p_action='trash' then 'trash_hidden' when p_action='archive' then 'archived_hidden' else 'content_review_hidden' end,updated_at=now()
      where source_history_id=h.id and (status='published' or p_action in ('trash','restore'));
  end if;
  if p_action in ('return','restore','resolve_dispute') then
    insert into public.alerts(type,user_id,history_id,message,read)
    values('approval_return',coalesce(h.assignee_id,h.user_id),h.id,
      'Kaydınız düzenleme için hazır. Soru: ' || coalesce(h.question_text,h.filename,'Denetim kaydı') || ' | Not: ' || note,false);
  end if;
  label := case p_action when 'save' then 'Kaydı düzenledi' when 'submit' then 'Onaya gönderdi' when 'approve' then 'Kaydı onayladı'
    when 'delete_draft' then 'Taslağını sildi' when 'return' then 'Düzeltmeye gönderdi' when 'trash' then 'Çöpe taşıdı' when 'restore' then 'Çöpten geri aldı'
    when 'dispute' then 'Sahiplik itirazı bildirdi' when 'resolve_dispute' then 'Sahiplik itirazını sonuçlandırdı'
    when 'reanalyze' then 'Aynı kaydı yeniden denetledi' when 'withdraw' then 'Onaydan geri çekti' else 'İnceleme kararı verdi' end;
  insert into public.admin_action_log(actor_user_id,actor_username,actor_name,actor_role,action,action_label,target_type,target_id,target_label,target_status_before,target_status_after,summary,metadata)
  values(actor.id,actor.username,actor.name,actor.role,'review.'||p_action,label,'history',h.id::text,h.question_text,old_h.status,h.status,label,
    jsonb_build_object('version',h.version,'workspace',p_workspace,'note',note,'ownerId',h.user_id,'assigneeId',h.assignee_id));
  perform set_config('app.review_actor','',true);
  perform set_config('app.review_action','',true);
  return to_jsonb(h);
end;
$$;

-- Same-owner/assigned source lookup also recognizes the saved corrected answer.
create or replace function public.review_find_existing_analysis(p_actor uuid,p_text text,p_hashes text[] default '{}')
returns jsonb language sql volatile security invoker set search_path = '' as $$
  select jsonb_build_object('id',h.id,'status',h.status,'user_id',h.user_id,'assignee_id',h.assignee_id)
  from public.history h
  where (h.user_id=p_actor or h.assignee_id=p_actor)
    and h.status not in ('copte','chunk_draft','submitted_part')
    and coalesce(h.filename,'') !~ ' - Parça [0-9]+/[0-9]+$'
    and public.review_text_key(p_text)<>''
    and (h.text_hash=any(p_hashes)
      or public.review_text_key(h.original_text)=public.review_text_key(p_text)
      or public.review_text_key(h.corrected_text)=public.review_text_key(p_text))
  order by (h.status<>'taslak') desc, h.created_at, h.id limit 1;
$$;

create or replace function public.history_prevent_duplicate_draft() returns trigger
language plpgsql security invoker set search_path = '' as $$
declare matched jsonb;
begin
  if new.status<>'taslak' then return new; end if;
  -- Serialize the short insert, never the AI call. Existing duplicate rows are untouched.
  perform pg_advisory_xact_lock(hashtextextended('history-create:'||new.user_id::text,0));
  matched := public.review_find_existing_analysis(new.user_id,
    coalesce(nullif(new.original_text,''),new.corrected_text),array[new.text_hash]);
  if matched is not null then
    raise exception 'ANALYSIS_EXISTS' using detail=jsonb_build_object('duplicateId',matched->>'id')::text;
  end if;
  return new;
end;
$$;
drop trigger if exists history_prevent_duplicate_draft on public.history;
create trigger history_prevent_duplicate_draft before insert on public.history
for each row execute function public.history_prevent_duplicate_draft();

revoke all on function public.review_history_is_protected(uuid), public.review_draft_protections(uuid[]),
  public.review_find_existing_analysis(uuid,text,text[]), public.history_prevent_duplicate_draft(),
  public.history_workflow_stamp(), public.review_history_change(uuid,uuid,integer,text,text,jsonb) from public,anon,authenticated;
grant execute on function public.review_history_is_protected(uuid), public.review_draft_protections(uuid[]),
  public.review_find_existing_analysis(uuid,text,text[]), public.history_prevent_duplicate_draft(),
  public.history_workflow_stamp(), public.review_history_change(uuid,uuid,integer,text,text,jsonb) to service_role;
