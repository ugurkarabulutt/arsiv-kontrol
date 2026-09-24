-- Rejected records must be corrected and resubmitted, not removed by members.
do $migration$
declare
  fn text;
  marker text := $line$p_action='dismiss_rejected'$line$;
  before_branch text := $line$  elsif p_action='dismiss_rejected' then
    if not worker or h.status<>'reddedildi' then raise exception 'INVALID_STATUS'; end if;
    if coalesce(h.workflow_meta->>'disputed','false')='true' then raise exception 'OWNERSHIP_REVIEW_REQUIRED'; end if;
    note := 'Ekip üyesi reddedilen kaydı aktif listesinden kaldırdı.';
    h.workflow_meta := h.workflow_meta || jsonb_build_object(
      'trashNote',note,'statusBeforeTrash',h.status,'trashedBy',actor.name,'trashedAt',now(),
      'memberDismissedRejected',true,'memberDismissedRejectedAt',now());
    h.status := 'copte';
  elsif p_action='delete_draft' then$line$;
  after_branch text := $line$  elsif p_action='delete_draft' then$line$;
  before_public_actions text := $line$if p_action in ('return','reject','review','dergah','conference','pending','archive','trash','close_duplicate','dispute','restore','revise_rejected','dismiss_rejected') then$line$;
  after_public_actions text := $line$if p_action in ('return','reject','review','dergah','conference','pending','archive','trash','close_duplicate','dispute','restore','revise_rejected') then$line$;
  before_public_status text := $line$case when p_action in ('trash','close_duplicate','dismiss_rejected') then 'trash_hidden'$line$;
  after_public_status text := $line$case when p_action in ('trash','close_duplicate') then 'trash_hidden'$line$;
  before_public_scope text := $line$p_action in ('trash','close_duplicate','restore','revise_rejected','dismiss_rejected')$line$;
  after_public_scope text := $line$p_action in ('trash','close_duplicate','restore','revise_rejected')$line$;
  before_labels text := $line$when 'revise_rejected' then 'Reddedilen kaydı düzenlemeye aldı' when 'dismiss_rejected' then 'Reddedilen kaydı listesinden kaldırdı'
    when 'delete_draft' then 'Taslağını sildi'$line$;
  after_labels text := $line$when 'revise_rejected' then 'Reddedilen kaydı düzenlemeye aldı'
    when 'delete_draft' then 'Taslağını sildi'$line$;
begin
  select pg_get_functiondef('public.review_history_change(uuid,uuid,integer,text,text,jsonb)'::regprocedure) into fn;
  if position(marker in fn)=0 then return; end if;
  if position(before_branch in fn)=0 or position(before_public_actions in fn)=0 or
     position(before_public_status in fn)=0 or position(before_public_scope in fn)=0 or
     position(before_labels in fn)=0 then
    raise exception 'review_history_change rejected-dismiss fragments not found';
  end if;
  fn := replace(fn,before_branch,after_branch);
  fn := replace(fn,before_public_actions,after_public_actions);
  fn := replace(fn,before_public_status,after_public_status);
  fn := replace(fn,before_public_scope,after_public_scope);
  fn := replace(fn,before_labels,after_labels);
  execute fn;
  if position(marker in fn) > 0 then raise exception 'INVALID_ACTION'; end if;
end;
$migration$;

revoke all on function public.review_history_change(uuid,uuid,integer,text,text,jsonb) from public,anon,authenticated;
grant execute on function public.review_history_change(uuid,uuid,integer,text,text,jsonb) to service_role;
notify pgrst, 'reload schema';
