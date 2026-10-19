-- Admins and super admins may approve records they own or are assigned to.
-- Approval remains versioned and written to history_revisions/admin_action_log.
-- This migration changes no rows.
do $migration$
declare
  fn text;
  guard text := $line$if p_actor=h.user_id or p_actor=h.assignee_id then raise exception 'SELF_APPROVAL_FORBIDDEN'; end if;$line$;
begin
  select pg_get_functiondef(
    'public.review_history_change(uuid,uuid,integer,text,text,jsonb)'::regprocedure
  ) into fn;

  if position('SELF_APPROVAL_FORBIDDEN' in fn)=0 then
    return;
  end if;
  if position(guard in fn)=0 then
    raise exception 'review_history_change self-approval guard not found';
  end if;

  fn := replace(fn,guard,'');
  execute fn;

  if position('SELF_APPROVAL_FORBIDDEN' in pg_get_functiondef(
    'public.review_history_change(uuid,uuid,integer,text,text,jsonb)'::regprocedure
  ))>0 then
    raise exception 'review_history_change self-approval guard still present';
  end if;
end;
$migration$;

notify pgrst, 'reload schema';
