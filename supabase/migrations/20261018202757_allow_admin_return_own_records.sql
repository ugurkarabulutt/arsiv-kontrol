-- Admins may return their own records for correction from the management workspace.
-- Self-approval remains forbidden. This migration changes no rows.
do $migration$
declare
  fn text;
  forbidden_guard text := $line$if p_actor=coalesce(h.assignee_id,h.user_id) then raise exception 'SELF_RETURN_FORBIDDEN'; end if;$line$;
begin
  select pg_get_functiondef(
    'public.review_history_change(uuid,uuid,integer,text,text,jsonb)'::regprocedure
  ) into fn;

  if position('SELF_RETURN_FORBIDDEN' in fn)=0 then
    return;
  end if;
  if position(forbidden_guard in fn)=0 then
    raise exception 'review_history_change self-return guard not found';
  end if;

  fn := replace(fn,forbidden_guard,'');
  execute fn;

  if position('SELF_RETURN_FORBIDDEN' in pg_get_functiondef(
    'public.review_history_change(uuid,uuid,integer,text,text,jsonb)'::regprocedure
  ))>0 then
    raise exception 'review_history_change self-return guard still present';
  end if;
end;
$migration$;

notify pgrst, 'reload schema';
