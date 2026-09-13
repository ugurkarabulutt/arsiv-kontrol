-- Allow managers to approve returned records after a final review.
-- No rows are changed by this migration; it only extends the review RPC transition.
do $migration$
declare
  fn text;
  before_line text := $line$if h.status not in ('bekliyor','teyit_bekliyor','dergah_sorulari','konferanslar') then raise exception 'INVALID_STATUS'; end if;$line$;
  after_line text := $line$if h.status not in ('bekliyor','teyit_bekliyor','geri_gonderildi','dergah_sorulari','konferanslar') then raise exception 'INVALID_STATUS'; end if;$line$;
begin
  select pg_get_functiondef('public.review_history_change(uuid,uuid,integer,text,text,jsonb)'::regprocedure) into fn;
  if position(after_line in fn) > 0 then
    return;
  end if;
  if position(before_line in fn) = 0 then
    raise exception 'review_history_change approve status guard not found';
  end if;
  execute replace(fn, before_line, after_line);
end;
$migration$;

notify pgrst, 'reload schema';
