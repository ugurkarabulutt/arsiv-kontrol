-- Bind publication eligibility to the exact question and answer checked by the server.
create or replace function public.review_analysis_hash(value text)
returns text language sql immutable security invoker set search_path = '' as $$
  select md5(regexp_replace(coalesce(value,''), E'\r\n?', E'\n', 'g'));
$$;

create or replace function public.review_assert_analysis(question text, answer text, meta jsonb)
returns void language plpgsql security invoker set search_path = '' as $$
declare receipt jsonb := coalesce(meta->'analysisReceipt','{}'::jsonb);
begin
  if coalesce(receipt->>'version','')<>'1'
    or coalesce(receipt->>'scope','')<>'question_and_answer'
    or coalesce(receipt->>'state','')<>'ready'
    or coalesce(receipt->>'questionHash','')<>public.review_analysis_hash(question)
    or coalesce(receipt->>'answerHash','')<>public.review_analysis_hash(answer)
    or coalesce((receipt->'question'->>'score')::integer,0)<60
    or coalesce((receipt->'answer'->>'score')::integer,0)<60
    or trim(coalesce(question,''))='' or trim(coalesce(answer,''))='' then
    raise exception 'ANALYSIS_REQUIRED';
  end if;
end;
$$;

do $migration$
declare fn text; old_fragment text; new_fragment text;
begin
  select pg_get_functiondef('public.review_history_change(uuid,uuid,integer,text,text,jsonb)'::regprocedure) into fn;
  old_fragment := $old$not (manager and p_action='save' and h.status in ('bekliyor','teyit_bekliyor','geri_gonderildi','dergah_sorulari','konferanslar'))$old$;
  new_fragment := $new$not (manager and p_action in ('save','reanalyze') and h.status in ('bekliyor','teyit_bekliyor','geri_gonderildi','dergah_sorulari','konferanslar','mukerrer_inceleme'))$new$;
  if position(old_fragment in fn)=0 then raise exception 'quality gate: manager guard not found'; end if;
  fn := replace(fn,old_fragment,new_fragment);
  old_fragment := $old$h.workflow_meta := h.workflow_meta || jsonb_build_object('analysisInput',p_payload->>'analysisInput');$old$;
  new_fragment := $new$h.workflow_meta := h.workflow_meta || jsonb_build_object('analysisInput',p_payload->'analysisInput','analysisReceipt',p_payload->'analysisReceipt');$new$;
  if position(old_fragment in fn)=0 then raise exception 'quality gate: receipt point not found'; end if;
  fn := replace(fn,old_fragment,new_fragment);
  old_fragment := $old$  if p_action in ('submit','approve') then$old$;
  new_fragment := $new$  if p_action in ('submit','approve','duplicate_clear') then
    perform public.review_assert_analysis(h.question_text,h.corrected_text,h.workflow_meta);
  end if;
  if p_action in ('submit','approve') then$new$;
  if position(old_fragment in fn)=0 then raise exception 'quality gate: publication guard not found'; end if;
  fn := replace(fn,old_fragment,new_fragment);
  execute fn;
end;
$migration$;

create or replace function public.history_analysis_guard()
returns trigger language plpgsql security invoker set search_path = '' as $$
declare receipt jsonb := new.workflow_meta->'analysisReceipt';
begin
  if receipt->>'scope'='question_and_answer' and
    (coalesce(receipt->>'questionHash','')<>public.review_analysis_hash(new.question_text)
      or coalesce(receipt->>'answerHash','')<>public.review_analysis_hash(new.corrected_text)) then
    new.workflow_meta := jsonb_set(new.workflow_meta,'{analysisReceipt,state}','"stale"'::jsonb);
  end if;
  if new.status in ('bekliyor','onaylandi') then
    if tg_op='INSERT' then
      perform public.review_assert_analysis(new.question_text,new.corrected_text,new.workflow_meta);
    elsif new.status is distinct from old.status then
      perform public.review_assert_analysis(new.question_text,new.corrected_text,new.workflow_meta);
    end if;
  end if;
  return new;
end;
$$;

drop trigger if exists history_analysis_guard on public.history;
create trigger history_analysis_guard before insert or update on public.history
for each row execute function public.history_analysis_guard();

revoke all on function public.review_analysis_hash(text),public.review_assert_analysis(text,text,jsonb),
  public.history_analysis_guard() from public,anon,authenticated;
grant execute on function public.review_analysis_hash(text),public.review_assert_analysis(text,text,jsonb),
  public.history_analysis_guard() to service_role;
