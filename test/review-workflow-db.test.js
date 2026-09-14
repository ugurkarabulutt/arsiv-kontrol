const { test, before, beforeEach, after } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { PGlite } = require('@electric-sql/pglite');
const { recordActions, canReadRecord, workspaceFor, cleanPayload, memberDisplayStatus } = require('../review-policy');

const ids = { user: '10000000-0000-4000-8000-000000000001', other: '10000000-0000-4000-8000-000000000002',
  admin: '10000000-0000-4000-8000-000000000003', super: '10000000-0000-4000-8000-000000000004' };
let db;
const migration = fs.readFileSync(path.join(__dirname,'../supabase/migrations/20260906142527_admin_review_workspaces.sql'),'utf8');
before(async () => {
  db = new PGlite();
  const schema = fs.readFileSync(path.join(__dirname,'../schema.sql'),'utf8');
  await db.exec('create role anon; create role authenticated; create role service_role bypassrls;');
  for (const name of ['users','history','alerts','admin_action_log','public_categories','public_qa']) {
    const block = schema.match(new RegExp(`create table if not exists public\\.${name} \\([\\s\\S]*?\\n\\);`));
    assert.ok(block, name);
    await db.exec(block[0]);
  }
  await db.exec('grant usage on schema public to service_role; grant all on all tables in schema public to service_role;');
  await db.exec(migration);
  await db.exec(migration);
  const queueMigration = fs.readFileSync(path.join(__dirname,'../supabase/migrations/20260906214233_review_submission_queue.sql'),'utf8');
  await db.exec(queueMigration);
  await db.exec(queueMigration);
  const statusQueueMigration = fs.readFileSync(path.join(__dirname,'../supabase/migrations/20260907030328_review_status_queue_order.sql'),'utf8');
  await db.exec(statusQueueMigration);
  await db.exec(statusQueueMigration);
  const safetyMigration = fs.readFileSync(path.join(__dirname,'../supabase/migrations/20260908195554_member_draft_safety.sql'),'utf8');
  await db.exec(safetyMigration);
  await db.exec(safetyMigration);
  const legacyChunkMigration = fs.readFileSync(path.join(__dirname,'../supabase/migrations/20260909122817_hide_legacy_chunk_drafts.sql'),'utf8');
  await db.exec(legacyChunkMigration);
  await db.exec(legacyChunkMigration);
  const duplicateCleanupMigration = fs.readFileSync(path.join(__dirname,'../supabase/migrations/20260912162000_member_duplicate_cleanup.sql'),'utf8');
  await db.exec(duplicateCleanupMigration);
  await db.exec(duplicateCleanupMigration);
  const specialSectionsMigration = fs.readFileSync(path.join(__dirname,'../supabase/migrations/20260913000100_review_special_holding_sections.sql'),'utf8');
  await db.exec(specialSectionsMigration);
  await db.exec(specialSectionsMigration);
  const returnedApproveMigration = fs.readFileSync(path.join(__dirname,'../supabase/migrations/20260913000200_management_can_approve_returned.sql'),'utf8');
  await db.exec(returnedApproveMigration);
  await db.exec(returnedApproveMigration);
});
beforeEach(async () => {
  await db.exec('reset role; truncate public.history_revisions,public.public_question_redirects,public.public_qa,public.alerts,public.admin_action_log,public.history,public.users cascade;');
  for (const [name,id] of Object.entries(ids)) await db.query('insert into users(id,username,password,name,role) values($1,$2,$3,$4,$5)',[id,name,'test-only',name==='admin'?'Elçin Test':name,name==='super'?'super_admin':name==='admin'?'admin':'user']);
});
after(async () => db?.close());
async function seed(owner='user',status='geri_gonderildi',q='Soru?',a='İlk paragraf.\n\nÂyet: نص\nMeali.\n\nAçıklama.') {
  return (await db.query(`insert into history(user_id,name,username,status,question_text,corrected_text,original_text,tags)
    values($1,$2,$2,$3,$4,$5,'Dokunulmayacak kaynak '||gen_random_uuid()::text, '["Takva"]') returning *`,[ids[owner],owner,status,q,a])).rows[0];
}
async function change(h,actor,space,action,payload={}) {
  await db.exec('set role service_role');
  try { return (await db.query('select review_history_change($1,$2,$3,$4,$5,$6) as h',[h.id,ids[actor],h.version,space,action,JSON.stringify(payload)])).rows[0].h; }
  finally { await db.exec('reset role'); }
}
async function publish(h,slug='test') {
  await db.query('insert into public_qa(slug,source_history_id,title,question,answer_text) values($1,$2,$3,$3,$4)',[slug,h.id,h.question_text,h.corrected_text]);
}

test('roles select workspace, not privileges; own and assigned reads stay scoped', async () => {
  const h=await seed();
  assert.equal(workspaceFor({role:'user'},'management'),'member');
  assert.equal(canReadRecord({id:ids.other,role:'user'},h,'member'),false);
  assert.equal(canReadRecord({id:ids.admin,role:'admin'},h,'member'),false);
  assert.equal(canReadRecord({id:ids.admin,role:'admin'},h,'management'),true);
  await assert.rejects(change(h,'other','member','save'),/FORBIDDEN/);
  await assert.rejects(change(h,'user','management','approve'),/FORBIDDEN/);
});
test('same-record save preserves exact Turkish, paragraphs, source and owner; revision is complete', async () => {
  const h=await seed('admin');
  const answer='Nebîler Sultanımız\n\nنص عربي\nMeali:\n\nAçıklama.\n';
  const saved=await change(h,'admin','member','save',{questionText:'Nasıl?',correctedText:answer,tags:['Nefs','İştiyak'],submissionNote:'Soru, cevap ve etiket uyumlu.'});
  assert.equal(saved.id,h.id);assert.equal(saved.corrected_text,answer);assert.equal(saved.original_text,h.original_text);assert.equal(saved.user_id,h.user_id);assert.equal(saved.version,1);
  const revision=(await db.query('select * from history_revisions')).rows[0];
  assert.equal(revision.actor_id,ids.admin);assert.equal(revision.before_data.corrected_text,h.corrected_text);assert.equal(revision.after_data.corrected_text,answer);
  assert.equal((await db.query('select count(*)::int as n from history')).rows[0].n,1);
});
test('stale writer cannot overwrite newer save or emit another log', async () => {
  const h=await seed();await change(h,'user','member','save',{questionText:'Yeni soru?'});
  await assert.rejects(change(h,'user','member','save',{questionText:'Eski ekrandan?'}),/VERSION_CONFLICT/);
  assert.equal((await db.query('select question_text from history')).rows[0].question_text,'Yeni soru?');
  assert.equal((await db.query('select count(*)::int as n from admin_action_log')).rows[0].n,1);
});
test('submit validates all fields; incomplete draft can still be saved', async () => {
  let h=await seed();h=await change(h,'user','member','save',{questionText:'',tags:[],correctedText:''});
  await assert.rejects(change(h,'user','member','submit'),/REQUIRED_FIELDS/);
  h=await change(h,'user','member','submit',{questionText:'Soru?',correctedText:'Kısa cevap.',tags:['Takva']});
  assert.equal(h.status,'bekliyor');
  await assert.rejects(change(h,'user','member','save',{questionText:'Gizli değişiklik?'}),/INVALID_STATUS/);
  h=await change(h,'user','member','withdraw');assert.equal(h.status,'geri_gonderildi');
});
test('both admin roles submit own work as members and cannot approve themselves', async () => {
  for (const owner of ['admin','super']) {
    let h=await seed(owner,'taslak',owner+'?');
    await assert.rejects(change(h,owner,'management','submit'),/MEMBER_WORKSPACE_REQUIRED/);
    h=await change(h,owner,'member','submit');
    await assert.rejects(change(h,owner,'management','approve'),/SELF_APPROVAL_FORBIDDEN/);
    await assert.rejects(change(h,owner,'management','return',{note:'Not'}),/SELF_RETURN_FORBIDDEN/);
    h=await change(h,owner==='admin'?'super':'admin','management','approve');assert.equal(h.status,'onaylandi');
  }
});
test('approve saves edited question, answer and tags in the same atomic revision', async () => {
  const h=await seed('user','bekliyor');
  const result=await change(h,'admin','management','approve',{questionText:'Kontrol edilmiş soru?',correctedText:'Kısa cevap.\n\nİkinci paragraf.',tags:['İman'],submissionNote:'Uyum kontrol edildi.'});
  assert.equal(result.corrected_text,'Kısa cevap.\n\nİkinci paragraf.');assert.equal(result.question_text,'Kontrol edilmiş soru?');assert.equal(result.status,'onaylandi');
  assert.equal((await db.query('select count(*)::int as n from history_revisions')).rows[0].n,1);
});
test('manager can approve returned records after final review', async () => {
  const h=await seed('user','geri_gonderildi','Geri dönen uygun soru?','Kontrol edilmiş cevap.');
  assert.ok(recordActions({id:ids.admin,role:'admin'},h,'management').includes('approve'));
  const result=await change(h,'admin','management','approve');
  assert.equal(result.status,'onaylandi');
  assert.equal(result.approved_by,'Elçin Test');
});
test('duplicate requires BOTH exact Q and A across users, never only similar question or answer', async () => {
  await seed('other','onaylandi','Aynı soru?','Aynı cevap.');
  const exact=await seed('user','taslak','Aynı  soru?','Aynı cevap.');
  await assert.rejects(change(exact,'user','member','submit'),/EXACT_DUPLICATE/);
  const otherAnswer=await seed('user','taslak','Aynı soru?','Farklı cevap.');
  assert.equal((await change(otherAnswer,'user','member','submit')).status,'bekliyor');
  const otherQuestion=await seed('user','taslak','Farklı soru?','Aynı cevap.');
  assert.equal((await change(otherQuestion,'user','member','submit')).status,'bekliyor');
});
test('ownership dispute freezes edits, original ownership never moves, assigned worker receives task', async () => {
  let h=await seed('admin');h=await change(h,'admin','member','dispute',{note:'Bu denetim dosyamda bulunmuyor.'});
  await assert.rejects(change(h,'admin','member','submit'),/OWNERSHIP_REVIEW_REQUIRED/);
  await assert.rejects(change(h,'super','management','pending'),/OWNERSHIP_REVIEW_REQUIRED/);
  h=await change(h,'super','management','resolve_dispute',{note:'Kaynak ve kullanıcı teyidi alındı.',assigneeId:ids.other});
  assert.equal(h.user_id,ids.admin);assert.equal(h.assignee_id,ids.other);
  assert.deepEqual(recordActions({id:ids.admin,role:'admin'},h,'member'),[]);
  await assert.rejects(change(h,'admin','member','save'),/FORBIDDEN/);
  assert.equal((await change(h,'other','member','save',{submissionNote:'Kontrol ettim.'})).id,h.id);
  const alert=(await db.query('select * from alerts')).rows[0];assert.equal(alert.user_id,ids.other);assert.match(alert.message,/Kaynak ve kullanıcı teyidi/);
});
test('trash atomically hides public content, logs reason, restores without publishing', async () => {
  let h=await seed('user','onaylandi');await publish(h);
  await assert.rejects(change(h,'user','member','trash',{note:'Not'}),/MANAGEMENT_WORKSPACE_REQUIRED/);
  h=await change(h,'admin','management','trash',{note:'Birebir kopya kontrolü.'});
  assert.equal(h.status,'copte');assert.equal((await db.query('select status from public_qa')).rows[0].status,'trash_hidden');
  await assert.rejects(change(h,'admin','management','approve'),/INVALID_STATUS/);
  h=await change(h,'super','management','restore',{note:'Kaynak tekrar kontrol edilecek.'});
  assert.equal(h.status,'geri_gonderildi');assert.equal((await db.query('select status from public_qa')).rows[0].status,'content_review_hidden');
});
test('exact duplicate redirect validates published target and restores reversibly', async () => {
  const target=await seed('other','onaylandi');await publish(target,'asil');
  let copy=await seed('user','onaylandi');await publish(copy,'kopya');
  assert.equal((await db.query('select * from review_duplicate_candidates($1)',[copy.id])).rows[0].id,target.id);
  copy=await change(copy,'admin','management','trash',{note:'Soru ve cevap birebir aynı.',duplicateId:target.id});
  assert.equal((await db.query('select to_slug from public_question_redirects')).rows[0].to_slug,'asil');
  await change(copy,'admin','management','restore',{note:'Tekrar kontrol'});
  assert.equal((await db.query('select * from public_question_redirects')).rows.length,0);
});
test('invalid duplicate target rolls back status, public visibility, revisions and logs', async () => {
  const target=await seed('other','onaylandi','Başka soru?');await publish(target,'diger');
  const h=await seed('user','onaylandi');await publish(h);
  await assert.rejects(change(h,'admin','management','trash',{note:'Not',duplicateId:target.id}),/NOT_EXACT_DUPLICATE/);
  assert.equal((await db.query('select status from history where id=$1',[h.id])).rows[0].status,'onaylandi');
  assert.equal((await db.query('select status from public_qa where slug=$1',['test'])).rows[0].status,'published');
  assert.equal((await db.query('select count(*)::int as n from history_revisions')).rows[0].n,0);
});
test('reanalysis writes same record, retains original source and stores input provenance', async () => {
  const h=await seed();
  const result=await change(h,'user','member','reanalyze',{correctedText:'Denetimden çıkan\n\nTam cevap.',analysisInput:'Düzenlenip verilen metin',score:100,totalErrors:0,catCounts:{},summary:'Kontrol edildi.'});
  assert.equal(result.id,h.id);assert.equal(result.original_text,h.original_text);assert.equal(result.workflow_meta.analysisInput,'Düzenlenip verilen metin');
  assert.equal((await db.query('select count(*)::int as n from history')).rows[0].n,1);
});
test('failure after history/public writes rolls the entire action back', async () => {
  const h=await seed('user','onaylandi');await publish(h);
  await db.exec("create function test_log_failure() returns trigger language plpgsql as $$begin raise exception 'TEST_LOG_FAILURE'; end$$; create trigger test_log_failure before insert on admin_action_log for each row execute function test_log_failure();");
  try{
    await assert.rejects(change(h,'admin','management','return',{note:'Kaynak kontrolü'}),/TEST_LOG_FAILURE/);
    assert.equal((await db.query('select status from history where id=$1',[h.id])).rows[0].status,'onaylandi');
    assert.equal((await db.query('select status from public_qa')).rows[0].status,'published');
    assert.equal((await db.query('select * from history_revisions')).rows.length,0);
    assert.equal((await db.query('select * from alerts')).rows.length,0);
  }finally{await db.exec('drop trigger test_log_failure on admin_action_log; drop function test_log_failure();');}
});
test('redirect chains flatten when the surviving exact copy is later replaced',async()=>{
  const a=await seed('user','onaylandi'),b=await seed('other','onaylandi'),c=await seed('super','onaylandi');
  await publish(a,'a');await publish(b,'b');await publish(c,'c');
  await change(a,'admin','management','trash',{note:'Kopya',duplicateId:b.id});
  await change(b,'admin','management','trash',{note:'Kopya',duplicateId:c.id});
  const redirects=(await db.query('select to_slug from public_question_redirects')).rows;assert.equal(redirects.length,2);assert.ok(redirects.every(r=>r.to_slug==='c'));
});
test('public callers cannot read private tables or invoke privileged RPCs', async () => {
  const h=await seed();
  for (const role of ['anon','authenticated']) {
    await db.exec(`set role ${role}`);
    await assert.rejects(db.query('select * from history_revisions'),/permission denied/);
    await assert.rejects(db.query('select * from review_history_queue'),/permission denied/);
    await assert.rejects(db.query('select review_duplicate_candidates($1)',[h.id]),/permission denied/);
    await assert.rejects(db.query('select review_history_change($1,$2,0,\'management\',\'approve\')',[h.id,ids.admin]),/permission denied/);
    await db.exec('reset role');
  }
});
test('owner immutable even outside RPC; external edits still produce revisions', async () => {
  const h=await seed();
  await assert.rejects(db.query('update history set user_id=$1 where id=$2',[ids.other,h.id]),/OWNER_IMMUTABLE/);
  await db.query('update history set submission_note=$1 where id=$2',['Dış işlem',h.id]);
  const revision=(await db.query('select * from history_revisions')).rows[0];assert.equal(revision.action,'external_update');assert.equal(revision.actor_id,null);
});
test('payload rejects forged types and limits privileges to explicit fields', () => {
  assert.throws(()=>cleanPayload({correctedText:{text:'X'}}),/INVALID_CONTENT/);
  assert.throws(()=>cleanPayload({tags:['Etiket',42]}),/INVALID_TAGS/);
  assert.deepEqual(cleanPayload({user_id:ids.other,role:'super_admin',questionText:'Soru?\r\n',tags:['İman','İman']}),{questionText:'Soru?\n',tags:['İman']});
});

test('member-facing statuses hide management queue vocabulary', () => {
  assert.equal(memberDisplayStatus('taslak'),'Taslak');
  assert.equal(memberDisplayStatus('geri_gonderildi'),'Geri gönderildi');
  assert.equal(memberDisplayStatus('bekliyor'),'Onaya gönderildi');
  assert.equal(memberDisplayStatus('teyit_bekliyor'),'Teyit bekliyor');
  assert.equal(memberDisplayStatus('dergah_sorulari'),'Dergah soruları');
  assert.equal(memberDisplayStatus('konferanslar'),'Konferanslar');
  assert.equal(memberDisplayStatus('onaylandi'),'Onaylandı');
  assert.equal(memberDisplayStatus('reddedildi'),'Reddedildi');
  assert.equal(memberDisplayStatus('arsivlendi'),'Arşivlendi');
});

test('review queue hides legacy split chunk drafts that detail pages reject', async () => {
  const normal=await seed('user','taslak','Gerçek taslak?','Gerçek cevap.');
  const chunk=(await db.query(`insert into history(user_id,name,username,filename,status,question_text,corrected_text,original_text,tags)
    values($1,'user','user','Metin Girişi - Parça 1/2','taslak','','Parça cevap.','Parça kaynak.','["Takva"]') returning *`,[ids.user])).rows[0];
  assert.equal(canReadRecord({id:ids.user,role:'user'},chunk,'member'),false);
  const rows=(await db.query('select id from review_history_queue order by created_at desc')).rows.map(row=>row.id);
  assert.ok(rows.includes(normal.id));
  assert.ok(!rows.includes(chunk.id));
});

test('approval queue derives last submission, not creation, save, moderation or reanalysis time', async () => {
  let h=await seed();
  const unsent=(await db.query('select * from review_history_queue where id=$1',[h.id])).rows[0];
  assert.equal(unsent.submitted_at,null);
  assert.equal(unsent.approval_sort_at.getTime(),h.created_at.getTime());
  h=await change(h,'user','member','submit');
  const first=(await db.query('select * from review_history_queue where id=$1',[h.id])).rows[0];
  assert.equal(first.submitted_by,ids.user);
  assert.equal(first.submitted_at.getTime(),Date.parse(h.updated_at));
  assert.equal(first.queue_sort_at.getTime(),first.submitted_at.getTime());
  h=await change(h,'admin','management','save',{submissionNote:'Yönetici kontrolü'});
  let row=(await db.query('select * from review_history_queue where id=$1',[h.id])).rows[0];
  assert.equal(row.submitted_at.getTime(),first.submitted_at.getTime());
  assert.equal(row.queue_sort_at.getTime(),first.submitted_at.getTime());
  h=await change(h,'admin','management','return',{note:'Kaynak kontrolü'});
  h=await change(h,'user','member','reanalyze',{correctedText:h.corrected_text,analysisInput:'Test'});
  row=(await db.query('select * from review_history_queue where id=$1',[h.id])).rows[0];
  assert.equal(row.submitted_at.getTime(),first.submitted_at.getTime());
  assert.equal(row.queue_sort_at.getTime(),Date.parse(h.updated_at));
  h=await change(h,'user','member','submit');
  row=(await db.query('select * from review_history_queue where id=$1',[h.id])).rows[0];
  assert.equal(row.submitted_at.getTime(),Date.parse(h.updated_at));
  assert.ok(row.submitted_at.getTime()>first.submitted_at.getTime());
  assert.equal(row.queue_sort_at.getTime(),row.submitted_at.getTime());
  const before=await db.query('select * from history order by id');
  const revisions=await db.query('select count(*)::int as n from history_revisions');
  await db.exec('set role service_role');
  assert.equal((await db.query('select * from review_history_queue')).rows.length,1);
  assert.equal((await db.query("select has_table_privilege('service_role','public.review_history_queue','UPDATE') as allowed")).rows[0].allowed,false);
  await assert.rejects(db.query("update review_history_queue set question_text='Changed' where id=$1",[h.id]),/permission denied|cannot update view/);
  await db.exec('reset role');
  assert.deepEqual((await db.query('select * from history order by id')).rows,before.rows);
  assert.deepEqual((await db.query('select count(*)::int as n from history_revisions')).rows,revisions.rows);
});

test('legacy submission logs and new revisions merge without duplicate rows or unrelated events', async () => {
  const h=await seed('user','bekliyor');
  const log=async(action,time,actor=ids.user,target='history')=>db.query(`insert into admin_action_log
    (action,target_type,target_id,created_at,actor_user_id) values($1,$2,$3,$4,$5)`,[action,target,h.id,time,actor]);
  await log('approval.submitted','2026-08-20T10:00:00Z');
  await log('approval.submitted','2026-08-20T11:00:00Z');
  await log('approval.content_updated','2026-08-21T10:00:00Z');
  await log('approval.submitted','2026-08-22T10:00:00Z',ids.other,'other_target');
  let row=(await db.query('select * from review_history_queue')).rows[0];
  assert.equal(row.submitted_at.toISOString(),'2026-08-20T11:00:00.000Z');
  assert.equal(row.submitted_by,ids.user);
  // The reviewer assigned to a returned item can be different from its immutable owner.
  await db.query(`insert into history_revisions(history_id,version,actor_id,action,before_data,after_data,created_at)
    values($1,1,$2,'submit','{}','{}','2026-08-23T10:00:00Z')`,[h.id,ids.other]);
  await log('review.submit','2026-08-23T10:00:00Z',ids.other);
  let rows=(await db.query('select * from review_history_queue')).rows;
  assert.equal(rows.length,1);
  assert.equal(rows[0].submitted_at.toISOString(),'2026-08-23T10:00:00.000Z');
  assert.equal(rows[0].submitted_by,ids.other);
  assert.equal(rows[0].user_id,ids.user);
  // An old open client may log a later submission through the legacy action.
  await log('approval.submitted','2026-08-24T10:00:00Z');
  row=(await db.query('select * from review_history_queue')).rows[0];
  assert.equal(row.submitted_at.toISOString(),'2026-08-24T10:00:00.000Z');
  assert.equal(row.submitted_by,ids.user);
});

test('member deletes only own unprotected draft, with one reversible revision', async () => {
  for (const owner of ['user','admin','super']) {
    const h=await seed(owner,'taslak',`${owner} taslağı?`);
    const actor={id:ids[owner],role:owner==='user'?'user':owner==='super'?'super_admin':'admin'};
    assert.ok(recordActions(actor,{...h,member_delete_protected:false},'member').includes('delete_draft'));
    assert.ok(!recordActions(actor,h,'member').includes('delete_draft')); // Unknown protection fails closed.
    await assert.rejects(change(h,'other','member','delete_draft'),/FORBIDDEN/);
    const deleted=await change(h,owner,'member','delete_draft');
    assert.equal(deleted.status,'copte');assert.equal(deleted.corrected_text,h.corrected_text);
    assert.equal(canReadRecord(actor,deleted,'member'),false);
    await assert.rejects(change(h,owner,'member','delete_draft'),/VERSION_CONFLICT/);
    const restored=await change(deleted,'admin','management','restore',{note:'Yanlışlıkla silinmiş.'});
    assert.equal(restored.status,'taslak');assert.equal(restored.original_text,h.original_text);
    assert.equal((await db.query('select count(*)::int as n from history_revisions where history_id=$1 and action=$2',[h.id,'delete_draft'])).rows[0].n,1);
  }
});

test('return protection survives submit, withdraw, metadata changes and external legacy updates', async () => {
  let h=await seed('user','bekliyor');
  h=await change(h,'admin','management','return',{note:'Ayet ve etiketi kontrol edin.'});
  await assert.rejects(change(h,'user','member','delete_draft'),/DRAFT_ONLY/);
  h=await change(h,'user','member','submit');
  h=await change(h,'user','member','withdraw');
  assert.equal(h.status,'geri_gonderildi');assert.equal(h.workflow_meta.returnNote,'Ayet ve etiketi kontrol edin.');
  h=(await db.query("update history set status='taslak',workflow_meta='{}' where id=$1 returning *",[h.id])).rows[0];
  assert.equal(h.workflow_meta.memberDeleteProtected,true);
  await assert.rejects(change(h,'user','member','delete_draft'),/DRAFT_PROTECTED/);
});

test('legacy return evidence, assignment and linked public rows protect drafts without a backfill', async () => {
  for(const evidence of ['revision','log','public','assigned']) {
    let h=await seed('user','taslak',evidence+'?');
    if(evidence==='revision')await db.query("insert into history_revisions(history_id,version,action,before_data,after_data) values($1,10,'withdraw','{\"status\":\"geri_gonderildi\"}','{}')",[h.id]);
    if(evidence==='log')await db.query("insert into admin_action_log(action,target_type,target_id,target_status_after) values('approval.returned','history',$1,'geri_gonderildi')",[h.id]);
    if(evidence==='public')await publish(h,'draft-protected');
    if(evidence==='assigned')h=(await db.query('update history set assignee_id=$2 where id=$1 returning *',[h.id,ids.user])).rows[0];
    const result=(await db.query('select * from review_draft_protections($1)',[[h.id]])).rows[0];
    assert.equal(result.member_delete_protected,true);
    await assert.rejects(change(h,'user','member','delete_draft'),/DRAFT_PROTECTED/);
    assert.equal((await db.query('select status from history where id=$1',[h.id])).rows[0].status,'taslak');
  }
});

test('ordinary submission may be withdrawn to a deletable draft', async () => {
  let h=await seed('user','taslak');
  h=await change(h,'user','member','submit');
  await assert.rejects(change(h,'user','member','delete_draft'),/DRAFT_ONLY/);
  h=await change(h,'user','member','withdraw');
  assert.equal(h.status,'taslak');
  assert.equal((await change(h,'user','member','delete_draft')).status,'copte');
});

test('member closes only duplicate-marked returned or draft records without deleting audit trail', async () => {
  let returned=await seed('user','geri_gonderildi','Mükerrer geri dönen?','Aynı cevap.');
  assert.ok(recordActions({id:ids.user,role:'user'},returned,'member').includes('close_duplicate'));
  await assert.rejects(change(returned,'user','member','close_duplicate'),/DUPLICATE_NOTE_REQUIRED/);
  returned=await change(returned,'user','member','save',{submissionNote:'MÜKERRER'});
  assert.ok(recordActions({id:ids.user,role:'user'},returned,'member').includes('close_duplicate'));
  const closed=await change(returned,'user','member','close_duplicate');
  assert.equal(closed.status,'copte');
  assert.equal(closed.workflow_meta.memberClosedDuplicate,true);
  assert.equal(closed.workflow_meta.statusBeforeTrash,'geri_gonderildi');
  assert.equal(canReadRecord({id:ids.user,role:'user'},closed,'member'),false);
  assert.equal(canReadRecord({id:ids.admin,role:'admin'},closed,'management'),true);
  assert.equal((await db.query("select count(*)::int as n from history_revisions where history_id=$1 and action='close_duplicate'",[returned.id])).rows[0].n,1);
  assert.equal((await db.query("select action_label from admin_action_log where target_id=$1 and action='review.close_duplicate'",[returned.id])).rows[0].action_label,'Mükerrer olarak kapattı');

  let draft=await seed('user','taslak','Mükerrer taslak?','Aynı cevap.');
  draft=await change(draft,'user','member','save',{submissionNote:'mükerrer'});
  assert.equal((await change(draft,'user','member','close_duplicate')).status,'copte');
});

test('managers can move records into special holding sections with audit notes', async () => {
  let dergah=await seed('user','bekliyor','Dergahla ilgili soru?','Cevap.');
  await assert.rejects(change(dergah,'admin','management','dergah'),/NOTE_REQUIRED/);
  dergah=await change(dergah,'admin','management','dergah',{note:'Dergah/kardeşlerimiz kapsamı nedeniyle ayrı tutuldu.'});
  assert.equal(dergah.status,'dergah_sorulari');
  assert.equal(dergah.workflow_meta.decisionNote,'Dergah/kardeşlerimiz kapsamı nedeniyle ayrı tutuldu.');
  assert.ok(recordActions({id:ids.super,role:'super_admin'},dergah,'management').includes('approve'));
  assert.ok(!recordActions({id:ids.admin,role:'admin'},dergah,'management').includes('dergah'));
  const dergahLog=(await db.query("select action_label,target_status_before,target_status_after from admin_action_log where target_id=$1 and action='review.dergah'",[dergah.id])).rows[0];
  assert.deepEqual(dergahLog,{action_label:'Dergah sorularına aldı',target_status_before:'bekliyor',target_status_after:'dergah_sorulari'});

  let conference=await seed('user','bekliyor','Uzun cevap?','Uzun konferans cevabı.');
  conference=await change(conference,'admin','management','conference',{note:'Cevap çok uzun; konferans/makale olarak ayrıca değerlendirilecek.'});
  assert.equal(conference.status,'konferanslar');
  assert.ok(recordActions({id:ids.super,role:'super_admin'},conference,'management').includes('pending'));
  assert.ok(!recordActions({id:ids.admin,role:'admin'},conference,'management').includes('conference'));
  assert.equal(memberDisplayStatus(conference.status),'Konferanslar');
});

test('repeated creation returns existing source, corrected text and respects scope and trash', async () => {
  let h=await seed('user','taslak');
  const insert=()=>db.query("insert into history(user_id,status,original_text,corrected_text) values($1,'taslak',$2,'Denetlenmiş sonuç') returning *",[ids.user,h.original_text]);
  await assert.rejects(insert(),error=>/ANALYSIS_EXISTS/.test(error.message)&&JSON.parse(error.detail).duplicateId===h.id);
  const match=async(actor,text)=>(await db.query('select review_find_existing_analysis($1,$2) as h',[ids[actor],text])).rows[0].h;
  assert.equal((await match('user',h.original_text)).id,h.id);
  assert.equal((await match('user',h.corrected_text)).id,h.id);
  assert.equal(await match('other',h.original_text),null);
  await change(h,'user','member','delete_draft');
  assert.equal(await match('user',h.original_text),null);
  const recreated=(await insert()).rows[0];assert.notEqual(recreated.id,h.id);
  const attempts=await Promise.allSettled([insert(),insert()]);assert.ok(attempts.every(r=>r.status==='rejected'));
  assert.equal((await db.query("select count(*)::int as n from history where status='taslak'")).rows[0].n,1);
});

test('new lookup and draft protection RPCs are private', async () => {
  for(const role of ['anon','authenticated']) {
    await db.exec(`set role ${role}`);
    await assert.rejects(db.query('select review_history_is_protected($1)',[ids.user]),/permission denied/);
    await assert.rejects(db.query('select * from review_draft_protections($1)',[[ids.user]]),/permission denied/);
    await assert.rejects(db.query('select review_find_existing_analysis($1,$2)',[ids.user,'Private source']),/permission denied/);
    await db.exec('reset role');
  }
});

test('two initial insert attempts keep one draft and return its identity for the retry', async () => {
  const insert=()=>db.query("insert into history(user_id,status,original_text,corrected_text) values($1,'taslak','Eşzamanlı kaynak','Yeni cevap') returning *",[ids.user]);
  const results=await Promise.allSettled([insert(),insert()]);
  const success=results.filter(r=>r.status==='fulfilled'),failure=results.filter(r=>r.status==='rejected');
  assert.equal(success.length,1);assert.equal(failure.length,1);
  assert.equal(JSON.parse(failure[0].reason.detail).duplicateId,success[0].value.rows[0].id);
  assert.equal((await db.query('select count(*)::int as n from history')).rows[0].n,1);
});
