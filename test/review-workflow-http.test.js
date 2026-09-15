const {test,before,after}=require('node:test');
const assert=require('node:assert/strict');
const fs=require('node:fs');
const path=require('node:path');
const vm=require('node:vm');
const {createFixture}=require('../test-support/review-fixture');
let fixture,server,base;
before(async()=>{fixture=await createFixture();server=fixture.app.listen(0,'127.0.0.1');await new Promise(resolve=>server.once('listening',resolve));base=`http://127.0.0.1:${server.address().port}`;});
after(async()=>{await new Promise(resolve=>server.close(resolve));await fixture.db.close();});
async function request(path,role='admin',workspace='member',body){const r=await fetch(base+path,{method:body?'POST':'GET',headers:{'Content-Type':'application/json','X-Demo-Role':role,'X-Review-Workspace':workspace},body:body?JSON.stringify(body):undefined});return {status:r.status,data:await r.json()};}
test('member listing is scoped for admin and super admin, management lists team',async()=>{
  for(const role of ['user','admin','super_admin']){
    const result=await request('/api/review/records',role);assert.equal(result.status,200);
    assert.ok(result.data.items.every(row=>row.userId===fixture.users.find(u=>u.role===role).id));
    assert.ok(result.data.items.every(row=>['Taslak','Geri gönderildi','Onaya gönderildi','Teyit bekliyor','Onaylandı','Reddedildi','Arşivlendi'].includes(row.displayStatus)));
  }
  assert.equal((await request('/api/review/records?status=teyit_bekliyor','user','member')).status,409);
  const result=await request('/api/review/records?status=all','admin','management');assert.equal(result.data.count,65);assert.equal(result.data.items.length,25);
});
test('detail and legacy APIs refuse other owner in member workspace',async()=>{
  const h=fixture.rows.find(row=>row.user_id===fixture.users[0].id);
  assert.equal((await request('/api/review/'+h.id)).status,404);
  assert.equal((await request('/api/history/'+h.id)).status,404);
  assert.equal((await request('/api/review/'+h.id,'admin','management')).status,200);
});
test('legacy split chunk drafts never appear as editable member drafts',async()=>{
  const chunk=(await fixture.db.query(`insert into history(user_id,name,status,filename,question_text,corrected_text,original_text,tags)
    values($1,'Parça Testi','taslak','Metin Girişi - Parça 1/2','','Ara parça cevabı.','Ara parça kaynak.','["Takva"]') returning *`,[fixture.users[0].id])).rows[0];
  const list=await request('/api/review/records?status=todo&q=Parça%20Testi','user','member');
  assert.equal(list.status,200);
  assert.equal(list.data.count,0);
  assert.equal((await request('/api/review/'+chunk.id,'user','member')).status,404);
});
test('old mutation endpoint requires version and cannot bypass role/approval safeguards',async()=>{
  const h=fixture.rows.find(row=>row.user_id===fixture.users[1].id&&row.status==='geri_gonderildi');
  assert.equal((await request(`/api/history/${h.id}/submit`,'admin','member',{})).status,409);
  const saved=await request(`/api/history/${h.id}/submit`,'admin','member',{version:0});assert.equal(saved.status,200);assert.equal(saved.data.version,1);
  assert.equal((await request(`/api/history/${h.id}/approve`,'admin','management',{version:1})).status,403);
  assert.equal((await request('/api/history/submit-merged','admin','member',{sourceIds:[h.id]})).status,409);
});
test('old submit endpoint is idempotent for records already past draft',async()=>{
  const pending=fixture.rows.find(row=>row.user_id===fixture.users[0].id&&row.status==='bekliyor');
  const pendingRetry=await request(`/api/history/${pending.id}/submit`,'user','member',{version:0,questionText:'Eski sekmeden soru?',correctedText:pending.corrected_text,tags:['Takva']});
  assert.equal(pendingRetry.status,200);
  assert.equal(pendingRetry.data.alreadySubmitted,true);
  assert.equal(pendingRetry.data.status,'bekliyor');

  const approved=(await fixture.db.query(`insert into history(user_id,name,status,question_text,corrected_text,original_text,tags,version)
    values($1,'Ekip Örnek','onaylandi','Onaylı eski soru?','Onaylı cevap.','Kaynak metin.','["Takva"]',3) returning *`,
    [fixture.users[0].id])).rows[0];
  const approvedRetry=await request(`/api/history/${approved.id}/submit`,'user','member',{version:0,questionText:'Eski sekmeden değiştirilmiş soru?',correctedText:'Değişmemeli.',tags:['Yeni']});
  assert.equal(approvedRetry.status,200);
  assert.equal(approvedRetry.data.alreadySubmitted,true);
  assert.equal(approvedRetry.data.status,'onaylandi');
  assert.equal(approvedRetry.data.questionText,'Onaylı eski soru?');
});
test('manual action cannot masquerade as completed reanalysis',async()=>{
  const h=fixture.rows.find(row=>row.user_id===fixture.users[0].id&&row.status==='geri_gonderildi');
  const result=await request(`/api/review/${h.id}/action`,'user','member',{version:0,action:'reanalyze',correctedText:'Fake AI'});assert.equal(result.status,400);
  const actual=await request(`/api/review/${h.id}/reanalyze`,'user','member',{version:0,correctedText:h.corrected_text});assert.equal(actual.status,200);assert.equal(actual.data.history.version,1);
});
test('all inline and external admin scripts parse, feature routing cannot fall through legacy writes',()=>{
  const root=path.join(__dirname,'..');const html=fs.readFileSync(path.join(root,'index.html'),'utf8');
  for(const match of html.matchAll(/<script>([\s\S]*?)<\/script>/g))new vm.Script(match[1]);
  const workspaceScript=fs.readFileSync(path.join(root,'review-workspace.js'),'utf8');
  new vm.Script(workspaceScript);
  assert.match(workspaceScript,/todo: 'Düzenlenecekler'/);
  assert.match(workspaceScript,/close_duplicate: 'Mükerrer Olarak Kapat'/);
  assert.match(workspaceScript,/dergah_sorulari: 'Dergah Soruları'/);
  assert.match(workspaceScript,/conference: 'Konferanslara Al'/);
  assert.match(workspaceScript,/: \['todo','in_review','done'\]/);
  assert.doesNotMatch(workspaceScript,/: \['all','taslak','geri_gonderildi','bekliyor','onaylandi','reddedildi','teyit_bekliyor','arsivlendi'\]/);
  const source=fs.readFileSync(path.join(root,'server.js'),'utf8');
  assert.ok(source.indexOf("app.use('/api/history', auth, review.legacy)")<source.indexOf("app.post('/api/history/:id/approve'"));
  assert.match(source,/ADMIN_REVIEW_WORKSPACES_ENABLED = process.env.ADMIN_REVIEW_WORKSPACES_ENABLED === '1'/);
});

test('resubmitted old records lead the entire pending queue before pagination for both admin roles',async()=>{
  const owner=fixture.users[0];
  const inserted=[];
  try {
    for(let i=0;i<32;i++) {
      const h=(await fixture.db.query(`insert into history(user_id,name,status,question_text,corrected_text,tags,created_at)
        values($1,$2,'geri_gonderildi',$3,$4,'["İştiyak"]','2026-01-01T00:00:00Z') returning *`,
        [owner.id,'Sıra Testi Ekip',`Sıra testi ${i}?`,`Cevap ${i}.\n\nİkinci paragraf.`])).rows[0];
      inserted.push(h.id);
      const submitted=await request(`/api/review/${h.id}/action`,'user','member',{version:0,action:'submit'});
      assert.equal(submitted.status,200);
    }
    const newest=inserted.at(-1);
    for(const role of ['admin','super_admin','user']) {
      const space=role==='user'?'member':'management';
      const memberQuery='/api/review/records?status=in_review&q=Sıra%20Testi';
      const managerQuery='/api/review/records?status=bekliyor&q=Sıra%20Testi';
      const first=await request(space==='member'?memberQuery:managerQuery,role,space);
      assert.equal(first.status,200);assert.equal(first.data.count,32);
      assert.deepEqual(first.data.items.map(h=>h.id),inserted.slice().reverse().slice(0,25));
      const second=await request((space==='member'?memberQuery:managerQuery)+'&page=2',role,space);
      assert.deepEqual(second.data.items.map(h=>h.id),inserted.slice().reverse().slice(25));
      assert.equal(first.data.items[0].submittedBy,owner.id);
      assert.equal(first.data.items[0].submittedByName,owner.name);
      assert.ok(Date.parse(first.data.items[0].submittedAt)>Date.parse(first.data.items[0].createdAt));
    }
    let all=await request('/api/review/records','admin','management');
    assert.equal(all.data.items[0].id,newest);
    const before=await request(`/api/review/${inserted[0]}`,'admin','management');
    const saved=await request(`/api/review/${inserted[0]}/action`,'admin','management',{version:before.data.version,action:'save',submissionNote:'Sonradan düzenleme'});
    assert.equal(saved.status,200);
    all=await request('/api/review/records','admin','management');
    assert.equal(all.data.items[0].id,newest);
    assert.equal(all.data.items[0].correctedText,undefined); // List response must not expose full answers.
    const own=await request('/api/review/records?status=in_review&q=Sıra%20Testi','admin','member');
    assert.equal(own.data.count,0);
    const withdrawn=await request(`/api/review/${inserted[0]}/action`,'user','member',{version:saved.data.history.version,action:'withdraw'});
    assert.equal(withdrawn.status,200);
    const resubmitted=await request(`/api/review/${inserted[0]}/action`,'user','member',{version:withdrawn.data.history.version,action:'submit'});
    assert.equal(resubmitted.status,200);
    all=await request('/api/review/records','admin','management');
    assert.equal(all.data.items[0].id,inserted[0]);
  } finally {
    await fixture.db.query('delete from history_revisions where history_id=any($1::uuid[])',[inserted]);
    await fixture.db.query('delete from history where id=any($1::uuid[])',[inserted]);
  }
});
test('every non-pending list uses latest workflow activity and search remains server-wide',async()=>{
  const owner=fixture.users[0],inserted=[];
  try {
    const older=(await fixture.db.query(`insert into history(user_id,name,status,question_text,corrected_text,tags,created_at,updated_at)
      values($1,'Bihter Sıra Testi','teyit_bekliyor','Eski kayıt, yeni işlem?','Cevap.','["Takva"]','2026-01-01T00:00:00Z','2026-09-07T01:42:00Z') returning *`,[owner.id])).rows[0];
    const newer=(await fixture.db.query(`insert into history(user_id,name,status,question_text,corrected_text,tags,created_at,updated_at)
      values($1,'Başka Kişi','teyit_bekliyor','Yeni kayıt, eski işlem?','Cevap.','["Takva"]','2026-08-31T00:00:00Z','2026-09-06T23:47:00Z') returning *`,[owner.id])).rows[0];
    inserted.push(older.id,newer.id);
    const list=await request('/api/review/records?status=teyit_bekliyor&q=işlem','admin','management');
    assert.equal(list.status,200);assert.equal(list.data.count,2);
    assert.deepEqual(list.data.items.map(row=>row.id),[older.id,newer.id]);
    assert.equal(list.data.items[0].queueAt,'2026-09-07T01:42:00.000Z');
    const search=await request('/api/review/records?status=teyit_bekliyor&q=Bihter','admin','management');
    assert.equal(search.status,200);assert.equal(search.data.count,1);assert.equal(search.data.items[0].id,older.id);
  } finally {
    await fixture.db.query('delete from history_revisions where history_id=any($1::uuid[])',[inserted]);
    await fixture.db.query('delete from history where id=any($1::uuid[])',[inserted]);
  }
});

test('duplicate response links only a readable record and leaves submitted edits untouched',async()=>{
  const seed=async(owner,status,question)=> (await fixture.db.query(`insert into history(user_id,name,status,question_text,corrected_text,original_text,tags)
    values($1,'Kopya Testi',$2,$3,'Birebir test cevabı.','Kaynak '||gen_random_uuid()::text,'["Takva"]') returning *`,[owner.id,status,question])).rows[0];
  const owner=fixture.users[0];
  const existing=await seed(owner,'bekliyor','Kopya bağlantısı?');
  const draft=await seed(owner,'taslak',existing.question_text);
  const result=await request(`/api/review/${draft.id}/action`,'user','member',{
    action:'submit',version:0,questionText:draft.question_text,correctedText:draft.corrected_text,tags:['Yeni etiket'],submissionNote:'Kaybolmamalı'
  });
  assert.equal(result.status,409);assert.equal(result.data.code,'EXACT_DUPLICATE');
  assert.deepEqual(result.data.duplicate,{id:existing.id,displayStatus:'Onaya gönderildi'});
  const after=(await fixture.db.query('select * from history where id=$1',[draft.id])).rows[0];
  assert.equal(after.version,0);assert.deepEqual(after.tags,['Takva']);
  const privateExisting=await seed(fixture.users[1],'onaylandi','Özel kayıt bağlantısı?');
  const privateCopy=await seed(owner,'taslak',privateExisting.question_text);
  const hidden=await request(`/api/review/${privateCopy.id}/action`,'user','member',{action:'submit',version:0});
  assert.equal(hidden.status,409);assert.equal(hidden.data.duplicate,undefined);
  assert.ok(!JSON.stringify(hidden.data).includes(privateExisting.id));
});

test('draft deletion is available in list and detail; repeat calls make only one transition',async()=>{
  const h=(await fixture.db.query(`insert into history(user_id,name,status,question_text,original_text,corrected_text,tags)
    values($1,'Silme Testi','taslak','Silinecek taslak?','Benzersiz silme kaynağı','Silme cevabı','["Takva"]') returning *`,[fixture.users[0].id])).rows[0];
  const list=await request('/api/review/records?status=todo&q=Silme%20Testi','user');
  assert.equal(list.data.items[0].displayStatus,'Taslak');assert.ok(list.data.items[0].allowedActions.includes('delete_draft'));
  const detail=await request('/api/review/'+h.id,'user');assert.ok(detail.data.allowedActions.includes('delete_draft'));
  const attempts=await Promise.all([1,2].map(()=>request(`/api/review/${h.id}/action`,'user','member',{action:'delete_draft',version:0})));
  assert.deepEqual(attempts.map(r=>r.status).sort(),[200,409]);
  assert.equal((await request('/api/review/'+h.id,'user')).status,404);
  const trash=await request('/api/review/records?status=copte&q=Silme%20Testi','admin','management');
  assert.equal(trash.data.items[0].id,h.id);
  assert.equal((await fixture.db.query('select count(*)::int as n from history_revisions where history_id=$1',[h.id])).rows[0].n,1);
});

test('duplicate-marked member records can be cleaned from active list without hard delete',async()=>{
  const h=(await fixture.db.query(`insert into history(user_id,name,status,question_text,original_text,corrected_text,tags,submission_note)
    values($1,'Mükerrer Test','geri_gonderildi','Mükerrer temizlenecek soru?','Kaynak','Cevap','["Takva"]','MÜKERRER') returning *`,[fixture.users[0].id])).rows[0];
  const list=await request('/api/review/records?status=todo&q=Mükerrer%20temizlenecek','user');
  assert.equal(list.status,200);assert.equal(list.data.count,1);assert.ok(list.data.items[0].allowedActions.includes('close_duplicate'));
  const closed=await request(`/api/review/${h.id}/action`,'user','member',{action:'close_duplicate',version:0});
  assert.equal(closed.status,200);assert.equal(closed.data.history.status,'copte');
  assert.equal((await request('/api/review/'+h.id,'user')).status,404);
  const trash=await request('/api/review/records?status=copte&q=Mükerrer%20temizlenecek','admin','management');
  assert.equal(trash.status,200);assert.equal(trash.data.items[0].id,h.id);
});

test('management can filter and act on special holding sections',async()=>{
  const h=(await fixture.db.query(`insert into history(user_id,name,status,question_text,original_text,corrected_text,tags)
    values($1,'Dergah Test','bekliyor','Dergah sorusu ayrı dursun mu?','Kaynak','Cevap','["Takva"]') returning *`,[fixture.users[0].id])).rows[0];
  const moved=await request(`/api/review/${h.id}/action`,'admin','management',{action:'dergah',version:0,note:'Dergah/kardeşlerimiz kapsamı nedeniyle ayrı tutuldu.'});
  assert.equal(moved.status,200);assert.equal(moved.data.history.status,'dergah_sorulari');
  const list=await request('/api/review/records?status=dergah_sorulari&q=Dergah%20Test','admin','management');
  assert.equal(list.status,200);assert.equal(list.data.count,1);assert.equal(list.data.items[0].id,h.id);
  assert.ok(list.data.items[0].allowedActions.includes('pending'));
  assert.ok(!list.data.items[0].allowedActions.includes('dergah'));
});
