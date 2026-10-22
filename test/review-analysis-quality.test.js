const { test, before, after } = require('node:test');
const assert = require('node:assert/strict');
const { createFixture } = require('../test-support/review-fixture');
const { analysisHash, analysisState, analyzeReviewPair } = require('../review-analysis');
let fixture, server, base, lowScore = false, failAnswer = false;
const analyzed = [];
before(async () => {
  fixture = await createFixture({ qualityGate: true, analyzeText: async text => {
    analyzed.push(text);
    if (failAnswer && !text.endsWith('?')) throw new Error('Synthetic provider failure');
    return { correctedText: text.replace('Muhtrem', 'Muhterem'), score: lowScore ? 49 : 100, totalErrors: lowScore ? 13 : 0,
      categories: { imla: { count: lowScore ? 1 : 0, issues: lowScore ? [{ original: 'Muhtrem', fixed: 'Muhterem', rule: 'Hitap' }] : [] } } };
  } });
  server = fixture.app.listen(0, '127.0.0.1');
  await new Promise(resolve => server.once('listening', resolve));
  base = `http://127.0.0.1:${server.address().port}`;
});
after(async () => { await new Promise(resolve => server.close(resolve)); await fixture.db.close(); });
async function request(id, body, management = false, suffix = '/action') {
  const response = await fetch(base + '/api/review/' + id + suffix, { method: 'POST', headers: {
    'Content-Type': 'application/json', 'X-Demo-Role': management ? 'admin' : 'user', 'X-Review-Workspace': management ? 'management' : 'member'
  }, body: JSON.stringify(body) });
  return { status: response.status, body: await response.json() };
}
async function draft(answer = 'Kaynak cevap.') {
  return (await fixture.db.query(`insert into history(user_id,name,status,question_text,corrected_text,original_text,tags,score)
    values($1,'Kalite Testi','taslak',$2,$3,'Orijinal kaynak cevap. '||gen_random_uuid()::text,'["Takva"]',49) returning *`,
  [fixture.users[0].id, 'Muhtrem Hocam, soru ' + crypto.randomUUID() + '?', answer])).rows[0];
}
const checked = async (h, management = false) => request(h.id, { version: h.version, questionText: h.question_text, correctedText: h.corrected_text }, management, '/reanalyze');

test('long record uses bounded signed parts, commits only when complete and preserves version safety', async () => {
  const h = await draft('Uzun kaynak cevap.\n\n'.repeat(2500));
  const body={version:0,questionText:h.question_text,correctedText:h.corrected_text,analysisRequestId:crypto.randomUUID()};
  const legacy=await request(h.id,body,false,'/reanalyze');
  assert.equal(legacy.status,422);
  assert.equal(legacy.body.code,'ANALYSIS_PARTS_REQUIRED');
  const tokens=[];
  const first=await request(h.id,{...body,partIndex:0},false,'/reanalyze-part');
  assert.equal(first.status,200);
  tokens.push(first.body.token);
  for(let index=1;index<first.body.total;index++){
    const part=await request(h.id,{...body,partIndex:index},false,'/reanalyze-part');
    assert.equal(part.status,200);
    tokens.push(part.body.token);
  }
  const unchanged=(await fixture.db.query('select version,status from history where id=$1',[h.id])).rows[0];
  assert.equal(unchanged.version,0);
  assert.equal(unchanged.status,'taslak');
  const wrongActor=await request(h.id,{...body,analysisTokens:tokens},true,'/reanalyze');
  assert.equal(wrongActor.status,403);
  const wrongText=await request(h.id,{...body,correctedText:body.correctedText+'Ek',analysisTokens:tokens},false,'/reanalyze');
  assert.equal(wrongText.status,422);
  const complete=await request(h.id,{...body,analysisTokens:tokens},false,'/reanalyze');
  assert.equal(complete.status,200);
  assert.equal(complete.body.history.correctedText,h.corrected_text);
  assert.equal(complete.body.history.quality.state,'ready');
  const replay=await request(h.id,{...body,analysisTokens:tokens},false,'/reanalyze');
  assert.equal(replay.status,409);
  assert.ok(analyzed.every(text=>text.length<=8000));
});

test('low-score correction draft is preserved, cannot submit, passes only after the second paired check', async () => {
  const h = await draft();
  lowScore = true;
  const first = await checked(h);
  lowScore = false;
  assert.equal(first.status, 200);
  let row = first.body.history;
  assert.equal(row.quality.state, 'low_score');
  assert.match(row.workflow.analysisReceipt.requestId,/^[a-f0-9-]{36}$/);
  assert.equal(row.correctedText, h.corrected_text);
  assert.match(row.questionText, /^Muhterem/);
  assert.equal(row.workflow.analysisReceipt.question.categories.imla.issues[0].rule, 'Hitap');
  assert.equal(row.workflow.analysisInput.question,h.question_text);
  assert.equal(row.workflow.analysisInput.answer,h.corrected_text);
  const blocked = await request(h.id, { action: 'submit', version: row.version });
  assert.equal(blocked.status, 422);
  assert.equal(blocked.body.code, 'ANALYSIS_REQUIRED');
  const second = await request(h.id, { version: row.version }, false, '/reanalyze');
  assert.equal(second.status, 200);
  row = second.body.history;
  assert.equal(row.quality.state, 'ready');
  const sent = await request(h.id, { action: 'submit', version: row.version });
  assert.equal(sent.status, 200);
  const approved = await request(h.id, { action: 'approve', version: sent.body.history.version }, true);
  assert.equal(approved.status, 200);
  assert.ok(fixture.publishedRecords.includes(h.id));
  const revisions = (await fixture.db.query('select action,after_data from history_revisions where history_id=$1 order by version', [h.id])).rows;
  assert.deepEqual(revisions.map(r => r.action), ['reanalyze','reanalyze','submit','approve']);
  assert.equal(revisions[0].after_data.workflow_meta.analysisReceipt.answer.score, 49);
});

test('raw paste, forged receipt, legacy endpoint, direct DB transition and duplicate-clear cannot bypass verification', async () => {
  const h = await draft('');
  const fake = { version: 1, scope: 'question_and_answer', state: 'ready', questionHash: analysisHash(h.question_text), answerHash: analysisHash('Kaynak') };
  const blocked = await request(h.id, { action: 'submit', version: 0, correctedText: 'Kaynak', analysisReceipt: fake, score: 100 });
  assert.equal(blocked.status, 422);
  const legacy = await fetch(base + '/api/history/' + h.id + '/submit', { method: 'POST', headers: {
    'Content-Type':'application/json','X-Demo-Role':'user','X-Review-Workspace':'member'
  }, body: JSON.stringify({version:0,correctedText:'Kaynak',analysisReceipt:fake}) });
  assert.equal(legacy.status, 422);
  await assert.rejects(fixture.db.query("update history set status='bekliyor' where id=$1", [h.id]), /ANALYSIS_REQUIRED/);
  await fixture.db.query("update history set status='mukerrer_inceleme' where id=$1", [h.id]);
  const cleared = await request(h.id, {action:'duplicate_clear',version:1,note:'Mükerrer değil.'}, true);
  assert.equal(cleared.status, 422);
  assert.ok(!fixture.publishedRecords.includes(h.id));
});

test('question and answer edits each invalidate verification, while notes and tags do not', async () => {
  const h = await draft();
  const result = await checked(h);
  let row = result.body.history;
  assert.equal(row.quality.state, 'ready');
  const notes = await request(h.id, {action:'save',version:row.version,submissionNote:'Kontrol edildi.',tags:['Zikir']});
  assert.equal(notes.body.history.quality.state, 'ready');
  row = notes.body.history;
  for (const field of ['questionText','correctedText']) {
    const blocked = await request(h.id, {action:'submit',version:row.version,[field]:row[field]+' '});
    assert.equal(blocked.status,422);
  }
  const save = await request(h.id, {action:'save',version:row.version,correctedText:row.correctedText+' Yeni cümle.'});
  assert.equal(save.status,200);
  assert.equal(save.body.history.quality.state,'stale');
  const persisted = (await fixture.db.query('select workflow_meta from history where id=$1',[h.id])).rows[0];
  assert.equal(persisted.workflow_meta.analysisReceipt.state,'stale');
});

test('legacy empty answer requires explicit source use and provider failure leaves the record unchanged', async () => {
  const h = await draft('');
  const blank = await checked(h);
  assert.equal(blank.status,400);
  assert.equal(blank.body.code,'REQUIRED_FIELDS');
  const recovered = await request(h.id,{version:0,useOriginalAnswer:true},false,'/reanalyze');
  assert.equal(recovered.status,200);
  assert.equal(recovered.body.history.correctedText,h.original_text);
  const version = recovered.body.history.version;
  failAnswer = true;
  const failed = await request(h.id,{version},false,'/reanalyze');
  failAnswer = false;
  assert.equal(failed.status,500);
  const after = (await fixture.db.query('select version,corrected_text from history where id=$1',[h.id])).rows[0];
  assert.equal(after.version,version);
  assert.equal(after.corrected_text,h.original_text);
});

test('admin can check an existing pending record; concurrent edits still reject the old result', async () => {
  const h = fixture.rows.find(row=>row.status==='bekliyor'&&row.user_id===fixture.users[0].id);
  const blocked = await request(h.id,{action:'approve',version:0},true);
  assert.equal(blocked.status,422);
  const result = await checked(h,true);
  assert.equal(result.status,200);
  assert.equal(result.body.history.status,'bekliyor');
  const stale = await request(h.id,{version:0},true,'/reanalyze');
  assert.equal(stale.status,409);
  const list = await fetch(base+'/api/review/records?status=analysis_required',{headers:{'X-Demo-Role':'admin','X-Review-Workspace':'management'}});
  assert.equal(list.status,200);
  assert.ok(!(await list.json()).items.some(row=>row.id===h.id));
});

test('hashes match PostgreSQL for Turkish, Arabic, line breaks and significant whitespace', async () => {
  for(const text of ['Muhtrem Hocam?','نص عربي\r\nTürkçe\rson',' x ','x']) {
    const result=(await fixture.db.query('select review_analysis_hash($1) as hash',[text])).rows[0];
    assert.equal(result.hash,analysisHash(text));
  }
  assert.notEqual(analysisHash('x '),analysisHash('x'));
  assert.equal(analysisState({workflow_meta:{},question_text:'?',corrected_text:'Cevap'}).state,'required');
  await assert.rejects(analyzeReviewPair(async()=>({score:NaN,correctedText:'x'}),'?','Cevap'),/ANALYSIS_OUTPUT_EMPTY/);
});

test('old published trash restores into review and all new database helpers remain private', async () => {
  const h=await draft();
  await fixture.db.query(`update history set status='copte',workflow_meta='{"statusBeforeTrash":"onaylandi"}'::jsonb where id=$1`,[h.id]);
  const current=(await fixture.db.query('select version from history where id=$1',[h.id])).rows[0];
  const restored=await request(h.id,{action:'restore',version:current.version,note:'Eski kaydı geri yükle.'},true);
  assert.equal(restored.status,200);
  assert.equal(restored.body.history.status,'geri_gonderildi');
  assert.ok(!fixture.publishedRecords.includes(h.id));
  for(const role of ['anon','authenticated']) {
    for(const fn of ['public.review_analysis_hash(text)','public.review_assert_analysis(text,text,jsonb)','public.history_analysis_guard()']) {
      const result=(await fixture.db.query('select has_function_privilege($1,$2,\u0027EXECUTE\u0027) as allowed',[role,fn])).rows[0];
      assert.equal(result.allowed,false);
    }
  }
});
