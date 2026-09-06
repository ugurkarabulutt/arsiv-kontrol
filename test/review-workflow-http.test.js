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
  }
  const result=await request('/api/review/records?status=all','admin','management');assert.equal(result.data.count,65);assert.equal(result.data.items.length,25);
});
test('detail and legacy APIs refuse other owner in member workspace',async()=>{
  const h=fixture.rows.find(row=>row.user_id===fixture.users[0].id);
  assert.equal((await request('/api/review/'+h.id)).status,404);
  assert.equal((await request('/api/history/'+h.id)).status,404);
  assert.equal((await request('/api/review/'+h.id,'admin','management')).status,200);
});
test('old mutation endpoint requires version and cannot bypass role/approval safeguards',async()=>{
  const h=fixture.rows.find(row=>row.user_id===fixture.users[1].id&&row.status==='geri_gonderildi');
  assert.equal((await request(`/api/history/${h.id}/submit`,'admin','member',{})).status,409);
  const saved=await request(`/api/history/${h.id}/submit`,'admin','member',{version:0});assert.equal(saved.status,200);assert.equal(saved.data.version,1);
  assert.equal((await request(`/api/history/${h.id}/approve`,'admin','management',{version:1})).status,403);
  assert.equal((await request('/api/history/submit-merged','admin','member',{sourceIds:[h.id]})).status,409);
});
test('manual action cannot masquerade as completed reanalysis',async()=>{
  const h=fixture.rows.find(row=>row.user_id===fixture.users[0].id&&row.status==='geri_gonderildi');
  const result=await request(`/api/review/${h.id}/action`,'user','member',{version:0,action:'reanalyze',correctedText:'Fake AI'});assert.equal(result.status,400);
  const actual=await request(`/api/review/${h.id}/reanalyze`,'user','member',{version:0,correctedText:h.corrected_text});assert.equal(actual.status,200);assert.equal(actual.data.history.version,1);
});
test('all inline and external admin scripts parse, feature routing cannot fall through legacy writes',()=>{
  const root=path.join(__dirname,'..');const html=fs.readFileSync(path.join(root,'index.html'),'utf8');
  for(const match of html.matchAll(/<script>([\s\S]*?)<\/script>/g))new vm.Script(match[1]);
  new vm.Script(fs.readFileSync(path.join(root,'review-workspace.js'),'utf8'));
  const source=fs.readFileSync(path.join(root,'server.js'),'utf8');
  assert.ok(source.indexOf("app.use('/api/history', auth, review.legacy)")<source.indexOf("app.post('/api/history/:id/approve'"));
  assert.match(source,/ADMIN_REVIEW_WORKSPACES_ENABLED = process.env.ADMIN_REVIEW_WORKSPACES_ENABLED === '1'/);
});
