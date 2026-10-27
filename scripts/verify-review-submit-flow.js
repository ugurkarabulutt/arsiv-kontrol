const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { chromium } = require('@playwright/test');
const { createFixture } = require('../test-support/review-fixture');

async function run() {
  const calls=[];
  let failOnce=false;
  const fixture=await createFixture({qualityGate:true,analyzeText:async text=>{
    calls.push(text);
    await new Promise(resolve=>setTimeout(resolve,350));
    if(failOnce&&text.includes('HATA_TEST')){failOnce=false;throw Object.assign(new Error('Synthetic timeout'),{statusCode:503});}
    return {correctedText:text.replace('Muhtrem','Muhterem'),score:100,totalErrors:0,categories:{}};
  }});
  const server=fixture.app.listen(0,'127.0.0.1');
  await new Promise(resolve=>server.once('listening',resolve));
  const base='http://127.0.0.1:'+server.address().port;
  const browser=await chromium.launch({headless:true});
  const errors=[],evidence=[];
  const output=path.join(__dirname,'..','.tmp-review-submit-flow');
  fs.mkdirSync(output,{recursive:true});
  async function draft(answer){
    return (await fixture.db.query("insert into history(user_id,name,status,question_text,corrected_text,original_text,tags,score) values($1,'Akış Testi','taslak',$2,$3,$3,'[\"Dua\"]',100) returning *",
      [fixture.users[0].id,'Muhtrem Hocam, dua '+crypto.randomUUID()+'?',answer])).rows[0];
  }
  async function open(page,row){
    await page.evaluate(async record=>{
      showTab('analiz');
      currentResult={id:record.id,correctedText:record.corrected_text,status:'taslak'};
      currentHistoryId=record.id;currentOriginalText=record.original_text;correctedText=record.corrected_text;
      document.getElementById('inputText').value=record.original_text;
      document.getElementById('resultsArea').innerHTML=renderApprovalSubmitPanel(currentResult);
    },row);
    await page.locator('#resultsArea').getByRole('button',{name:'Onaya Gönder',exact:true}).click();
    await page.locator('#rwQuestion').waitFor();
  }
  try{
    for(const width of [1440,390]){
      const context=await browser.newContext({viewport:{width,height:1000},extraHTTPHeaders:{'X-Demo-Role':'user'}});
      const page=await context.newPage();
      page.on('pageerror',error=>errors.push(error.message));
      await page.goto(base+'/admin');
      await page.waitForFunction(()=>typeof ReviewWorkspace!=='undefined'&&me?.loggedIn);
      const long='Görünüm '+width+'.\n\n'+'Paragraf bir. İkinci cümle.\n\n'.repeat(1800);
      const row=await draft(long);
      await open(page,row);
      await page.locator('#rwNote').fill('Ekip notu.');
      await page.locator('#detailModal').getByRole('button',{name:'Onaya Gönder',exact:true}).click();
      await page.locator('#rwDetailMessage.rw-processing').waitFor();
      assert.equal(await page.locator('#rwAnswer').isDisabled(),true);
      assert.equal(await page.locator('#detailModal [data-rw-active]').count(),1);
      await page.screenshot({path:path.join(output,'progress-'+width+'.png'),fullPage:true});
      await page.locator('.rw-submit-success').waitFor({timeout:30000});
      assert.equal(await page.locator('#inputText').inputValue(),'');
      assert.match(await page.locator('#resultsArea').innerText(),/Onay kuyruğuna alındı/);
      const stored=(await fixture.db.query('select * from history where id=$1',[row.id])).rows[0];
      assert.equal(stored.status,'bekliyor');
      assert.equal(stored.corrected_text,long);
      assert.equal(stored.submission_note,'Ekip notu.');
      assert.match(stored.question_text,/^Muhterem/);
      await page.screenshot({path:path.join(output,'submitted-'+width+'.png'),fullPage:true});
      await page.locator('#detailModal').getByRole('button',{name:'Yeni Denetime Başla',exact:true}).click();
      await page.waitForFunction(()=>!document.querySelector('#detailModal').classList.contains('open'));
      assert.equal(await page.locator('#inputText').inputValue(),'');
      assert.equal(await page.evaluate(()=>currentResult),null);
      await page.locator('#inputText').fill('İkinci soru için yeni metin.');
      assert.equal(await page.locator('#inputText').inputValue(),'İkinci soru için yeni metin.');
      evidence.push({width,status:stored.status,longCharacters:long.length,newAnalysis:true});
      await context.close();
    }
    const context=await browser.newContext({extraHTTPHeaders:{'X-Demo-Role':'user'}});
    const page=await context.newPage();
    page.on('pageerror',error=>errors.push(error.message));
    await page.goto(base+'/admin');
    await page.waitForFunction(()=>typeof ReviewWorkspace!=='undefined'&&me?.loggedIn);
    const row=await draft('HATA_TEST '+ 'Uzun cevap. '.repeat(2600));
    await open(page,row);
    failOnce=true;
    await page.locator('#detailModal').getByRole('button',{name:'Onaya Gönder',exact:true}).click();
    await page.waitForFunction(()=>document.querySelector('#rwDetailMessage.rw-error')?.textContent.includes('tamamlayamadı'));
    assert.equal(await page.locator('#rwAnswer').inputValue(),row.corrected_text);
    assert.equal((await fixture.db.query('select status from history where id=$1',[row.id])).rows[0].status,'taslak');
    const questionCalls=calls.filter(text=>text===row.question_text).length;
    await page.locator('#detailModal').getByRole('button',{name:'Onaya Gönder',exact:true}).click();
    await page.locator('.rw-submit-success').waitFor({timeout:30000});
    assert.equal(calls.filter(text=>text===row.question_text).length,questionCalls);
    await page.locator('#detailModal').getByRole('button',{name:'Kapat',exact:true}).click();
    assert.match(await page.locator('#resultsArea').innerText(),/Yeni Denetime Başla/);
    evidence.push({retryPreservesText:true,completedPartsReused:true,closeShowsSuccess:true});
    await context.close();
    const adminMember=await browser.newContext({viewport:{width:390,height:900},extraHTTPHeaders:{'X-Demo-Role':'admin'}});
    const adminMemberPage=await adminMember.newPage();
    adminMemberPage.on('pageerror',error=>errors.push(error.message));
    await adminMemberPage.goto(base+'/admin');
    await adminMemberPage.waitForFunction(()=>typeof ReviewWorkspace!=='undefined'&&me?.loggedIn);
    assert.equal(await adminMemberPage.evaluate(()=>ReviewWorkspace.workspace()),'member');
    const adminUser=fixture.users.find(user=>user.role==='admin');
    const adminMemberRow=(await fixture.db.query("insert into history(user_id,name,status,question_text,corrected_text,original_text,tags,score) values($1,'Admin Ekip Akışı','taslak',$2,$3,$3,'[\"Dua\"]',100) returning *",
      [adminUser.id,'Muhterem Hocam, ekip alanı sade mi?','Ekip alanında yalnız ekip işlemleri görünmelidir.'])).rows[0];
    await adminMemberPage.evaluate(id=>ReviewWorkspace.open(id),adminMemberRow.id);
    await adminMemberPage.locator('#rwQuestion').waitFor();
    assert.equal(await adminMemberPage.getByRole('button',{name:'Onaya Gönder',exact:true}).isVisible(),true);
    for(const label of ['Onayla','Düzeltmeye Gönder','Reddet','Teyide Al','Dergah Sorularına Al','Konferanslara Al','Arşivle','Çöpe Taşı']){
      assert.equal(await adminMemberPage.getByRole('button',{name:label,exact:true}).count(),0);
    }
    assert.equal(await adminMemberPage.getByRole('button',{name:'Kaydet',exact:true}).isVisible(),false);
    assert.equal(await adminMemberPage.getByRole('button',{name:'Soru ve Cevabı Denetle',exact:true}).isVisible(),false);
    assert.match(await adminMemberPage.locator('.rw-member-submit-help').innerText(),/otomatik yapar/);
    await adminMemberPage.screenshot({path:path.join(output,'admin-member-primary-390.png'),fullPage:true});
    await adminMemberPage.locator('details.rw-more > summary').click();
    assert.equal(await adminMemberPage.getByRole('button',{name:'Kaydet',exact:true}).isVisible(),true);
    assert.equal(await adminMemberPage.getByRole('button',{name:'Soru ve Cevabı Denetle',exact:true}).isVisible(),true);
    assert.equal(await adminMemberPage.evaluate(()=>document.documentElement.scrollWidth<=window.innerWidth),true);
    await adminMemberPage.screenshot({path:path.join(output,'admin-member-options-390.png'),fullPage:true});
    await adminMemberPage.evaluate(()=>ReviewWorkspace.close(true));
    await adminMemberPage.locator('#hamburger').click();
    const adminQuestionNav=adminMemberPage.locator('.mobile-menu button.question-manager-only').filter({hasText:'Soru Talepleri'});
    assert.equal(await adminQuestionNav.isVisible(),true);
    await adminQuestionNav.click();
    await adminMemberPage.locator('[data-ops-view="publicQuestions"].archive-ops-section:not([hidden])').waitFor();
    assert.equal(await adminMemberPage.locator('#archivePublicQuestionList .archive-release-card').count(),1);
    assert.equal(await adminMemberPage.getByRole('button',{name:'Onaylıları Siteye Hazırla',exact:true}).isVisible(),false);
    const adminQuestionCapability=await adminMemberPage.evaluate(async()=>{
      const [questions,sync]=await Promise.all([
        fetch('/api/public-archive/question-submissions').then(r=>r.status),
        fetch('/api/public-archive/sync-status').then(r=>r.status)
      ]);
      return {questions,sync};
    });
    assert.deepEqual(adminQuestionCapability,{questions:200,sync:403});
    await adminMemberPage.screenshot({path:path.join(output,'admin-question-access-390.png'),fullPage:true});
    evidence.push({adminInMemberWorkspace:true,managementActionsHidden:true,optionalToolsPreserved:true,questionManagementVisible:true,questionListStatus:adminQuestionCapability.questions,forbiddenSyncStatus:adminQuestionCapability.sync});
    await adminMember.close();
    const questionManager=await browser.newContext({viewport:{width:390,height:900},extraHTTPHeaders:{'X-Demo-Role':'question_manager'}});
    const questionManagerPage=await questionManager.newPage();
    questionManagerPage.on('pageerror',error=>errors.push(error.message));
    await questionManagerPage.goto(base+'/admin');
    await questionManagerPage.waitForFunction(()=>typeof ReviewWorkspace!=='undefined'&&me?.role==='question_manager');
    await questionManagerPage.locator('#hamburger').click();
    const questionManagerNav=questionManagerPage.locator('.mobile-menu button.question-manager-only').filter({hasText:'Soru Talepleri'});
    assert.equal(await questionManagerNav.isVisible(),true);
    await questionManagerNav.click();
    await questionManagerPage.locator('[data-ops-view="publicQuestions"].archive-ops-section:not([hidden])').waitFor();
    assert.equal(await questionManagerPage.locator('#archivePublicQuestionList .archive-release-card').count(),1);
    assert.equal(await questionManagerPage.getByRole('button',{name:'Onaylıları Siteye Hazırla',exact:true}).isVisible(),false);
    for(const label of ['Dashboard','İş Panosu','Kullanıcılar','Kurallar','İçerik Kontrolü','E-posta Bülteni']){
      assert.equal(await questionManagerPage.getByRole('button',{name:label,exact:true}).evaluateAll(nodes=>nodes.filter(node=>!node.hidden&&getComputedStyle(node).display!=='none').length),0);
    }
    const capability=await questionManagerPage.evaluate(async()=>{
      const [questions,sync,users]=await Promise.all([
        fetch('/api/public-archive/question-submissions').then(r=>r.status),
        fetch('/api/public-archive/sync-status').then(r=>r.status),
        fetch('/api/users').then(r=>r.status)
      ]);
      return {questions,sync,users};
    });
    assert.deepEqual(capability,{questions:200,sync:403,users:403});
    await questionManagerPage.locator('#archivePublicQuestionList .archive-release-card').click();
    await questionManagerPage.locator('#archivePublicQuestionAnswer').fill('Hacet namazı dört rekât olarak kılınır.');
    await questionManagerPage.getByRole('button',{name:'Cevabı Kaydet ve Kullanıcıya Göster',exact:true}).click();
    await questionManagerPage.locator('#systemConfirmModal.open').waitFor();
    await questionManagerPage.locator('#systemConfirmInput').fill('Kullanıcı sorusu kaynak metne göre cevaplandı.');
    await questionManagerPage.getByRole('button',{name:'Notu Kaydet ve Devam Et',exact:true}).click();
    await questionManagerPage.getByText('Cevap kaydedildi',{exact:true}).waitFor();
    assert.match(await questionManagerPage.locator('#archivePublicQuestionDetail').innerText(),/Kullanıcıya gösterilen cevap/);
    assert.equal(await questionManagerPage.evaluate(()=>document.documentElement.scrollWidth<=window.innerWidth),true);
    await questionManagerPage.screenshot({path:path.join(output,'question-manager-390.png'),fullPage:true});
    evidence.push({questionManagerUi:true,questionWrite:true,questionListStatus:capability.questions,forbiddenSyncStatus:capability.sync,forbiddenUsersStatus:capability.users});
    await questionManager.close();
    const admin=await browser.newContext({extraHTTPHeaders:{'X-Demo-Role':'admin'}});
    const adminPage=await admin.newPage();
    adminPage.on('pageerror',error=>errors.push(error.message));
    await adminPage.goto(base+'/admin');
    await adminPage.waitForFunction(()=>typeof ReviewWorkspace!=='undefined'&&me?.loggedIn);
    await adminPage.evaluate(()=>ReviewWorkspace.switchSpace('management'));
    await adminPage.evaluate(id=>ReviewWorkspace.open(id),row.id);
    await adminPage.route('**/api/review/records?**',async route=>{
      await new Promise(resolve=>setTimeout(resolve,2500));
      try{await route.continue();}catch{}
    });
    await adminPage.getByRole('button',{name:'Soru ve Cevabı Denetle',exact:true}).click();
    await adminPage.waitForFunction(()=>document.querySelector('#rwDetailMessage')?.textContent.includes('Denetim tamamlandı'));
    await adminPage.getByRole('button',{name:'Kaydet',exact:true}).click();
    await adminPage.locator('#systemConfirmModal.open').waitFor({timeout:3000});
    await adminPage.locator('#systemConfirmInput').fill('Geciken liste yenilemesi sırasında kaydet testi.');
    await adminPage.getByRole('button',{name:'Notu Kaydet ve Devam Et',exact:true}).click();
    await adminPage.waitForFunction(()=>document.querySelector('#rwDetailMessage')?.textContent.includes('İşlem tamamlandı'));
    evidence.push({saveDuringSlowListRefresh:true});
    await adminPage.locator('#rwAnswer').fill(row.corrected_text+'\nYönetici düzeltmesi.');
    await adminPage.getByRole('button',{name:'Onayla',exact:true}).click();
    await adminPage.locator('#rwDetailMessage.rw-processing').waitFor();
    await adminPage.waitForFunction(()=>document.querySelector('#rwDetailMessage')?.textContent.includes('İşlem tamamlandı'));
    assert.equal(await adminPage.locator('#systemConfirmModal.open').count(),0);
    const approved=(await fixture.db.query('select status,corrected_text from history where id=$1',[row.id])).rows[0];
    assert.equal(approved.status,'onaylandi');
    assert.ok(approved.corrected_text.endsWith('Yönetici düzeltmesi.'));
    assert.ok(fixture.publishedRecords.includes(row.id));
    evidence.push({adminLongEditApproval:true,published:true,noTechnicalNote:true});
    await admin.close();
    assert.ok(calls.every(text=>text.length<=8000));
    assert.deepEqual(errors,[]);
    console.log(JSON.stringify({verified:true,evidence,analyzerCalls:calls.length,pageErrors:errors}));
  }finally{
    await browser.close();
    await new Promise(resolve=>server.close(resolve));
    await fixture.db.close();
  }
}
run().catch(error=>{console.error(error);process.exitCode=1;});
