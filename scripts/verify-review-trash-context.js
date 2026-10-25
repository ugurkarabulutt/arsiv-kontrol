const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { chromium } = require('@playwright/test');
const { createFixture } = require('../test-support/review-fixture');

async function run(){
  const fixture=await createFixture({qualityGate:true});
  const row=(await fixture.db.query(`insert into history(user_id,name,status,question_text,original_text,corrected_text,tags)
    values($1,'Silinen Taslak Testi','taslak','Silinen taslak nasıl görünür?','Kaynak','Cevap','["Taslak"]') returning *`,[fixture.users[0].id])).rows[0];
  const server=fixture.app.listen(0,'127.0.0.1');
  await new Promise(resolve=>server.once('listening',resolve));
  const base=`http://127.0.0.1:${server.address().port}`;
  const deleted=await fetch(`${base}/api/review/${row.id}/action`,{
    method:'POST',headers:{'content-type':'application/json','X-Demo-Role':'user','X-Review-Workspace':'member'},
    body:JSON.stringify({action:'delete_draft',version:row.version})
  });
  assert.equal(deleted.status,200);
  const browser=await chromium.launch({headless:true});
  const errors=[];
  const output=path.join(__dirname,'..','.tmp-review-trash-context');
  fs.mkdirSync(output,{recursive:true});
  try{
    for(const width of [1440,390]){
      const context=await browser.newContext({viewport:{width,height:900},extraHTTPHeaders:{'X-Demo-Role':'admin'}});
      const page=await context.newPage();
      page.on('pageerror',error=>errors.push(`${width}: ${error.message}`));
      await page.goto(base+'/admin');
      await page.waitForFunction(()=>typeof ReviewWorkspace!=='undefined'&&me?.loggedIn);
      await page.evaluate(()=>ReviewWorkspace.switchSpace('management'));
      await page.evaluate(id=>ReviewWorkspace.open(id),row.id);
      const box=page.locator('.rw-trash-self-deleted');
      await box.waitFor();
      const copy=await box.innerText();
      assert.match(copy,/Kullanıcı tarafından silinen taslak/);
      assert.match(copy,/onaya gönderilmedi ve yönetici tarafından geri gönderilmedi/);
      assert.equal(copy.includes('Atılma sebebi: Diğer'),false);
      assert.equal(await page.locator('.rw-return').count(),0);
      assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth),true);
      await page.screenshot({path:path.join(output,`trash-context-${width}.png`),fullPage:true});
      await context.close();
    }
    const stored=(await fixture.db.query('select status,workflow_meta from history where id=$1',[row.id])).rows[0];
    assert.equal(stored.status,'copte');
    assert.equal(stored.workflow_meta.statusBeforeTrash,'taslak');
    assert.equal(stored.workflow_meta.trashNote,'Kullanıcı kendi taslağını sildi.');
    assert.deepEqual(errors,[]);
    console.log(JSON.stringify({verified:true,viewports:[1440,390],status:stored.status,statusBeforeTrash:stored.workflow_meta.statusBeforeTrash,pageErrors:errors}));
  }finally{
    await browser.close();
    await new Promise(resolve=>server.close(resolve));
    await fixture.db.close();
  }
}

run().catch(error=>{console.error(error);process.exitCode=1;});
