const fs = require('node:fs');
const path = require('node:path');
const assert = require('node:assert/strict');
const { chromium } = require('@playwright/test');
const { createFixture } = require('../test-support/review-fixture');

async function run() {
  let low = true;
  const fixture = await createFixture({ qualityGate: true, analyzeText: async text => ({
    correctedText: text.replace('Muhtrem', 'Muhterem'), score: low ? 49 : 100, totalErrors: low ? 13 : 0,
    categories: { imla: { count: low ? 1 : 0, issues: low ? [{ original:'Muhtrem',fixed:'Muhterem',rule:'Hitap yazımı' }] : [] } }
  }) });
  const h = (await fixture.db.query(`insert into history(user_id,name,status,question_text,corrected_text,original_text,tags,score)
    values($1,'Kalite Örneği','taslak','Muhtrem Hocam, dua nedir?','',$2,'["Dua"]',49) returning *`,[fixture.users[0].id,"Dua, Allah'a yönelmektir."])).rows[0];
  const server = fixture.app.listen(0,'127.0.0.1');
  await new Promise(resolve => server.once('listening',resolve));
  const base = `http://127.0.0.1:${server.address().port}`;
  const output = path.join(__dirname,'..','.tmp-review-quality');
  fs.mkdirSync(output,{recursive:true});
  const browser = await chromium.launch({headless:true});
  const errors = [];
  try {
    for(const [name,width,height] of [['mobile',390,844],['desktop',1440,1000]]) {
      const context = await browser.newContext({viewport:{width,height},extraHTTPHeaders:{'X-Demo-Role':'user'}});
      const page = await context.newPage();
      page.on('pageerror',error=>errors.push(error.message));
      await page.goto(base+'/admin');
      await page.waitForFunction(()=>typeof ReviewWorkspace!=='undefined' && typeof me!=='undefined' && me?.loggedIn);
      await page.evaluate(id=>ReviewWorkspace.open(id),h.id);
      await page.locator('#rwQuestion').waitFor();
      assert.equal(await page.locator('[data-rw-publish]').isDisabled(),name==='mobile');
      if(name==='mobile') {
        await page.locator('#rwUseSource').check();
        await page.getByRole('button',{name:'Soru ve Cevabı Denetle',exact:true}).click();
        await page.waitForFunction(()=>document.querySelector('#rwQualityStatus')?.textContent.includes('Düzeltme taslağı'));
        assert.equal(await page.locator('[data-rw-publish]').isDisabled(),true);
        assert.match(await page.locator('#rwQuestion').inputValue(),/^Muhterem/);
        assert.ok((await page.locator('#rwAnswer').inputValue()).length>0);
        await page.screenshot({path:path.join(output,'mobile-low-score.png'),fullPage:true});
        low = false;
        await page.route(base+'/api/review/'+h.id+'/reanalyze',async route=>{
          await route.fetch();
          await route.abort('failed');
        },{times:1});
        await page.getByRole('button',{name:'Soru ve Cevabı Denetle',exact:true}).click();
        await page.waitForFunction(()=>document.querySelector('#rwQualityStatus')?.textContent.includes('son hâli denetlendi'));
        await page.waitForFunction(()=>document.querySelector('#rwDetailMessage')?.textContent.includes('sonuç sunucudan doğrulandı'));
        assert.equal(await page.locator('[data-rw-publish]').isDisabled(),false);
        const answer = await page.locator('#rwAnswer').inputValue();
        await page.locator('#rwAnswer').fill(answer+' Yeni cümle.');
        assert.equal(await page.locator('[data-rw-publish]').isDisabled(),true);
        await page.locator('#rwAnswer').fill(answer);
        assert.equal(await page.locator('[data-rw-publish]').isDisabled(),false);
      }
      const overflow = await page.evaluate(()=>document.documentElement.scrollWidth>innerWidth);
      assert.equal(overflow,false);
      await page.screenshot({path:path.join(output,name+'-ready.png'),fullPage:true});
      if(name==='desktop') {
        await page.getByRole('button',{name:'Onaya Gönder',exact:true}).click();
        await page.waitForFunction(()=>document.querySelector('.rw-record-meta')?.textContent.includes('Onaya gönderildi'));
        const row=(await fixture.db.query('select status,workflow_meta from history where id=$1',[h.id])).rows[0];
        assert.equal(row.status,'bekliyor');
        assert.equal(row.workflow_meta.analysisReceipt.scope,'question_and_answer');
      }
      await context.close();
    }
    assert.deepEqual(errors,[]);
    console.log(JSON.stringify({verified:true,viewports:[390,1440],provider:'synthetic',database:'local PostgreSQL',screenshots:output}));
  } finally {
    await browser.close();
    await new Promise(resolve=>server.close(resolve));
    await fixture.db.close();
  }
}
run().catch(error=>{console.error(error);process.exitCode=1;});
