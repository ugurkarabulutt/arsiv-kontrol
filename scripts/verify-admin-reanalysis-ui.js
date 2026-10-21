const fs = require('node:fs');
const path = require('node:path');
const assert = require('node:assert/strict');
const { chromium } = require('@playwright/test');
const { createFixture } = require('../test-support/review-fixture');

async function run() {
  const fixture = await createFixture({
    qualityGate: true,
    analyzeText: async text => ({
      correctedText: text.replace('Muhtrem', 'Muhterem'),
      score: 100,
      totalErrors: 0,
      categories: {}
    })
  });
  const record = (await fixture.db.query(
    `insert into history(user_id,name,status,question_text,corrected_text,original_text,tags,score)
     values($1,'Yönetim Denetim Testi','taslak','Muhtrem Hocam, dua nedir?',$2,$2,'["Dua"]',100)
     returning *`,
    [fixture.users[0].id, "Dua, Allah'a yönelmektir."]
  )).rows[0];
  const server = fixture.app.listen(0, '127.0.0.1');
  await new Promise(resolve => server.once('listening', resolve));
  const base = `http://127.0.0.1:${server.address().port}`;
  const memberHeaders = {
    'Content-Type': 'application/json',
    'X-Demo-Role': 'user',
    'X-Review-Workspace': 'member'
  };
  const initialCheckResponse = await fetch(base + `/api/review/${record.id}/reanalyze`, {
    method: 'POST',
    headers: memberHeaders,
    body: JSON.stringify({
      version: 0,
      questionText: record.question_text,
      correctedText: record.corrected_text
    })
  });
  assert.equal(initialCheckResponse.status, 200);
  const checked = (await initialCheckResponse.json()).history;
  const submitResponse = await fetch(base + `/api/review/${record.id}/action`, {
    method: 'POST',
    headers: memberHeaders,
    body: JSON.stringify({
      action: 'submit',
      version: checked.version,
      questionText: checked.questionText,
      correctedText: checked.correctedText,
      tags: checked.tags,
      submissionNote: 'Yönetim denetim testi'
    })
  });
  assert.equal(submitResponse.status, 200);
  const output = path.join(__dirname, '..', '.tmp-review-quality');
  fs.mkdirSync(output, { recursive: true });
  const browser = await chromium.launch({ headless: true });
  const errors = [];
  try {
    const context = await browser.newContext({
      viewport: { width: 1440, height: 1000 },
      extraHTTPHeaders: { 'X-Demo-Role': 'admin' }
    });
    const page = await context.newPage();
    page.on('pageerror', error => errors.push(error.message));
    await page.goto(base + '/admin');
    await page.waitForFunction(() => typeof ReviewWorkspace !== 'undefined' && me?.loggedIn);
    await page.evaluate(() => ReviewWorkspace.switchSpace('management'));
    await page.waitForFunction(() => ReviewWorkspace.workspace() === 'management');
    await page.evaluate(id => ReviewWorkspace.open(id), record.id);
    await page.locator('#rwQuestion').waitFor();
    await page.evaluate(() => {
      window.__adminActionPromptOpened = false;
      new MutationObserver(() => {
        if (document.querySelector('#systemConfirmModal.open')) window.__adminActionPromptOpened = true;
      }).observe(document.querySelector('#systemConfirmModal'), { attributes: true, attributeFilter: ['class'] });
    });

    const requestPromise = page.waitForRequest(request => request.url().endsWith(`/api/review/${record.id}/reanalyze`));
    const responsePromise = page.waitForResponse(response => response.url().endsWith(`/api/review/${record.id}/reanalyze`));
    await page.getByRole('button', { name: 'Soru ve Cevabı Denetle', exact: true }).click();
    const [request, response] = await Promise.all([requestPromise, responsePromise]);
    assert.equal(response.status(), 200);
    assert.equal(request.headers()['x-admin-action-note'], undefined);
    await page.waitForFunction(() => document.querySelector('#rwQualityStatus')?.textContent.includes('son hâli denetlendi'));
    assert.equal(await page.evaluate(() => window.__adminActionPromptOpened), false);
    assert.equal(await page.locator('#systemConfirmModal').evaluate(node => node.classList.contains('open')), false);
    const stored = (await fixture.db.query(
      `select h.status, h.version, h.workflow_meta,
        (select count(*)::int from history_revisions r where r.history_id=h.id and r.action='reanalyze') as checks
       from history h where h.id=$1`,
      [record.id]
    )).rows[0];
    assert.equal(stored.status, 'bekliyor');
    assert.equal(stored.version, 3);
    assert.equal(stored.checks, 2);
    assert.equal(stored.workflow_meta.analysisReceipt.scope, 'question_and_answer');
    await page.screenshot({ path: path.join(output, 'admin-reanalysis-no-note.png'), fullPage: true });
    await context.close();
    assert.deepEqual(errors, []);
    console.log(JSON.stringify({
      verified: true,
      browser: 'Chromium',
      role: 'admin',
      workspace: 'management',
      actionNotePromptOpened: false,
      requestStatus: 200,
      databaseRevision: 'reanalyze'
    }));
  } finally {
    await browser.close();
    await new Promise(resolve => server.close(resolve));
    await fixture.db.close();
  }
}

run().catch(error => {
  console.error(error);
  process.exitCode = 1;
});
