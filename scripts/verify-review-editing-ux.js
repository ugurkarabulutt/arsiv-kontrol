const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { chromium } = require('@playwright/test');
const { createFixture } = require('../test-support/review-fixture');

async function run() {
  const fixture = await createFixture({ qualityGate: true });
  const server = fixture.app.listen(0, '127.0.0.1');
  await new Promise(resolve => server.once('listening', resolve));
  const base = `http://127.0.0.1:${server.address().port}`;
  const browser = await chromium.launch({ headless: true });
  const errors = [];
  const evidence = [];
  const output = path.join(__dirname, '..', '.tmp-review-editing-ux');
  fs.mkdirSync(output, { recursive: true });

  try {
    for (const width of [1440, 390]) {
      const context = await browser.newContext({
        viewport: { width, height: 900 },
        extraHTTPHeaders: { 'X-Demo-Role': 'user' }
      });
      await context.grantPermissions(['clipboard-read', 'clipboard-write'], { origin: base });
      const page = await context.newPage();
      page.on('pageerror', error => errors.push(`${width}: ${error.message}`));
      await page.goto(base + '/admin');
      await page.waitForFunction(() => typeof ReviewWorkspace !== 'undefined' && me?.loggedIn);

      const longText = 'Uzun metin başlangıcı.\n\n' + 'Bir cümle daha. İkinci cümle.\n'.repeat(1700);
      const caret = Math.floor(longText.length / 2);
      const editing = await page.evaluate(({ text, caret }) => {
        const input = document.getElementById('inputText');
        input.value = text;
        handleTextInput();
        input.focus({ preventScroll: true });
        input.scrollTop = Math.floor(input.scrollHeight / 2);
        input.setSelectionRange(caret, caret);
        window.scrollTo(0, Math.min(120, document.documentElement.scrollHeight - innerHeight));
        const pageScrollBefore = window.scrollY;
        const inputScrollBefore = input.scrollTop;
        input.setRangeText('X', caret, caret, 'end');
        input.dispatchEvent(new Event('input', { bubbles: true }));
        return {
          pageScrollBefore,
          pageScrollAfter: window.scrollY,
          inputScrollBefore,
          inputScrollAfter: input.scrollTop,
          selectionStart: input.selectionStart,
          selectionEnd: input.selectionEnd,
          height: input.getBoundingClientRect().height,
          maxHeight: Math.max(180, Math.min(Math.round(innerHeight * .62), 720)),
          overflowY: getComputedStyle(input).overflowY
        };
      }, { text: longText, caret });
      assert.equal(editing.selectionStart, caret + 1);
      assert.equal(editing.selectionEnd, caret + 1);
      assert.ok(Math.abs(editing.pageScrollAfter - editing.pageScrollBefore) <= 1);
      assert.ok(Math.abs(editing.inputScrollAfter - editing.inputScrollBefore) <= 2);
      assert.ok(editing.height <= editing.maxHeight + 2);
      assert.equal(editing.overflowY, 'auto');

      const unique = crypto.randomUUID();
      const row = (await fixture.db.query(
        "insert into history(user_id,name,status,question_text,corrected_text,original_text,tags,score) values($1,'Düzenleme UX','taslak',$2,$3,$4,'[\"Dua\"]',92) returning *",
        [fixture.users[0].id, `Muhterem Hocam, dua nedir? ${unique}`, 'Düzeltilmiş cevap metni.', `Duzeltilmis cevap metni. ${unique}`]
      )).rows[0];
      await page.evaluate(record => {
        currentOriginalText = record.original_text;
        correctedText = record.corrected_text;
        currentHistoryId = record.id;
        renderResults({
          id: record.id,
          status: record.status,
          correctedText: record.corrected_text,
          score: record.score,
          totalErrors: 1,
          categories: { sozluk: { count: 1, issues: [{ original: 'Duzeltilmis', fixed: 'Düzeltilmiş', rule: 'İmla' }] } }
        }, document.getElementById('resultsArea'));
      }, row);

      assert.equal(await page.locator('#resultsArea .compare-panel').count(), 1);
      assert.equal(await page.locator('#resultsArea .corrected-body-wrap').count(), 0);
      assert.equal(await page.locator('#resultsArea .corrected-body').count(), 0);
      assert.equal(await page.locator('#resultsArea').getByRole('button', { name: 'Onaya Gönder', exact: true }).count(), 1);
      await page.locator('#resultsArea').getByRole('button', { name: 'Onaya Gönder', exact: true }).click();
      await page.locator('#rwAnswer').waitFor();
      assert.equal(await page.locator('#rwAnswer').isEditable(), true);
      await page.locator('#rwAnswer').fill('Son kontrolde düzenlenen cevap.');
      await page.getByRole('button', { name: 'Cevabı Kopyala', exact: true }).click();
      await page.getByRole('button', { name: 'Kopyalandı', exact: true }).waitFor();
      assert.equal(await page.evaluate(() => navigator.clipboard.readText()), 'Son kontrolde düzenlenen cevap.');
      assert.equal(await page.getByText('Kaynak ve işlem geçmişi', { exact: true }).count(), 1);
      assert.equal(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth), true);
      await page.screenshot({ path: path.join(output, `review-editing-${width}.png`), fullPage: true });
      evidence.push({ width, editing, comparePanels: 1, duplicateCorrectedBodies: 0, finalAnswerEditable: true, copyVerified: true });
      await context.close();
    }
    assert.deepEqual(errors, []);
    console.log(JSON.stringify({ verified: true, evidence, pageErrors: errors }));
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
