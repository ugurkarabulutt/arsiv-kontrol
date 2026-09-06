const {test,expect}=require('@playwright/test');
async function login(page,role='admin'){
  await page.context().addCookies([{name:'reviewDemoRole',value:role,url:'http://127.0.0.1:4317'}]);
  await page.goto('/admin');
  await expect(page.locator('#rwRows .rw-row').first()).toBeVisible();
}
async function selectSpace(page,value){
  const select=page.locator('[data-review-selector]:visible').first();
  await select.selectOption(value);
  await expect(page.locator('#rwRows')).toHaveAttribute('aria-busy','false');
}
test('admin sees own work, then independent management view, no mixed buttons',async({page})=>{
  const errors=[];page.on('pageerror',error=>errors.push(error.message));
  await login(page);
  await expect(page.locator('.rw-row .rw-meta')).not.toContainText(['Ekip Örnek']);
  await expect(page.locator('.side-link[data-tab="analiz"]')).toBeVisible();
  await expect(page.locator('.side-link[data-tab="onay"]')).toBeHidden();
  await selectSpace(page,'management');
  await expect(page.locator('.side-link[data-tab="analiz"]')).toBeHidden();
  await expect(page.locator('.side-link[data-tab="onay"]')).toBeVisible();
  await page.locator('#rwStatus').selectOption('geri_gonderildi');
  await expect(page.locator('#rwCount')).toHaveText('48 kayıt');
  await page.getByRole('button',{name:'Sonraki',exact:true}).click();
  await expect(page.locator('#rwPages')).toContainText('2 / 2');
  await page.locator('#rwSearch').fill('sorusu 17:');
  await expect(page.locator('#rwCount')).toHaveText('1 kayıt');
  await selectSpace(page,'member');await selectSpace(page,'management');
  await expect(page.locator('#rwSearch')).toHaveValue('sorusu 17:');
  await expect(page.locator('#rwRows')).toHaveCount(1);
  await page.screenshot({path:'.tmp-review-test-results/management-desktop.png',fullPage:true});
  expect(errors).toEqual([]);
});
test('returned Q/tags/answer/note edit together, save preserves line breaks, no cloned record',async({page})=>{
  await login(page);await page.locator('#rwStatus').selectOption('geri_gonderildi');
  await page.locator('.rw-open').first().click();
  await expect(page.locator('#rwAnswer')).toBeEditable();
  const id=await page.evaluate(()=>document.querySelector('.rw-record-meta').textContent.match(/No: (\w+)/)[1]);
  const answer='Türkçe karakterler: İ ı Ş ş Ğ ğ Ü ü.\n\nنص عربي\nMeal satırı.\n\nAçıklama.';
  await page.locator('#rwAnswer').fill(answer);await page.locator('#rwQuestion').fill('Tek ekranda kontrol sorusu?');
  await page.locator('#rwTags').fill('İman, Takva');await page.locator('#rwNote').fill('Soru, cevap ve etiket uyumlu.');
  await page.getByRole('button',{name:'Kaydet',exact:true}).click();
  await expect(page.locator('#rwDetailMessage')).toContainText('İşlem tamamlandı');
  await expect(page.locator('#rwAnswer')).toHaveValue(answer);
  await expect(page.locator('.rw-record-meta')).toContainText(id);await expect(page.locator('.rw-record-meta')).toContainText('Sürüm 1');
  await page.getByRole('button',{name:'Onaya Gönder',exact:true}).click();
  await expect(page.locator('.rw-record-meta')).toContainText('Onay bekleyenler');
  await expect(page.getByRole('button',{name:'Onayla',exact:true})).toHaveCount(0);
  await page.locator('.rw-more summary').click();await page.getByRole('button',{name:'Geri Çek',exact:true}).click();
  await page.locator('#rwDecision').getByRole('button',{name:'Geri Çek',exact:true}).click();
  await expect(page.locator('.rw-record-meta')).toContainText('Taslaklar');
  await expect(page.locator('#rwAnswer')).toHaveValue(answer);
});
test('modal preserves unsaved changes and displays conflict next to editor',async({page})=>{
  await login(page,'user');await page.locator('#rwStatus').selectOption('geri_gonderildi');await page.locator('.rw-open').first().click();
  await page.locator('#rwAnswer').fill('Kaybolmaması gereken değişiklik.');
  await page.getByRole('button',{name:'Kapat',exact:true}).click();
  await expect(page.locator('#systemConfirmModal')).toBeVisible();await page.getByRole('button',{name:'Düzenlemeye dön',exact:true}).click();
  await expect(page.locator('#rwAnswer')).toHaveValue('Kaybolmaması gereken değişiklik.');
  await page.route('**/api/review/*/action',route=>route.fulfill({status:409,contentType:'application/json',body:JSON.stringify({error:'Kayıt başka bir işlemle değişti. Metninizi koruyun; güncel kaydı açıp karşılaştırın.'})}));
  await page.getByRole('button',{name:'Kaydet',exact:true}).click();
  await expect(page.locator('#rwDetailMessage')).toContainText('Kayıt başka bir işlemle değişti');await expect(page.locator('#rwAnswer')).toHaveValue('Kaybolmaması gereken değişiklik.');
});
test('mobile returned edit has no overflow and no management actions for member',async({page})=>{
  await page.setViewportSize({width:390,height:844});await login(page,'user');
  await expect(page.locator('[data-review-selector]:visible')).toHaveCount(0);
  await page.locator('#rwStatus').selectOption('geri_gonderildi');await page.locator('.rw-open').first().click();
  await expect(page.locator('#rwQuestion')).toBeEditable();await expect(page.locator('#rwTags')).toBeEditable();
  await expect(page.getByRole('button',{name:'Onayla',exact:true})).toHaveCount(0);
  expect(await page.locator('#rwAnswer').evaluate(el=>Number.parseFloat(getComputedStyle(el).fontSize))).toBeGreaterThanOrEqual(16);
  expect(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth)).toBe(true);
  const bounds=await page.locator('.rw-detail').boundingBox();expect(bounds.x).toBeGreaterThanOrEqual(0);expect(bounds.x+bounds.width).toBeLessThanOrEqual(390);
  await page.screenshot({path:'.tmp-review-test-results/member-mobile.png'});
});
test('read-only preview labels the state and disables all mutation controls',async({page})=>{
  await page.route('**/api/auth/me',async route=>{const response=await route.fetch();const data=await response.json();await route.fulfill({response,json:{...data,reviewReadOnly:true}});});
  await login(page);await expect(page.locator('#rwPreviewNotice')).toContainText('Salt okunur');
  await page.locator('#rwStatus').selectOption('geri_gonderildi');await page.locator('.rw-open').first().click();
  await expect(page.getByRole('button',{name:'Kaydet',exact:true})).toBeDisabled();
  await expect(page.getByRole('button',{name:'Onaya Gönder',exact:true})).toBeDisabled();
});
test('super admin own submission has no self-approval even in management',async({page})=>{
  await login(page,'super_admin');await selectSpace(page,'management');await page.locator('#rwSearch').fill('Süper Yönetici');
  await expect(page.locator('#rwCount')).toHaveText('5 kayıt');await page.locator('.rw-open').first().click();
  await expect(page.locator('.rw-record-meta')).toContainText('Kendi kaydınız');
  await expect(page.getByRole('button',{name:'Onayla',exact:true})).toHaveCount(0);
  await page.locator('.rw-more summary').click();await page.getByRole('button',{name:'Çöpe Taşı',exact:true}).click();
  await page.locator('#rwReason').fill('Yerel test: yanlış kayıt.');
  await page.locator('#rwDecision').getByRole('button',{name:'Çöpe Taşı',exact:true}).click();
  await expect(page.locator('.rw-record-meta')).toContainText('Çöp kutusu');
  await page.locator('.rw-more summary').click();await page.getByRole('button',{name:'Geri Al',exact:true}).click();
  await page.locator('#rwReason').fill('Yerel test: tekrar incelenecek.');
  await page.locator('#rwDecision').getByRole('button',{name:'Geri Al',exact:true}).click();
  await expect(page.locator('.rw-record-meta')).toContainText('Geri dönenler');
});
