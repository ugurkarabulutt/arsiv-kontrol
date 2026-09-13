const {test,expect}=require('@playwright/test');
async function login(page,role='admin'){
  await page.context().addCookies([{name:'reviewDemoRole',value:role,url:'http://127.0.0.1:4317'}]);
  await page.goto('/admin');
  await expect(page.locator('#tabContent-analiz')).toBeVisible();
  await expect(page.locator('#tabContent-analiz')).toHaveClass(/active/);
}
async function openList(page,space='member'){
  const tab=space==='management'?'onay':'gecmis';
  if(await page.locator('#hamburger').isVisible()){
    if(!await page.locator('#mobileMenu').isVisible())await page.locator('#hamburger').click();
    await page.locator(`#mobileMenu [onclick="mNav('${tab}')"]`).click();
  }else await page.locator(`.side-nav .side-link[data-tab="${tab}"]`).click();
  await expect(page.locator('#rwRows')).toHaveAttribute('aria-busy','false');
  await expect(page.locator('#rwRows .rw-row').first()).toBeVisible();
}
async function selectSpace(page,value){
  if(!await page.locator('[data-review-selector]:visible').count())await page.locator('#hamburger').click();
  const select=page.locator('[data-review-selector]:visible').first();
  await select.selectOption(value);
  await expect(page.locator(value==='management'?'#tabContent-dash':'#tabContent-analiz')).toBeVisible();
  await expect(page.locator('#tabContent-onay')).toBeHidden();
  await expect(page.locator('#tabContent-gecmis')).toBeHidden();
}
test('admin sees own work, then independent management view, no mixed buttons',async({page})=>{
  const errors=[];page.on('pageerror',error=>errors.push(error.message));
  await login(page);await openList(page);
  await expect(page.locator('.rw-row .rw-meta')).not.toContainText(['Ekip Örnek']);
  await expect(page.locator('.side-link[data-tab="analiz"]')).toBeVisible();
  await expect(page.locator('.side-link[data-tab="onay"]')).toBeHidden();
  await selectSpace(page,'management');
  await openList(page,'management');
  await expect(page.locator('.side-link[data-tab="analiz"]')).toBeHidden();
  await expect(page.locator('.side-link[data-tab="onay"]')).toBeVisible();
  await page.locator('#rwStatus').selectOption('geri_gonderildi');
  await expect(page.locator('#rwCount')).toHaveText('48 kayıt');
  await page.getByRole('button',{name:'Sonraki',exact:true}).click();
  await expect(page.locator('#rwPages')).toContainText('2 / 2');
  await page.locator('#rwSearch').fill('sorusu 17:');
  await expect(page.locator('#rwCount')).toHaveText('1 kayıt');
  await selectSpace(page,'member');await selectSpace(page,'management');
  await openList(page,'management');
  await expect(page.locator('#rwSearch')).toHaveValue('sorusu 17:');
  await expect(page.locator('#rwRows')).toHaveCount(1);
  await page.screenshot({path:'.tmp-review-test-results/management-desktop.png',fullPage:true});
  expect(errors).toEqual([]);
});
test('returned Q/tags/answer/note edit together, save preserves line breaks, no cloned record',async({page})=>{
  await login(page);await openList(page);await page.locator('#rwStatus').selectOption('todo');
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
  await expect(page.locator('.rw-record-meta')).toContainText('Onaya gönderildi');
  await expect(page.getByRole('button',{name:'Onayla',exact:true})).toHaveCount(0);
  await page.locator('.rw-more summary').click();await page.getByRole('button',{name:'Geri Çek',exact:true}).click();
  await page.locator('#rwDecision').getByRole('button',{name:'Geri Çek',exact:true}).click();
  await expect(page.locator('.rw-record-meta')).toContainText('Geri gönderildi');
  await expect(page.locator('#rwAnswer')).toHaveValue(answer);
});
test('modal preserves unsaved changes and displays conflict next to editor',async({page})=>{
  await login(page,'user');await openList(page);await page.locator('#rwStatus').selectOption('todo');await page.locator('.rw-open').last().click();
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
  await openList(page);
  await page.locator('#rwStatus').selectOption('todo');await page.locator('.rw-open').last().click();
  await expect(page.locator('#rwQuestion')).toBeEditable();await expect(page.locator('#rwTags')).toBeEditable();
  await expect(page.getByRole('button',{name:'Onayla',exact:true})).toHaveCount(0);
  expect(await page.locator('#rwAnswer').evaluate(el=>Number.parseFloat(getComputedStyle(el).fontSize))).toBeGreaterThanOrEqual(16);
  expect(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth)).toBe(true);
  const bounds=await page.locator('.rw-detail').boundingBox();expect(bounds.x).toBeGreaterThanOrEqual(0);expect(bounds.x+bounds.width).toBeLessThanOrEqual(390);
  await page.screenshot({path:'.tmp-review-test-results/member-mobile.png'});
});
test('read-only preview labels the state and disables all mutation controls',async({page})=>{
  await page.route('**/api/auth/me',async route=>{const response=await route.fetch();const data=await response.json();await route.fulfill({response,json:{...data,reviewReadOnly:true}});});
  await login(page);await openList(page);await expect(page.locator('#rwPreviewNotice')).toContainText('Salt okunur');
  await page.locator('#rwStatus').selectOption('todo');await page.locator('.rw-open').first().click();
  await expect(page.getByRole('button',{name:'Kaydet',exact:true})).toBeDisabled();
  await expect(page.getByRole('button',{name:'Onaya Gönder',exact:true})).toBeDisabled();
});
test('super admin own submission has no self-approval even in management',async({page})=>{
  await login(page,'super_admin');await selectSpace(page,'management');await openList(page,'management');await page.locator('#rwSearch').fill('Süper Yönetici');
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

for(const role of ['user','admin','super_admin']){
  test(`${role} starts on the workspace home, including reload and restored selection`,async({page})=>{
    const errors=[],lists=[];
    page.on('pageerror',error=>errors.push(error.message));
    page.on('request',request=>{if(request.url().includes('/api/review/records'))lists.push(request.url());});
    await login(page,role);
    await expect(page.locator('#rwRows')).toHaveCount(0);
    await page.reload();
    await expect(page.locator('#tabContent-analiz')).toBeVisible();
    if(role!=='user'){
      await selectSpace(page,'management');
      await expect(page.locator('#dashContent .stat-val').first()).toHaveText('65');
      await page.reload();
      await expect(page.locator('#tabContent-dash')).toBeVisible();
      await expect(page.locator('[data-review-selector]:visible').first()).toHaveValue('management');
      await expect(page.locator('#dashContent')).not.toContainText('undefined');
      await selectSpace(page,'member');
      await page.reload();
      await expect(page.locator('#tabContent-analiz')).toBeVisible();
    }
    // Home navigation must not load a record list in the background either.
    expect(lists).toEqual([]);
    expect(errors).toEqual([]);
    await openList(page);
    expect(lists.length).toBe(1);
  });
}

test('mobile workspace changes open their homes and keep the menu closed',async({page})=>{
  await page.setViewportSize({width:390,height:844});await login(page);
  await page.screenshot({path:'.tmp-review-test-results/home-member-mobile.png'});
  await selectSpace(page,'management');
  await expect(page.locator('#dashContent .stat-val').first()).toHaveText('65');
  await expect(page.locator('#mobileMenu')).toBeHidden();
  await expect(page.locator('#rwRows')).toHaveCount(0);
  expect(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth)).toBe(true);
  await page.screenshot({path:'.tmp-review-test-results/home-management-mobile.png'});
  await openList(page,'management');
  await selectSpace(page,'member');
  await expect(page.locator('#mobileMenu')).toBeHidden();
  await expect(page.locator('#rwRows')).toHaveCount(0);
  await openList(page);
});

test('unavailable tab falls back to workspace home, legacy startup remains unchanged',async({page})=>{
  await login(page,'user');
  await page.evaluate(()=>showTab('onay'));
  await expect(page.locator('#tabContent-analiz')).toBeVisible();
  await expect(page.locator('#rwRows')).toHaveCount(0);
  await page.route('**/api/auth/me',async route=>{const response=await route.fetch();const data=await response.json();await route.fulfill({response,json:{...data,reviewWorkspacesEnabled:false}});});
  await page.reload();
  await expect(page.locator('#tabContent-analiz')).toBeVisible();
  await expect(page.locator('[data-review-selector]:visible')).toHaveCount(0);
});

test('latest submission appears first with its submission date on desktop and mobile',async({page})=>{
  const errors=[];page.on('pageerror',error=>errors.push(error.message));
  await login(page,'admin');await openList(page);
  await page.locator('#rwStatus').selectOption('todo');
  await page.locator('.rw-open').last().click();
  const question=await page.locator('#rwQuestion').inputValue();
  await page.getByRole('button',{name:'Onaya Gönder',exact:true}).click();
  await expect(page.locator('.rw-record-meta')).toContainText('Onaya gönderildi');
  await page.getByRole('button',{name:'Kapat',exact:true}).click();
  await page.locator('#rwStatus').selectOption('in_review');
  const first=page.locator('#rwRows .rw-row').first();
  await expect(first.locator('.rw-question')).toHaveText(question);
  await expect(first.locator('.rw-meta')).toContainText('Onaya gönderim:');
  await selectSpace(page,'management');await openList(page,'management');
  await expect(first.locator('.rw-question')).toHaveText(question);
  await expect(first.locator('.rw-meta')).toContainText('Onaya gönderim:');
  const rows=page.locator('#rwRows .rw-row');
  expect(await rows.filter({hasText:'İlk kayıt:'}).count()).toBeGreaterThan(0);
  await page.screenshot({path:'.tmp-review-test-results/submission-order-desktop.png',fullPage:true});
  await page.setViewportSize({width:390,height:844});
  await expect(first.locator('.rw-question')).toBeVisible();
  expect(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth)).toBe(true);
  await page.screenshot({path:'.tmp-review-test-results/submission-order-mobile.png'});
  expect(errors).toEqual([]);
});

test('confirmation list shows the latest workflow date instead of the old creation date',async({page})=>{
  await page.setViewportSize({width:390,height:844});
  await page.route('**/api/review/records?*',async route=>{
    const url=new URL(route.request().url());
    if(url.searchParams.get('status')!=='teyit_bekliyor')return route.continue();
    await route.fulfill({status:200,contentType:'application/json',body:JSON.stringify({items:[{
      id:'de84a98b-9f68-46f3-a7f9-c210c304eba6',userId:'10000000-0000-4000-8000-000000000001',name:'Bihter Oksak',
      status:'teyit_bekliyor',questionText:'Unutmak nefsin bir afeti midir?',tags:['Nefs'],createdAt:'2026-08-14T18:58:35.302Z',
      updatedAt:'2026-09-06T22:42:44.634Z',queueAt:'2026-09-06T22:42:44.634Z',allowedActions:['save','approve'],workflow:{},publication:null
    }],count:1,page:1,pageSize:25,workspace:'management'})});
  });
  await login(page,'admin');await selectSpace(page,'management');await openList(page,'management');
  await page.locator('#rwStatus').selectOption('teyit_bekliyor');
  const first=page.locator('#rwRows .rw-row').first();
  await expect(first.locator('.rw-question')).toHaveText('Unutmak nefsin bir afeti midir?');
  await expect(first.locator('.rw-meta')).toContainText('Son işlem: 07.09.2026 01:42:44');
  await expect(page.locator('#rwCount')).toHaveText('1 kayıt');
  expect(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth)).toBe(true);
  await page.screenshot({path:'.tmp-review-test-results/confirmation-order-mobile.png'});
});

test('management can select rows and run bulk approve or reject through safe item actions',async({page})=>{
  const calls=[];
  let records=[{
    id:'de84a98b-9f68-46f3-a7f9-c210c304eba6',userId:'10000000-0000-4000-8000-000000000001',name:'Bihter Oksak',
    status:'bekliyor',questionText:'Toplu onay birinci soru?',tags:['Zikir'],createdAt:'2026-09-06T18:58:35.302Z',
    updatedAt:'2026-09-06T22:42:44.634Z',queueAt:'2026-09-06T22:42:44.634Z',version:2,allowedActions:['approve','reject'],workflow:{},publication:null
  },{
    id:'8154624e-071a-4dc8-bc85-1c981e0b69f1',userId:'10000000-0000-4000-8000-000000000002',name:'Ebru Kalaycı 💗',
    status:'bekliyor',questionText:'Toplu onay ikinci soru?',tags:['Teslimiyet'],createdAt:'2026-09-06T18:59:35.302Z',
    updatedAt:'2026-09-06T22:43:44.634Z',queueAt:'2026-09-06T22:43:44.634Z',version:5,allowedActions:['approve','reject'],workflow:{},publication:null
  }];
  await page.route('**/api/review/records?*',async route=>{
    await route.fulfill({status:200,contentType:'application/json',body:JSON.stringify({items:records,count:records.length,page:1,pageSize:25,workspace:'management'})});
  });
  await page.route('**/api/review/*/action',async route=>{
    const body=route.request().postDataJSON();
    const id=route.request().url().match(/\/api\/review\/([0-9a-f-]{36})\/action/i)?.[1];
    calls.push({id,...body});
    records=records.filter(row=>row.id!==id);
    await route.fulfill({status:200,contentType:'application/json',body:JSON.stringify({success:true,history:{...(records[0]||{}),id,status:body.action==='approve'?'onaylandi':'reddedildi',allowedActions:[],publication:body.action==='approve'?{status:'published',slug:'toplu-test'}:null}})});
  });
  await login(page,'admin');await selectSpace(page,'management');await openList(page,'management');
  await expect(page.locator('#rwBulkBar')).toContainText('0 seçili');
  await page.getByRole('button',{name:'Bu Sayfayı Seç',exact:true}).click();
  await expect(page.locator('#rwBulkBar')).toContainText('2 seçili');
  await page.locator('#rwBulkAction').selectOption('approve');
  await page.getByRole('button',{name:'Uygula',exact:true}).click();
  await page.locator('#systemConfirmModal').getByRole('button',{name:'Onayla Uygula',exact:true}).click();
  await expect(page.locator('#rwListMessage')).toContainText('2 kayıt onaylandı');
  expect(calls.map(call=>[call.id,call.action,call.version])).toEqual([
    ['de84a98b-9f68-46f3-a7f9-c210c304eba6','approve',2],
    ['8154624e-071a-4dc8-bc85-1c981e0b69f1','approve',5]
  ]);

  records=[{
    id:'de84a98b-9f68-46f3-a7f9-c210c304eba6',userId:'10000000-0000-4000-8000-000000000001',name:'Bihter Oksak',
    status:'bekliyor',questionText:'Toplu red soru?',tags:['Zikir'],createdAt:'2026-09-06T18:58:35.302Z',
    updatedAt:'2026-09-06T22:42:44.634Z',queueAt:'2026-09-06T22:42:44.634Z',version:6,allowedActions:['approve','reject'],workflow:{},publication:null
  }];
  await page.evaluate(()=>ReviewWorkspace.load());
  await expect(page.locator('#rwRows .rw-row')).toHaveCount(1);
  await page.getByRole('button',{name:'Bu Sayfayı Seç',exact:true}).click();
  await page.locator('#rwBulkAction').selectOption('reject');
  await page.locator('#rwBulkNote').fill('Toplu red gerekçesi');
  await page.getByRole('button',{name:'Uygula',exact:true}).click();
  await page.locator('#systemConfirmModal').getByRole('button',{name:'Reddet Uygula',exact:true}).click();
  await expect(page.locator('#rwListMessage')).toContainText('1 kayıt reddedildi');
  expect(calls.at(-1)).toMatchObject({id:'de84a98b-9f68-46f3-a7f9-c210c304eba6',action:'reject',version:6,note:'Toplu red gerekçesi'});
});

test('own draft can be deleted after confirmation at narrow and desktop widths',async({page})=>{
  const errors=[];page.on('pageerror',error=>errors.push(error.message));
  await login(page,'user');
  await page.goto('/admin?reviewRecord=50000000-0000-4000-8000-000000000001');
  await expect(page.locator('#rwQuestion')).toHaveValue('Silinebilir taslak örneği?');
  await expect(page.locator('.rw-record-meta')).toContainText('Taslak');
  const remove=page.getByRole('button',{name:'Taslağı Sil',exact:true});
  await expect(remove).toBeVisible();
  for(const width of [1440,390,320]){
    await page.setViewportSize({width,height:width===1440?1000:740});
    await expect(remove).toBeVisible();
    expect(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth)).toBe(true);
    const box=await remove.boundingBox();expect(box.x).toBeGreaterThanOrEqual(0);expect(box.x+box.width).toBeLessThanOrEqual(width);
    await page.screenshot({path:`.tmp-review-test-results/draft-delete-${width}.png`});
  }
  await remove.click();await expect(page.locator('#systemConfirmModal')).toBeVisible();
  await page.locator('#systemConfirmModal').getByRole('button',{name:'Vazgeç',exact:true}).click();
  await expect(page.locator('#rwQuestion')).toHaveValue('Silinebilir taslak örneği?');
  await remove.click();await page.locator('#systemConfirmModal').getByRole('button',{name:'Taslağı Sil',exact:true}).click();
  await expect(page.locator('#detailModal')).toBeHidden();
  const response=await page.request.get('/api/review/50000000-0000-4000-8000-000000000001');expect(response.status()).toBe(404);
  expect(errors).toEqual([]);
});

test('returned and historically protected records have no draft delete action',async({page})=>{
  await login(page,'user');
  await page.goto('/admin?reviewRecord=50000000-0000-4000-8000-000000000002');
  await expect(page.locator('#rwQuestion')).toHaveValue('Geçmişi korunan taslak örneği?');
  await expect(page.getByRole('button',{name:'Taslağı Sil',exact:true})).toHaveCount(0);
  const response=await page.request.post('/api/review/50000000-0000-4000-8000-000000000002/action',{data:{action:'delete_draft',version:0}});
  expect(response.status()).toBe(403);
  await page.getByRole('button',{name:'Kapat',exact:true}).click();
  await openList(page);await page.locator('.rw-row').filter({hasText:'Geri gönderildi'}).first().getByRole('button',{name:'Düzenle',exact:true}).click();
  await expect(page.getByRole('button',{name:'Taslağı Sil',exact:true})).toHaveCount(0);
});

test('duplicate link opens the existing record in a new tab without losing edits',async({page,context})=>{
  const errors=[];page.on('pageerror',error=>errors.push(error.message));
  await page.setViewportSize({width:360,height:740});await login(page,'user');
  await page.goto('/admin?reviewRecord=50000000-0000-4000-8000-000000000003');
  await expect(page.locator('#rwAnswer')).toBeEditable();
  const question=await page.locator('#rwQuestion').inputValue();
  await page.locator('#rwTags').fill('Takva, İstiğfar');
  await page.locator('#rwNote').fill('Yeni kontrol notum korunmalı.');
  await page.getByRole('button',{name:'Onaya Gönder',exact:true}).click();
  await expect(page.locator('#rwDetailMessage')).toContainText('Onaya gönderildi');
  const popupPromise=context.waitForEvent('page');
  await page.getByRole('link',{name:'Mevcut kaydı aç',exact:true}).click();
  const popup=await popupPromise;
  await expect(popup.locator('#rwQuestion')).toHaveValue(question);
  await expect(popup.locator('.rw-record-meta')).toContainText('Onaya gönderildi');
  await expect(page.locator('#rwTags')).toHaveValue('Takva, İstiğfar');
  await expect(page.locator('#rwNote')).toHaveValue('Yeni kontrol notum korunmalı.');
  expect(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth)).toBe(true);
  await page.screenshot({path:'.tmp-review-test-results/duplicate-link-mobile.png'});
  await popup.close();expect(errors).toEqual([]);
});
