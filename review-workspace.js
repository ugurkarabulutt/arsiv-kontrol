/* Shared member/management workspace. Capabilities come from the server. */
const ReviewWorkspace = (() => {
  const labels = { all: 'Tümü', taslak: 'Taslaklar', bekliyor: 'Onay bekleyenler', geri_gonderildi: 'Geri dönenler',
    teyit_bekliyor: 'Teyit bekleyenler', onaylandi: 'Onaylananlar', reddedildi: 'Reddedilenler',
    arsivlendi: 'Arşivlenenler', copte: 'Çöp kutusu', disputed: 'Sahiplik itirazları' };
  const actions = { save: 'Kaydet', submit: 'Onaya Gönder', approve: 'Onayla', return: 'Düzeltmeye Gönder',
    reject: 'Reddet', review: 'Teyide Al', pending: 'Bekleyenlere Al', archive: 'Arşivle', trash: 'Çöpe Taşı',
    restore: 'Geri Al', dispute: 'Bu Kayıt Bana Ait Değil', resolve_dispute: 'İtirazı Sonuçlandır',
    reanalyze: 'Yeniden Denetle', withdraw: 'Geri Çek' };
  const memberTabs = new Set(['analiz', 'gecmis', 'bildirim', 'standartlar', 'profil', 'ayarlar']);
  const states = { member: { status: 'all', q: '', page: 1 }, management: { status: 'bekliyor', q: '', page: 1 } };
  let space = 'member', item = null, baseline = '', busy = false, requestNumber = 0, detailRequest = 0, searchTimer, returnFocus;
  const node = id => document.getElementById(id);
  const safe = value => String(value ?? '').replace(/[&<>"']/g, char => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[char]));
  const management = () => space === 'management' && hasAdminRole(me?.role);
  const homeTab = () => management() ? 'dash' : 'analiz';
  const state = () => states[space];
  const date = value => value ? new Date(value).toLocaleString('tr-TR') : '—';
  const listDate = row => row.status === 'bekliyor'
    ? row.submittedAt ? `Onaya gönderim: ${date(row.submittedAt)}` : `İlk kayıt: ${date(row.createdAt)}`
    : date(row.createdAt);
  const can = action => (item?.allowedActions || []).includes(action);
  const values = () => ({ questionText: node('rwQuestion')?.value ?? item?.questionText ?? '',
    correctedText: node('rwAnswer')?.value ?? item?.correctedText ?? '',
    tags: (node('rwTags')?.value ?? (item?.tags || []).join(', ')).split(',').map(tag => tag.trim()).filter(Boolean),
    submissionNote: node('rwNote')?.value ?? item?.submissionNote ?? '' });
  const dirty = () => !!item && !!node('rwQuestion') && JSON.stringify(values()) !== baseline;
  function message(text, error = false) {
    const target = node('rwDetailMessage') || node('rwListMessage') || node('reviewToast');
    if (target) { target.textContent = text; target.classList.toggle('rw-error', error); }
  }
  async function request(path, method = 'GET', payload) {
    return api(method, '/api/review' + path, payload);
  }
  function allowedTab(name) {
    return management() ? !['analiz', 'gecmis'].includes(name) : memberTabs.has(name);
  }
  function refreshNav() {
    if(!me?.reviewWorkspacesEnabled)return;
    const allowed = hasAdminRole(me?.role);
    document.querySelectorAll('[data-review-selector]').forEach(select => {
      select.hidden = !allowed; select.value = space;
    });
    document.querySelectorAll('.side-nav .side-link[data-tab]').forEach(link => {
      const tab = link.dataset.tab;
      link.hidden = !allowedTab(tab) || (link.classList.contains('super-admin-only') && !hasSuperAdminRole(me?.role));
    });
    document.querySelectorAll('.side-section-label').forEach(label => { label.hidden = true; });
    document.querySelectorAll('.admin-only,.super-admin-only,.admin-route-only').forEach(element => {
      const permitted = management() && (!element.classList.contains('super-admin-only') || hasSuperAdminRole(me?.role));
      element.style.display = permitted ? '' : 'none';
    });
    document.querySelectorAll('.btn-mobile,.btn-top').forEach(button => {
      const match = (button.getAttribute('onclick') || '').match(/(?:mNav|showTab)\('([^']+)'\)/);
      if (match) button.hidden = !allowedTab(match[1]);
    });
  }
  function showHome() {
    showTab(homeTab());
    if(me.reviewReadOnly){
      const title=node('tabContent-'+homeTab())?.querySelector('.page-sub');
      if(title)title.textContent='Önizleme: kayıt değişiklikleri kapalı.';
    }
  }
  function start() {
    close(true);
    space = 'member';
    if (hasAdminRole(me?.role)) {
      try { space = localStorage.getItem(`review-workspace:${me.id}`) === 'management' ? 'management' : 'member'; } catch {}
    }
    refreshNav();
    showHome();
  }
  async function switchSpace(next) {
    if (busy || isAnalyzing) { message('Devam eden işlemin tamamlanmasını bekleyin.', true); refreshNav(); return; }
    if (dirty() && !await openSystemConfirm({title:'Kaydedilmemiş değişiklikler',message:'Değişiklikleri kaydetmeden çalışma alanından çıkılsın mı?',confirmText:'Kaydetmeden çık',cancelText:'Düzenlemeye dön'})) { refreshNav(); return; }
    close(true);
    space = next === 'management' && hasAdminRole(me?.role) ? next : 'member';
    try { localStorage.setItem(`review-workspace:${me.id}`, space); } catch {}
    historyRows = [];
    ['histContent','onayContent'].forEach(id => { if (node(id)?.querySelector('.rw-list')) node(id).replaceChildren(); });
    clearTimeout(searchTimer);
    requestNumber++;
    refreshNav();
    showHome();
    closeMobileMenu();
  }
  async function prepareLogout(){
    if(busy)return false;
    if(dirty()&&!await openSystemConfirm({title:'Kaydedilmemiş değişiklikler',message:'Değişiklikleri kaydetmeden oturum kapatılsın mı?',confirmText:'Kaydetmeden çık',cancelText:'Düzenlemeye dön'}))return false;
    await close(true);node('detailBody').replaceChildren();
    ['histContent','onayContent'].forEach(id=>{if(node(id)?.querySelector('.rw-list'))node(id).replaceChildren();});
    for(const key of ['member','management'])Object.assign(states[key],{status:key==='management'?'bekliyor':'all',q:'',page:1});
    clearTimeout(searchTimer);requestNumber++;return true;
  }
  function selectorHTML() {
    return '<label class="rw-workspace"><span>Çalışma alanı</span><select data-review-selector aria-label="Çalışma alanı" onchange="ReviewWorkspace.switchSpace(this.value)"><option value="member">Ekip Üyesi</option><option value="management">Yönetim</option></select></label>';
  }
  async function load() {
    const container = node(management() ? 'onayContent' : 'histContent');
    if (!container) return;
    const currentSpace = space, currentRequest = ++requestNumber;
    const s = { ...state() };
    const holder = node('histStatusFilter')?.closest('.history-toolbar');
    if (holder) holder.hidden = true;
    if (node('scoreChartBox')) node('scoreChartBox').style.display='none';
    const options = management() ? ['bekliyor','onaylandi','reddedildi','geri_gonderildi','disputed','teyit_bekliyor','arsivlendi','copte','all']
      : ['all','taslak','geri_gonderildi','bekliyor','onaylandi','reddedildi','teyit_bekliyor','arsivlendi'];
    const inactive = node(management() ? 'histContent' : 'onayContent');
    if (inactive?.querySelector('.rw-list')) inactive.replaceChildren();
    if (!container.querySelector('.rw-list')) {
      container.innerHTML = `<section class="rw-list"><div class="rw-toolbar"><label><span>Durum</span><select id="rwStatus" onchange="ReviewWorkspace.filter(this.value)">${options.map(key=>`<option value="${key}">${labels[key]}</option>`).join('')}</select></label><label class="rw-search"><span>Ara</span><input id="rwSearch" type="search" placeholder="Soru, cevap veya kişi ara" oninput="ReviewWorkspace.search(this.value)" autocomplete="off"></label><span id="rwCount" class="rw-count"></span></div><div id="rwListMessage" role="status" aria-live="polite"></div><div id="rwRows" aria-busy="true"></div><nav id="rwPages" class="rw-pages" aria-label="Kayıt sayfaları"></nav></section>`;
    }
    node('rwStatus').value = s.status;
    if(me.reviewReadOnly&&!node('rwPreviewNotice'))container.querySelector('.rw-toolbar').insertAdjacentHTML('beforebegin','<p id="rwPreviewNotice" role="status">Salt okunur önizleme: kayıt değişiklikleri kapalı.</p>');
    if (node('rwSearch') !== document.activeElement) node('rwSearch').value = s.q;
    node('rwRows').setAttribute('aria-busy','true');
    const params = new URLSearchParams({ status: s.status, q: s.q, page: String(s.page) });
    const result = await request('/records?' + params);
    if (currentRequest !== requestNumber || currentSpace !== space) return;
    node('rwRows').setAttribute('aria-busy','false');
    if (result.error) { message(result.error, true); return; }
    if (!result.items.length && s.page > 1) { state().page--; return load(); }
    node('rwListMessage').textContent = '';
    node('rwCount').textContent = `${result.count} kayıt`;
    const totalPages = Math.max(1,Math.ceil(result.count/result.pageSize));
    node('rwRows').innerHTML = result.items.length ? `<div class="rw-table" role="list">${result.items.map(row => `<article class="rw-row" role="listitem"><div class="rw-row-main"><button class="rw-question" onclick="ReviewWorkspace.open('${row.id}')">${safe(row.questionText || 'Soru eklenmemiş')}</button><div class="rw-meta"><span>${safe(row.name)}</span>${row.submittedBy && row.submittedBy !== row.userId ? `<span>Gönderen: ${safe(row.submittedByName || 'Kayıtlı ekip üyesi')}</span>` : ''}<span>${safe(listDate(row))}</span><span>${safe(labels[row.status] || row.status)}</span>${row.workflow?.disputed?'<span class="rw-warning">Sahiplik itirazı</span>':''}${row.publication?.status==='published'?'<span class="rw-published">Yayında</span>':''}</div><div class="rw-tags">${(row.tags||[]).map(tag=>`<span>${safe(tag)}</span>`).join('')}</div>${row.returnNote?`<p class="rw-return">${safe(row.returnNote)}</p>`:''}</div><button class="btn-sec rw-open" onclick="ReviewWorkspace.open('${row.id}')">${management()?'İncele':row.allowedActions.includes('save')?'Düzenle':'Gör'}</button></article>`).join('')}</div>` : '<p class="rw-empty">Bu filtrede kayıt bulunamadı.</p>';
    node('rwPages').innerHTML = `<button class="btn-sec" ${s.page<=1?'disabled':''} onclick="ReviewWorkspace.page(-1)">Önceki</button><span>${s.page} / ${totalPages}</span><button class="btn-sec" ${s.page>=totalPages?'disabled':''} onclick="ReviewWorkspace.page(1)">Sonraki</button>`;
  }
  function filter(status) { state().status=status; state().page=1; load(); }
  function search(q) { state().q=q; state().page=1; clearTimeout(searchTimer); searchTimer=setTimeout(load,300); }
  function page(delta) { state().page=Math.max(1,state().page+delta); load(); }

  async function open(id) {
    if (busy) return;
    if (dirty() && !await openSystemConfirm({title:'Kaydedilmemiş değişiklikler',message:'Değişiklikler kaydedilmeden diğer kayıt açılsın mı?',confirmText:'Diğer kaydı aç',cancelText:'Düzenlemeye dön'})) return;
    returnFocus = document.activeElement;
    const req = ++detailRequest;
    const modal = node('detailModal');
    document.documentElement.classList.add('rw-modal-open');
    modal.classList.add('rw-modal');
    modal.classList.add('open'); modal.setAttribute('role','dialog'); modal.setAttribute('aria-modal','true'); modal.setAttribute('aria-label','Denetim kaydı');
    modal.querySelector('.modal-foot').style.display='none';
    node('detailBody').style.whiteSpace='normal';
    node('detailBody').innerHTML='<p role="status">Kayıt yükleniyor…</p>';
    item=null;
    const result=await request('/'+id);
    if (req !== detailRequest) return;
    if(result.error){node('detailBody').innerHTML=`<p class="rw-error" role="alert">${safe(result.error)}</p>`;return;}
    item=result;
    renderDetail();
  }
  function renderDetail() {
    const editable=can('save'), meta=item.workflow||{};
    const primary=can('submit')?'submit':can('approve')?'approve':'';
    const others=(item.allowedActions||[]).filter(action=>!['save',primary].includes(action));
    node('detailBody').innerHTML=`<div class="rw-detail"><div class="rw-record-meta"><strong>${safe(item.name)}</strong><span>${safe(labels[item.status]||item.status)}</span><span>No: ${safe(item.id.slice(0,8))} · Sürüm ${item.version}</span><span>${date(item.updatedAt||item.createdAt)}</span><span>${item.publication?.status==='published'?'Yayında':'Yayında değil'}</span>${item.userId===me.id?'<span>Kendi kaydınız</span>':''}${item.assigneeId?`<span>Düzeltme sorumlusu: ${safe(item.assigneeName||item.assigneeId.slice(0,8))}</span>`:''}</div>
      ${item.returnNote?`<p class="rw-return">${safe(item.returnNote)}</p>`:''}
      ${meta.disputed?`<p class="rw-warning">Sahiplik itirazı: ${safe(meta.disputeNote)}</p>`:''}
      ${meta.trashNote&&item.status==='copte'?`<p class="rw-warning">Çöpe taşıma gerekçesi: ${safe(meta.trashNote)}</p>`:''}
      <label class="rw-field"><span>Soru</span><textarea id="rwQuestion" ${editable?'':'readonly'} rows="3">${safe(item.questionText||'')}</textarea></label>
      <label class="rw-field"><span>Etiketler</span><textarea id="rwTags" ${editable?'':'readonly'} rows="2">${safe((item.tags||[]).join(', '))}</textarea></label>
      <label class="rw-field"><span>Cevap (düzeltilmiş metin)</span><textarea id="rwAnswer" ${editable?'':'readonly'} rows="12" dir="auto">${safe(item.correctedText||'')}</textarea></label>
      <label class="rw-field"><span>Kontrol notu</span><textarea id="rwNote" ${editable?'':'readonly'} rows="2" maxlength="1200">${safe(item.submissionNote||'')}</textarea></label>
      <details class="rw-source"><summary>Kaynak ve işlem geçmişi</summary><p>İlk denetleyen: ${safe(item.name)} · ${date(item.createdAt)}</p>${item.originalText?`<pre dir="auto">${safe(item.originalText)}</pre>`:'<p>Orijinal denetim metni bu kayıtta saklanmamış.</p>'}<button class="btn-sec" onclick="ReviewWorkspace.revisions()">Sürümleri Gör</button><div id="rwRevisions"></div></details>
      <div id="rwDetailMessage" role="status" aria-live="polite"></div><div id="rwDecision"></div>
      <div class="rw-actions">${can('save')?'<button class="btn-sec" data-rw-write onclick="ReviewWorkspace.act(\'save\')">Kaydet</button>':''}${primary?`<button class="btn-primary" data-rw-write onclick="ReviewWorkspace.act('${primary}')">${actions[primary]}</button>`:''}
      ${others.length?`<details class="rw-more"><summary aria-label="Diğer işlemler" title="Diğer işlemler">Diğer işlemler</summary><div>${others.map(action=>`<button type="button" data-rw-write onclick="ReviewWorkspace.decide('${action}')">${actions[action]||safe(action)}</button>`).join('')}</div></details>`:''}<button class="btn-sec" onclick="ReviewWorkspace.close()">Kapat</button></div></div>`;
    baseline=JSON.stringify(values());
    const footer=node('detailModal').querySelector('.modal-foot');
    footer.replaceChildren(node('rwDetailMessage'),node('detailBody').querySelector('.rw-detail > .rw-actions'));
    footer.style.display='block';
    if(management()&&item.status!=='copte'){
      const favorite=document.createElement('button');
      favorite.type='button';favorite.id='rwFavorite';favorite.className='work-star';
      favorite.setAttribute('aria-pressed',String(!!item.favorite));
      favorite.title=favorite.ariaLabel=item.favorite?'Favorilerden çıkar':'Favoriye ekle';
      favorite.textContent=item.favorite?'★':'☆';favorite.onclick=toggleFavorite;
      favorite.disabled=Boolean(me.reviewReadOnly);
      node('detailBody').querySelector('.rw-record-meta').append(favorite);
    }
    node('rwQuestion').focus({preventScroll:true});
    if(me.reviewReadOnly)document.querySelectorAll('[data-rw-write]').forEach(button=>button.disabled=true);
  }
  async function close(force=false) {
    if (!force && busy) return;
    if (!force && dirty() && !await openSystemConfirm({title:'Kaydedilmemiş değişiklikler',message:'Değişiklikleri kaydetmeden çıkılsın mı?',confirmText:'Kaydetmeden çık',cancelText:'Düzenlemeye dön'})) return;
    detailRequest++; item=null; baseline=''; node('detailModal').classList.remove('open');
    document.documentElement.classList.remove('rw-modal-open');
    returnFocus?.focus?.({preventScroll:true});
  }
  async function decide(action) {
    if (!can(action)||busy) return;
    const decidingId=item.id;
    if (dirty() && action!=='reanalyze') {message('Önce değişikliklerinizi kaydedin veya güncel kaydı yeniden açın.',true);return;}
    const host=node('rwDecision');
    host.dataset.action=action;
    document.querySelector('.rw-more')?.removeAttribute('open');
    const needsNote=!['withdraw','pending','reanalyze'].includes(action);
    host.innerHTML=`<section class="rw-decision"><h4>${actions[action]}</h4>${needsNote?'<label class="rw-field"><span>Gerekçe</span><textarea id="rwReason" maxlength="1200" rows="3"></textarea></label>':''}<div id="rwDecisionOptions"></div><p id="rwDecisionHelp">${action==='trash'?'Kayıt çöp kutusuna taşınır ve yayından kaldırılır. Daha sonra geri alınabilir.':action==='restore'?'Kayıt düzenleme için geri alınır; otomatik yayımlanmaz.':action==='reanalyze'?'Cevap yeniden denetlenecek ve aynı kaydın yeni sürümü olarak saklanacak. Önceki sürüm korunur.':''}</p><div class="rw-actions"><button class="btn-primary" data-rw-write onclick="ReviewWorkspace.act('${action}')">${actions[action]}</button><button class="btn-sec" onclick="document.getElementById('rwDecision').replaceChildren()">Vazgeç</button></div></section>`;
    node('rwReason')?.focus();
    if(!node('rwReason'))host.scrollIntoView({block:'end'});
    if(action==='resolve_dispute') {
      const result=await request('/assignees');
      if(result.error){message(result.error,true);return;}
      if(item?.id!==decidingId||node('rwDecision')?.dataset.action!==action||!node('rwDecisionOptions'))return;
      node('rwDecisionOptions').innerHTML=`<label class="rw-field"><span>Düzeltme sorumlusu</span><select id="rwAssignee">${result.items.map(user=>`<option value="${user.id}" ${user.id===(item.assigneeId||item.userId)?'selected':''}>${safe(user.name)}</option>`).join('')}</select></label>`;
    }
    if(action==='trash') {
      const result=await request('/'+item.id+'/duplicates');
      if(result.error){message(result.error,true);return;}
      if(item?.id!==decidingId||node('rwDecision')?.dataset.action!==action||!node('rwDecisionOptions'))return;
      if(result.items.length)node('rwDecisionOptions').innerHTML=`<label class="rw-field"><span>Birebir kopya için yönlendirme</span><select id="rwDuplicate"><option value="">Yönlendirme yok</option>${result.items.map(row=>`<option value="${row.id}">${safe(row.name)} · ${safe(row.id.slice(0,8))}</option>`).join('')}</select></label>`;
    }
  }
  async function act(action) {
    if (busy||!can(action)) return;
    const payload={action,version:item.version,...(['save','submit','approve','reanalyze'].includes(action)?values():{}),note:node('rwReason')?.value||''};
    if(node('rwAssignee'))payload.assigneeId=node('rwAssignee').value;
    if(node('rwDuplicate')?.value)payload.duplicateId=node('rwDuplicate').value;
    busy=true; node('detailModal').setAttribute('aria-busy','true');
    document.querySelectorAll('[data-rw-write]').forEach(button=>button.disabled=true);
    message(action==='reanalyze'?'Denetleniyor…':'İşlem sürüyor…');
    try {
      const result=await request('/'+item.id+(action==='reanalyze'?'/reanalyze':'/action'),'POST',payload);
      if(result.error){message(result.error,true);return;}
      item=result.history; renderDetail(); message('İşlem tamamlandı.');
      await load();
    } finally {
      busy=false; node('detailModal').removeAttribute('aria-busy');
      document.querySelectorAll('[data-rw-write]').forEach(button=>button.disabled=false);
    }
  }
  async function revisions(beforeVersion) {
    const id=item?.id;if(!id)return;
    const result=await request('/'+id+'/revisions'+(beforeVersion?'?beforeVersion='+beforeVersion:''));
    if(item?.id!==id)return;
    if(result.error){message(result.error,true);return;}
    const fields=[['question_text','Soru'],['corrected_text','Cevap'],['tags','Etiketler'],['submission_note','Kontrol notu']];
    const snapshot=data=>fields.map(([field,label])=>`<h5>${label}</h5><pre dir="auto">${safe(Array.isArray(data[field])?data[field].join(', '):data[field]||'')}</pre>`).join('');
    const html=result.items.map(row=>`<details class="rw-revision"><summary>Sürüm ${row.version} · ${safe(actions[row.action]||row.action)} · ${safe(row.actorName)} · ${date(row.created_at)}</summary><h4>Önceki sürüm</h4>${snapshot(row.before_data)}<h4>Yeni sürüm</h4>${snapshot(row.after_data)}</details>`).join('');
    node('rwRevisionMore')?.remove();
    if(beforeVersion)node('rwRevisions').insertAdjacentHTML('beforeend',html);
    else node('rwRevisions').innerHTML=html||'<p>Bu kayıt için henüz sürüm değişikliği yok.</p>';
    if(result.nextVersion)node('rwRevisions').insertAdjacentHTML('beforeend',`<button class="btn-sec" id="rwRevisionMore" onclick="ReviewWorkspace.revisions(${Number(result.nextVersion)})">Önceki sürümler</button>`);
  }
  function card(row){
    return `<article class="rw-row"><div class="rw-row-main"><button class="rw-question" onclick="ReviewWorkspace.open('${row.id}')">${safe(row.questionText||'Soru eklenmemiş')}</button><div class="rw-meta"><span>İlk denetleyen: ${safe(row.name)}</span><span>${safe(labels[row.status]||row.status)}</span></div></div><button class="btn-sec rw-open" onclick="ReviewWorkspace.open('${row.id}')">İncele</button></article>`;
  }
  async function toggleFavorite(){
    if(busy||!management()||!item)return;
    const id=item.id,button=node('rwFavorite');button.disabled=true;
    const result=await api('POST',`/api/history/${id}/favorite`,{favorite:!item.favorite});
    if(item?.id!==id)return;
    button.disabled=false;
    if(result.error){message(result.error,true);return;}
    item.favorite=Boolean(result.favorite);button.textContent=item.favorite?'★':'☆';
    button.setAttribute('aria-pressed',String(item.favorite));
    button.title=button.ariaLabel=item.favorite?'Favorilerden çıkar':'Favoriye ekle';
    message(item.favorite?'Favoriye eklendi.':'Favorilerden çıkarıldı.');
  }
  window.addEventListener('beforeunload',event=>{if(dirty()||busy){event.preventDefault();event.returnValue='';}});
  document.addEventListener('keydown',event=>{
    if(!me?.reviewWorkspacesEnabled)return;
    const modal=node('detailModal');
    if(!modal?.classList.contains('open')||node('systemConfirmModal')?.classList.contains('open'))return;
    if(event.key==='Escape'){event.preventDefault();close();}
    if(event.key==='Tab'){
      const focusable=[...modal.querySelectorAll('button,input,textarea,select,summary,[tabindex="0"]')].filter(element=>!element.disabled&&element.getClientRects().length);
      const first=focusable[0],last=focusable.at(-1);
      if(event.shiftKey&&document.activeElement===first){event.preventDefault();last?.focus();}
      else if(!event.shiftKey&&document.activeElement===last){event.preventDefault();first?.focus();}
    }
  });
  document.addEventListener('DOMContentLoaded',()=>{
    const sidebar=document.querySelector('.side-nav'); if(sidebar)sidebar.insertAdjacentHTML('afterbegin',selectorHTML());
    const menu=node('mobileMenu'); if(menu)menu.insertAdjacentHTML('afterbegin',selectorHTML());
    document.querySelectorAll('[data-review-selector]').forEach(select=>select.hidden=true);
    refreshNav();
  });
  return {start,switchSpace,refreshNav,allowedTab,homeTab,load,filter,search,page,open,close,act,decide,revisions,card,prepareLogout,
    workspace:()=>space, isDetailOpen:()=>!!item, dirty};
})();
