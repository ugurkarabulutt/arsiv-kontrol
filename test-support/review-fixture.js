// Local verification only: synthetic records, in-memory PostgreSQL, no external services.
const express = require('express');
const fs = require('node:fs');
const path = require('node:path');
const { PGlite } = require('@electric-sql/pglite');
const { createReviewWorkflow } = require('../review-workflow');
const root = path.join(__dirname,'..');
const users = ['user','admin','super_admin'].map((role,i)=>({id:`10000000-0000-4000-8000-00000000000${i+1}`,role,username:role,name:`${role==='user'?'Ekip':role==='admin'?'Yönetici':'Süper Yönetici'} Örnek`,reviewWorkspacesEnabled:true}));
const mapHistory=h=>({id:h.id,userId:h.user_id,name:h.name,filename:h.filename,status:h.status,questionText:h.question_text,
  correctedText:h.corrected_text,originalText:h.original_text,tags:h.tags,submissionNote:h.submission_note,createdAt:h.created_at});

async function createFixture() {
  const db = new PGlite();
  const schema=fs.readFileSync(path.join(root,'schema.sql'),'utf8');
  await db.exec('create role anon; create role authenticated; create role service_role bypassrls;');
  for(const name of ['users','history','alerts','admin_action_log','public_categories','public_qa'])
    await db.exec(schema.match(new RegExp(`create table if not exists public\\.${name} \\([\\s\\S]*?\\n\\);`))[0]);
  await db.exec(fs.readFileSync(path.join(root,'supabase/migrations/20260906142527_admin_review_workspaces.sql'),'utf8'));
  await db.exec(fs.readFileSync(path.join(root,'supabase/migrations/20260906214233_review_submission_queue.sql'),'utf8'));
  await db.exec(fs.readFileSync(path.join(root,'supabase/migrations/20260907030328_review_status_queue_order.sql'),'utf8'));
  await db.exec(fs.readFileSync(path.join(root,'supabase/migrations/20260908195554_member_draft_safety.sql'),'utf8'));
  await db.exec(fs.readFileSync(path.join(root,'supabase/migrations/20260909122817_hide_legacy_chunk_drafts.sql'),'utf8'));
  await db.exec(fs.readFileSync(path.join(root,'supabase/migrations/20260912162000_member_duplicate_cleanup.sql'),'utf8'));
  await db.exec(fs.readFileSync(path.join(root,'supabase/migrations/20260913000100_review_special_holding_sections.sql'),'utf8'));
  await db.exec(fs.readFileSync(path.join(root,'supabase/migrations/20260913000200_management_can_approve_returned.sql'),'utf8'));
  for(const user of users)await db.query('insert into users(id,role,username,name,password) values($1,$2,$3,$4,$5)',[user.id,user.role,user.username,user.name,'test-only']);
  const rows=[];
  for(let i=0;i<65;i++){
    const user=users[i%3],status=i%4===0?'bekliyor':'geri_gonderildi';
    const h=(await db.query(`insert into history(user_id,username,name,filename,status,question_text,corrected_text,original_text,tags,submission_note)
      values($1,$2,$3,'Yerel test kaydı',$4,$5,$6,$7,'["Takva","İştiyak"]','Soru, cevap ve etiket kontrol edilecek.') returning *`,
      [user.id,user.username,user.name,status,`Kontrol sorusu ${i}: Uzun başlıkta Türkçe karakterler ve kelimeler düzgün görünüyor mu?`,
      `Bu bir test cevabıdır. Kayıt ${i}.\n\nنص عربي\nTürkçe meal.\n\nSon açıklama.`, 'İlk denetim metni.\n\nParagraf yapısı korunur.'])).rows[0];
    rows.push(h);
  }
  for(const [suffix,question,answer,meta] of [
    ['1','Silinebilir taslak örneği?','Taslak cevabı.','{}'],
    ['2','Geçmişi korunan taslak örneği?','Korumalı taslak cevabı.','{"memberDeleteProtected":true}'],
    ['3',rows[0].question_text,rows[0].corrected_text,'{}']
  ]) await db.query(`insert into history(id,user_id,name,status,question_text,corrected_text,original_text,tags,workflow_meta)
    values($1::uuid,$2,'Ekip Örnek','taslak',$3,$4,'Taslak test kaynağı '||($1::uuid)::text,'["Takva"]',$5)`,
    ['50000000-0000-4000-8000-00000000000'+suffix,users[0].id,question,answer,meta]);
  // Supabase read adapter for fixtures. Writes always execute the actual migration RPC.
  const value=(row,key)=>key.includes('->')?row[key.split(/->>?/)[0]]?.[key.split(/->>?/)[1]]:row[key];
  const supabase={from(table){
    if(!['users','history','public_qa','history_revisions','review_history_queue'].includes(table))throw Error('Unexpected fixture table');
    const filters=[],orders=[];let start=0,end=Infinity,single=false,columns=['*'];
    const b={select(fields='*'){columns=fields.split(',');return b;},eq(k,v){filters.push(r=>String(value(r,k))===String(v));return b;},neq(k,v){filters.push(r=>r[k]!==v);return b;},
      in(k,vs){filters.push(r=>vs.includes(r[k]));return b;},lt(k,v){filters.push(r=>r[k]<v);return b;},not(k,op,v){if(op!=='in')throw Error('Fixture operator');filters.push(r=>!v.slice(1,-1).split(',').includes(r[k]));return b;},
      or(expression){const rules=expression.split(',').map(part=>{const [field,op,...v]=part.split('.');const term=v.join('.');return r=>op==='eq'?r[field]===term:op==='ilike'?String(r[field]||'').toLocaleLowerCase('tr-TR').includes(term.replaceAll('%','').toLocaleLowerCase('tr-TR')):false;});filters.push(r=>rules.some(fn=>fn(r)));return b;},
      order(k,{ascending=true}={}){orders.push([k,ascending]);return b;},range(a,z){start=a;end=z+1;return b;},limit(n){end=n;return b;},maybeSingle(){single=true;return b;},
      async then(resolve,reject){try{let items=(await db.query(`select * from public.${table}`)).rows.filter(row=>filters.every(fn=>fn(row)));const count=items.length;
        items.sort((a,c)=>{for(const[k,ascending]of orders){const result=a[k] instanceof Date && c[k] instanceof Date ? a[k]-c[k] : String(a[k]||'').localeCompare(String(c[k]||''));if(result)return ascending?result:-result;}return 0;});
        items=items.slice(start,end);
        if(!columns.includes('*'))items=items.map(row=>Object.fromEntries(columns.map(field=>{const [alias,key]=field.split(':');return [alias,value(row,key||alias)];})));
        return resolve({data:single?(items[0]||null):items,count});}catch(error){return reject?reject(error):Promise.reject(error);}}};return b;},
    async rpc(name,p){try{
      if(name==='review_draft_protections')return {data:(await db.query('select * from review_draft_protections($1)',[p.p_ids])).rows};
      if(name==='review_find_existing_analysis')return {data:(await db.query('select review_find_existing_analysis($1,$2,$3) as value',[p.p_actor,p.p_text,p.p_hashes])).rows[0].value};
      const result=name==='review_history_change'
        ? await db.query('select review_history_change($1,$2,$3,$4,$5,$6) as value',[p.p_id,p.p_actor,p.p_version,p.p_workspace,p.p_action,JSON.stringify(p.p_payload)])
        : await db.query('select * from review_duplicate_candidates($1)',[p.p_id]);
      return {data:name==='review_history_change'?result.rows[0].value:result.rows};
    }catch(error){return {error};}}
  };
  const app=express();app.use(express.json());
  app.use((req,_res,next)=>{
    const role=req.get('X-Demo-Role')||String(req.headers.cookie||'').match(/reviewDemoRole=([^;]+)/)?.[1]||'admin';
    const user=users.find(u=>u.role===role)||users[1];req.demoUser=user;req.session={userId:user.id,role:user.role};next();
  });
  app.get('/api/auth/me',(req,res)=>res.json({...req.demoUser,loggedIn:true}));
  const review=createReviewWorkflow({supabase,mapHistory,loadApprovalReturnNotes:async()=>({}),attachApprovalReturnMeta:h=>h,
    clearPublicArchiveCaches:()=>{},analyzeText:async text=>({correctedText:text,score:100,totalErrors:0,categories:{},summary:'Yerel test, AI çağrısı yapılmadı.'}),analysisRateLimiter:(_req,_res,next)=>next()});
  app.use('/api/review',review.router);app.use('/api/history',review.legacy);
  app.get('/api/history/approval-board',(_req,res)=>res.json({groups:{}}));
  app.get('/api/stats',(_req,res)=>res.json({totals:{allTime:65,last30:65,activeUsers:3,avgScore:90,unreadAlerts:0,pendingApproval:17,feedbackOpen:0},
    daily:[{label:'05.09',count:30},{label:'06.09',count:35}]}));
  app.get('/api/my-notifications',(_req,res)=>res.json([]));
  app.get('/api/*',(_req,res)=>res.json({items:[],notifications:[],unread:0,total:0,count:0}));
  app.get('/health',(_req,res)=>res.json({ok:true,synthetic:true}));
  app.get('/admin',(_req,res)=>res.sendFile(path.join(root,'index.html')));
  app.get('/sw.js',(_req,res)=>res.type('js').send('self.addEventListener("install",()=>self.skipWaiting());'));
  for(const file of ['review-workspace.js','review-workspace.css'])app.get('/'+file,(_req,res)=>res.sendFile(path.join(root,file)));
  app.use('/icons',express.static(path.join(root,'icons')));
  return {app,db,rows,users,supabase};
}
module.exports={createFixture};
if(require.main===module){
  createFixture().then(({app,db})=>{
    const server=app.listen(Number(process.env.PORT||4317),'127.0.0.1',()=>console.log('SYNTHETIC REVIEW DEMO http://127.0.0.1:'+server.address().port+'/admin'));
    for(const signal of ['SIGINT','SIGTERM'])process.on(signal,()=>server.close(async()=>{await db.close();process.exit(0);}));
  }).catch(error=>{console.error(error);process.exit(1);});
}
