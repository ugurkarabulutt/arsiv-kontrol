const fs=require('node:fs');
const path=require('node:path');
const crypto=require('node:crypto');
const assert=require('node:assert/strict');
const {execFileSync}=require('node:child_process');
const root=path.join(__dirname,'..');
const deployment=process.argv[2];
const production=process.argv.includes('--production');
assert.match(deployment||'',/^https:\/\/(?:[a-z0-9-]+\.vercel\.app|arsiv\.ibrahimlive\.ai)$/);
const output=path.join(root,production?'.tmp-review-production-smoke':'.tmp-review-smoke');fs.mkdirSync(output,{recursive:true});
const hash=buffer=>crypto.createHash('sha256').update(buffer).digest('hex');
function request(route,name,extra=[]){
  const file=path.join(output,name+'.body'),headers=path.join(output,name+'.headers');
  execFileSync('vercel.cmd',['curl',route,'--deployment',deployment,'--','--silent','--show-error','--output',file,'--dump-header',headers,...extra],{cwd:root,shell:true,stdio:'pipe',timeout:90000});
  const header=fs.readFileSync(headers,'utf8');const status=Number([...header.matchAll(/HTTP\/\S+ (\d+)/g)].at(-1)?.[1]);
  return {status,header,body:fs.readFileSync(file)};
}
const results=[];
for(const [route,name,file] of [['/admin','admin','index.html'],['/review-workspace.js?v=1','script','review-workspace.js'],['/review-workspace.css?v=1','style','review-workspace.css']]){
  const response=request(route,name);assert.equal(response.status,200);
  assert.equal(hash(response.body),hash(fs.readFileSync(path.join(root,file))));
  assert.match(response.header,/cache-control:.*no-store/i);
  if(name==='admin')assert.match(response.header,/x-robots-tag:.*noindex/i);
  results.push({route,status:response.status,sha256:hash(response.body)});
}
const health=request('/health','health');assert.equal(health.status,200);results.push({route:'/health',status:health.status});
const session=request('/api/auth/me','session');assert.equal(JSON.parse(session.body).loggedIn,false);
const records=request('/api/review/records','records');assert.equal(records.status,401);results.push({route:'/api/review/records',status:records.status});
const write=request('/api/review/readonly-probe','write',['--request','POST']);
assert.equal(write.status,production?401:403);
if(!production)assert.match(JSON.parse(write.body).error,/Bu önizlemede kayıt değişiklikleri kapalı/);
results.push({route:'POST readonly-probe',status:write.status});
if(production){
  const home=request('/','home');assert.equal(home.status,200);
  assert.match(home.body.toString(),/<meta name="robots" content="index,follow"/);
  assert.match(home.body.toString(),/<link rel="canonical" href="https:\/\/arsiv\.ibrahimlive\.ai\/"/);
  assert.match(home.body.toString(),/class="pa-/);
  results.push({route:'/',status:home.status,publicRoot:true,indexFollow:true});
  for(const route of ['/arsiv','/arama','/hesabim','/soru-sor','/sitemap.xml','/robots.txt']){
    const response=request(route,route.slice(1));assert.equal(response.status,200);
    if(route==='/sitemap.xml')assert.match(response.body.toString(),/<(?:urlset|sitemapindex)\b/);
    if(route==='/robots.txt')assert.match(response.body.toString(),/Sitemap: https:\/\/arsiv\.ibrahimlive\.ai\/sitemap.xml/);
    results.push({route,status:response.status});
  }
}
fs.writeFileSync(path.join(output,'results.json'),JSON.stringify({deployment,production,checkedAt:new Date().toISOString(),results},null,2));
console.log(JSON.stringify({deployment,results},null,2));
