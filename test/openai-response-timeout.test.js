const {test}=require('node:test');
const assert=require('node:assert/strict');
const http=require('node:http');
const fs=require('node:fs');
const vm=require('node:vm');
const source=fs.readFileSync(require.resolve('../server.js'),'utf8');
test('findings-only response reconstructs the complete answer from its source',()=>{
  const {finalizeResult}=require('../analysis-core');
  const text='Dua, kulun Allah’a yönelmesidir.\n\nİnsan Rabbinden yardım ister.';
  const result=finalizeResult({correctedText:'',categories:{}},text);
  assert.ok(result.correctedText.length>0);
  assert.ok(result.correctedText.includes('İnsan Rabbinden yardım ister.'));
  assert.ok(result.correctedText.includes('\n\n'));
});
const start=source.indexOf('async function fetchOpenAIChatCompletion(');
const end=source.indexOf('\n}',start)+2;
function client(url){
  return vm.runInNewContext(source.slice(start,end)+';fetchOpenAIChatCompletion',{
    fetch,AbortController,setTimeout,clearTimeout,
    OPENAI_CHAT_URL:url,OPENAI_API_KEY:'test',OPENAI_TIMEOUT_MS:100,
    OPENAI_RETRY_DELAYS_MS:[],OPENAI_RETRYABLE_STATUS:new Set([429,500,502,503,504]),
    AI_TEMPORARY_UNAVAILABLE_MSG:'temporary',console:{warn(){}},
    safeJson:async r=>{try{return await r.json();}catch{return {};}},
    httpError:(message,statusCode)=>Object.assign(new Error(message),{statusCode}),
    openaiUserMessage:()=> 'provider error',sleep:ms=>new Promise(resolve=>setTimeout(resolve,ms))
  });
}
test('OpenAI deadline includes stalled response body after headers arrive',async()=>{
  const server=http.createServer((_req,res)=>{res.writeHead(200,{'Content-Type':'application/json'});res.flushHeaders();res.write('{"choices":');});
  await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));
  try{
    await assert.rejects(client('http://127.0.0.1:'+server.address().port)({},'test',{timeoutMs:80,retryDelays:[]}),error=>error.statusCode===504);
  }finally{server.closeAllConnections();await new Promise(resolve=>server.close(resolve));}
});
test('OpenAI bounded retry permits transient failure without unbounded requests',async()=>{
  let calls=0;
  const server=http.createServer((_req,res)=>{
    calls++;res.writeHead(calls===1?503:200,{'Content-Type':'application/json'});
    res.end(JSON.stringify(calls===1?{error:{message:'unavailable'}}:{choices:[{message:{content:'{}'}}]}));
  });
  await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));
  try{
    const result=await client('http://127.0.0.1:'+server.address().port)({},'test',{timeoutMs:1000,retryDelays:[1]});
    assert.equal(calls,2);assert.equal(result.choices.length,1);
  }finally{server.closeAllConnections();await new Promise(resolve=>server.close(resolve));}
});
