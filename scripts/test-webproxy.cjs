const assert=require('node:assert/strict');
const fs=require('node:fs');
const path=require('node:path');
const vm=require('node:vm');
const {webcrypto}=require('node:crypto');
const root=path.resolve(__dirname,'..');
const secret='0123456789abcdef0123456789abcdef';
const web={server:'web.example.com',port:'',secret};
const mtp={server:'mtp.example.com',port:443,secret:'dd'+secret};
const pages=JSON.parse(fs.readFileSync(path.join(root,'public/pages.json'),'utf8'));
const files=['index.html',...pages.map(page=>path.join('public',page.url,'index.html'))];

async function verify(file){
  const source=fs.readFileSync(path.join(root,file),'utf8');
  let click;
  const button={addEventListener:(event,handler)=>{assert.equal(event,'click');click=handler;}};
  const container={querySelectorAll:()=>[button]};
  const context=vm.createContext({
    URLSearchParams,atob,btoa,TextDecoder,crypto:webcrypto,
    window:{location:{href:''}},
    Math,document:{getElementById:()=>container},
  });
  vm.runInContext(source.slice(source.indexOf('function prepareProxies('),source.indexOf('function loadProxies(')),context);
  vm.runInContext(source.slice(source.indexOf('function proxyConnectUrl('),source.indexOf('function toggleMobile(')),context);
  vm.runInContext(source.slice(source.indexOf('function shuffle('),source.indexOf('function togglePublicProxies(')),context);
  const encryptedStart=source.indexOf('var _0x3e=');
  vm.runInContext(source.slice(encryptedStart,source.indexOf('function shuffle(',encryptedStart)),context);
  const connect=p=>new URL(context.proxyConnectUrl(p));
  for(const candidate of [web,{...web,secret:'dd'+secret}]){
    const url=connect(candidate);
    assert.equal(url.protocol,'tg:');
    assert.equal(url.hostname,'webproxy');
    assert.equal(url.searchParams.get('server'),candidate.server);
    assert.equal(url.searchParams.get('secret'),candidate.secret);
    assert(!url.searchParams.has('port'));
  }
  for(const value of [secret,'dd'+secret]){
    const url=connect({...web,server:'web.example.com/My-App',secret:value});
    assert.equal(url.searchParams.get('server'),'web.example.com/My-App');
    assert.deepEqual(Buffer.from(url.searchParams.get('secret'),'base64url'),Buffer.concat([Buffer.from([0x70]),Buffer.from(value,'hex')]));
    assert(!url.searchParams.has('port'));
  }
  for(const port of [443,'443']){
    const url=connect({...mtp,port});
    assert.equal(url.hostname,'proxy');
    assert.equal(url.searchParams.get('port'),'443');
    assert.equal(url.searchParams.get('secret'),mtp.secret);
  }
  const prepared=context.prepareProxies([
    {host:web.server,country:'XX',port:'',secret,placement_id:'proxy_1',status:'online',highlight:true},
    {host:web.server,country:'XX',port:'',secret,placement_id:'proxy_1',status:'online'},
    {host:mtp.server,country:'DE',port:443,secret:mtp.secret,placement_id:'proxy_2',status:'offline'},
  ]);
  assert.equal(prepared.length,2);
  assert.equal(prepared[0].eventId,'proxy_1');
  assert.equal(prepared[0].port,'');
  assert.equal(prepared[0].highlight,true);
  context.bindProxyButtons(container,[prepared[0]]);
  click();
  assert.equal(new URL(context.window.location.href).hostname,'webproxy');
  context.bindProxyButtons(container,[prepared[1]]);
  click();
  assert.equal(new URL(context.window.location.href).hostname,'proxy');
  if(process.argv[2]){
    const encrypted=JSON.parse(fs.readFileSync(process.argv[2],'utf8'));
    const decoded=await context._0x7b(encrypted);
    const items=context.prepareProxies(decoded);
    const item=items.find(p=>p.port==='');
    assert(item);
    assert.equal(item.status,'online');
    assert.equal(item.eventId,'proxy_42');
    const url=connect(item);
    assert.equal(url.hostname,'webproxy');
    assert.equal(url.searchParams.get('server'),'web.example.com/My-App');
    assert.deepEqual(Buffer.from(url.searchParams.get('secret'),'base64url'),Buffer.concat([Buffer.from([0x70]),Buffer.from(secret,'hex')]));
  }
}

(async()=>{
  for(const file of files)await verify(file);
  console.log('PASS: WEB and MTProto connection routes, encoded base paths, click handlers, pin ordering, analytics IDs and optional encrypted API fixture in '+files.length+' pages.');
})().catch(error=>{console.error(error);process.exitCode=1;});
