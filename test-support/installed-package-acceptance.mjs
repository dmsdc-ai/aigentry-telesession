// Developer acceptance only: explicit installed artifact and private fixture daemon.
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import { createRequire } from 'node:module';
import { pathToFileURL } from 'node:url';
import { execFile } from 'node:child_process';
import assert from 'node:assert/strict';
const installed=process.env.TELESESSION_TEST_INSTALLED_PACKAGE;
if (!installed || !path.isAbsolute(installed) || !process.env.TELESESSION_TEST_TELEPTY_DIR || !path.isAbsolute(process.env.TELESESSION_TEST_TELEPTY_DIR)) {
 console.error('INSTALLED_ACCEPTANCE_REQUIRES_EXPLICIT_PACKAGE_AND_CANDIDATE');process.exit(2);
}
const root=fs.mkdtempSync(path.join(os.tmpdir(),'ts-installed-acceptance-'));fs.chmodSync(root,0o700);
const prefix=path.resolve(installed,'../../..');
const require=createRequire(path.join(installed,'package.json'));
const clientFile=require.resolve('@modelcontextprotocol/sdk/client/index.js');
assert.ok(fs.realpathSync(clientFile).startsWith(fs.realpathSync(prefix)+path.sep));
assert.ok(fs.realpathSync(installed).startsWith(fs.realpathSync(prefix)+path.sep));
const {Client}=await import(pathToFileURL(clientFile));
const {StdioClientTransport}=await import(pathToFileURL(require.resolve('@modelcontextprotocol/sdk/client/stdio.js')));
const H=await import('../test/helpers.js');
const home=H.makeTempHome('ts-installed-home-');
const bin=path.join(installed,'bin','telesession-mcp.js');
const invoke=args=>new Promise(resolve=>execFile(process.execPath,[bin,...args],{env:{PATH:process.env.PATH,...home.env},timeout:5000},(error,stdout,stderr)=>resolve({code:error?(Number.isInteger(error.code)?error.code:1):0,stdout,stderr})));
for(const flag of ['--help','--version']){const r=await invoke([flag]);assert.equal(r.code,0);}
assert.equal((await invoke(['--install'])).code,2);
let npmShimChecked=false;
if(process.platform!=='win32'){
 const shim=path.join(prefix,'node_modules','.bin','telesession-mcp');
 const result=await new Promise(resolve=>execFile(shim,['--help'],{env:{PATH:process.env.PATH,...home.env},timeout:5000},(error,stdout)=>resolve({error,stdout})));
 assert.equal(result.error,null);assert.match(result.stdout,/Usage: telesession-mcp/);npmShimChecked=true;
}
const daemon=await H.startTeleptyDaemon({orchestratorSids:'ts-orch'}),sink=await H.startAtermEndpoint();
let client;
const stderrFile=path.join(root,'installed-mcp-stderr.log'),fd=fs.openSync(stderrFile,'w',0o600);
try {
 const target=await H.registerAterm(daemon,'ts-orch',sink.endpoint);
 const tokenFile=path.join(home.dir,'fixture-token.json');fs.writeFileSync(tokenFile,JSON.stringify({authToken:daemon.token}),{mode:0o600});
 fs.mkdirSync(path.join(home.dir,'.local','state'),{recursive:true,mode:0o700});
 const stateDir=path.join(home.dir,'.local','state','telesession');
 const transport=new StdioClientTransport({command:process.execPath,args:[bin],cwd:home.dir,stderr:fd,env:{PATH:process.env.PATH,...home.env,
  TELESESSION_TELEPTY_URL:daemon.origin,TELESESSION_TELEPTY_TOKEN_FILE:tokenFile,TELESESSION_TARGETS:'ts-orch',TELESESSION_INBOX_PREFIX:'installed',TELESESSION_STATE_DIR:stateDir}});
 client=new Client({name:'isolated-install-acceptance',version:'0.0.0'});await client.connect(transport);
 const tools=await client.listTools();assert.equal(tools.tools.length,5);
 const call=async(name,args={})=>{const result=await client.callTool({name,arguments:args});const record=JSON.parse(result.content[0].text);assert.equal(record.completion_fact,null);return record;};
 const before=await H.listSessionIds(daemon);
 const health=await call('telesession_health');assert.deepEqual(health.telepty.capabilities_missing,[]);
 const targets=await call('telesession_list_targets');assert.deepEqual(targets.targets,[{id:'ts-orch',present:true}]);
 assert.deepEqual(await H.listSessionIds(daemon),before);
 const args={target:'ts-orch',text:'installed synthetic prompt',request_id:'installed-once'};
 const sent=await call('telesession_send',args);assert.equal(sent.accepted,true);assert.equal(sent.durability,'durable');
 const duplicate=await call('telesession_send',args);assert.equal(duplicate.nonce,sent.nonce);assert.equal(duplicate.deduplicated,true);
 await H.waitFor(()=>sink.received.length===1);
 const receipt=await call('telesession_receipt',{inject_id:sent.inject_id});assert.equal(receipt.ok,true);
 const response=await daemon.request('/api/sessions/'+encodeURIComponent(sent.reply_to)+'/inject',{method:'POST',sessionToken:target.bearer,body:{prompt:'REPLY '+sent.nonce+' installed synthetic reply',from:'ts-orch'}});assert.equal(response.status,200);
 const reply=await call('telesession_read_reply',{nonce:sent.nonce,wait_ms:8000});assert.equal(reply.reply,'trusted');assert.equal(reply.text,'REPLY '+sent.nonce+' installed synthetic reply');
 await client.close();client=null;
 await H.waitFor(async()=>!(await H.listSessionIds(daemon)).includes(sent.reply_to));assert.ok((await H.listSessionIds(daemon)).includes('ts-orch'));
 const state=fs.readFileSync(path.join(stateDir,'state.json'),'utf8');assert.ok(!state.includes(daemon.token));assert.ok(!state.includes(args.text));
 const stderr=fs.readFileSync(stderrFile,'utf8');assert.ok(!stderr.includes(daemon.token));assert.ok(!stderr.includes(target.bearer));
 console.log(JSON.stringify({installed_help_version:true,npm_bin_shim:npmShimChecked,unknown_args_refused:true,installed_dependency_tree:true,mcp_tools:tools.tools.length,health_missing_caps:0,read_only_health_targets:true,durable_send:true,request_id_no_resend:true,credential_verified_reply:true,owned_shutdown_cleanup:true,target_preserved:true,no_secret_or_prompt_in_state:true,remote_gateway_tested:false,mac_tested:false}));
} finally {if(client)await client.close();fs.closeSync(fd);await sink.close();await daemon.stop();home.remove();}
