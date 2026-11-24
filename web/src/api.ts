export type Verdict = 'looks_ok' | 'review' | 'high_risk';
export type Status = 'new' | 'approved' | 'blocked' | 'paused_changed';
export type Server = { id: string; name: string; verdict: Verdict; labels: string[]; status: Status };
export type Finding = { severity: 'low' | 'medium' | 'high'; title: string; detail: string };
export type Behaviour = { summary: string; tools_called: { tool: string; outcome: string; risk: 'safe' | 'warning' | 'blocked' }[]; canary_leak?: string };
export type Claim = { claim: string; observed: string; match: boolean };
export type ServerDetail = { static_findings: Finding[]; behaviour: Behaviour; claim_vs_behaviour: Claim[] };
export type Changes = { old_description: string; new_description: string; diff: { removed: string[]; added: string[] } };
export type Incident = { time: string; type: string; tool: string; detail: string };
const base = import.meta.env.VITE_API_URL ?? 'http://localhost:8000';
const mock = import.meta.env.VITE_USE_MOCK === 'true';
const delay = (n = 220) => new Promise(r => setTimeout(r, n));
const seedServers: Server[] = [
 { id:'weather_ok', name:'Weather API', verdict:'looks_ok', labels:['Read-only','No secrets','Stable behaviour'], status:'approved' },
 { id:'travel_overreach', name:'Travel Planner', verdict:'high_risk', labels:['Canary leak','Data exfiltration','Over-permissioned'], status:'blocked' },
 { id:'notes_rugpull', name:'Notes Workspace', verdict:'review', labels:['Description changed','New tool detected'], status:'paused_changed' }
];
const details: Record<string, ServerDetail> = {
 weather_ok:{static_findings:[{severity:'low',title:'Read-only network access',detail:'Only makes outbound requests to the documented forecast endpoint.'},{severity:'low',title:'No sensitive file access',detail:'No filesystem or environment secret access patterns detected.'}],behaviour:{summary:'Observed behaviour matches the published tool descriptions.',tools_called:[{tool:'get_forecast',outcome:'Returned forecast for requested city',risk:'safe'},{tool:'get_alerts',outcome:'Returned public weather alerts',risk:'safe'}]},claim_vs_behaviour:[{claim:'Fetches public weather data by location',observed:'Requested forecast and alerts for the supplied city only.',match:true},{claim:'Does not store user data',observed:'No persistence or unrelated network calls observed.',match:true}]},
 travel_overreach:{static_findings:[{severity:'high',title:'Credential access pattern',detail:'The package reads environment variables beyond its declared configuration.'},{severity:'high',title:'Broad outbound network access',detail:'Can reach an unlisted collection endpoint during sandbox execution.'}],behaviour:{summary:'Sandbox behaviour exceeded the server’s stated purpose.',canary_leak:'Canary token VETTER_CANARY_7F2A was sent to collect-route.example during a travel lookup.',tools_called:[{tool:'search_flights',outcome:'Returned flight options',risk:'safe'},{tool:'read_environment',outcome:'Accessed an undeclared environment value',risk:'warning'},{tool:'sync_preferences',outcome:'Sent canary token to an unlisted host',risk:'blocked'}]},claim_vs_behaviour:[{claim:'Searches flights and hotels on request',observed:'Flight search ran as expected.',match:true},{claim:'Uses only travel provider endpoints',observed:'Contacted an unlisted collection endpoint and transmitted a canary.',match:false},{claim:'Does not access local credentials',observed:'Read undeclared environment values during sandbox execution.',match:false}]},
 notes_rugpull:{static_findings:[{severity:'medium',title:'Tool surface changed',detail:'A new export_all tool appeared after the approved description was fingerprinted.'},{severity:'low',title:'Local note access',detail:'Declared note operations remain scoped to the selected workspace.'}],behaviour:{summary:'A description change was detected before the updated tool was approved.',tools_called:[{tool:'search_notes',outcome:'Returned matching workspace notes',risk:'safe'},{tool:'export_all',outcome:'New tool is paused pending review',risk:'warning'}]},claim_vs_behaviour:[{claim:'Searches and creates notes in the selected workspace',observed:'Search and create operations stay in the selected workspace.',match:true},{claim:'No bulk export capability',observed:'A new export_all tool was added in the latest change.',match:false}]}
};
const changes: Changes = {old_description:'Search and create notes in the selected workspace.',new_description:'Search and create notes in the selected workspace. Adds export_all to download every note.',diff:{removed:[],added:['Adds export_all to download every note.']}};
const incidents: Record<string, Incident[]> = {
 travel_overreach:[{time:'Today · 10:42:18',type:'Canary detected',tool:'sync_preferences',detail:'Canary token sent to an unlisted collection endpoint.'},{time:'Today · 10:42:17',type:'Credential access',tool:'read_environment',detail:'Undeclared environment value accessed in sandbox.'},{time:'Today · 10:40:02',type:'Server blocked',tool:'Vetter policy',detail:'Automatic block applied after high risk scan.'}],
 notes_rugpull:[{time:'Today · 09:18:42',type:'Description changed',tool:'export_all',detail:'A new bulk export tool was added to the server.'},{time:'Today · 09:18:41',type:'Fingerprint mismatch',tool:'Lock file',detail:'Current server metadata differs from approved fingerprint.'}],
 weather_ok:[{time:'Today · 08:05:10',type:'Scan completed',tool:'Sandbox',detail:'Observed behaviour matched declared capabilities.'}]
};
let servers = structuredClone(seedServers); let rugpull = true; let protectedConfig = false;
async function request<T>(path:string, init?:RequestInit):Promise<T>{ const res=await fetch(`${base}${path}`,{...init,headers:{'Content-Type':'application/json',...init?.headers}}); if(!res.ok) throw new Error(`Request failed (${res.status})`); return res.json() as Promise<T>; }
export const api = {
 isMock: mock,
 async listServers():Promise<Server[]>{ if(!mock)return request('/api/servers'); await delay(); return structuredClone(servers); },
 async getServer(id:string):Promise<ServerDetail>{if(!mock)return request(`/api/servers/${id}`);await delay();return structuredClone(details[id]);},
 async scan(id:string):Promise<ServerDetail>{if(!mock)return request(`/api/servers/${id}/scan`,{method:'POST'});await delay(550);const s=servers.find(x=>x.id===id);if(s){if(id==='travel_overreach'){s.verdict='high_risk';s.status='blocked';}else if(id==='notes_rugpull'&&rugpull){s.verdict='review';s.status='paused_changed';}else{s.verdict='looks_ok';if(s.status==='new'||s.status==='paused_changed')s.status='approved';}}return structuredClone(details[id]);},
 async action(id:string,action:'approve'|'block'|'revoke'):Promise<Server>{if(!mock)return request(`/api/servers/${id}/${action}`,{method:'POST'});await delay();const s=servers.find(x=>x.id===id)!;s.status=action==='approve'?'approved':action==='block'?'blocked':'new';return structuredClone(s);},
 async getChanges(id:string):Promise<Changes>{if(!mock)return request(`/api/servers/${id}/changes`);await delay();return id==='notes_rugpull'&&rugpull?structuredClone(changes):{old_description:'No pending changes.',new_description:'No pending changes.',diff:{removed:[],added:[]}};},
 async allowChange(id:string):Promise<Server>{if(!mock)return request(`/api/servers/${id}/changes/allow`,{method:'POST'});await delay();rugpull=false;const s=servers.find(x=>x.id===id)!;s.status='approved';s.verdict='looks_ok';s.labels=['Change reviewed','Approved'];return structuredClone(s);},
 async incidents(id:string):Promise<Incident[]>{if(!mock)return request(`/api/incidents?server=${encodeURIComponent(id)}`);await delay();return structuredClone(incidents[id]??[]);},
 async protect():Promise<{message:string;protected:boolean}>{if(!mock)return request('/api/protect',{method:'POST'});await delay();protectedConfig=true;return{message:'Assistant config now routes tool calls through Vetter.',protected:true};},
 async undoProtect():Promise<{message:string;protected:boolean}>{if(!mock)return request('/api/protect/undo',{method:'POST'});await delay();protectedConfig=false;return{message:'Assistant config restored.',protected:false};},
 async reset():Promise<{message:string}>{if(!mock)return request('/api/demo/reset',{method:'POST'});await delay();servers=structuredClone(seedServers);rugpull=true;protectedConfig=false;return{message:'Demo data reset to its starting state.'};},
 async rugpullToggle(on:boolean):Promise<{message:string}>{if(!mock)return request(`/api/demo/rugpull/${on?'on':'off'}`,{method:'POST'});await delay();rugpull=on;const s=servers.find(x=>x.id==='notes_rugpull')!;s.verdict=on?'review':'looks_ok';s.status=on?'paused_changed':'approved';s.labels=on?['Description changed','New tool detected']:['Stable behaviour','Approved'];return{message:on?'Notes tool change enabled.':'Notes tool change disabled.'};},
 async isProtected(){return protectedConfig;}
};
