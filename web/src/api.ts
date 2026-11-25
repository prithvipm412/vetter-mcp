export type Verdict = 'looks_ok' | 'review' | 'high_risk' | null;
export type Status = 'new' | 'approved' | 'blocked' | 'paused_changed';
export type Server = { id: string; name: string; verdict: Verdict; labels: string[]; status: Status; sandbox_supported?: boolean };
export type Finding = { category: string; severity: 'low' | 'medium' | 'high'; label: string; detail: string; tool_name?: string | null };
export type FileAccess = { path: string; is_decoy: boolean };
export type CanaryLeak = { leaked: boolean; secret?: string | null; destination?: string | null };
export type ToolCallOutcome = { tool: string; arguments: Record<string, unknown>; ok: boolean; error?: string | null };
export type Behaviour = { declared_tools: { name: string; description: string }[]; detected_actions: string[]; extra_tools: string[]; files_opened: FileAccess[]; network_destinations: string[]; canary_leak: CanaryLeak | null; tool_calls: ToolCallOutcome[]; sandbox_error?: string | null; sandbox_mode?: 'docker' | 'lite' | null };
export type ClaimVsBehaviour = { stated_purpose: string; capability_match: boolean; mismatches: string[] };
export type ServerDetail = { static_findings: Finding[]; behaviour: Behaviour; claim_vs_behaviour: ClaimVsBehaviour };
export type ServerScanResult = Server & ServerDetail & { sandbox_mode?: 'docker' | 'lite' | null };
export type Changes = { old_description: string | null; new_description: string | null; diff: string };
export type Incident = { time: string; type: string; tool: string | null; detail: string };
export type ConfigChange = { server: string; before: { command?: string; args?: string[] }; after: { command?: string; args?: string[] } };
export type ProtectResult = { status: string; message?: string; path?: string; changed?: ConfigChange[] };
export type ImportedTool = { id?: string; name: string; sandbox_supported?: boolean; sandbox?: string; language?: string; verdict?: Verdict; status?: Status; [key: string]: unknown };
export type ImportSource = { path: string; found: boolean; servers_imported: string[] };
export type ImportResult = { tools?: ImportedTool[]; servers?: ImportedTool[]; imported_tools?: ImportedTool[]; sources?: ImportSource[]; count?: number; found?: number; imported_count?: number; [key: string]: unknown };

const base = import.meta.env.VITE_API_URL ?? 'http://localhost:8000';
const mock = import.meta.env.VITE_USE_MOCK === 'true';
const delay = (n = 220) => new Promise(r => setTimeout(r, n));
const seedServers: Server[] = [
 { id:'weather_ok', name:'Weather', verdict:'looks_ok', labels:['Only public weather data','No access to local files'], status:'approved', sandbox_supported:true },
 { id:'travel_overreach', name:'Travel Planner', verdict:'high_risk', labels:['Hidden instructions to the AI','Can read your SSH keys','Can contact unknown servers'], status:'blocked', sandbox_supported:true },
 { id:'notes_rugpull', name:'Notes Saver', verdict:'review', labels:['Adds unapproved bulk export','Description changed'], status:'paused_changed', sandbox_supported:false }
];
const emptyBehaviour = { declared_tools:[], detected_actions:[], extra_tools:[], files_opened:[], network_destinations:[], canary_leak:null, tool_calls:[] } satisfies Behaviour;
const details: Record<string, ServerDetail> = {
 weather_ok:{static_findings:[{category:'permissions',severity:'low',label:'Read-only network access',detail:'Only makes outbound requests to the documented forecast endpoint.'},{category:'filesystem',severity:'low',label:'No sensitive file access',detail:'No filesystem or environment secret access patterns detected.'}],behaviour:{...structuredClone(emptyBehaviour),declared_tools:[{name:'get_forecast',description:'Fetch public forecast data by location.'},{name:'get_alerts',description:'Fetch weather alerts for a location.'}],detected_actions:['Requested forecast for the supplied city','Requested public weather alerts'],claim_vs_behaviour:undefined} as unknown as Behaviour,claim_vs_behaviour:{stated_purpose:'Fetch public weather data by location.',capability_match:true,mismatches:[]}},
 travel_overreach:{static_findings:[{category:'credentials',severity:'high',label:'Credential access pattern',detail:'The package reads environment variables beyond its declared configuration.'},{category:'network',severity:'high',label:'Broad outbound network access',detail:'Can reach an unlisted collection endpoint during sandbox execution.'}],behaviour:{...structuredClone(emptyBehaviour),declared_tools:[{name:'search_flights',description:'Search flight options for a destination.'}],detected_actions:['Read a decoy SSH key','Sent a canary to collect.unknown-domain.test'],extra_tools:[],files_opened:[{path:'/home/assistant/.ssh/id_rsa',is_decoy:true}],network_destinations:['travel-provider.example','collect.unknown-domain.test'],canary_leak:{leaked:true,secret:'SSH key',destination:'collect.unknown-domain.test'},tool_calls:[{tool:'search_flights',arguments:{destination:'Lisbon'},ok:true},{tool:'sync_preferences',arguments:{},ok:false,error:'Blocked after a canary leak'}]},claim_vs_behaviour:{stated_purpose:'Searches flights and hotels on request.',capability_match:false,mismatches:['Read a decoy SSH key outside the stated purpose.','Contacted collect.unknown-domain.test and sent the canary.']}},
 notes_rugpull:{static_findings:[{category:'tools',severity:'medium',label:'Tool surface changed',detail:'A new export_all tool appeared after the approved description was fingerprinted.'},{category:'filesystem',severity:'low',label:'Local note access',detail:'Declared note operations remain scoped to the selected workspace.'}],behaviour:{...structuredClone(emptyBehaviour),declared_tools:[{name:'search_notes',description:'Search notes in the selected workspace.'}],detected_actions:['Added export_all after approval'],extra_tools:['export_all'],tool_calls:[{tool:'search_notes',arguments:{query:'trip'},ok:true}]},claim_vs_behaviour:{stated_purpose:'Searches and creates notes in the selected workspace.',capability_match:false,mismatches:['Added an unapproved bulk export tool.']}}
};
const changes: Changes = {old_description:'Search and create notes in the selected workspace.',new_description:'Search and create notes in the selected workspace.\nAdds export_all to download every note.',diff:'@@ -1 +1,2 @@\n Search and create notes in the selected workspace.\n+Adds export_all to download every note.'};
const incidents: Record<string, Incident[]> = {
 travel_overreach:[{time:'',type:'canary_leak',tool:'sync_preferences',detail:'Canary token sent to an unlisted collection endpoint.'},{time:'',type:'call_blocked',tool:'sync_preferences',detail:'Vetter blocked the call after detecting a canary leak.'}],
 notes_rugpull:[{time:'',type:'drift_detected',tool:'export_all',detail:'A new bulk export tool was added to the server.'}],
 weather_ok:[]
};
let servers = structuredClone(seedServers); let rugpull = true;
async function request<T>(path:string, init?:RequestInit):Promise<T>{ const res=await fetch(`${base}${path}`,{...init,headers:{'Content-Type':'application/json',...init?.headers}}); if(!res.ok) throw new ApiError(`Request failed (${res.status})`,res.status); if(res.status===204)return undefined as T; const body=await res.text();return body?JSON.parse(body) as T:undefined as T; }
export class ApiError extends Error { constructor(message:string,readonly status:number){super(message);this.name='ApiError';} }
export const api = {
 async listServers():Promise<Server[]>{ if(!mock)return request('/api/servers'); await delay(); return structuredClone(servers); },
 async getServer(id:string):Promise<ServerDetail>{if(!mock)return request(`/api/servers/${id}`);await delay();return structuredClone(details[id]);},
 async scan(id:string):Promise<ServerScanResult>{if(!mock)return request(`/api/servers/${id}/scan`,{method:'POST'});await delay(2600);const s=servers.find(x=>x.id===id);if(!s)throw new ApiError('Server was not found',404);if(id==='travel_overreach'){s.verdict='high_risk';s.status='blocked';}else if(id==='notes_rugpull'&&rugpull){s.verdict='high_risk';s.status='paused_changed';}else{s.verdict='looks_ok';if(s.status==='new'||s.status==='paused_changed')s.status='approved';}return structuredClone({...s,...details[id]});},
 async action(id:string,action:'approve'|'block'|'revoke'):Promise<Server>{if(!mock)return request(`/api/servers/${id}/${action}`,{method:'POST'});await delay();const s=servers.find(x=>x.id===id);if(!s)throw new ApiError('Server was not found',404);s.status=action==='approve'?'approved':action==='block'?'blocked':'new';return structuredClone(s);},
 async getChanges(id:string):Promise<Changes>{if(!mock)return request(`/api/servers/${id}/changes`);await delay();return id==='notes_rugpull'&&rugpull?structuredClone(changes):{old_description:null,new_description:null,diff:''};},
 async allowChange(id:string):Promise<Server>{if(!mock)return request(`/api/servers/${id}/changes/allow`,{method:'POST'});await delay();rugpull=false;const s=servers.find(x=>x.id===id);if(!s)throw new ApiError('Server was not found',404);s.status='approved';s.verdict='looks_ok';return structuredClone(s);},
 async incidents(id:string):Promise<Incident[]>{if(!mock)return request(`/api/incidents?server=${id}`);await delay();return structuredClone(incidents[id]??[]);},
 async protect():Promise<ProtectResult>{if(!mock)return request('/api/protect',{method:'POST'});await delay();return{status:'protected',path:'claude_desktop_config.json',changed:[{server:'weather',before:{command:'weather-mcp',args:['--stdio']},after:{command:'vetter-proxy',args:['--server','weather','--','weather-mcp','--stdio']}}]};},
 async undoProtect():Promise<ProtectResult>{if(!mock)return request('/api/protect/undo',{method:'POST'});await delay();return{status:'restored',path:'claude_desktop_config.json'};},
 async reset():Promise<{status:string}>{if(!mock)return request('/api/demo/reset',{method:'POST'});await delay();servers=structuredClone(seedServers);rugpull=true;return{status:'reset'};},
 async rugpullToggle(on:boolean):Promise<unknown>{if(!mock)return request(`/api/demo/rugpull/${on?'on':'off'}`,{method:'POST'});await delay();rugpull=on;const s=servers.find(x=>x.id==='notes_rugpull');if(s){s.verdict=on?'review':'looks_ok';s.status=on?'paused_changed':'approved';s.labels=on?['Adds unapproved bulk export','Description changed']:['Only accesses selected notes','Stable behaviour'];}return{rugpull:on};},
 async importAssistant():Promise<ImportResult>{if(!mock)return request('/api/import',{method:'POST'});await delay(650);return{tools:[{id:'weather_ok',name:'Weather',sandbox_supported:true},{id:'travel_overreach',name:'Travel Planner',sandbox_supported:true},{id:'notes_rugpull',name:'Notes Saver',sandbox_supported:false}]};}
};
