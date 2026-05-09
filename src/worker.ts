interface Env { IMMUNE_KV: KVNamespace; DEEPSEEK_API_KEY?: string; GITHUB_TOKEN?: string; }

const CSP: Record<string, string> = { 'default-src': "'self'", 'script-src': "'self' 'unsafe-inline' 'unsafe-eval'", 'style-src': "'self' 'unsafe-inline' https://fonts.googleapis.com", 'font-src': "'self' https://fonts.gstatic.com", 'img-src': "'self' data: https:", 'connect-src': "'self' https://api.deepseek.com https://api.github.com https://*'" };

function json(data: unknown, s = 200) { return new Response(JSON.stringify(data), { status: s, headers: { 'Content-Type': 'application/json', ...CSP } }); }

function getLanding(): string {
  return `<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Fleet Immune — Cocapn</title><style>
body{font-family:system-ui,sans-serif;background:#0a0a0f;color:#e0e0e0;margin:0;min-height:100vh}
.container{max-width:800px;margin:0 auto;padding:40px 20px}
h1{color:#ef4444;font-size:2.2em}a{color:#ef4444;text-decoration:none}
.sub{color:#8A93B4;margin-bottom:2em}
.card{background:#16161e;border:1px solid #2a2a3a;border-radius:12px;padding:24px;margin:20px 0}
.card h3{color:#ef4444;margin:0 0 12px 0}
.threat{background:#1a0a0a;border-left:3px solid #ef4444;padding:12px;margin:8px 0;border-radius:0 8px 8px 0}
.threat .sev{font-weight:bold}.sev-high{color:#ef4444}.sev-med{color:#f59e0b}.sev-low{color:#22c55e}
.btn{background:#ef4444;color:#fff;border:none;padding:10px 20px;border-radius:8px;cursor:pointer;font-weight:bold}
.btn:hover{background:#dc2626}
textarea,select,input{background:#0a0a0f;color:#e0e0e0;border:1px solid #2a2a3a;border-radius:8px;padding:10px}
.stats{display:grid;grid-template-columns:repeat(4,1fr);gap:12px;margin:20px 0}
.stat{text-align:center;padding:16px;background:#16161e;border-radius:8px;border:1px solid #2a2a3a}
.stat .num{font-size:2em;color:#ef4444;font-weight:bold}.stat .label{color:#8A93B4;font-size:.8em}
</style></head><body><div class="container">
<h1>🛡 Fleet Immune</h1><p class="sub">Collective threat detection and vaccine distribution across the fleet.</p>
<div class="stats"><div class="stat"><div class="num" id="totalReports">0</div><div class="label">Reports</div></div>
<div class="stat"><div class="num" id="activeThreats">0</div><div class="label">Active Threats</div></div>
<div class="stat"><div class="num" id="vaccines">0</div><div class="label">Vaccines</div></div>
<div class="stat"><div class="num" id="coverage">0%</div><div class="label">Coverage</div></div></div>
<div class="card"><h3>Report Anomaly</h3>
<textarea id="anomaly" rows="2" placeholder="Describe the anomaly..." style="width:100%;box-sizing:border-box"></textarea>
<div style="margin-top:12px;display:flex;gap:8px">
<select id="severity"><option value="low">Low</option><option value="medium" selected>Medium</option><option value="high">High</option></select>
<input id="vessel" placeholder="Reporting vessel" style="flex:1">
<button class="btn" onclick="report()">Report</button></div></div>
<div id="threats" class="card"><h3>Active Threats</h3><p style="color:#8A93B4">Loading...</p></div>
<div id="vaccineList" class="card"><h3>Vaccines</h3><p style="color:#8A93B4">Loading...</p></div>
<script>
async function load(){try{const r=await fetch('/api/stats');const s=await r.json();
document.getElementById('totalReports').textContent=s.total||0;
document.getElementById('activeThreats').textContent=s.threats||0;
document.getElementById('vaccines').textContent=s.vaccines||0;
document.getElementById('coverage').textContent=(s.coverage||0)+'%';}catch(e){}
try{const r=await fetch('/api/threats');const t=await r.json();
const el=document.getElementById('threats');
if(!t.length){el.innerHTML='<h3>Active Threats</h3><p style="color:#8A93B4">No active threats. Fleet is healthy.</p>';return;}
el.innerHTML='<h3>Active Threats</h3>'+t.map(x=>'<div class="threat"><span class="sev sev-'+x.severity+'">'+x.severity.toUpperCase()+'</span> <strong>'+x.pattern+'</strong><br><span style="color:#8A93B4;font-size:.85em">'+x.count+' reports · '+x.vessels+' vessels affected · '+x.date+'</span></div>').join('');}catch(e){}
try{const r=await fetch('/api/vaccines');const v=await r.json();
const el=document.getElementById('vaccineList');
if(!v.length){el.innerHTML='<h3>Vaccines</h3><p style="color:#8A93B4">No vaccines distributed yet.</p>';return;}
el.innerHTML='<h3>Vaccines</h3>'+v.map(x=>'<div style="padding:8px;background:#0a0f0a;border-left:3px solid #22c55e;margin:8px 0;border-radius:0 8px 8px 0"><strong>'+x.pattern+'</strong><br><span style="color:#22c55e;font-size:.85em">'+x.vaccine+'</span></div>').join('');}catch(e){}}
async function report(){const a=document.getElementById('anomaly').value.trim();if(!a)return;
const s=document.getElementById('severity').value;const v=document.getElementById('vessel').value.trim()||'unknown';
await fetch('/api/report',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({anomaly:a,severity:s,vessel:v})});
document.getElementById('anomaly').value='';load();}
load();</script>
<div style="text-align:center;padding:24px;color:#475569;font-size:.75rem"><a href="https://the-fleet.casey-digennaro.workers.dev" style="color:#64748b">The Fleet</a> · <a href="https://cocapn.ai" style="color:#64748b">Cocapn</a></div>
</div></body></html>`;
}

interface Report { anomaly: string; severity: string; vessel: string; ts: string; }
interface Threat { pattern: string; severity: string; count: number; vessels: string[]; date: string; }
interface Vaccine { pattern: string; vaccine: string; confidence: number; }

const securityHeaders = {
  'Content-Security-Policy': "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' https://fonts.gstatic.com; img-src 'self' data: https:; frame-ancestors 'none'",
  'X-Frame-Options': 'DENY',
};

export default {
  async fetch(request: Request): Promise<Response> {
    const url = new URL(request.url);
    if (url.pathname === '/health') {
      return new Response(JSON.stringify({ status: 'ok', timestamp: new Date().toISOString() }), {
        headers: { 'Content-Type': 'application/json', ...securityHeaders }
      });
    }
    return new Response(html, {
      headers: { 'Content-Type': 'text/html;charset=UTF-8', ...securityHeaders }
    });
  }
};
