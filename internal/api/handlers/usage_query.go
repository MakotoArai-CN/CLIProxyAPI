package handlers

import (
	"net/http"
	"strings"
	"sync"

	"github.com/gin-gonic/gin"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/usage"
)

// UsageQueryHandler serves the per-API-key usage query endpoint and the self-service HTML page.
type UsageQueryHandler struct {
	mu  sync.RWMutex
	cfg *config.Config
}

// NewUsageQueryHandler creates a new usage query handler.
func NewUsageQueryHandler(cfg *config.Config) *UsageQueryHandler {
	return &UsageQueryHandler{cfg: cfg}
}

// SetConfig updates the config reference on hot-reload.
func (h *UsageQueryHandler) SetConfig(cfg *config.Config) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.cfg = cfg
}

// getConfig returns the current config safely.
func (h *UsageQueryHandler) getConfig() *config.Config {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.cfg
}

// isKeyAllowed checks whether the given API key is in the usage-query-keys whitelist.
func (h *UsageQueryHandler) isKeyAllowed(apiKey string) bool {
	cfg := h.getConfig()
	if cfg == nil || len(cfg.UsageQueryKeys) == 0 {
		return false
	}
	for _, k := range cfg.UsageQueryKeys {
		if strings.TrimSpace(k) == apiKey {
			return true
		}
	}
	return false
}

// maskAPIKey returns a masked version of the API key for display purposes.
// Shows the first 4 and last 4 characters with dots in between.
func maskAPIKey(key string) string {
	if len(key) <= 8 {
		return strings.Repeat("*", len(key))
	}
	return key[:4] + "..." + key[len(key)-4:]
}

// usageQueryResponse is the JSON response for the usage query endpoint.
type usageQueryResponse struct {
	APIKeyMasked  string                         `json:"api_key_masked"`
	TotalRequests int64                          `json:"total_requests"`
	SuccessCount  int64                          `json:"success_count"`
	FailureCount  int64                          `json:"failure_count"`
	TotalTokens   int64                          `json:"total_tokens"`
	Models        map[string]usage.ModelSnapshot `json:"models"`
	RequestsByDay map[string]int64               `json:"requests_by_day"`
	TokensByDay   map[string]int64               `json:"tokens_by_day"`
}

// GetUsage returns usage statistics filtered to the authenticated API key.
func (h *UsageQueryHandler) GetUsage(c *gin.Context) {
	apiKey, exists := c.Get("apiKey")
	if !exists || apiKey == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "missing api key"})
		return
	}
	key, ok := apiKey.(string)
	if !ok || key == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid api key"})
		return
	}

	if !h.isKeyAllowed(key) {
		c.JSON(http.StatusForbidden, gin.H{"error": "this api key is not allowed to query usage"})
		return
	}

	stats := usage.GetRequestStatistics()
	if stats == nil {
		c.JSON(http.StatusOK, usageQueryResponse{APIKeyMasked: maskAPIKey(key)})
		return
	}

	snapshot := stats.Snapshot()
	apiSnapshot, found := snapshot.APIs[key]

	resp := usageQueryResponse{
		APIKeyMasked:  maskAPIKey(key),
		RequestsByDay: make(map[string]int64),
		TokensByDay:   make(map[string]int64),
	}

	if found {
		resp.TotalRequests = apiSnapshot.TotalRequests
		resp.TotalTokens = apiSnapshot.TotalTokens
		resp.Models = apiSnapshot.Models

		// Compute per-key success/failure counts and per-day breakdowns from model details
		for _, modelSnap := range apiSnapshot.Models {
			for _, detail := range modelSnap.Details {
				if detail.Failed {
					resp.FailureCount++
				} else {
					resp.SuccessCount++
				}
				dayKey := detail.Timestamp.Format("2006-01-02")
				resp.RequestsByDay[dayKey]++
				resp.TokensByDay[dayKey] += detail.Tokens.TotalTokens
			}
		}
	}

	c.JSON(http.StatusOK, resp)
}

// ServeUsageQueryPage serves the self-contained HTML page for usage querying.
func (h *UsageQueryHandler) ServeUsageQueryPage(c *gin.Context) {
	cfg := h.getConfig()
	if cfg == nil || len(cfg.UsageQueryKeys) == 0 {
		c.AbortWithStatus(http.StatusNotFound)
		return
	}

	c.Header("Content-Type", "text/html; charset=utf-8")
	c.Header("Cache-Control", "no-cache, no-store, must-revalidate")
	c.String(http.StatusOK, usageQueryHTML)
}

// usageQueryHTML is the self-contained HTML page for usage querying.
// The API key is only sent via Authorization header, never exposed in URLs.
// Features: Glassmorphism UI, animated gradients, Vocaloid character theme switcher.
const usageQueryHTML = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Usage Dashboard - CLIProxyAPI</title>
<style>
:root{
--c1:#39c5bb;--c2:#86e3ce;--c3:#2a9d8f;
--bg1:#0c1821;--bg2:#162032;
--glass:rgba(255,255,255,.04);--glass-border:rgba(255,255,255,.08);
--text:#e8edf4;--text-dim:#8899aa;--text-muted:#556677;
}
*{margin:0;padding:0;box-sizing:border-box}
@keyframes gradientShift{0%,100%{background-position:0% 50%}50%{background-position:100% 50%}}
@keyframes fadeUp{from{opacity:0;transform:translateY(16px)}to{opacity:1;transform:translateY(0)}}
@keyframes pulse{0%,100%{opacity:.6}50%{opacity:1}}
@keyframes shimmer{0%{background-position:-200% 0}100%{background-position:200% 0}}
@keyframes float{0%,100%{transform:translateY(0)}50%{transform:translateY(-6px)}}
body{
font-family:'Inter',-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;
background:var(--bg1);color:var(--text);min-height:100vh;overflow-x:hidden;
}
body::before{
content:'';position:fixed;top:-50%;left:-50%;width:200%;height:200%;
background:radial-gradient(ellipse at 20% 50%,color-mix(in srgb,var(--c1) 12%,transparent),transparent 50%),
radial-gradient(ellipse at 80% 20%,color-mix(in srgb,var(--c2) 8%,transparent),transparent 50%),
radial-gradient(ellipse at 50% 80%,color-mix(in srgb,var(--c3) 6%,transparent),transparent 50%);
animation:gradientShift 20s ease infinite;background-size:200% 200%;z-index:0;pointer-events:none;
}
.wrapper{position:relative;z-index:1;max-width:960px;margin:0 auto;padding:2rem 1.25rem 4rem}

/* Theme Switcher */
.theme-bar{
display:flex;justify-content:center;gap:.5rem;margin-bottom:2rem;flex-wrap:wrap;
animation:fadeUp .5s ease both;
}
.theme-btn{
width:38px;height:38px;border-radius:50%;border:2.5px solid transparent;cursor:pointer;
transition:all .3s cubic-bezier(.4,0,.2,1);position:relative;overflow:hidden;
}
.theme-btn:hover{transform:scale(1.18);box-shadow:0 0 20px color-mix(in srgb,var(--btn-c) 50%,transparent)}
.theme-btn.active{border-color:#fff;transform:scale(1.15);box-shadow:0 0 24px color-mix(in srgb,var(--btn-c) 60%,transparent)}
.theme-btn::after{
content:attr(data-label);position:absolute;bottom:-22px;left:50%;transform:translateX(-50%);
font-size:.6rem;color:var(--text-dim);white-space:nowrap;opacity:0;transition:opacity .2s;pointer-events:none;
}
.theme-btn:hover::after{opacity:1}

/* Header */
.header{text-align:center;margin-bottom:2rem;animation:fadeUp .5s ease .1s both}
.header h1{
font-size:1.6rem;font-weight:700;letter-spacing:-.02em;
background:linear-gradient(135deg,var(--c1),var(--c2));
-webkit-background-clip:text;-webkit-text-fill-color:transparent;background-clip:text;
}
.header p{color:var(--text-dim);font-size:.85rem;margin-top:.35rem}

/* Glass panels */
.glass{
background:var(--glass);backdrop-filter:blur(24px);-webkit-backdrop-filter:blur(24px);
border:1px solid var(--glass-border);border-radius:16px;
}

/* Query box */
.query-box{
padding:1.25rem;margin-bottom:1.5rem;display:flex;gap:.75rem;align-items:center;flex-wrap:wrap;
animation:fadeUp .5s ease .2s both;
}
.input-wrap{flex:1;min-width:220px;position:relative}
.input-wrap input{
width:100%;padding:.8rem 1rem .8rem 2.6rem;border-radius:12px;
border:1px solid var(--glass-border);background:rgba(0,0,0,.3);
color:var(--text);font-size:.9rem;outline:none;transition:all .3s;
}
.input-wrap input:focus{border-color:var(--c1);box-shadow:0 0 0 3px color-mix(in srgb,var(--c1) 15%,transparent)}
.input-wrap input::placeholder{color:var(--text-muted)}
.input-wrap svg{position:absolute;left:.85rem;top:50%;transform:translateY(-50%);width:16px;height:16px;color:var(--text-muted)}
.query-btn{
padding:.8rem 2rem;border-radius:12px;border:none;font-size:.9rem;font-weight:600;cursor:pointer;
color:#fff;background:linear-gradient(135deg,var(--c1),var(--c3));
transition:all .3s cubic-bezier(.4,0,.2,1);white-space:nowrap;letter-spacing:.02em;
}
.query-btn:hover{transform:translateY(-1px);box-shadow:0 8px 24px color-mix(in srgb,var(--c1) 30%,transparent)}
.query-btn:active{transform:translateY(0)}
.query-btn:disabled{opacity:.4;cursor:not-allowed;transform:none;box-shadow:none}

/* Error */
.error-box{
background:rgba(220,38,38,.12);border:1px solid rgba(220,38,38,.25);color:#fca5a5;
padding:1rem 1.25rem;border-radius:12px;margin-bottom:1rem;display:none;
font-size:.88rem;animation:fadeUp .3s ease both;
}

/* Stats */
.stats{display:none}
.stats.visible{display:block}

/* Cards grid */
.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:.75rem;margin-bottom:1.25rem}
.card{
padding:1.25rem 1rem;text-align:center;position:relative;overflow:hidden;
animation:fadeUp .4s ease both;transition:transform .3s,box-shadow .3s;
}
.card:hover{transform:translateY(-3px);box-shadow:0 12px 32px rgba(0,0,0,.2)}
.card::before{
content:'';position:absolute;top:0;left:0;right:0;height:2px;
background:linear-gradient(90deg,transparent,var(--c1),transparent);opacity:.6;
}
.card .label{font-size:.7rem;color:var(--text-dim);text-transform:uppercase;letter-spacing:.08em;margin-bottom:.6rem;font-weight:500}
.card .value{font-size:1.6rem;font-weight:800;color:var(--text);letter-spacing:-.02em}
.card .value.accent{color:var(--c1)}
.card .value.success{color:#34d399}
.card .value.fail{color:#f87171}
.card .value.key-val{font-size:1rem;color:var(--c2);font-family:'JetBrains Mono',monospace;word-break:break-all}

/* Sections */
.section{padding:1.25rem;margin-bottom:1rem;animation:fadeUp .4s ease both}
.section-title{
display:flex;align-items:center;gap:.5rem;font-size:.85rem;font-weight:600;color:var(--text-dim);
margin-bottom:1rem;padding-bottom:.6rem;border-bottom:1px solid var(--glass-border);text-transform:uppercase;letter-spacing:.06em;
}
.section-title svg{width:16px;height:16px;color:var(--c1)}

/* Table */
table{width:100%;border-collapse:collapse;font-size:.82rem}
th{text-align:left;padding:.6rem .75rem;color:var(--text-muted);font-weight:600;font-size:.72rem;text-transform:uppercase;letter-spacing:.06em}
td{padding:.65rem .75rem;border-top:1px solid var(--glass-border);color:var(--text-dim);transition:all .2s}
tr:hover td{color:var(--text);background:rgba(255,255,255,.02)}
td:first-child{color:var(--c2);font-family:'JetBrains Mono',monospace;font-size:.8rem}

/* Bar chart */
.bar-chart{display:flex;flex-direction:column;gap:.5rem}
.bar-row{display:flex;align-items:center;gap:.75rem;animation:fadeUp .3s ease both}
.bar-label{min-width:80px;font-size:.75rem;color:var(--text-dim);text-align:right;font-family:'JetBrains Mono',monospace}
.bar-track{flex:1;height:26px;background:rgba(0,0,0,.25);border-radius:8px;overflow:hidden;position:relative}
.bar-fill{
height:100%;border-radius:8px;transition:width .6s cubic-bezier(.4,0,.2,1);min-width:3px;position:relative;
background:linear-gradient(90deg,var(--c1),var(--c2));
}
.bar-fill::after{
content:'';position:absolute;inset:0;
background:linear-gradient(90deg,transparent,rgba(255,255,255,.15),transparent);
background-size:200% 100%;animation:shimmer 2s linear infinite;
}
.bar-value{min-width:70px;font-size:.78rem;color:var(--text-dim);font-family:'JetBrains Mono',monospace}

/* Footer */
.footer{text-align:center;margin-top:2rem;color:var(--text-muted);font-size:.72rem;animation:fadeUp .5s ease .6s both}
.footer a{color:var(--c1);text-decoration:none}
.footer a:hover{text-decoration:underline}

/* Loading spinner */
.spinner{display:inline-block;width:16px;height:16px;border:2px solid rgba(255,255,255,.3);border-top-color:#fff;border-radius:50%;animation:spin .6s linear infinite;vertical-align:middle;margin-right:.4rem}
@keyframes spin{to{transform:rotate(360deg)}}

/* Responsive */
@media(max-width:600px){
.cards{grid-template-columns:repeat(2,1fr)}
.card .value{font-size:1.3rem}
.wrapper{padding:1rem .75rem 3rem}
.header h1{font-size:1.3rem}
}
</style>
</head>
<body>
<div class="wrapper">

<div class="theme-bar" id="themeBar">
<button class="theme-btn active" data-theme="miku" data-label="Miku" style="background:linear-gradient(135deg,#39c5bb,#86e3ce);--btn-c:#39c5bb" onclick="setTheme('miku')"></button>
<button class="theme-btn" data-theme="rin" data-label="Rin" style="background:linear-gradient(135deg,#f5c518,#fde68a);--btn-c:#f5c518" onclick="setTheme('rin')"></button>
<button class="theme-btn" data-theme="len" data-label="Len" style="background:linear-gradient(135deg,#d4a017,#facc15);--btn-c:#d4a017" onclick="setTheme('len')"></button>
<button class="theme-btn" data-theme="luka" data-label="Luka" style="background:linear-gradient(135deg,#f472b6,#fda4af);--btn-c:#f472b6" onclick="setTheme('luka')"></button>
<button class="theme-btn" data-theme="kaito" data-label="KAITO" style="background:linear-gradient(135deg,#3b82f6,#93c5fd);--btn-c:#3b82f6" onclick="setTheme('kaito')"></button>
<button class="theme-btn" data-theme="meiko" data-label="MEIKO" style="background:linear-gradient(135deg,#dc2626,#f87171);--btn-c:#dc2626" onclick="setTheme('meiko')"></button>
<button class="theme-btn" data-theme="gumi" data-label="GUMI" style="background:linear-gradient(135deg,#22c55e,#86efac);--btn-c:#22c55e" onclick="setTheme('gumi')"></button>
<button class="theme-btn" data-theme="ia" data-label="IA" style="background:linear-gradient(135deg,#e8d5eb,#f5e6f8);--btn-c:#d4b8d9" onclick="setTheme('ia')"></button>
</div>

<div class="header">
<h1>Usage Dashboard</h1>
<p>Query your API key usage statistics</p>
</div>

<div class="query-box glass">
<div class="input-wrap">
<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0110 0v4"/></svg>
<input type="password" id="apiKeyInput" placeholder="Enter your API Key..." autocomplete="off">
</div>
<button class="query-btn" id="queryBtn" onclick="queryUsage()">Query</button>
</div>

<div class="error-box" id="errorBox"></div>

<div class="stats" id="statsBox">
<div class="cards">
<div class="card glass" style="animation-delay:.1s"><div class="label">API Key</div><div class="value key-val" id="statKey">-</div></div>
<div class="card glass" style="animation-delay:.15s"><div class="label">Total Requests</div><div class="value accent" id="statRequests">0</div></div>
<div class="card glass" style="animation-delay:.2s"><div class="label">Success</div><div class="value success" id="statSuccess">0</div></div>
<div class="card glass" style="animation-delay:.25s"><div class="label">Failed</div><div class="value fail" id="statFail">0</div></div>
<div class="card glass" style="animation-delay:.3s"><div class="label">Total Tokens</div><div class="value accent" id="statTokens">0</div></div>
</div>

<div class="section glass" id="modelSection" style="animation-delay:.35s">
<div class="section-title">
<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 16V8a2 2 0 00-1-1.73l-7-4a2 2 0 00-2 0l-7 4A2 2 0 003 8v8a2 2 0 001 1.73l7 4a2 2 0 002 0l7-4A2 2 0 0021 16z"/></svg>
Usage by Model
</div>
<table><thead><tr><th>Model</th><th>Requests</th><th>Tokens</th></tr></thead><tbody id="modelTable"></tbody></table>
</div>

<div class="section glass" id="daySection" style="animation-delay:.4s">
<div class="section-title">
<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="4" width="18" height="18" rx="2" ry="2"/><line x1="16" y1="2" x2="16" y2="6"/><line x1="8" y1="2" x2="8" y2="6"/><line x1="3" y1="10" x2="21" y2="10"/></svg>
Requests by Day
</div>
<div class="bar-chart" id="dayChart"></div>
</div>

<div class="section glass" id="tokenDaySection" style="animation-delay:.45s">
<div class="section-title">
<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="22 12 18 12 15 21 9 3 6 12 2 12"/></svg>
Tokens by Day
</div>
<div class="bar-chart" id="tokenDayChart"></div>
</div>
</div>

<div class="footer">Powered by <a href="https://github.com/router-for-me/CLIProxyAPI" target="_blank">CLIProxyAPI</a></div>
</div>

<script>
const themes={
miku:{c1:'#39c5bb',c2:'#86e3ce',c3:'#2a9d8f'},
rin:{c1:'#f5c518',c2:'#fde68a',c3:'#ca8a04'},
len:{c1:'#d4a017',c2:'#facc15',c3:'#a16207'},
luka:{c1:'#f472b6',c2:'#fda4af',c3:'#db2777'},
kaito:{c1:'#3b82f6',c2:'#93c5fd',c3:'#1d4ed8'},
meiko:{c1:'#dc2626',c2:'#f87171',c3:'#991b1b'},
gumi:{c1:'#22c55e',c2:'#86efac',c3:'#15803d'},
ia:{c1:'#d4b8d9',c2:'#f5e6f8',c3:'#9333ea'}
};
function setTheme(name){
const t=themes[name]||themes.miku;
const r=document.documentElement.style;
r.setProperty('--c1',t.c1);r.setProperty('--c2',t.c2);r.setProperty('--c3',t.c3);
document.querySelectorAll('.theme-btn').forEach(b=>{b.classList.toggle('active',b.dataset.theme===name)});
try{localStorage.setItem('cpa-theme',name)}catch(e){}
}
try{const saved=localStorage.getItem('cpa-theme');if(saved&&themes[saved])setTheme(saved)}catch(e){}

const $=id=>document.getElementById(id);
const input=$('apiKeyInput'),btn=$('queryBtn'),errBox=$('errorBox'),statsBox=$('statsBox');
input.addEventListener('keydown',e=>{if(e.key==='Enter')queryUsage()});

async function queryUsage(){
const key=input.value.trim();
if(!key){showError('Please enter your API Key');return}
errBox.style.display='none';statsBox.classList.remove('visible');
btn.disabled=true;btn.innerHTML='<span class="spinner"></span>Querying...';
try{
const resp=await fetch('/v1/usage',{method:'GET',headers:{'Authorization':'Bearer '+key}});
if(!resp.ok){const body=await resp.json().catch(()=>({}));showError(body.error||('Request failed: HTTP '+resp.status));return}
renderStats(await resp.json());
}catch(e){showError('Network error: '+e.message)}
finally{btn.disabled=false;btn.textContent='Query'}
}
function showError(msg){errBox.textContent=msg;errBox.style.display='block';statsBox.classList.remove('visible')}
function fmtNum(n){return n==null?'0':n.toLocaleString()}

function renderStats(d){
statsBox.classList.add('visible');
$('statKey').textContent=d.api_key_masked||'-';
$('statRequests').textContent=fmtNum(d.total_requests);
$('statSuccess').textContent=fmtNum(d.success_count);
$('statFail').textContent=fmtNum(d.failure_count);
$('statTokens').textContent=fmtNum(d.total_tokens);
const tbody=$('modelTable');tbody.innerHTML='';
const models=d.models||{},names=Object.keys(models).sort();
if(!names.length){tbody.innerHTML='<tr><td colspan="3" style="text-align:center;color:var(--text-muted);padding:1.5rem">No model data yet</td></tr>'}
else{names.forEach(n=>{const m=models[n],tr=document.createElement('tr');tr.innerHTML='<td>'+esc(n)+'</td><td>'+fmtNum(m.total_requests)+'</td><td>'+fmtNum(m.total_tokens)+'</td>';tbody.appendChild(tr)})}
renderBarChart($('dayChart'),d.requests_by_day||{});
renderBarChart($('tokenDayChart'),d.tokens_by_day||{});
}
function renderBarChart(el,data){
el.innerHTML='';const entries=Object.entries(data).sort((a,b)=>a[0].localeCompare(b[0]));
if(!entries.length){el.innerHTML='<div style="text-align:center;color:var(--text-muted);padding:1rem">No data yet</div>';return}
const max=Math.max(...entries.map(e=>e[1]),1);
entries.forEach(([label,value],i)=>{
const pct=(value/max*100).toFixed(1);const row=document.createElement('div');row.className='bar-row';row.style.animationDelay=(i*.05)+'s';
row.innerHTML='<div class="bar-label">'+esc(label)+'</div><div class="bar-track"><div class="bar-fill" style="width:'+pct+'%"></div></div><div class="bar-value">'+fmtNum(value)+'</div>';
el.appendChild(row)});
}
function esc(s){const d=document.createElement('div');d.textContent=s;return d.innerHTML}
</script>
</body>
</html>` + "\n"
