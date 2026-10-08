"""The Query view of the offline report: a BQL console with highlighting, completion and a library.

The engine is `BQL` (bql_js.py); this is only the front end. Left, a library of ready queries built
from this model (its busiest endpoint, a code-only one, ...), pins and history. Right, the editor
with live syntax colouring and completion, then the results as a sortable table, or as chains
for graph paths.
"""

QRY_CSS = r"""
/* ask: one box for plain questions and BQL */
.m-ask{padding:26px 32px 50px}
.askx{max-width:none}
.atabs{display:flex;gap:4px;margin:16px 0 10px;border-bottom:1px solid var(--line)}
.atab{font:600 12.5px var(--sans);padding:8px 14px;border:0;background:none;color:var(--muted);border-bottom:2px solid transparent;margin-bottom:-1px}
.atab.on{color:var(--text);border-bottom-color:var(--signal)}
.achips{display:flex;flex-wrap:wrap;gap:8px;margin-bottom:6px}
.achip{font:500 13px var(--sans);padding:7px 13px;border-radius:999px;border:1px solid var(--line2);background:var(--panel);color:var(--text);max-width:100%}
.achip.mono{font:500 12px var(--mono)}
.achip:hover{border-color:var(--signal)}
.achip small{color:var(--faint);margin-left:6px;font-size:11px}
.qed{margin-top:4px;position:relative;border:1px solid var(--line2);border-radius:12px;background:var(--panel);box-shadow:var(--shadow)}
.qed:focus-within{border-color:var(--signal)}
.qed .hl,.qed textarea{font:14px/1.6 var(--mono);padding:14px 16px;margin:0;white-space:pre-wrap;word-wrap:break-word;overflow-wrap:break-word;min-height:76px;letter-spacing:0;tab-size:2}
.qed .hl{position:absolute;inset:0;pointer-events:none;color:var(--text);overflow:hidden}
.qed textarea{position:relative;display:block;width:100%;height:76px;resize:vertical;border:0;background:transparent;color:transparent;caret-color:var(--signal);outline:none}
.qed textarea::selection{background:rgba(232,80,2,.28);color:transparent}
.hl .f{color:var(--observed)}.hl .o{color:var(--inferred)}.hl .v{color:var(--ok)}.hl .n{color:var(--warn)}.hl .k{color:var(--signal);font-weight:700}.hl .vb{color:var(--l3);font-weight:700}.hl .p{color:var(--faint)}
.qbar2{display:flex;align-items:center;gap:8px;padding:8px 10px;border-top:1px solid var(--line);background:var(--panel2);border-radius:0 0 12px 12px}
.qbar2 .hint{color:var(--faint);font:11.5px var(--mono);margin-right:auto}
.qbar2 kbd{font:600 10.5px var(--mono);border:1px solid var(--line2);border-bottom-width:2px;border-radius:4px;padding:0 5px;background:var(--panel);color:var(--muted)}
.qrun2{height:32px;padding:0 18px;border:1px solid var(--signal);border-radius:8px;background:var(--signal);color:#fff;font:700 13px var(--sans);display:inline-flex;align-items:center;gap:7px}
.qrun2:hover{filter:brightness(1.07)}
.qbtn{height:32px;padding:0 11px;border:1px solid var(--line2);border-radius:8px;background:var(--panel);color:var(--muted);font:600 12px var(--sans)}
.qbtn:hover{color:var(--text)}
.qac{position:absolute;left:14px;top:calc(100% + 4px);z-index:30;min-width:260px;max-width:420px;background:var(--panel);border:1px solid var(--line2);border-radius:10px;box-shadow:var(--shadow);padding:4px;max-height:260px;overflow:auto}
.qac button{display:flex;gap:10px;width:100%;text-align:left;padding:6px 9px;border:0;background:none;border-radius:6px;font:12.5px var(--mono);color:var(--text);align-items:baseline}
.qac button.on,.qac button:hover{background:var(--signal-soft)}
.qac .dd{color:var(--faint);font:11px var(--sans);margin-left:auto;white-space:nowrap}
.qerr2{margin-top:14px;padding:12px 14px;border:1px solid var(--bad);border-left-width:4px;border-radius:10px;background:var(--panel);color:var(--bad);font:13px/1.5 var(--mono)}
.qerr2 .tip{display:block;color:var(--muted);font:12px var(--sans);margin-top:4px}
.qres{margin-top:16px;display:flex;flex-direction:column;min-height:0}
.qst{display:flex;align-items:center;gap:8px;flex-wrap:wrap;margin-bottom:10px;font:12px var(--mono);color:var(--muted)}
.qst b{color:var(--text)}
.qst .sp{flex:1}
.qfacets{display:flex;gap:6px;flex-wrap:wrap;margin-bottom:10px}
.qf{font:600 11px var(--mono);padding:3px 9px;border-radius:999px;border:1px solid var(--line2);background:var(--panel);color:var(--muted)}
.qf:hover{border-color:var(--signal);color:var(--text)}
.qf b{color:var(--text)}
.qtab{border:1px solid var(--line);border-radius:12px;background:var(--panel);overflow:auto;max-height:calc(100vh - 360px);min-height:120px}
.qtab table{font:12.5px var(--mono)}
.qtab th{position:sticky;top:0;z-index:2}
.qtab td{max-width:520px;overflow-wrap:anywhere;vertical-align:top}
.qtab tbody tr:nth-child(even){background:var(--panel3)}
.qtab tr.rowclick{cursor:pointer}
.qtab .sg{color:var(--ok)}.qtab .sy{color:var(--warn)}.qtab .sr{color:var(--bad)}.qtab .sb{color:var(--observed)}
.qtab .st2{font-weight:700}
.qtab .ob{color:var(--ok)}.qtab .in{color:var(--inferred)}.qtab .ex{color:var(--l6)}
.qtab .evl{color:var(--signal);font-weight:700}
.qpaths{display:flex;flex-direction:column;gap:12px}
.qpath{border:1px solid var(--line);border-radius:12px;background:var(--panel);padding:14px 16px}
.qpath .ph2{font:600 10.5px var(--mono);letter-spacing:.08em;text-transform:uppercase;color:var(--faint);margin-bottom:10px}
.qchain{display:flex;flex-wrap:wrap;align-items:center;gap:6px 4px}
.qn{font:600 12px var(--mono);padding:5px 10px;border-radius:8px;background:var(--panel2);border:1px solid var(--line2)}
.qa{font:600 10.5px var(--mono);color:var(--c,var(--muted));display:inline-flex;align-items:center;gap:3px;padding:0 4px}
.qa::after{content:"→";font-size:14px}
.qa.ob{--c:var(--observed)}.qa.in{--c:var(--inferred)}.qa.ex{--c:var(--l6)}
.qref{margin-top:14px;padding:16px 18px;border:1px solid var(--line);border-radius:12px;background:var(--panel);font:12.5px/1.7 var(--mono);color:var(--muted)}
.qref b{color:var(--text)}
.qref .row{display:grid;grid-template-columns:110px 1fr;gap:12px;padding:4px 0;border-bottom:1px solid var(--line)}
.qref .row:last-child{border:0}
.qempty{margin-top:24px;padding:30px;border:1px dashed var(--line2);border-radius:14px;text-align:center;color:var(--faint);font-size:13px}
.qempty .big{font:700 15px var(--sans);color:var(--muted);margin-bottom:6px}
"""

QRY_JS = r"""
/* ---------- QUERY (BQL console) ---------- */
let qText="",qRes=null,qErr=null,qHist=[],qMs=0,qSort=null;
try{qHist=JSON.parse(localStorage.getItem("b2m-qhist")||"[]");}catch(e){}
const qSave=()=>{try{localStorage.setItem("b2m-qhist",JSON.stringify(qHist));}catch(e){}};
function qRun(text){
  qText=text;qErr=null;qRes=null;qSort=null;
  if(!BQLDB){qErr="This report was built without graph.db. Rebuild with burp2model to enable queries.";return;}
  const t0=performance.now();
  try{qRes=BQL.run(BQLDB,text);qMs=performance.now()-t0;
    qHist=[text].concat(qHist.filter(x=>x!==text)).slice(0,15);qSave();
  }catch(e){qErr=e instanceof BQL.BQLError?e.message:"error: "+e.message;}
}
/* ready queries, filled in from this model so they work the first time */
function qLibrary(){
  const so=EP.find(e=>e.state==="STATIC_ONLY"),busy=[...EP].sort((a,b)=>b.requests-a.requests)[0],pv=EP.find(e=>e.privileged&&e.requests>0),
        post=EP.find(e=>e.method!=="GET"&&e.method!=="*"&&e.requests>0)||busy;
  const lab=e=>e?e.label:null;
  const g=[
   ["Requests",[
    ["POST requests that did not fail","req.method:POST AND resp.code.lt:400","every state-changing call that worked"],
    ["Client and server errors","resp.code.gte:400","4xx and 5xx responses"],
    ["API traffic","req.path.cont:\"/api/\"","anything under /api/"],
    ["Set-Cookie responses","resp.header.cont:\"set-cookie\"","who hands out cookies"],
    ["Mentions of tokens or traces","resp.body.regex:\"stack ?trace|exception|token\"","masked bodies, searched"]]],
   ["Nodes and edges",[
    ["Endpoints named only in code","node.type:endpoint AND node.state:STATIC_ONLY","never called in this capture"],
    ["Everything one role reached","node.role:"+((D.roles||[])[0]||"user"),"nodes tagged with a role"],
    ["Inferred edges","edge.state:INFERRED limit 50","references read from code"]]],
   ["Paths",[]],
   ["Model",[["Open questions","unknowns","what the capture could not answer"],["Stats","stats","counts for this graph"]]]];
  if(post)g[2][1].push(["How "+lab(post)+" is reached","reach \""+lab(post)+"\"","entry point to endpoint"]);
  if(busy&&busy!==post)g[2][1].push(["Blast radius of "+lab(busy),"blast \""+lab(busy)+"\" depth 2","what it touches"]);
  if(so)g[2][1].push(["Who references "+lab(so),"upstream \""+lab(so)+"\"","scripts and pages naming it"]);
  if(pv)g[2][1].push(["Neighbours of "+lab(pv),"neighbors \""+lab(pv)+"\"","one hop each way"]);
  if(!g[2][1].length)g.splice(2,1);
  if(BQLDB&&BQLDB.osint)g.push(["Recon",[["TLS","osint tls","certificate facts"],["Hosts seen only via recon","node.type:subdomain AND node.attr.seen_in_capture:0","never visited"]]]);
  return g;
}
const Q_FIELDS=[
 ["req.method","request method"],["req.host","request host"],["req.path","request path"],["req.template","templated path"],["req.header","request headers"],["req.body","request body"],
 ["resp.code","status code (gte, lt…)"],["resp.mime","response type"],["resp.header","response headers"],["resp.body","response body"],["role","role that sent it"],["id","evidence id"],
 ["node.type","node kind"],["node.label","node label"],["node.id","node id"],["node.layer","layer 1-6"],["node.source","traffic, code or recon"],["node.role","roles that reached it"],["node.state","BOTH · STATIC_ONLY · RUNTIME_ONLY"],["node.evidence","evidence ids"],["node.attr.","any node attribute"],
 ["edge.type","edge kind"],["edge.state","OBSERVED · INFERRED · EXTERNAL"],["edge.src","source id"],["edge.dst","target id"],["edge.src.type","source kind"],["edge.dst.type","target kind"],["edge.src.label","source label"],["edge.dst.label","target label"]];
const Q_VERBS=[["reach","how a node is reached"],["blast","what a node touches"],["upstream","what leads to a node"],["neighbors","one hop each way"],["path","a to b"],["osint","recon facts"],["unknowns","open questions"],["stats","graph counts"],["help","the language"],["AND",""],["OR",""],["NOT",""],["limit","cap the rows"]];
const Q_OPS=[["cont","contains"],["ncont","does not contain"],["eq","equals"],["ne","not equal"],["like","wildcard *"],["regex","regular expression"],["gt","greater"],["gte","greater or equal"],["lt","less"],["lte","less or equal"]];
function qValues(field){
  const u=a=>[...new Set(a.filter(Boolean))].sort();
  if(/^req\.method/.test(field))return u(EVL.map(e=>e.method));
  if(/^req\.host|^host/.test(field))return u(EVL.map(e=>e.host));
  if(/^role|^node\.role/.test(field))return u(D.roles||[]);
  if(/^resp\.mime/.test(field))return u(EVL.map(e=>e.mime));
  if(/^node\.type/.test(field))return u((D.graph.nodes||[]).map(n=>n.type));
  if(/^node\.state/.test(field))return ["BOTH","STATIC_ONLY","RUNTIME_ONLY"];
  if(/^edge\.state/.test(field))return ["OBSERVED","INFERRED","EXTERNAL"];
  if(/^edge\.type/.test(field))return u((D.graph.edges||[]).map(e=>e.type));
  if(/^resp\.code/.test(field))return ["200","301","401","403","404","500"];
  return [];
}
/* syntax colouring: one pass, tokens never overlap */
function qHighlight(t){
  const re=/("(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*')|\b([A-Za-z_][\w.\-]*)(:)("(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*'|[^\s()]*)|\b(AND|OR|NOT)\b|\b(reach|blast|upstream|neighbors|path|osint|unknowns|stats|help|limit|depth|to)\b|(\d+)|([()])/g;
  let out="",i=0,m;
  while((m=re.exec(t))){
    out+=esc(t.slice(i,m.index));i=re.lastIndex;
    if(m[1])out+=`<span class="v">${esc(m[1])}</span>`;
    else if(m[2]){const parts=m[2].split(".");let op="";if(parts.length>1&&Q_OPS.some(o=>o[0]===parts[parts.length-1]))op=parts.pop();
      out+=`<span class="f">${esc(parts.join("."))}</span>${op?`<span class="o">.${esc(op)}</span>`:""}<span class="p">:</span><span class="${/^["']/.test(m[4])||isNaN(+m[4])?"v":"n"}">${esc(m[4])}</span>`;}
    else if(m[5])out+=`<span class="k">${m[5]}</span>`;
    else if(m[6])out+=`<span class="vb">${m[6]}</span>`;
    else if(m[7])out+=`<span class="n">${m[7]}</span>`;
    else out+=`<span class="p">${esc(m[8])}</span>`;
  }
  return out+esc(t.slice(i))+"\n";
}
function qCell2(col,v,row){
  if(Array.isArray(v))v=v.join(", ");if(v==null)return "";
  if(col==="status"||col==="code"){const n=+v,c=n>=500?"sr":n>=400?"sy":n>=300?"sb":n>=200?"sg":"";return `<span class="st2 ${c}">${esc(v)}</span>`;}
  if(col==="method")return methodm(String(v));
  if(col==="state")return `<span class="${v==="OBSERVED"?"ob":v==="INFERRED"?"in":v==="EXTERNAL"?"ex":""}">${esc(v)}</span>`;
  if(col==="ev"||col==="evidence")return `<span class="evl">${esc(String(v).replace(/\bev_(\d+)/g,"EVD $1"))}</span>`;
  return esc(String(v));
}
function qCsv(r){const q=s=>'"'+String(s==null?"":Array.isArray(s)?s.join(";"):s).replace(/"/g,'""')+'"';return [r.columns.map(q).join(",")].concat(r.rows.map(x=>r.columns.map(c=>q(x[c])).join(","))).join("\n");}
function qDownload(name,text,type){const b=new Blob([text],{type});const u=URL.createObjectURL(b);const a=document.createElement("a");a.href=u;a.download=name;a.click();URL.revokeObjectURL(u);}
function qResults(){
  if(qErr){
    const tip=/cannot read|unexpected|expected|missing/.test(qErr)?"Terms look like field:value, joined with AND, OR, NOT. Type a field name for suggestions.":/no node matches|ambiguous/.test(qErr)?"Use a label from the Map or the Inventory, in quotes.":"";
    return `<div class="qerr2">${esc(qErr)}${tip?`<span class="tip">${esc(tip)}</span>`:""}</div>`;
  }
  const r=qRes;
  if(!r)return `<div class="qempty"><div class="big">Ask a question</div>Type one above or pick one. Answers are worked out from this report and cite the requests behind them.</div>`;
  if(r.kind==="text")return `<div class="qref">${qReference()}</div>`;
  let facets="";
  if(r.kind==="requests"&&r.rows.length){
    const m=tally(r.rows,x=>x.method),s=tally(r.rows,x=>statusClass(x.status));
    facets=`<div class="qfacets">${m.slice(0,5).map(([k,v])=>`<button class="qf" data-add="req.method:${esc(k)}">${esc(k)} <b>${v}</b></button>`).join("")}${s.map(([k,v])=>`<button class="qf" data-add="${k==="2xx"?"resp.code.gte:200 AND resp.code.lt:300":k==="3xx"?"resp.code.gte:300 AND resp.code.lt:400":k==="4xx"?"resp.code.gte:400 AND resp.code.lt:500":"resp.code.gte:500"}">${esc(k)} <b>${v}</b></button>`).join("")}</div>`;
  }
  const bar=`<div class="qst"><span><b>${r.total==null?r.rows.length:r.total}</b> ${r.kind==="paths"?"path(s)":"row(s)"}</span><span>· ${qMs<1?"<1":Math.round(qMs)} ms</span><span>· ${esc(r.kind)}</span><span class="sp"></span>
    <button class="qbtn" id="qcopyj">Copy JSON</button><button class="qbtn" id="qcsv">CSV</button></div>`;
  if(r.kind==="paths"){
    const by={};r.rows.forEach(x=>{(by[x.path]=by[x.path]||[]).push(x);});
    const cls=s=>s==="INFERRED"?"in":s==="EXTERNAL"?"ex":"ob";
    return bar+`<div class="qpaths">${Object.keys(by).map(k=>{const hs=by[k];return `<div class="qpath"><div class="ph2">path ${k} · ${hs.length} hop${hs.length===1?"":"s"}</div><div class="qchain"><span class="qn">${esc(hs[0].from)}</span>${hs.map(h=>`<span class="qa ${cls(h.state)}" title="${esc(h.state)} · ${esc(h.evidence||"")}">${esc(humanize(h.edge).toLowerCase())}</span><span class="qn">${esc(h.to)}</span>`).join("")}</div></div>`;}).join("")||'<div class="empty">No path found.</div>'}</div>`;
  }
  let rows=r.rows.slice();
  if(qSort){const{k,d}=qSort;rows.sort((a,b)=>{const x=a[k],y=b[k];return (typeof x==="number"&&typeof y==="number"?x-y:String(x==null?"":x).localeCompare(String(y==null?"":y)))*d;});}
  const rowAttr=row=>row.ev&&/^ev_\d+$/.test(row.ev)?` class="rowclick" data-ev="${row.ev.slice(3)}"`:(row.id&&r.kind==="nodes"?` class="rowclick" data-node="${esc(row.id)}"`:"");
  return bar+facets+`<div class="qtab"><table><thead><tr>${r.columns.map(c=>`<th data-sk="${esc(c)}">${esc(c==="ev"?"evidence":c)}${qSort&&qSort.k===c?`<span class="ar">${qSort.d>0?" ▲":" ▼"}</span>`:""}</th>`).join("")}</tr></thead><tbody>${
    rows.length?rows.map(row=>`<tr${rowAttr(row)}>${r.columns.map(c=>`<td>${qCell2(c,row[c],row)}</td>`).join("")}</tr>`).join(""):`<tr><td colspan="${r.columns.length}"><div class="empty">No rows match.</div></td></tr>`}</tbody></table></div>`;
}
function qReference(){
  return `<b>BQL</b> filters requests, nodes or edges, and walks the graph.
  <div class="row"><b>request</b><span>req.method req.host req.path req.template req.header req.body · resp.code resp.mime resp.header resp.body · role id</span></div>
  <div class="row"><b>node</b><span>node.type node.label node.id node.layer node.source node.role node.state node.evidence node.attr.&lt;name&gt;</span></div>
  <div class="row"><b>edge</b><span>edge.type edge.state edge.src edge.dst edge.src.type edge.dst.type edge.src.label edge.dst.label</span></div>
  <div class="row"><b>operators</b><span>${Q_OPS.map(o=>o[0]).join(" ")} · e.g. <span style="color:var(--text)">resp.code.gte:400</span></span></div>
  <div class="row"><b>combine</b><span>AND OR NOT ( ) and end with <span style="color:var(--text)">limit N</span></span></div>
  <div class="row"><b>verbs</b><span>reach &lt;node&gt; · blast &lt;node&gt; [depth N] · upstream &lt;node&gt; · neighbors &lt;node&gt; · path &lt;a&gt; to &lt;b&gt; · osint [section] · unknowns · stats</span></div>`;
}
/* a question is BQL when it has field:value terms, a graph verb or AND/OR/NOT; anything else is plain English */
function looksBql(t){
  t=(t||"").trim();if(!t)return false;
  return /^(reach|blast|upstream|neighbors|path|osint|unknowns|stats|help|schema)\b/i.test(t)||/\b[a-z][\w.]*:\S/i.test(t)||/\b(req|resp|node|edge)\.[a-z]/i.test(t)||/\s(AND|OR|NOT)\s/.test(t);
}
const ASK_PRESETS=[
  ["List the endpoints","list the endpoints"],
  ["What is in the code but never called?","what is referenced in code but never called"],
  ["Which endpoints only returned errors?","which endpoints only returned errors"],
  ["Which paths look privileged?","which endpoints look privileged"],
  ["Who are the third parties?","third parties"],
  ["What needs a login?","auth and cookies"],
  ["Which endpoints take parameters?","parameters"],
  ["What is still unknown?","what are the open questions"],
];
let aTab="questions",aNL=null;
function aAnswerHtml(a){return `<div class="answer"><div class="ahd">${esc(a.title)}</div>${a.html}</div><div class="askfoot">Answered from this report. No AI was called.</div>`;}
function aOut(){
  if(aNL)return aAnswerHtml(aNL);
  return qResults();
}
function aChips(){
  if(aTab==="questions")return ASK_PRESETS.map(([t,q])=>`<button class="achip" data-nl="${esc(q)}">${esc(t)}</button>`).join("");
  if(aTab==="bql")return qLibrary().flatMap(([g,xs])=>xs).map(x=>`<button class="achip" data-q="${esc(x[1])}" title="${esc(x[1])}">${esc(x[0])}</button>`).join("")+`<button class="achip" id="qhelp">BQL reference</button>`;
  return qHist.length?qHist.slice(0,10).map(q=>`<button class="achip mono" data-q="${esc(q)}">${esc(q.length>70?q.slice(0,69)+"…":q)}</button>`).join(""):'<span style="color:var(--faint);font-size:13px">Nothing yet. Questions you run will show up here.</span>';
}
function vAsk(){
  return `<div class="askx"><h1 class="vt">Ask</h1><p class="vsub">Ask in plain English, or type a BQL query for exact filters and graph paths. Answers come from this report.</p>
   <div class="qed"><div class="hl" id="qhl"></div><textarea id="qin" spellcheck="false" autocomplete="off" placeholder='What is in the code but never called?    ·    req.method:POST AND resp.code.gte:400    ·    reach "POST /api/checkout"'>${esc(qText)}</textarea>
    <div class="qbar2"><span class="hint"><kbd>Enter</kbd> to ask · <kbd>Shift</kbd>+<kbd>Enter</kbd> new line</span><button class="qrun2" id="qgo">Ask</button></div>
    <div class="qac" id="qac" hidden></div></div>
   <div class="atabs"><button class="atab${aTab==="questions"?" on":""}" data-atab="questions">Questions</button>${BQLDB?`<button class="atab${aTab==="bql"?" on":""}" data-atab="bql">BQL examples</button>`:""}<button class="atab${aTab==="recent"?" on":""}" data-atab="recent">Recent</button></div>
   <div class="achips" id="achips">${aChips()}</div>
   <div class="qres" id="qout">${aOut()}</div></div>`;
}
function initAsk(){
  const inp=$("#qin"),hl=$("#qhl"),ac=$("#qac");
  const paint=()=>{hl.innerHTML=looksBql(inp.value)?qHighlight(inp.value):esc(inp.value)+"\n";hl.scrollTop=inp.scrollTop;const h=Math.max(76,Math.min(240,inp.scrollHeight));if(inp.scrollHeight>inp.clientHeight)inp.style.height=h+"px";};
  const out=()=>{$("#qout").innerHTML=aOut();wire();};
  function ask(text){
    qText=text;aNL=null;qRes=null;qErr=null;qSort=null;
    if(!text.trim()){render();return;}
    if(looksBql(text)&&BQLDB)qRun(text);
    else{aNL=askEngine(text);qHist=[text].concat(qHist.filter(x=>x!==text)).slice(0,15);qSave();}
    render();
  }
  const go=()=>{ac.hidden=true;ask(inp.value);};
  /* completion only for BQL-looking words */
  let items=[],sel=0;
  function suggest(){
    const v=inp.value,pos=inp.selectionStart,left=v.slice(0,pos);
    items=[];
    const m=/([A-Za-z_][\w.\-]*)(:)?([^\s():]*)?$/.exec(left);
    if(m&&BQLDB){
      const word=m[1],hasColon=m[2]===":",val=m[3]||"";
      const fieldish=/^(req|resp|node|edge|role|id)\b/i.test(word),first=left.trim()===word&&word.length>=2;
      if(hasColon){const f=word.replace(/\.(cont|ncont|eq|ne|like|regex|gt|gte|lt|lte)$/,"");
        items=qValues(f).filter(x=>x.toLowerCase().startsWith(val.toLowerCase())&&x!==val).slice(0,8).map(x=>({ins:/\s/.test(x)?'"'+x+'"':x,lab:x,d:"value",at:pos-val.length,end:pos}));}
      else if(fieldish){
        const parts=word.split("."),last=parts[parts.length-1],base=parts.slice(0,-1).join(".");
        if(parts.length>1&&Q_FIELDS.some(f=>f[0]===base)&&!Q_OPS.some(o=>o[0]===last)&&base!=="node.attr")
          items=Q_OPS.filter(o=>o[0].startsWith(last)&&o[0]!==last).map(o=>({ins:o[0]+":",lab:base+"."+o[0],d:o[1],at:pos-last.length,end:pos}));
        if(!items.length)items=Q_FIELDS.filter(f=>f[0].toLowerCase().startsWith(word.toLowerCase())&&f[0].toLowerCase()!==word.toLowerCase()).slice(0,8)
          .map(f=>({ins:f[0]+(f[0].endsWith(".")?"":":"),lab:f[0],d:f[1],at:pos-word.length,end:pos}));
      }else if(first)items=Q_VERBS.filter(f=>/^[a-z]/.test(f[0])&&f[0].startsWith(word.toLowerCase())&&f[0]!==word.toLowerCase()).slice(0,6).map(f=>({ins:f[0]+" ",lab:f[0],d:f[1],at:pos-word.length,end:pos}));
    }
    sel=0;
    if(!items.length){ac.hidden=true;return;}
    ac.innerHTML=items.map((it,i)=>`<button data-i="${i}" class="${i===sel?"on":""}"><span>${esc(it.lab)}</span><span class="dd">${esc(it.d)}</span></button>`).join("");
    ac.hidden=false;
    $$("button",ac).forEach(b=>b.onmousedown=e=>{e.preventDefault();accept(+b.dataset.i);});
  }
  function accept(i){const it=items[i];if(!it)return;const v=inp.value;inp.value=v.slice(0,it.at)+it.ins+v.slice(it.end);const p=it.at+it.ins.length;inp.setSelectionRange(p,p);ac.hidden=true;paint();suggest();}
  function mark(){$$("button",ac).forEach((b,i)=>b.classList.toggle("on",i===sel));const b=$$("button",ac)[sel];if(b)b.scrollIntoView({block:"nearest"});}
  inp.addEventListener("input",()=>{paint();suggest();});
  inp.addEventListener("scroll",()=>{hl.scrollTop=inp.scrollTop;});
  inp.addEventListener("click",()=>{ac.hidden=true;});
  inp.addEventListener("blur",()=>setTimeout(()=>{ac.hidden=true;},120));
  inp.addEventListener("keydown",e=>{
    if(!ac.hidden){
      if(e.key==="ArrowDown"){e.preventDefault();sel=(sel+1)%items.length;mark();return;}
      if(e.key==="ArrowUp"){e.preventDefault();sel=(sel-1+items.length)%items.length;mark();return;}
      if(e.key==="Tab"){e.preventDefault();accept(sel);return;}
      if(e.key==="Escape"){ac.hidden=true;return;}
    }
    if(e.key==="Enter"&&!e.shiftKey){e.preventDefault();go();}
  });
  function wire(){
    const o=$("#qout");
    $$("[data-ep]",o).forEach(el=>el.onclick=()=>openEp(el.dataset.ep));
    $$("[data-ev]",o).forEach(r=>r.onclick=()=>openEv(r.dataset.ev));
    $$("[data-node]",o).forEach(r=>r.onclick=()=>{try{openNode(r.dataset.node);}catch(e){}});
    $$("[data-sk]",o).forEach(h=>h.onclick=()=>{const k=h.dataset.sk;qSort=qSort&&qSort.k===k?{k,d:-qSort.d}:{k,d:1};out();});
    $$("[data-add]",o).forEach(b=>b.onclick=()=>{inp.value=inp.value.replace(/\s+limit\s+\d+\s*$/i,"").trim()+" AND "+b.dataset.add;paint();go();});
    const cj=$("#qcopyj");if(cj)cj.onclick=()=>fallbackCopy(JSON.stringify(qRes,null,2),()=>{cj.textContent="Copied";setTimeout(()=>cj.textContent="Copy JSON",1200);});
    const cv=$("#qcsv");if(cv)cv.onclick=()=>qDownload((D.app||"query")+".bql.csv",qCsv(qRes),"text/csv");
  }
  $("#qgo").onclick=go;
  $$("[data-atab]").forEach(b=>b.onclick=()=>{aTab=b.dataset.atab;$$(".atab").forEach(x=>x.classList.toggle("on",x===b));$("#achips").innerHTML=aChips();bindChips();});
  function bindChips(){
    $$("[data-nl]",$("#achips")).forEach(b=>b.onclick=()=>{inp.value=b.dataset.nl;ask(b.dataset.nl);});
    $$("[data-q]",$("#achips")).forEach(b=>b.onclick=()=>{inp.value=b.dataset.q;ask(b.dataset.q);});
    const h=$("#qhelp");if(h)h.onclick=()=>{aNL=null;qErr=null;qRes={kind:"text",columns:[],rows:[],note:"",total:null};out();};
  }
  bindChips();paint();wire();
  inp.focus();inp.setSelectionRange(inp.value.length,inp.value.length);
}
"""
