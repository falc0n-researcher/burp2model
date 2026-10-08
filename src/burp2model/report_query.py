"""The Query view of the offline report: a BQL console with highlighting, completion and a library.

The engine is `BQL` (bql_js.py); this is only the front end. Left, a library of ready queries built
from this model (its busiest endpoint, a code-only one, ...), pins and history. Right, the editor
with live syntax colouring and completion, then the results as a sortable table, or as chains
for graph paths.
"""

QRY_CSS = r"""
/* query console */
.m-query{padding:0!important;overflow:hidden!important}
.m-query .view{max-width:none;height:100%}
.m-query .foot{display:none}
.qx{display:grid;grid-template-columns:268px minmax(0,1fr);height:100%}
@media(max-width:900px){.qx{grid-template-columns:minmax(0,1fr)}.qside{display:none}}
.qside{border-right:1px solid var(--line);background:var(--panel);overflow:auto;padding:14px 10px 30px}
.qside h4{font:600 10px var(--mono);letter-spacing:.13em;text-transform:uppercase;color:var(--faint);margin:16px 8px 6px}
.qside h4:first-child{margin-top:0}
.qi{display:block;width:100%;text-align:left;border:0;background:none;padding:7px 9px;border-radius:8px;color:var(--text);cursor:pointer}
.qi:hover{background:var(--panel2)}
.qi .t{font:600 12.5px var(--sans);display:block}
.qi .d{font:11px var(--mono);color:var(--faint);display:block;margin-top:2px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.qi .x{float:right;color:var(--faint);font-size:11px;padding:0 4px}
.qi .x:hover{color:var(--bad)}
.qmain{display:flex;flex-direction:column;min-width:0;min-height:0;height:100%;overflow:auto;padding:20px 26px 40px}
.qh{display:flex;align-items:baseline;gap:12px;margin-bottom:12px}
.qh h1{font:700 22px var(--sans);letter-spacing:-.02em;margin:0}
.qh .s{color:var(--muted);font-size:13px}
.qed{position:relative;border:1px solid var(--line2);border-radius:12px;background:var(--panel);box-shadow:var(--shadow)}
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
let qText="",qRes=null,qErr=null,qHist=[],qPins=[],qMs=0,qSort=null;
try{qHist=JSON.parse(localStorage.getItem("b2m-qhist")||"[]");}catch(e){}
try{qPins=JSON.parse(localStorage.getItem("b2m-qpins")||"[]");}catch(e){}
const qSave=()=>{try{localStorage.setItem("b2m-qhist",JSON.stringify(qHist));localStorage.setItem("b2m-qpins",JSON.stringify(qPins));}catch(e){}};
function qRun(text){
  qText=text;qErr=null;qRes=null;qSort=null;
  if(!BQLDB){qErr="This report was built without graph.db — rebuild with burp2model to enable queries.";return;}
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
  if(col==="ev"||col==="evidence")return `<span class="evl">${esc(v)}</span>`;
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
  if(!r)return `<div class="qempty"><div class="big">Ask the graph anything</div>Pick a query on the left, or type one. Every answer is computed from this model, cites its evidence, and never calls an AI.</div>`;
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
  return bar+facets+`<div class="qtab"><table><thead><tr>${r.columns.map(c=>`<th data-sk="${esc(c)}">${esc(c)}${qSort&&qSort.k===c?`<span class="ar">${qSort.d>0?" ▲":" ▼"}</span>`:""}</th>`).join("")}</tr></thead><tbody>${
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
function vQuery(){
  const lib=qLibrary();
  const item=(t,q,d)=>`<button class="qi" data-q="${esc(q)}" title="${esc(q)}"><span class="t">${esc(t)}</span><span class="d">${esc(d||q)}</span></button>`;
  return `<div class="qx"><aside class="qside">
    ${qPins.length?`<h4>Pinned</h4>${qPins.map(q=>`<button class="qi" data-q="${esc(q)}" title="${esc(q)}"><span class="x" data-unpin="${esc(q)}" title="Unpin">✕</span><span class="d" style="color:var(--text)">${esc(q)}</span></button>`).join("")}`:""}
    ${lib.map(([g,xs])=>`<h4>${esc(g)}</h4>${xs.map(x=>item(x[0],x[1],x[2])).join("")}`).join("")}
    ${qHist.length?`<h4>Recent</h4>${qHist.slice(0,8).map(q=>`<button class="qi" data-q="${esc(q)}" title="${esc(q)}"><span class="d" style="color:var(--muted)">${esc(q)}</span></button>`).join("")}`:""}
   </aside><section class="qmain">
    <div class="qh"><h1>Query</h1><span class="s">Ask the graph with BQL. Answered from this model, cited, no AI.</span></div>
    <div class="qed"><div class="hl" id="qhl"></div><textarea id="qin" spellcheck="false" autocomplete="off" placeholder='req.method:POST AND resp.code.gte:400    ·    reach "POST /api/checkout"    ·    help'>${esc(qText)}</textarea>
     <div class="qbar2"><span class="hint"><kbd>Enter</kbd> run · <kbd>Shift</kbd>+<kbd>Enter</kbd> new line · <kbd>Tab</kbd> complete</span>
      <button class="qbtn" id="qpin" title="Pin this query">${qPins.includes(qText.trim())?"★ Pinned":"☆ Pin"}</button><button class="qbtn" id="qhelp">Reference</button><button class="qrun2" id="qgo">Run</button></div>
     <div class="qac" id="qac" hidden></div></div>
    <div class="qres" id="qout">${qResults()}</div></section></div>`;
}
function initQuery(){
  const inp=$("#qin"),hl=$("#qhl"),ac=$("#qac");
  const paint=()=>{hl.innerHTML=qHighlight(inp.value);hl.scrollTop=inp.scrollTop;const h=Math.max(76,Math.min(240,inp.scrollHeight));if(inp.scrollHeight>inp.clientHeight)inp.style.height=h+"px";};
  const out=()=>{$("#qout").innerHTML=qResults();wire();};
  const go=()=>{ac.hidden=true;qRun(inp.value);render();};
  /* completion: the word under the caret */
  let items=[],sel=0;
  function suggest(){
    const v=inp.value,pos=inp.selectionStart,left=v.slice(0,pos);
    const m=/([A-Za-z_][\w.\-]*)(:)?([^\s():]*)?$/.exec(left);
    items=[];
    if(m){
      const word=m[1],hasColon=m[2]===":",val=m[3]||"";
      if(hasColon){const f=word.replace(/\.(cont|ncont|eq|ne|like|regex|gt|gte|lt|lte)$/,"");
        items=qValues(f).filter(x=>x.toLowerCase().startsWith(val.toLowerCase())&&x!==val).slice(0,8).map(x=>({ins:/\s/.test(x)?'"'+x+'"':x,lab:x,d:"value",at:pos-val.length,end:pos}));}
      else{
        const parts=word.split(".");const last=parts[parts.length-1];
        const base=parts.slice(0,-1).join(".");
        if(parts.length>1&&Q_FIELDS.some(f=>f[0]===base)&&!Q_OPS.some(o=>o[0]===last)&&base!=="node.attr")
          items=Q_OPS.filter(o=>o[0].startsWith(last)&&o[0]!==last).map(o=>({ins:o[0]+":",lab:base+"."+o[0],d:o[1],at:pos-last.length,end:pos}));
        if(!items.length&&word.length>=1)
          items=Q_FIELDS.concat(Q_VERBS).filter(f=>f[0].toLowerCase().startsWith(word.toLowerCase())&&f[0].toLowerCase()!==word.toLowerCase())
            .slice(0,8).map(f=>({ins:f[0]+(f[0].endsWith(".")||/^[A-Z]|^(reach|blast|upstream|neighbors|path|osint|limit)$/.test(f[0])?(f[0].endsWith(".")?"":" "):":"),lab:f[0],d:f[1],at:pos-word.length,end:pos}));
      }
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
      if(e.key==="Tab"||(e.key==="Enter"&&items.length&&!e.shiftKey&&!e.metaKey&&!e.ctrlKey&&false)){e.preventDefault();accept(sel);return;}
      if(e.key==="Escape"){ac.hidden=true;return;}
    }else if(e.key==="Tab"&&!e.shiftKey&&inp.value.trim()===""){/* leave focus handling alone */}
    if(e.key==="Enter"&&!e.shiftKey){e.preventDefault();go();}
  });
  function wire(){
    $$("[data-ev]",$("#qout")).forEach(r=>r.onclick=()=>openEv(r.dataset.ev));
    $$("[data-node]",$("#qout")).forEach(r=>r.onclick=()=>{try{openNode(r.dataset.node);}catch(e){}});
    $$("[data-sk]",$("#qout")).forEach(h=>h.onclick=()=>{const k=h.dataset.sk;qSort=qSort&&qSort.k===k?{k,d:-qSort.d}:{k,d:1};out();});
    $$("[data-add]",$("#qout")).forEach(b=>b.onclick=()=>{inp.value=inp.value.replace(/\s+limit\s+\d+\s*$/i,"").trim()+" AND "+b.dataset.add;paint();go();});
    const cj=$("#qcopyj");if(cj)cj.onclick=()=>fallbackCopy(JSON.stringify(qRes,null,2),()=>{cj.textContent="Copied";setTimeout(()=>cj.textContent="Copy JSON",1200);});
    const cv=$("#qcsv");if(cv)cv.onclick=()=>qDownload((D.app||"query")+".bql.csv",qCsv(qRes),"text/csv");
  }
  $("#qgo").onclick=go;
  $("#qhelp").onclick=()=>{qRes={kind:"text",columns:[],rows:[],note:"",total:null};qErr=null;out();};
  $("#qpin").onclick=()=>{const q=inp.value.trim();if(!q)return;qPins=qPins.includes(q)?qPins.filter(x=>x!==q):[q].concat(qPins).slice(0,12);qSave();qText=inp.value;render();};
  $$("[data-q]",$("#main")).forEach(b=>b.onclick=e=>{if(e.target.closest("[data-unpin]")){qPins=qPins.filter(x=>x!==e.target.closest("[data-unpin]").dataset.unpin);qSave();render();return;}qRun(b.dataset.q);render();});
  paint();wire();
  if(!qRes&&!qErr&&!qText){}
  inp.focus();inp.setSelectionRange(inp.value.length,inp.value.length);
}
"""
