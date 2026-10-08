"""The Inventory view of the offline report: a Burp-style site map, request table and viewer.

Left, a site-map tree (host, then path folders; endpoints the code names but nothing requested
show greyed out). Top right, the request table with sortable, resizable columns and filters.
Bottom right, the redacted request and response side by side. Every value is already masked in
the payload; this only lays it out.
"""

INV_CSS = r"""
/* inventory (Burp-style) */
.m-inventory{padding:0!important;overflow:hidden!important;display:flex;flex-direction:column}
.m-inventory .view{max-width:none;flex:1;min-height:0;display:flex;flex-direction:column}
.m-inventory .foot{display:none}
.inv{display:flex;flex-direction:column;flex:1;min-height:0}
.inv-bar{display:flex;align-items:center;gap:10px;flex-wrap:wrap;padding:10px 14px;border-bottom:1px solid var(--line);background:var(--panel)}
.inv-bar h1{font:700 15px var(--sans);margin:0 6px 0 0;letter-spacing:-.01em}
.inv-q{position:relative;flex:1 1 280px;min-width:200px;max-width:560px}
.inv-q input{width:100%;height:32px;padding:0 10px 0 30px;border:1px solid var(--line2);border-radius:7px;background:var(--panel2);color:var(--text);font:12.5px var(--mono)}
.inv-q input:focus{border-color:var(--signal);outline:none}
.inv-q svg{position:absolute;left:9px;top:8px;width:15px;height:15px;color:var(--faint)}
.inv-chips{display:flex;gap:5px;flex-wrap:wrap;align-items:center}
.ichip{font:600 11px var(--mono);padding:4px 9px;border-radius:6px;border:1px solid var(--line2);background:var(--panel);color:var(--muted)}
.ichip:hover{color:var(--text);border-color:var(--faint)}
.ichip.on{background:var(--text);color:var(--ink);border-color:var(--text)}
.ichip.s2.on{background:var(--ok);border-color:var(--ok);color:#fff}.ichip.s3.on{background:var(--observed);border-color:var(--observed);color:#fff}
.ichip.s4.on{background:var(--warn);border-color:var(--warn);color:#fff}.ichip.s5.on{background:var(--bad);border-color:var(--bad);color:#fff}
.inv-bar select{height:30px;border:1px solid var(--line2);border-radius:7px;background:var(--panel);color:var(--text);font:600 11px var(--mono);padding:0 6px}
.inv-stat{margin-left:auto;color:var(--muted);font:12px var(--mono);white-space:nowrap}
.inv-err{padding:6px 14px;background:var(--panel);color:var(--bad);font:12px var(--mono);border-bottom:1px solid var(--line)}
.inv-main{display:flex;flex:1;min-height:0;background:var(--ink)}
.inv-tree{width:var(--tw,250px);min-width:150px;max-width:60%;overflow:auto;background:var(--panel);border-right:1px solid var(--line);padding:6px 0;font:12px var(--mono);flex:none}
.tn{display:flex;align-items:center;gap:5px;padding:3px 8px 3px calc(8px + var(--d,0)*14px);cursor:pointer;white-space:nowrap;border-left:2px solid transparent}
.tn:hover{background:var(--panel2)}
.tn.on{background:var(--signal-soft);border-left-color:var(--signal);color:var(--text)}
.tn .tg{width:12px;color:var(--faint);font-size:9px;flex:none;text-align:center}
.tn .nm{overflow:hidden;text-overflow:ellipsis;flex:1;min-width:0}
.tn .cnt{color:var(--faint);font-size:10.5px;flex:none}
.tn .sd{width:7px;height:7px;border-radius:50%;flex:none;background:var(--ok)}
.tn.host .nm{font-weight:700}
.tn.ghost .nm{color:var(--faint);font-style:italic}
.tn.ghost .sd{background:transparent;border:1.5px dashed var(--signal)}
.tn .gt{font:600 9px var(--mono);color:var(--signal);border:1px solid var(--signal);border-radius:4px;padding:0 4px;flex:none}
.inv-gut{flex:none;background:var(--line);position:relative;z-index:2}
.inv-gut.v{width:3px;cursor:col-resize}.inv-gut.h{height:3px;cursor:row-resize}
.inv-gut:hover,.inv-gut.drag{background:var(--signal)}
.inv-right{flex:1;min-width:0;display:flex;flex-direction:column}
.inv-tbl{display:flex;flex-direction:column;min-height:90px;background:var(--panel)}
.th{display:grid;grid-template-columns:var(--cols);align-items:stretch;background:var(--panel2);border-bottom:1px solid var(--line);flex:none;font:600 10.5px var(--mono);letter-spacing:.05em;text-transform:uppercase;color:var(--muted);user-select:none}
.th>div{position:relative;padding:6px 8px;cursor:pointer;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;border-right:1px solid var(--line)}
.th>div:hover{color:var(--text)}
.th .ar{color:var(--signal);margin-left:3px}
.th .rz{position:absolute;right:-3px;top:0;bottom:0;width:7px;cursor:col-resize;z-index:3}
.tbody{flex:1;overflow:auto;position:relative;outline:none}
.tr{display:grid;grid-template-columns:var(--cols);height:24px;align-items:center;font:12px var(--mono);cursor:default;border-bottom:1px solid transparent}
.tr.z{background:var(--panel3)}
.tr:hover{background:var(--panel2)}
.tr.sel,.tr.sel:hover{background:var(--signal-soft);box-shadow:inset 2px 0 var(--signal)}
.tr>div{padding:0 8px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.tr .c-id{color:var(--faint)}.tr .c-host{color:var(--muted)}
.tr .c-url .q{color:var(--faint)}
.tr .c-method{font-weight:700}.tr .c-method.w{color:var(--signal)}
.tr .c-status{font-weight:700}.tr .c-status.g{color:var(--ok)}.tr .c-status.y{color:var(--warn)}.tr .c-status.r{color:var(--bad)}.tr .c-status.b{color:var(--observed)}
.tr .c-params{color:var(--ok)}.tr .c-len,.tr .c-mime,.tr .c-role{color:var(--muted)}
.tr .c-len{text-align:right}
.inv-empty{padding:34px 20px;color:var(--faint);text-align:center;font:13px var(--sans)}
.inv-view{flex:1;min-height:120px;display:flex;background:var(--panel);overflow:hidden}
.inv-view>.rr{flex:1}
.ghostcard{padding:22px 24px;color:var(--muted);font-size:13px;max-width:640px}
.ghostcard h3{margin:0 0 6px;font:700 15px var(--sans);color:var(--text)}
.ghostcard .tags{display:flex;gap:6px;flex-wrap:wrap;margin-top:10px}
.ghostcard .tags span{font:600 11.5px var(--mono);padding:3px 8px;border-radius:6px;background:var(--panel2)}
@media(max-width:820px){.inv-tree{display:none}.inv-gut.v{display:none}}
"""

INV_JS = r"""
/* ---------- INVENTORY (Burp-style: site map + request table + viewer) ---------- */
const INV_COLS=[
  {k:"id",t:"#",w:54,dir:1},{k:"host",t:"Host",w:150,dir:1},{k:"method",t:"Method",w:74,dir:1},{k:"url",t:"URL",w:0,dir:1},
  {k:"params",t:"Params",w:64,dir:-1},{k:"status",t:"Status",w:66,dir:1},{k:"len",t:"Length",w:76,dir:-1},{k:"mime",t:"MIME type",w:92,dir:1},{k:"role",t:"Role",w:100,dir:1}];
const INV=Object.assign({q:"",methods:new Set(),sc:new Set(),role:"",paramsOnly:false,sel:null,node:"",sortKey:"id",sortDir:1,
  tw:250,th:300,open:new Set(),tab:{req:"pretty",res:"pretty"},widths:{},bql:null,bqlErr:null},
  (function(){try{const s=JSON.parse(localStorage.getItem("b2m-inv")||"{}")||{};const o={};["tw","th","widths"].forEach(k=>{if(s[k]!=null)o[k]=s[k];});return o;}catch(e){return {};}})());
function invSave(){try{localStorage.setItem("b2m-inv",JSON.stringify({tw:INV.tw,th:INV.th,widths:INV.widths}));}catch(e){}}
const INV_ROW=EVL.map(e=>{
  const path=e.path||"",qi=path.indexOf("?"),clean=qi<0?path:path.slice(0,qi);
  const body=e.response&&e.response.body?e.response.body.length:0;
  return {e,id:e.id,host:e.host||"",method:e.method||"?",path,clean,
    params:(qi>=0||(e.request&&e.request.body))?1:0,status:e.status==null?0:e.status,
    len:body,lenTr:!!(e.response&&e.response.truncated),mime:(e.mime||"").toLowerCase(),role:e.role||"",
    hay:`${e.method} ${e.host}${path} ${e.status} ${e.mime||""} ${e.role||""}`.toLowerCase()};
});
function invTree(){
  const root={key:"",kids:new Map(),n:0,worst:0,ghost:0};
  const add=(host,clean,ghost,status)=>{
    const segs=clean.split("/").filter(Boolean);let nd=root,key="";
    [host].concat(segs).forEach((sg,i)=>{key+=(i?"/":"")+sg;
      let k=nd.kids.get(sg);if(!k){k={key,name:sg,kids:new Map(),n:0,worst:0,ghost:ghost?1:0,host:i===0};nd.kids.set(sg,k);}
      if(!ghost){k.n++;k.ghost=0;k.worst=Math.max(k.worst,status>=500?4:status>=400?3:status>=300?2:status>=200?1:0);}
      nd=k;});
  };
  INV_ROW.forEach(r=>add(r.host,r.clean,false,r.status));
  EP.filter(x=>x.state==="STATIC_ONLY").forEach(x=>add(x.host||"",x.path||"",true,0));
  return root;
}
const INV_TREE=invTree();
function invMatchNode(r){if(!INV.node)return true;const k=r.host+r.clean.replace(/\/$/,"");return k===INV.node||k.startsWith(INV.node+"/");}
function invFiltered(){
  const q=(INV.q||"").trim().toLowerCase(),g=(query||"").toLowerCase();
  let rows=INV_ROW.filter(r=>{
    if(INV.bql&&!INV.bql.has(r.id))return false;
    if(q&&!INV.bql&&!r.hay.includes(q))return false;
    if(g&&!r.hay.includes(g))return false;
    if(INV.methods.size&&!INV.methods.has(r.method))return false;
    if(INV.sc.size&&!INV.sc.has(String(statusClass(r.status||null)).replace("xx","")))return false;
    if(INV.role&&r.role!==INV.role)return false;
    if(INV.paramsOnly&&!r.params)return false;
    return invMatchNode(r);});
  const k=INV.sortKey,d=INV.sortDir;
  const key=r=>k==="url"?r.clean:k==="params"?r.params:r[k];
  rows=rows.slice().sort((a,b)=>{const x=key(a),y=key(b);return (typeof x==="number"?x-y:String(x).localeCompare(String(y)))*d||a.id-b.id;});
  return rows;
}
const BQLISH=/(^|\s)(req|resp|node|edge)\.[a-z.]+:|(^|\s)(role|id):/i;
function invApplyQuery(v){
  INV.q=v;INV.bql=null;INV.bqlErr=null;
  if(BQLDB&&BQLISH.test(v)){
    try{const r=BQL.run(BQLDB,v+" limit 5000");
      if(r.kind!=="requests")INV.bqlErr="This filters requests: use req.* / resp.* fields.";
      else INV.bql=new Set(r.rows.map(x=>+x.ev.slice(3)));}
    catch(e){INV.bqlErr=e.message;}}
}
function vEvidence(){
  const meths=tally(EVL,e=>e.method||"?").map(x=>x[0]).slice(0,8);
  const roles=[...new Set(EVL.map(e=>e.role).filter(Boolean))].sort();
  return `<div class="inv" id="inv"><div class="inv-bar"><h1>Inventory</h1>
   <div class="inv-q"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="11" cy="11" r="7"/><path d="M21 21l-4.3-4.3"/></svg>
    <input id="invq" spellcheck="false" autocomplete="off" placeholder="${BQLDB?"filter: text, or BQL e.g. req.method:POST AND resp.code.gte:400":"filter by method, URL, status, role"}" value="${esc(INV.q)}"></div>
   <div class="inv-chips" id="invchips">${meths.map(m=>`<button class="ichip${INV.methods.has(m)?" on":""}" data-m="${esc(m)}">${esc(m)}</button>`).join("")}
    <span style="width:6px"></span>${["2","3","4","5"].map(x=>`<button class="ichip s${x}${INV.sc.has(x)?" on":""}" data-sc="${x}">${x}xx</button>`).join("")}
    <button class="ichip${INV.paramsOnly?" on":""}" id="invparams">params</button>
    ${roles.length?`<select id="invrole"><option value="">all roles</option>${roles.map(r=>`<option${INV.role===r?" selected":""}>${esc(r)}</option>`).join("")}</select>`:""}
    <button class="ichip" id="invclear" title="Clear every filter">clear</button></div>
   <span class="inv-stat" id="invstat"></span></div>
   <div id="inverr"></div>
   <div class="inv-main"><aside class="inv-tree" id="invtree" style="--tw:${INV.tw}px"></aside><div class="inv-gut v" id="gv"></div>
    <section class="inv-right"><div class="inv-tbl" id="invtbl" style="height:${INV.th}px;flex:none"><div class="th" id="invth"></div><div class="tbody" id="invbody" tabindex="0"></div></div>
     <div class="inv-gut h" id="gh"></div><div class="inv-view" id="invview"></div></section></div></div>`;
}
function invColsCss(){
  const w=INV_COLS.map(c=>c.w?(INV.widths[c.k]||c.w)+"px":"minmax(180px,1fr)").join(" ");
  return w;
}
function initEvq(){
  const root=$("#inv");if(!root)return;
  const ROWH=24;let rows=[],cols=invColsCss();
  const body=$("#invbody"),th=$("#invth"),tree=$("#invtree");
  root.style.setProperty("--cols",cols);

  /* header */
  function drawHead(){
    th.innerHTML=INV_COLS.map(c=>`<div data-k="${c.k}">${esc(c.t)}${INV.sortKey===c.k?`<span class="ar">${INV.sortDir>0?"▲":"▼"}</span>`:""}${c.w?`<span class="rz" data-rz="${c.k}"></span>`:""}</div>`).join("");
    th.style.setProperty("--cols",invColsCss());
    $$("[data-k]",th).forEach(d=>d.onclick=ev=>{if(ev.target.closest(".rz"))return;const k=d.dataset.k;if(INV.sortKey===k)INV.sortDir*=-1;else{INV.sortKey=k;INV.sortDir=INV_COLS.find(c=>c.k===k).dir;}refresh();});
    $$("[data-rz]",th).forEach(h=>h.onpointerdown=ev=>{ev.preventDefault();ev.stopPropagation();const k=h.dataset.rz,c=INV_COLS.find(x=>x.k===k),sx=ev.clientX,w0=INV.widths[k]||c.w;h.setPointerCapture(ev.pointerId);
      h.onpointermove=e2=>{INV.widths[k]=Math.max(40,w0+e2.clientX-sx);root.style.setProperty("--cols",invColsCss());th.style.setProperty("--cols",invColsCss());drawBody();};
      h.onpointerup=()=>{h.onpointermove=h.onpointerup=null;invSave();};});
  }
  /* table body, windowed so a 20,000-request capture stays instant */
  function rowHtml(r,i){
    const e=r.e,ssc=r.status>=500?"r":r.status>=400?"y":r.status>=300?"b":r.status>=200?"g":"";
    const u=r.path,qi=u.indexOf("?");
    return `<div class="tr${i%2?" z":""}${INV.sel===r.id?" sel":""}" data-id="${r.id}"><div class="c-id">${r.id}</div><div class="c-host" title="${esc(r.host)}">${esc(r.host)}</div>
     <div class="c-method${r.method!=="GET"&&r.method!=="HEAD"?" w":""}">${esc(r.method)}</div>
     <div class="c-url" title="${esc(u)}">${qi<0?esc(u):esc(u.slice(0,qi))+'<span class="q">'+esc(u.slice(qi))+"</span>"}</div>
     <div class="c-params">${r.params?"✓":""}</div><div class="c-status ${ssc}">${r.status||""}</div>
     <div class="c-len">${r.len?(r.lenTr?"≥":"")+r.len:""}</div><div class="c-mime">${esc(r.mime)}</div><div class="c-role">${esc(r.role)}</div></div>`;
  }
  function drawBody(){
    if(!rows.length){body.innerHTML=`<div class="inv-empty">${INV.node&&!INV_ROW.some(invMatchNode)?"Named in the client code, but no request to it was captured.":"No request matches these filters."}</div>`;return;}
    const vh=body.clientHeight||400,st=body.scrollTop,first=Math.max(0,Math.floor(st/ROWH)-10),last=Math.min(rows.length,Math.ceil((st+vh)/ROWH)+10);
    body.innerHTML=`<div style="height:${rows.length*ROWH}px;position:relative"><div style="position:absolute;left:0;right:0;top:${first*ROWH}px">${rows.slice(first,last).map((r,i)=>rowHtml(r,first+i)).join("")}</div></div>`;
  }
  body.addEventListener("scroll",drawBody);
  body.addEventListener("click",e=>{const t=e.target.closest(".tr");if(t)select(+t.dataset.id);});
  body.addEventListener("keydown",e=>{
    if(!["ArrowDown","ArrowUp","j","k","Home","End","PageDown","PageUp"].includes(e.key))return;e.preventDefault();
    let i=rows.findIndex(r=>r.id===INV.sel);const d=e.key==="ArrowDown"||e.key==="j"?1:e.key==="ArrowUp"||e.key==="k"?-1:e.key==="PageDown"?15:e.key==="PageUp"?-15:0;
    i=e.key==="Home"?0:e.key==="End"?rows.length-1:Math.max(0,Math.min(rows.length-1,(i<0?0:i)+d));
    if(rows[i]){select(rows[i].id);const y=i*ROWH;if(y<body.scrollTop)body.scrollTop=y;else if(y+ROWH>body.scrollTop+body.clientHeight)body.scrollTop=y+ROWH-body.clientHeight;}});
  function select(id){INV.sel=id;drawBody();drawView();}

  /* viewer: the shared request/response component */
  function drawView(){
    const vw=$("#invview");
    const r=INV_ROW.find(x=>x.id===INV.sel);
    if(!r){
      const ghost=INV.node?EP.filter(x=>x.state==="STATIC_ONLY"&&(x.host||"")+(x.path||"")===INV.node):[];
      vw.innerHTML=ghost.length?`<div class="ghostcard"><h3>${methodm(ghost[0].method)} ${esc(ghost[0].path)}</h3>Named in the client code, never requested in this capture, so there is no request or response to show.
        <div class="tags">${ghost[0].referenced_by.map(x=>`<span>${esc(x)}</span>`).join("")}</div></div>`
        :`<div class="inv-empty" style="flex:1">Select a request to see it here. Arrow keys move through the table.</div>`;return;}
    const e=r.e;
    rrMount(vw,[e.id],{actions:[["Copy URL",(i,b)=>fallbackCopy(`${e.host}${e.path}`,()=>{b.textContent="Copied";setTimeout(()=>b.textContent="Copy URL",1200);})],["Details",()=>openEv(e.id)]]});
  }

  /* site map */
  function drawTree(){
    const out=[];
    const walk=(nd,d)=>{
      [...nd.kids.values()].sort((a,b)=>(b.kids.size>0)-(a.kids.size>0)||a.name.localeCompare(b.name)).forEach(k=>{
        const isOpen=INV.open.has(k.key)||(d===0&&!INV.open.has("-"+k.key));
        const kids=k.kids.size>0,gh=k.ghost&&!k.n;
        out.push(`<div class="tn${k.host?" host":""}${INV.node===k.key?" on":""}${gh?" ghost":""}" style="--d:${d}" data-key="${esc(k.key)}">
          <span class="tg" data-tg="${esc(k.key)}">${kids?(isOpen?"▼":"▶"):""}</span>${gh?"":`<span class="sd" style="background:${["var(--faint)","var(--ok)","var(--observed)","var(--warn)","var(--bad)"][k.worst]}"></span>`}${gh?'<span class="sd"></span>':""}
          <span class="nm" title="${esc(k.key)}">${esc(k.name||"/")}</span>${gh?'<span class="gt">code</span>':`<span class="cnt">${k.n}</span>`}</div>`);
        if(kids&&isOpen)walk(k,d+1);});
    };
    walk(INV_TREE,0);
    tree.innerHTML=`<div class="tn${INV.node===""?" on":""}" style="--d:0" data-key=""><span class="tg"></span><span class="nm" style="font-weight:700">All requests</span><span class="cnt">${INV_ROW.length}</span></div>`+out.join("");
    $$(".tn",tree).forEach(t=>t.onclick=ev=>{
      const k=t.dataset.key;
      if(ev.target.closest("[data-tg]")){const was=t.querySelector("[data-tg]").textContent==="▼";
        if(was){INV.open.delete(k);INV.open.add("-"+k);}else{INV.open.add(k);INV.open.delete("-"+k);}drawTree();return;}
      INV.node=k;INV.sel=null;refresh();});
  }
  function refresh(){
    rows=invFiltered();
    if(INV.sel!=null&&!rows.some(r=>r.id===INV.sel))INV.sel=null;
    drawHead();drawBody();drawTree();drawView();
    $("#invstat").textContent=`${rows.length} of ${INV_ROW.length} requests`;
    $("#inverr").innerHTML=INV.bqlErr?`<div class="inv-err">${esc(INV.bqlErr)}</div>`:"";
    $$("#invchips [data-m]").forEach(b=>b.classList.toggle("on",INV.methods.has(b.dataset.m)));
    $$("#invchips [data-sc]").forEach(b=>b.classList.toggle("on",INV.sc.has(b.dataset.sc)));
    $("#invparams").classList.toggle("on",INV.paramsOnly);
  }
  /* filters */
  const qi=$("#invq");
  qi.addEventListener("input",()=>{invApplyQuery(qi.value);refresh();});
  $$("#invchips [data-m]").forEach(b=>b.onclick=()=>{const m=b.dataset.m;INV.methods.has(m)?INV.methods.delete(m):INV.methods.add(m);refresh();});
  $$("#invchips [data-sc]").forEach(b=>b.onclick=()=>{const m=b.dataset.sc;INV.sc.has(m)?INV.sc.delete(m):INV.sc.add(m);refresh();});
  $("#invparams").onclick=()=>{INV.paramsOnly=!INV.paramsOnly;refresh();};
  const rs=$("#invrole");if(rs)rs.onchange=()=>{INV.role=rs.value;refresh();};
  $("#invclear").onclick=()=>{INV.q="";INV.bql=null;INV.bqlErr=null;INV.methods.clear();INV.sc.clear();INV.role="";INV.paramsOnly=false;INV.node="";qi.value="";if(rs)rs.value="";refresh();};
  /* splitters */
  const drag=(el,move,end)=>{el.onpointerdown=ev=>{ev.preventDefault();el.classList.add("drag");el.setPointerCapture(ev.pointerId);
    el.onpointermove=e2=>move(e2);el.onpointerup=()=>{el.classList.remove("drag");el.onpointermove=el.onpointerup=null;end();};};};
  drag($("#gv"),e=>{const b=$(".inv-main").getBoundingClientRect();INV.tw=Math.max(150,Math.min(b.width*.55,e.clientX-b.left));tree.style.setProperty("--tw",INV.tw+"px");},()=>invSave());
  drag($("#gh"),e=>{const b=$(".inv-right").getBoundingClientRect();INV.th=Math.max(90,Math.min(b.height-140,e.clientY-b.top));$("#invtbl").style.height=INV.th+"px";drawBody();},()=>invSave());
  qi.addEventListener("keydown",e=>{if(e.key==="ArrowDown"){e.preventDefault();body.focus();if(INV.sel==null&&rows[0])select(rows[0].id);}});
  if(!INV.thSet){INV.thSet=true;try{if(!localStorage.getItem("b2m-inv")){const h=$(".inv-right").getBoundingClientRect().height;if(h>300){INV.th=Math.round(h*.42);$("#invtbl").style.height=INV.th+"px";}}}catch(e){}}
  refresh();
  if(INV.sel==null&&rows[0])select(rows[0].id);
}
"""
