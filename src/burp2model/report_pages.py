"""Pages with a request/response viewer underneath: To check, and Reference (the layered sunburst).

Every list on these pages is master-detail: pick a row and the masked request and response for it
appear in the viewer at the bottom, the way Burp's HTTP history works. The Reference page peels the
app in layers: click a ring of the chart and the table below lists what is in it.
"""

PG_CSS = r"""
/* split pages: content on top, viewer below */
.m-priorities,.m-reference,.m-ask{padding:0!important;overflow:hidden!important}
.m-priorities .view,.m-reference .view,.m-ask .view{max-width:none;height:100%}
.m-priorities .foot,.m-reference .foot,.m-ask .foot{display:none}
.splitpg{display:flex;flex-direction:column;height:100%;min-height:0}
.splitpg .top{flex:1 1 auto;min-height:140px;overflow:auto;padding:24px 32px 28px}
.splitpg .gut{height:4px;flex:none;background:var(--line);cursor:row-resize;position:relative;z-index:2}
.splitpg .gut:hover,.splitpg .gut.drag{background:var(--signal)}
.splitpg .bot{flex:none;min-height:190px;max-height:80%;border-top:1px solid var(--line);background:var(--panel)}
.splitpg .gut[hidden],.splitpg .bot[hidden]{display:none}
.rrnote{font:500 11.5px var(--sans);color:var(--faint);font-style:italic}
.rrp .code .l.hit{background:var(--signal-soft);box-shadow:inset 3px 0 var(--signal)}
.ptab{font:600 11px var(--mono);padding:3px 9px;border-radius:5px;border:1px solid transparent;background:none;color:var(--muted)}
.ptab.on{background:var(--panel);border-color:var(--line2);color:var(--text)}
.arow.sel{background:var(--signal-soft);border-color:var(--signal)}
.qtab tr.sel{background:var(--signal-soft);box-shadow:inset 3px 0 var(--signal)}
/* tabs and chips */
.tabs{display:flex;gap:4px;margin:6px 0 16px;border-bottom:1px solid var(--line)}
.tabs button{font:600 13px var(--sans);padding:9px 16px;border:0;background:none;color:var(--muted);border-bottom:2px solid transparent;margin-bottom:-1px}
.tabs button.on{color:var(--text);border-bottom-color:var(--signal)}
.tabs button .n{font:600 11px var(--mono);color:var(--faint);margin-left:6px}
.fchips{display:flex;gap:6px;flex-wrap:wrap;margin-bottom:14px;align-items:center}
.fchip{font:600 12px var(--sans);padding:5px 12px;border-radius:999px;border:1px solid var(--line2);background:var(--panel);color:var(--muted)}
.fchip.on{background:var(--text);color:var(--ink);border-color:var(--text)}
.fchip .n{font:600 11px var(--mono);margin-left:5px;opacity:.7}
/* leads */
.lrow{display:grid;grid-template-columns:34px minmax(0,1fr);gap:0 12px;background:var(--panel);border:1px solid var(--line);border-left:4px solid var(--c);border-radius:12px;padding:13px 16px 12px 12px;margin-bottom:9px;cursor:pointer}
.lrow:hover{border-color:var(--line2);border-left-color:var(--c)}
.lrow.sel{background:var(--panel2);border-color:var(--c);box-shadow:var(--shadow)}
.lrow .rk{font:700 13px var(--mono);color:var(--c);text-align:right;padding-top:2px}
.lrow .t{display:flex;gap:8px;align-items:center;flex-wrap:wrap}
.lrow .p{font:700 13.5px var(--mono);word-break:break-all}
.lrow .sevb{font:700 9.5px var(--mono);letter-spacing:.08em;text-transform:uppercase;color:var(--c);border:1px solid var(--c);border-radius:5px;padding:1px 6px}
.lrow .w{font:600 13.5px var(--sans);margin-top:5px}
.lrow .y{color:var(--muted);font-size:12.5px;margin-top:3px;max-width:90ch}
.lrow .nx{font-size:12.5px;margin-top:6px}
.lrow .nx b{font:700 10px var(--mono);letter-spacing:.08em;text-transform:uppercase;color:var(--c);margin-right:6px}
.lrow .more{color:var(--faint);font-size:12px;margin-top:4px}
.sev-hot{--c:var(--signal)}.sev-warn{--c:var(--warn)}.sev-info{--c:var(--observed)}
/* open questions */
.qgrp{margin:18px 0 8px;font:700 13px var(--display,var(--sans));display:flex;gap:8px;align-items:baseline}
.qgrp .n{font:600 11px var(--mono);color:var(--faint)}
.qrow{background:var(--panel);border:1px solid var(--line);border-radius:12px;padding:12px 16px;margin-bottom:8px;cursor:pointer}
.qrow:hover{border-color:var(--line2)}
.qrow.sel{background:var(--panel2);border-color:var(--l6)}
.qrow .e{font:700 13px var(--mono);word-break:break-all}
.qrow ul{margin:6px 0 0;padding-left:18px;color:var(--muted);font-size:12.5px}
.qrow .un{color:var(--l6)}
.qrow .nx{margin-top:7px;font-size:12.5px}
.qrow .nx b{font:700 10px var(--mono);letter-spacing:.08em;text-transform:uppercase;color:var(--l6);margin-right:6px}
/* reference: the layered chart */
.splitpg .top.refpg{display:flex;flex-direction:column;overflow:hidden;padding-bottom:0}
.refhd{flex:none}
.refgrid{flex:1;min-height:0;display:grid;grid-template-columns:minmax(300px,460px) minmax(0,1fr);gap:30px}
.refl,.refr{min-height:0;overflow:auto;padding-bottom:24px}
@media(max-width:1000px){.splitpg .top.refpg{overflow:auto}.refgrid{grid-template-columns:minmax(0,1fr)}.refl,.refr{overflow:visible}}
.sunwrap{position:relative;width:min(460px,100%,calc(58vh - 190px));min-width:260px;margin:0 auto 12px}
.sunwrap svg{width:100%;height:auto;display:block}
.sun path{stroke:var(--panel);stroke-width:1.2;cursor:pointer;transition:opacity .12s}
.sun path:hover{opacity:.82}
.sun path.pick{stroke:var(--text);stroke-width:2.2}
.sun text{font:600 10.5px var(--sans);fill:#fff;pointer-events:none;paint-order:stroke;stroke:rgba(0,0,0,.18);stroke-width:2px}
.sun .ctr{fill:var(--panel);stroke:var(--line2);stroke-width:1.5;cursor:pointer}
.sun .ctr:hover{fill:var(--panel2)}
.sun .ct1{font:700 15px var(--display,var(--sans));fill:var(--text);stroke:none;text-anchor:middle}
.sun .ct2{font:500 10.5px var(--sans);fill:var(--muted);stroke:none;text-anchor:middle}
.suntip{position:absolute;pointer-events:none;background:var(--panel);border:1px solid var(--line2);border-radius:9px;box-shadow:var(--shadow);padding:6px 10px;font:12px var(--mono);display:none;z-index:4;max-width:280px}
.suntip b{display:block;font:700 12.5px var(--mono);word-break:break-all}
.suntip span{color:var(--muted);font-size:11px}
.crumbs2{display:flex;gap:4px;flex-wrap:wrap;align-items:center;font:600 12px var(--mono);color:var(--muted);margin-bottom:10px}
.crumbs2 button{border:0;background:none;color:var(--muted);font:inherit;padding:2px 4px;border-radius:5px}
.crumbs2 button:hover{color:var(--signal)}
.crumbs2 .cur{color:var(--text)}
.reft h2{font:700 24px var(--display,var(--sans));letter-spacing:-.03em;margin:0 0 6px}
.reft p{color:var(--muted);font-size:14px;line-height:1.6;max-width:62ch;margin:0 0 14px}
.refkids{display:flex;gap:8px;flex-wrap:wrap}
.refkid{display:inline-flex;align-items:center;gap:7px;font:600 12.5px var(--sans);padding:6px 12px;border-radius:9px;border:1px solid var(--line2);background:var(--panel);color:var(--text)}
.refkid:hover{border-color:var(--signal)}
.refkid i{width:9px;height:9px;border-radius:3px;background:var(--c)}
.refkid .n{font:600 11px var(--mono);color:var(--faint)}
.layers{display:grid;grid-template-columns:repeat(auto-fill,minmax(230px,1fr));gap:12px}
.layer{background:var(--panel);border:1px solid var(--line);border-top:3px solid var(--c);border-radius:12px;padding:14px 16px;text-align:left;cursor:pointer}
.layer:hover{border-color:var(--c);box-shadow:var(--shadow)}
.layer{display:flex;flex-direction:column;align-items:flex-start;justify-content:flex-start}
.layer .nn{font:700 26px var(--display,var(--sans));letter-spacing:-.03em}
.layer b{display:block;font:700 13.5px var(--sans);margin:2px 0}
.layer span{color:var(--muted);font-size:12.5px}
.dtable{width:100%;border-collapse:collapse;font-size:13px;background:var(--panel);border:1px solid var(--line);border-radius:12px;overflow:hidden}
.dtable th{position:static;text-align:left;font:600 10.5px var(--mono);letter-spacing:.06em;text-transform:uppercase;color:var(--muted);background:var(--panel2);padding:8px 12px;border-bottom:1px solid var(--line);cursor:default}
.dtable td{padding:8px 12px;border-bottom:1px solid var(--line);vertical-align:middle}
.dtable tbody tr{cursor:pointer}
.dtable tbody tr:last-child td{border-bottom:0}
.dtable tbody tr:hover{background:var(--panel2)}
.dtable tbody tr.sel{background:var(--signal-soft);box-shadow:inset 3px 0 var(--signal)}
.dtable .mono{font:12.5px var(--mono)}
.dtable .dim{color:var(--muted)}
.dhead{display:flex;align-items:center;gap:12px;margin:0 0 10px;flex-wrap:wrap}
.dhead h3{font:700 16px var(--display,var(--sans));margin:0;letter-spacing:-.01em}
.dhead .n{color:var(--faint);font:600 12px var(--mono)}
.dhead input{margin-left:auto;height:32px;min-width:220px;padding:0 10px;border:1px solid var(--line2);border-radius:8px;background:var(--panel);color:var(--text);font:12.5px var(--mono)}
.dhead input:focus{border-color:var(--signal);outline:none}
.pickinfo{margin:12px 0 4px;display:flex;gap:6px;flex-wrap:wrap;align-items:center}
.pickinfo .k{font:600 10px var(--mono);letter-spacing:.09em;text-transform:uppercase;color:var(--faint);margin-right:2px}
.pickinfo .c{font:12px var(--mono);padding:3px 9px;border-radius:7px;background:var(--panel2);border:1px solid var(--line);color:var(--text)}
.pickinfo button.c:hover{border-color:var(--signal);color:var(--signal)}
.dsec{margin-bottom:22px}
.stackrow{display:grid;grid-template-columns:repeat(auto-fit,minmax(340px,1fr));gap:14px;margin-bottom:18px}
"""

PG_JS = r"""
/* ---------- split page helpers ---------- */
const SPL=(function(){let h=.4;try{const v=parseFloat(localStorage.getItem("b2m-split"));if(v>.15&&v<.8)h=v;}catch(e){}return{h};})();
function splitShell(inner,cls){return `<div class="splitpg" id="splitpg"><div class="top ${cls||""}" id="sptop">${inner}</div><div class="gut" id="spgut" hidden></div><div class="bot" id="spbot" hidden style="height:${Math.round(SPL.h*100)}%"></div></div>`;}
function highlightIn(el,text){
  if(!text)return;
  const lines=[...el.querySelectorAll(".rrp:last-child .code .l")];
  const hit=lines.find(l=>l.textContent.includes(text));
  if(!hit){const t=$(".rrt",el);if(t&&!$(".rrnote",el))t.insertAdjacentHTML("afterend",`<span class="rrnote">${esc(text)} is further into this script than the report keeps</span>`);return;}
  hit.classList.add("hit");
  const box=hit.closest(".code");if(box)box.scrollTop=Math.max(0,hit.offsetTop-box.clientHeight/3);
}
function splitShow(ids,opts){
  const bot=$("#spbot"),gut=$("#spgut");if(!bot)return;
  opts=opts||{};
  if((!ids||!ids.length)&&!opts.empty){bot.hidden=gut.hidden=true;return;}
  bot.hidden=gut.hidden=false;
  rrMount(bot,ids||[],opts);
  if(opts.find)highlightIn(bot,opts.find);
}
function splitInit(){
  const g=$("#spgut"),root=$("#splitpg");if(!g)return;
  g.onpointerdown=ev=>{ev.preventDefault();g.classList.add("drag");g.setPointerCapture(ev.pointerId);
    g.onpointermove=e=>{const b=root.getBoundingClientRect();SPL.h=Math.max(.16,Math.min(.78,(b.bottom-e.clientY)/b.height));$("#spbot").style.height=Math.round(SPL.h*100)+"%";};
    g.onpointerup=()=>{g.classList.remove("drag");g.onpointermove=g.onpointerup=null;try{localStorage.setItem("b2m-split",String(SPL.h));}catch(e){}};};
}
/* old section names keep working as links */
const LEGACY={surface:["reference","endpoints"],code:["reference","scripts"],supply:["reference","parties"],trust:["reference","trust"],
  crossrole:["reference","roles"],infra:["reference","infra"],unknowns:["priorities","open"],query:["ask"],evidence:["inventory"]};
function go(id){
  const l=LEGACY[id];
  if(!l){view=id;return;}
  view=l[0];
  if(l[0]==="reference"){REF.focusId=l[1];REF.pickId=null;}
  if(l[0]==="priorities")CHK.tab=l[1];
}
function evForLabel(label){
  if(!label)return [];
  const ep=EP.find(e=>e.label===label||e.path===label||(e.method+" "+e.path)===label);if(ep)return ep.evidence||[];
  const s=(D.scripts||[]).find(x=>x.label===label);if(s)return s.evidence||[];
  const r=(D.routes||[]).find(x=>x.label===label);if(r)return r.evidence||[];
  const t=(D.third_parties||[]).find(x=>x.label===label);if(t)return t.evidence||[];
  const c=(D.cookies||[]).find(x=>x.name===label);if(c)return c.evidence||[];
  return [];
}

/* ---------- TO CHECK: leads and open questions in one place ---------- */
const CHK={tab:"leads",sev:"all",type:"all",sel:null};
function chkLeads(){
  const items=PRIO.map(p=>({sev:p.sev,ep:p.ep,lead:p.sig[0],more:p.sig.slice(1),ids:p.ep.evidence||[],find:p.ep.state==="STATIC_ONLY"?p.ep.path:null,title:p.ep.method+" "+p.ep.path}));
  weakCookies.forEach(k=>{const miss=[!k.httponly&&"HttpOnly",!k.secure&&"Secure"].filter(Boolean);
    items.push({sev:"warn",cookie:k,lead:{ttl:`Cookie set without ${miss.join(" and ")}`,why:`SameSite is ${k.samesite||"unset"}. A cookie without ${miss.join(" or ")} is easier to steal or use cross-site.`,next:"Confirm whether this cookie carries a session or auth state."},more:[],ids:k.evidence||[],title:"cookie "+k.name});});
  return items;
}
function chkLeadRow(it,i){
  const e=it.ep,col={hot:"High",warn:"Medium",info:"Note"}[it.sev];
  return `<div class="lrow sev-${it.sev}${CHK.sel===i?" sel":""}" data-lead="${i}"><div class="rk">${i+1}</div><div>
    <div class="t"><span class="sevb">${col}</span>${e?methodm(e.method)+`<span class="p">${esc(e.path)}</span>`:`<span class="p">cookie ${esc(it.cookie.name)}</span>`}</div>
    <div class="w">${esc(it.lead.ttl)}</div><div class="y">${esc(it.lead.why)}</div><div class="nx"><b>Do next</b>${esc(it.lead.next)}</div>
    ${it.more.length?`<div class="more">+ ${it.more.map(s=>esc(s.ttl)).join(" · ")}</div>`:""}</div></div>`;
}
function vPriorities(){
  const leads=chkLeads(),open=D.unknowns||[];
  const body=CHK.tab==="leads"?chkLeadsHtml(leads):chkOpenHtml(open);
  return splitShell(`<h1 class="vt">To check</h1><p class="vsub">Leads worth a look first, and the questions this capture could not answer. Pick one to see the requests behind it below.</p>
   <div class="tabs"><button data-ctab="leads" class="${CHK.tab==="leads"?"on":""}">Leads<span class="n">${leads.length}</span></button><button data-ctab="open" class="${CHK.tab==="open"?"on":""}">Open questions<span class="n">${open.length}</span></button></div>${body}`);
}
function chkLeadsHtml(leads){
  if(!leads.length)return '<div class="empty">Nothing stood out in this capture. That says something about the capture, not the target.</div>';
  const cnt=s=>leads.filter(x=>x.sev===s).length;
  const shown=leads.map((x,i)=>[x,i]).filter(([x])=>CHK.sev==="all"||x.sev===CHK.sev);
  return `<div class="fchips">${[["all","All",leads.length],["hot","High",cnt("hot")],["warn","Medium",cnt("warn")],["info","Note",cnt("info")]].filter(c=>c[2]||c[0]==="all").map(([k,l,n])=>`<button class="fchip${CHK.sev===k?" on":""}" data-csev="${k}">${l}<span class="n">${n}</span></button>`).join("")}</div>
   <div id="leadlist">${shown.map(([x,i])=>chkLeadRow(x,i)).join("")||'<div class="empty">None at this level.</div>'}</div>`;
}
function chkOpenHtml(open){
  if(!open.length)return '<div class="empty">Nothing was left open in this capture.</div>';
  const types=tally(open,u=>u.type);
  const shown=open.map((u,i)=>[u,i]).filter(([u])=>CHK.type==="all"||u.type===CHK.type);
  const groups=new Map();shown.forEach(([u,i])=>{(groups.get(u.type)||groups.set(u.type,[]).get(u.type)).push([u,i]);});
  return `<div class="fchips"><button class="fchip${CHK.type==="all"?" on":""}" data-ctype="all">All<span class="n">${open.length}</span></button>${types.map(([k,n])=>`<button class="fchip${CHK.type===k?" on":""}" data-ctype="${esc(k)}">${esc(openTitle(k))}<span class="n">${n}</span></button>`).join("")}</div>
   <div id="openlist">${[...groups.entries()].map(([k,xs])=>`<div class="qgrp">${esc(openTitle(k))}<span class="n">${xs.length}</span></div>${xs.slice(0,60).map(([u,i])=>`<div class="qrow${CHK.sel===i?" sel":""}" data-open="${i}"><div class="e">${esc(u.entity)}</div>
     <ul>${u.we_know.map(x=>`<li>${esc(x)}</li>`).join("")}<li class="un">Unknown: ${esc(u.we_dont_know)}</li></ul><div class="nx"><b>To find out</b>${esc(u.next)}</div></div>`).join("")}${xs.length>60?`<div class="more" style="color:var(--faint);font-size:12px">+ ${xs.length-60} more of this kind</div>`:""}`).join("")}</div>`;
}
function initPriorities(){
  splitInit();
  const leads=chkLeads(),open=D.unknowns||[];
  $$("[data-ctab]").forEach(b=>b.onclick=()=>{CHK.tab=b.dataset.ctab;CHK.sel=null;render();});
  $$("[data-csev]").forEach(b=>b.onclick=()=>{CHK.sev=b.dataset.csev;CHK.sel=null;render();});
  $$("[data-ctype]").forEach(b=>b.onclick=()=>{CHK.type=b.dataset.ctype;CHK.sel=null;render();});
  const pick=(attr,list,show)=>$$(`[${attr}]`).forEach(r=>r.onclick=()=>{const i=+r.dataset[attr.replace("data-","")];CHK.sel=i;
    $$(`[${attr}]`).forEach(x=>x.classList.toggle("sel",x===r));show(list[i]);});
  pick("data-lead",leads,it=>splitShow(it.ids,{title:it.title,find:it.find,empty:{head:"No request for this one",text:"It was named in the code or the capture, but nothing was requested."}}));
  pick("data-open",open,u=>{const ids=evForLabel(u.entity);splitShow(ids,{title:u.entity,empty:{head:"Nothing to open",text:"This question is about something the capture does not contain, so there is no request to show."}});});
  const first=CHK.tab==="leads"?$("[data-lead]"):$("[data-open]");
  if(first)first.click();
}

/* ---------- REFERENCE: the app in layers ---------- */
const REF={focusId:"root",pickId:null,rowId:null,q:""};
const REF_COL={pages:"var(--l2)",scripts:"var(--l3)",endpoints:"var(--l4)",parties:"var(--l5)",trust:"var(--signal)",infra:"var(--l1)"};
const REF_INFO={
  root:["The whole app","Peel it layer by layer. Click a ring to open it; click the middle to go back out."],
  pages:["Pages","The HTML documents the server returns. Each one loads scripts and calls endpoints."],
  scripts:["Scripts","The JavaScript the browser runs. Code names more endpoints than the app ever calls."],
  endpoints:["Endpoints","The API the app talks to, grouped by feature."],
  parties:["Third parties","Code and services served from other domains, running in your users' browsers."],
  trust:["Trust","How the app knows who you are: credentials, cookies and roles."],
  infra:["Infrastructure","The hosts, servers and technologies underneath."],
  auth:["Credentials","Schemes the app sent on requests."],cookies:["Cookies","Set by the server, with their protective flags."],
  roles:["Roles","The accounts the capture was recorded as, and what each reached."],hosts:["Hosts","First-party hosts the app is served from."],stack:["Technology stack","Servers, frameworks and services read from the capture."]
};
let REF_TREE=null,REF_IDX=null;
function refBuild(){
  const routeName=r=>r.label.replace(/^[^/]*/,"")||"/";
  const areas=new Map();
  EP.slice().sort((a,b)=>a.path.localeCompare(b.path)).forEach(e=>{const a=areaOf({type:"endpoint",label:e.label})||"root";(areas.get(a)||areas.set(a,[]).get(a)).push(e);});
  const other=[];[...areas.entries()].forEach(([k,v])=>{if(v.length<2&&areas.size>6){other.push(...v);areas.delete(k);}});
  if(other.length)areas.set("other",other);
  const leaf=(kind,id,name,data,extra)=>Object.assign({kind,id,name,data,value:1},extra||{});
  const nodes=[];
  if((D.routes||[]).length)nodes.push({kind:"pages",id:"pages",name:"Pages",children:D.routes.map(r=>leaf("route","route:"+r.id,routeName(r),r))});
  if((D.scripts||[]).length)nodes.push({kind:"scripts",id:"scripts",name:"Scripts",children:D.scripts.map(s=>leaf("script","script:"+s.id,s.label,s))});
  if(EP.length)nodes.push({kind:"endpoints",id:"endpoints",name:"Endpoints",children:[...areas.entries()].sort((a,b)=>b[1].length-a[1].length||a[0].localeCompare(b[0])).map(([a,es])=>({kind:"area",id:"area:"+a,name:a,children:es.map(e=>leaf("endpoint","ep:"+e.id,(e.method!=="*"?e.method+" ":"")+e.path,e))}))});
  if((D.third_parties||[]).length)nodes.push({kind:"parties",id:"parties",name:"Third parties",children:D.third_parties.map(t=>leaf("party","party:"+t.id,t.label,t))});
  const tr=[];
  if((D.auth||[]).length)tr.push({kind:"auth",id:"auth",name:"Credentials",children:D.auth.map(a=>leaf("authx","auth:"+a.id,a.label,a))});
  if((D.cookies||[]).length)tr.push({kind:"cookies",id:"cookies",name:"Cookies",children:D.cookies.map(k=>leaf("cookie","cookie:"+k.name,k.name,k))});
  if((D.roles||[]).length>0)tr.push({kind:"roles",id:"roles",name:"Roles",children:D.roles.map(r=>leaf("role","role:"+r,r,{label:r}))});
  if(tr.length)nodes.push({kind:"trust",id:"trust",name:"Trust",children:tr});
  const inf=[];
  if((D.hosts||[]).length)inf.push({kind:"hosts",id:"hosts",name:"Hosts",children:D.hosts.map(h=>leaf("host","host:"+h.label,h.label,h))});
  if((D.stack||[]).length)inf.push({kind:"stack",id:"stack",name:"Stack",children:(D.stack||[]).map(t=>leaf("tech","tech:"+t.category+":"+t.name,t.name+(t.version?" "+t.version:""),t))});
  if(inf.length)nodes.push({kind:"infra",id:"infra",name:"Infrastructure",children:inf});
  const root={kind:"root",id:"root",name:D.app,children:nodes};
  REF_IDX=new Map();
  const walk=(n,p)=>{n.parent=p;REF_IDX.set(n.id,n);if(n.children){n.children.forEach(c=>walk(c,n));n.value=n.children.reduce((a,c)=>a+c.value,0);}};
  walk(root,null);
  const tag=(n,t)=>{n.top=t;(n.children||[]).forEach(x=>tag(x,t));};
  root.children.forEach(c=>tag(c,c.kind));root.top="root";
  REF_TREE=root;
}
const refLeaves=n=>n.children?n.children.flatMap(refLeaves):[n];
function refCrumbs(n){const a=[];for(let x=n;x;x=x.parent)a.unshift(x);return a;}
function vReference(){
  if(!REF_TREE)refBuild();
  return splitShell(`<div class="refhd"><h1 class="vt">Reference</h1><p class="vsub">Peel the app in layers. Click a ring to go deeper, the middle to go back. The list on the right shows what you opened; its request is below.</p></div>
   <div class="refgrid"><div class="refl"><div class="sunwrap" id="sunwrap"><svg viewBox="0 0 600 600" id="sun" class="sun" role="img" aria-label="The app in layers"></svg><div class="suntip" id="suntip"></div></div><div class="reft" id="reft"></div></div>
   <div class="refr" id="refdetail"></div></div>`,"refpg");
}
function arcPath(cx,cy,a0,a1,r0,r1){
  if(a1-a0>=Math.PI*2-1e-4)a1=a0+Math.PI*2-1e-4;
  const P=(r,a)=>[cx+r*Math.sin(a),cy-r*Math.cos(a)],large=a1-a0>Math.PI?1:0,A=P(r1,a0),B=P(r1,a1),C=P(r0,a1),Dd=P(r0,a0);
  return `M${A[0].toFixed(2)} ${A[1].toFixed(2)}A${r1} ${r1} 0 ${large} 1 ${B[0].toFixed(2)} ${B[1].toFixed(2)}L${C[0].toFixed(2)} ${C[1].toFixed(2)}A${r0} ${r0} 0 ${large} 0 ${Dd[0].toFixed(2)} ${Dd[1].toFixed(2)}Z`;
}
function initReference(){
  splitInit();
  if(!REF_TREE)refBuild();
  if(!REF_IDX.has(REF.focusId))REF.focusId="root";
  drawReference();
}
function drawReference(){
  const focus=REF_IDX.get(REF.focusId)||REF_TREE,svg=$("#sun"),tip=$("#suntip");
  const cx=300,cy=300,R0=74,RMAX=290;
  const depthOf=n=>n.children?1+Math.max(...n.children.map(depthOf)):0;
  const D3=Math.max(1,Math.min(3,depthOf(focus))),T=(RMAX-R0)/D3;
  const col=n=>REF_COL[n.top]||"var(--l1)";
  const arcs=[];
  const place=(n,a0,a1,d)=>{
    if(d>D3)return;
    if(d>0)arcs.push({n,a0,a1,d});
    if(!n.children||d>=D3)return;
    const w=n.children.map(c=>Math.pow(c.value,.62)),tot=w.reduce((a,b)=>a+b,0);let a=a0;
    n.children.forEach((c,i)=>{const span=(a1-a0)*w[i]/tot;place(c,a,a+span,d+1);a+=span;});
  };
  place(focus,0,Math.PI*2,0);
  let h="";
  arcs.forEach((x,i)=>{
    const r0=R0+(x.d-1)*T,r1=r0+T-1.5,op=[1,.86,.7][x.d-1];
    const pick=REF.pickId===x.n.id;
    h+=`<path d="${arcPath(cx,cy,x.a0,x.a1,r0,r1)}" style="fill:${col(x.n)};opacity:${op}" class="${pick?"pick":""}" data-n="${esc(x.n.id)}"></path>`;
    const mid=(x.a0+x.a1)/2,rm=(r0+r1)/2,len=(x.a1-x.a0)*rm;
    if(len>15){
      const deg=mid*180/Math.PI,flip=deg>180,rot=flip?deg+90:deg-90,tx=cx+rm*Math.sin(mid),ty=cy-rm*Math.cos(mid);
      const max=Math.max(3,Math.floor((T-8)/6.3));let t=x.n.name||"";if(t.length>max)t=t.slice(0,max-1)+"…";
      h+=`<text transform="translate(${tx.toFixed(1)} ${ty.toFixed(1)}) rotate(${rot.toFixed(1)})" text-anchor="middle" dominant-baseline="central">${esc(t)}</text>`;
    }
  });
  const up=focus.parent;
  h+=`<circle class="ctr" cx="${cx}" cy="${cy}" r="${R0-3}" data-up="1"></circle><text class="ct1" x="${cx}" y="${cy-2}">${esc((focus.name||"").slice(0,16))}</text><text class="ct2" x="${cx}" y="${cy+16}">${up?"click to go back":"click a ring"}</text>`;
  svg.innerHTML=h;
  const byId=id=>REF_IDX.get(id);
  $$("path[data-n]",svg).forEach(p=>{
    p.onclick=()=>{const n=byId(p.dataset.n);REF.pickId=n.id;REF.rowId=null;
      if(n.children&&n.children.length)REF.focusId=n.id;else REF.focusId=(n.parent||REF_TREE).id;
      if(!n.children&&n.kind==="endpoint")REF.rowId=n.data.id;else if(!n.children)REF.rowId=n.id;
      drawReference();};
    p.onpointermove=e=>{const n=byId(p.dataset.n),r=$("#sunwrap").getBoundingClientRect();tip.style.display="block";tip.style.left=Math.min(r.width-200,e.clientX-r.left+14)+"px";tip.style.top=(e.clientY-r.top+14)+"px";
      tip.innerHTML=`<b>${esc(n.name)}</b><span>${esc(n.children?n.value+" item"+(n.value===1?"":"s"):humanize(n.kind))}</span>`;};
    p.onpointerleave=()=>{tip.style.display="none";};
  });
  $(".ctr",svg).onclick=()=>{if(focus.parent){REF.focusId=focus.parent.id;REF.pickId=null;REF.rowId=null;drawReference();}};
  refPanel(focus);refDetail(focus);
}
function refPanel(focus){
  const info=REF_INFO[focus.kind]||[focus.name,""];
  const crumbs=refCrumbs(focus);
  const kids=focus.children||[];
  $("#reft").innerHTML=`<div class="crumbs2">${crumbs.map((c,i)=>i<crumbs.length-1?`<button data-rc="${esc(c.id)}">${esc(c.name)}</button><span>/</span>`:`<span class="cur">${esc(c.name)}</span>`).join("")}</div>
    <h2>${esc(focus.kind==="root"?D.app:info[0]&&focus.kind!=="area"?info[0]:focus.name)}</h2><p>${esc(focus.kind==="area"?`Endpoints under /${focus.name}.`:info[1])}</p>
    ${kids.length?`<div class="refkids">${kids.slice(0,16).map(k=>`<button class="refkid" style="--c:${REF_COL[k.top]||"var(--l1)"}" data-rk="${esc(k.id)}"><i></i>${esc((k.name||"").slice(0,26))}<span class="n">${k.children?k.value:""}</span></button>`).join("")}${kids.length>16?`<span class="refkid" style="border-style:dashed">+${kids.length-16} more</span>`:""}</div>`:""}`;
  $$("[data-rc],[data-rk]",$("#reft")).forEach(b=>b.onclick=()=>{const n=REF_IDX.get(b.dataset.rc||b.dataset.rk);if(!n)return;REF.pickId=null;REF.rowId=null;
    if(n.children&&n.children.length)REF.focusId=n.id;else{REF.focusId=(n.parent||REF_TREE).id;REF.pickId=n.id;REF.rowId=n.kind==="endpoint"?n.data.id:n.id;}drawReference();});
}
/* what sits in the focused layer, as a table; a row opens its request below */
function refTable(cols,rows,rowId,selId){
  return `<table class="dtable"><thead><tr>${cols.map(c=>`<th>${esc(c)}</th>`).join("")}</tr></thead><tbody>${rows.map(r=>`<tr data-row="${esc(rowId(r))}" class="${rowId(r)===selId?"sel":""}">${r.cells.map(c=>`<td>${c}</td>`).join("")}</tr>`).join("")||`<tr><td colspan="${cols.length}"><div class="empty">Nothing here.</div></td></tr>`}</tbody></table>`;
}
function refDetail(focus){
  const box=$("#refdetail");let html="",onRow=null,pre=null;
  const leaves=refLeaves(focus).filter(l=>l!==focus||!focus.children);
  const of=k=>leaves.filter(l=>l.kind===k);
  const k=focus.kind;
  const sel=REF.rowId;
  const info=(label,items,fn)=>items&&items.length?`<span class="k">${label}</span>${items.slice(0,14).map(fn||(x=>`<span class="c">${esc(x)}</span>`)).join("")}${items.length>14?`<span class="c">+${items.length-14}</span>`:""}`:"";
  const jump=(label)=>{const e=EP.find(x=>x.label===label||(x.method+" "+x.path)===label||x.path===label);return e?`<button class="c" data-jump="${esc(e.id)}">${esc(label)}</button>`:`<span class="c">${esc(label)}</span>`;};
  if(k==="root"){
    html=`<div class="layers">${REF_TREE.children.map(c=>`<button class="layer" style="--c:${REF_COL[c.kind]||"var(--l1)"}" data-rk="${esc(c.id)}"><div class="nn">${refLeaves(c).length}</div><b>${esc(c.name)}</b><span>${esc((REF_INFO[c.kind]||["",""])[1])}</span></button>`).join("")}</div>`;
  }else if(k==="pages"||k==="route"){
    const rows=of("route").map(l=>({id:l.id,n:l,cells:[`<span class="mono">${esc(l.name)}</span>`,statuses(l.data.statuses),`<span class="dim">${l.data.calls.length} call${l.data.calls.length===1?"":"s"}</span>`,`<span class="dim">${l.data.scripts.length} script${l.data.scripts.length===1?"":"s"}</span>`,`<span class="dim mono">${esc((l.data.roles||[]).join(", ")||"")}</span>`]}));
    html=`<div class="dhead"><h3>Pages</h3><span class="n">${rows.length}</span></div>${refTable(["Page","Status","Calls","Scripts","Roles"],rows,r=>r.id,sel)}<div class="pickinfo" id="pickinfo"></div>`;
    onRow=id=>{const l=rows.find(r=>r.id===id).n;splitShow(l.data.evidence,{title:l.data.label});
      $("#pickinfo").innerHTML=info("Calls",l.data.calls,jump)+info("Loads",l.data.scripts);};
  }else if(k==="scripts"||k==="script"){
    const rows=of("script").map(l=>({id:l.id,n:l,cells:[`<span class="mono">${esc(l.name)}</span>`,`<span class="dim mono">${esc(l.data.host||"")}</span>`,`<span class="dim">${l.data.references.length} endpoint reference${l.data.references.length===1?"":"s"}</span>`]}));
    html=`<div class="dhead"><h3>Scripts</h3><span class="n">${rows.length}</span></div>${refTable(["Script","Host","References"],rows,r=>r.id,sel)}<div class="pickinfo" id="pickinfo"></div>`;
    onRow=id=>{const l=rows.find(r=>r.id===id).n;splitShow(l.data.evidence,{title:l.data.label+" (beautified)"});
      $("#pickinfo").innerHTML=info("Names these endpoints",l.data.references,jump);};
  }else if(k==="endpoints"||k==="area"||k==="endpoint"){
    const all=of("endpoint").map(l=>l.data),q=(REF.q||"").toLowerCase();
    const list=all.filter(e=>!q||(e.label+" "+e.host).toLowerCase().includes(q));
    const rows=list.slice(0,400).map(e=>({id:e.id,e,cells:[methodm(e.method),`<span class="mono">${esc(e.path)}</span>${e.privileged?' <span class="m w">admin</span>':""}`,
      `<span class="dim">${e.state==="BOTH"?"code + traffic":e.state==="STATIC_ONLY"?"code only":"traffic only"}</span>`,statuses(e.statuses),`<span class="dim">${e.params.length||""}</span>`,`<span class="dim mono">${esc((e.roles||[]).join(", "))}</span>`]}));
    html=`<div class="dhead"><h3>${esc(k==="area"?"/"+focus.name:"Endpoints")}</h3><span class="n">${list.length}${q?" of "+all.length:""}</span><input id="refq" placeholder="filter endpoints" value="${esc(REF.q)}"></div>${refTable(["","Endpoint","Seen","Status","Params","Roles"],rows,r=>r.id,sel)}${list.length>400?`<div class="dnote">Showing the first 400. Filter to narrow.</div>`:""}<div class="pickinfo" id="pickinfo"></div>`;
    onRow=id=>{const e=EP.find(x=>x.id===id);splitShow(e.evidence,{title:e.label,find:e.state==="STATIC_ONLY"?e.path:null,empty:{head:"Not requested",text:"The code names this endpoint but nothing in the capture called it."}});
      $("#pickinfo").innerHTML=info("Params",e.params)+info("Named in",e.referenced_by)+info("Called from",e.called_from)+info("Credentials",e.credentials)+info("Reached by",e.roles);};
  }else if(k==="parties"||k==="party"){
    const rows=of("party").map(l=>({id:l.id,n:l,cells:[`<span class="mono">${esc(l.name)}</span>`,`<span class="dim">${l.data.requests||(l.data.evidence||[]).length} request${(l.data.requests||(l.data.evidence||[]).length)===1?"":"s"}</span>`,`<span class="dim mono">${esc((l.data.referenced_by||[]).join(", "))}</span>`]}));
    html=`<div class="dhead"><h3>Third parties</h3><span class="n">${rows.length}</span></div>${refTable(["Host","Requests","Named in"],rows,r=>r.id,sel)}`;
    onRow=id=>{const l=rows.find(r=>r.id===id).n;splitShow(l.data.evidence,{title:l.data.label});};
  }else if(k==="trust"||k==="auth"||k==="cookies"){
    const au=k==="trust"||k==="auth"?of("authx"):[],ck=k==="trust"||k==="cookies"?of("cookie"):[];
    const yes=v=>v?'<span class="st g">yes</span>':'<span class="st r">no</span>';
    const ar=au.map(l=>({id:l.id,n:l,cells:[`<span class="mono">${esc(l.name)}</span>`,`<span class="dim">${l.data.endpoints.length} endpoint${l.data.endpoints.length===1?"":"s"}</span>`]}));
    const cr=ck.map(l=>({id:l.id,n:l,cells:[`<span class="mono">${esc(l.name)}</span>`,yes(l.data.httponly),yes(l.data.secure),`<span class="mono dim">${esc(l.data.samesite||"unset")}</span>`]}));
    html=(ar.length?`<div class="dsec"><div class="dhead"><h3>Credentials</h3><span class="n">${ar.length}</span></div>${refTable(["Scheme","Seen on"],ar,r=>r.id,sel)}</div>`:"")+
      (cr.length?`<div class="dsec"><div class="dhead"><h3>Cookies</h3><span class="n">${cr.length}</span></div>${refTable(["Cookie","HttpOnly","Secure","SameSite"],cr,r=>r.id,sel)}</div>`:"")+
      (k==="trust"&&(D.roles||[]).length?`<div class="pickinfo"><span class="k">Roles</span>${D.roles.map(r=>`<button class="c" data-rk="roles">${esc(r)}</button>`).join("")}</div>`:"")+
      (!ar.length&&!cr.length?'<div class="empty">No credentials or cookies were observed.</div>':"")+`<div class="pickinfo" id="pickinfo"></div>`;
    onRow=id=>{const r=ar.concat(cr).find(x=>x.id===id);if(!r)return;let ids=r.n.data.evidence||[];
      if(r.n.kind==="authx"){const e=EP.find(x=>r.n.data.endpoints.includes(x.label));ids=e?e.evidence:[];}
      splitShow(ids,{title:r.n.name});
      $("#pickinfo").innerHTML=r.n.kind==="authx"?info("Seen on",r.n.data.endpoints,jump):"";};
  }else if(k==="roles"||k==="role"){
    html=`<div id="xrole">${vCrossrole().replace(/<h1[^>]*>.*?<\/h1>/,"").replace(/<p class="vsub">.*?<\/p>/,"")}</div>`;
  }else if(k==="infra"||k==="hosts"||k==="stack"||k==="host"||k==="tech"){
    const hs=(D.hosts||[]);
    const hrows=hs.map(h=>({id:"host:"+h.label,h,cells:[`<span class="mono">${esc(h.label)}</span>`,`<span class="dim mono">${esc((h.schemes||[]).join("/")+(h.ports&&h.ports.length?":"+h.ports.join(","):""))}</span>`,`<span class="dim mono">${esc(Object.entries(h.tech||{}).map(([a,b])=>b?a+": "+b:a).join(" · ")||"")}</span>`]}));
    const sc=k==="stack"||k==="infra"||k==="tech"?stackCard():"",ic=k==="infra"||k==="hosts"||k==="host"?infraCard():"";
    html=(k!=="stack"&&k!=="tech"?`<div class="dsec"><div class="dhead"><h3>Hosts</h3><span class="n">${hs.length}</span></div>${refTable(["Host","Served over","Headers"],hrows,r=>r.id,sel)}</div>`:"")+
      `<div class="stackrow">${ic}${sc}</div>`+(k!=="stack"&&k!=="tech"&&BQLDB&&BQLDB.osint?`<div class="dsec"><div class="dhead"><h3>External recon</h3></div>${vInfra().replace(/<h1[^>]*>.*?<\/h1>/,"").replace(/<p class="vsub">[\s\S]*?<\/p>/,"")}</div>`:"")+`<div class="pickinfo" id="pickinfo"></div>`;
    onRow=id=>{const r=hrows.find(x=>x.id===id);if(r)splitShow(r.h.evidence,{title:r.h.label});};
  }
  box.innerHTML=html;
  const qi=$("#refq");if(qi)qi.oninput=()=>{REF.q=qi.value;const p=qi.selectionStart;refDetail(focus);const n=$("#refq");n.focus();n.setSelectionRange(p,p);};
  $$("[data-rk]",box).forEach(b=>b.onclick=()=>{const n=REF_IDX.get(b.dataset.rk);if(n){REF.focusId=n.id;REF.pickId=null;REF.rowId=null;drawReference();}});
  $$("[data-jump]",box).forEach(b=>b.onclick=()=>{REF.focusId="endpoints";REF.pickId="ep:"+b.dataset.jump;REF.rowId=b.dataset.jump;REF.q="";drawReference();});
  $$("[data-ev]",box).forEach(b=>b.onclick=()=>openEv(b.dataset.ev));
  $$("[data-ep]",box).forEach(b=>b.onclick=()=>openEp(b.dataset.ep));
  $$("tr[data-row]",box).forEach(r=>r.onclick=()=>{REF.rowId=r.dataset.row;$$("tr[data-row]",box).forEach(x=>x.classList.toggle("sel",x===r));if(onRow)onRow(r.dataset.row);});
  if(onRow&&sel&&$(`tr[data-row="${CSS.escape(sel)}"]`,box)){const tr=$(`tr[data-row="${CSS.escape(sel)}"]`,box);tr.classList.add("sel");onRow(sel);tr.scrollIntoView({block:"nearest"});}
  else if(onRow){const f=$("tr[data-row]",box);if(f)f.click();else splitShow([]);}
  else splitShow([]);
}
"""
