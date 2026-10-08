"""The Dashboard view of the offline report: charts and rankings drawn as plain SVG/CSS.

Kept apart from report.py so the template stays readable. `DASH_CSS` and `DASH_JS` are
spliced into the page; everything is computed from the payload `D` the report embeds.
"""

DASH_CSS = r"""
/* dashboard */
/* at a glance: screenshot, infrastructure, stack */
.band{display:grid;gap:18px;align-items:start;margin-bottom:24px;grid-template-columns:minmax(0,1fr) minmax(0,1.25fr)}
.band.shot{grid-template-columns:minmax(0,.95fr) minmax(0,.9fr) minmax(0,1.3fr)}
@media(max-width:1250px){.band.shot{grid-template-columns:minmax(0,1fr) minmax(0,1fr)}.band.shot .shotcard{grid-column:1/-1}}
@media(max-width:900px){.band,.band.shot{grid-template-columns:minmax(0,1fr)}}
.shotcard{background:var(--panel);border:1px solid var(--line);border-radius:14px;overflow:hidden;display:flex;flex-direction:column}
.shotcard .sbar{display:flex;align-items:center;gap:6px;padding:9px 12px;background:var(--panel2);border-bottom:1px solid var(--line)}
.shotcard .sbar i{width:9px;height:9px;border-radius:50%;background:var(--line2)}
.shotcard .sbar span{margin-left:8px;flex:1;font:11.5px var(--mono);color:var(--muted);background:var(--panel);border:1px solid var(--line);border-radius:6px;padding:3px 9px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.shotcard button.simg{border:0;padding:0;background:var(--ink);cursor:zoom-in;flex:1;min-height:200px;display:block}
.shotcard img{width:100%;height:100%;min-height:200px;max-height:340px;object-fit:cover;object-position:top;display:block}
.lightbox{position:fixed;inset:0;z-index:80;background:rgba(10,13,18,.82);display:grid;place-items:center;padding:30px;cursor:zoom-out}
.lightbox img{max-width:100%;max-height:100%;border-radius:10px;box-shadow:var(--shadow)}
.irows{display:grid;grid-template-columns:104px minmax(0,1fr);gap:0}
.irows .k{color:var(--muted);font-size:12.5px;padding:6px 0;border-bottom:1px solid var(--line)}
.irows .v{font:12.5px var(--mono);padding:6px 0;border-bottom:1px solid var(--line);overflow-wrap:anywhere}
.irows .k:nth-last-child(2),.irows .v:last-child{border-bottom:0}
.irows .v small{color:var(--faint);margin-left:6px}
.smap{display:flex;align-items:stretch;gap:0;flex-wrap:wrap;row-gap:12px}
.smap .sn{background:var(--panel2);border:1px solid var(--line);border-radius:10px;padding:8px 10px;min-width:96px;display:flex;flex-direction:column;gap:5px;align-self:stretch}
.smap .sn.you{justify-content:center;align-items:center;font:600 12px var(--mono);color:var(--muted);min-width:70px}
.smap .sl{font:600 9.5px var(--mono);letter-spacing:.1em;text-transform:uppercase;color:var(--faint)}
.smap .sa{display:grid;place-items:center;width:24px;color:var(--faint);font-size:15px}
.tp{display:inline-flex;align-items:center;gap:6px;font:600 12px var(--sans);padding:3px 4px 3px 0;border:0;background:none;color:var(--text);text-align:left}
.tp i{width:8px;height:8px;border-radius:2px;flex:none}
.tp small{color:var(--faint);font:500 10.5px var(--mono)}
.tp:hover{color:var(--signal)}
.svc{margin-top:14px;display:grid;grid-template-columns:96px minmax(0,1fr);gap:8px 12px;align-items:baseline}
.svc .sk{font:600 10px var(--mono);letter-spacing:.09em;text-transform:uppercase;color:var(--faint)}
.svc .sv{display:flex;flex-wrap:wrap;gap:4px 14px}
.m-overview{padding:26px 32px 60px}
.ovh{display:grid;grid-template-columns:minmax(0,1.5fr) minmax(0,1fr);gap:28px;align-items:end;margin-bottom:26px}
@media(max-width:1000px){.ovh{grid-template-columns:minmax(0,1fr)}}
.ovh h1{font:700 30px/1.1 var(--sans);letter-spacing:-.025em;margin:0 0 8px}
.ovh .sum{font-size:16px;line-height:1.55;color:var(--muted);max-width:62ch;margin:0}
.ovh .sum b{color:var(--text);font-weight:700}
.ovh .meta{color:var(--faint);font:12px var(--mono);margin-top:10px}
.big4{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:10px}
.big4 button{background:var(--panel);border:1px solid var(--line);border-radius:14px;padding:14px 14px 12px;text-align:left;cursor:pointer}
.big4 button:hover{border-color:var(--line2);box-shadow:var(--shadow)}
.big4 .n{font:700 32px/1 var(--sans);letter-spacing:-.03em}
.big4 .k{font-size:12px;color:var(--muted);margin-top:6px}
.big4 .hot .n{color:var(--signal)}
.ovg{display:grid;grid-template-columns:minmax(0,1.6fr) minmax(0,1fr);gap:18px;margin-bottom:22px}
@media(max-width:1100px){.ovg{grid-template-columns:minmax(0,1fr)}}
.sech{display:flex;align-items:baseline;gap:10px;margin:0 0 12px}
.sech h2{font:700 16px var(--sans);margin:0;letter-spacing:-.01em}
.sech .s{color:var(--faint);font-size:12.5px}
.sech .lnk{margin-left:auto;font:600 12.5px var(--sans);color:var(--signal);background:none;border:0}
.lead{display:grid;grid-template-columns:30px minmax(0,1fr) auto;gap:14px;align-items:start;background:var(--panel);border:1px solid var(--line);border-left:4px solid var(--c,var(--signal));border-radius:12px;padding:14px 16px;margin-bottom:10px}
.lead .num{font:700 14px var(--mono);color:var(--c,var(--signal));padding-top:2px}
.lead .t{display:flex;gap:8px;align-items:center;flex-wrap:wrap;font:700 14px var(--mono);word-break:break-all}
.lead .w{font:600 13px var(--sans);margin-top:4px}
.lead .y{color:var(--muted);font-size:12.5px;margin-top:2px;max-width:80ch}
.lead .nx{font-size:12.5px;margin-top:6px;color:var(--text)}
.lead .nx b{font:700 10px var(--mono);letter-spacing:.08em;text-transform:uppercase;color:var(--c,var(--signal));margin-right:6px}
.lead .acts{display:flex;flex-direction:column;gap:6px}
.abtn{font:600 12px var(--sans);padding:6px 11px;border-radius:8px;border:1px solid var(--line2);background:var(--panel);color:var(--muted);white-space:nowrap}
.abtn:hover{color:var(--text);border-color:var(--faint)}
.abtn.pri{background:var(--text);color:var(--ink);border-color:var(--text)}
@media(max-width:700px){.lead{grid-template-columns:24px minmax(0,1fr)}.lead .acts{grid-column:2;flex-direction:row}}
.side{display:flex;flex-direction:column;gap:14px}
.tiles{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:12px;margin-bottom:22px}
@media(max-width:1000px){.tiles{grid-template-columns:repeat(2,minmax(0,1fr))}}
.tile{background:var(--panel);border:1px solid var(--line);border-radius:14px;padding:16px;cursor:pointer;text-align:left}
.tile:hover{border-color:var(--signal);box-shadow:var(--shadow)}
.tile b{display:block;font:700 14.5px var(--sans);margin-bottom:4px}
.tile span{color:var(--muted);font-size:12.5px}
details.more{border:1px solid var(--line);border-radius:14px;background:var(--panel);margin-bottom:18px}
details.more>summary{cursor:pointer;list-style:none;padding:14px 18px;font:700 14px var(--sans);display:flex;gap:10px;align-items:center}
details.more>summary::-webkit-details-marker{display:none}
details.more>summary::before{content:"▸";color:var(--faint);transition:transform .15s}
details.more[open]>summary::before{transform:rotate(90deg)}
details.more>summary span{font-weight:500;color:var(--faint);font-size:12.5px}
details.more .inner{padding:0 18px 18px}
.dh1{display:flex;align-items:flex-end;gap:18px;flex-wrap:wrap;margin-bottom:18px}
.dh1 h1{font:700 28px/1.1 var(--sans);letter-spacing:-.025em;margin:0}
.dh1 .sub{color:var(--muted);font:12.5px var(--mono);margin-top:6px}
.dh1 .sp{flex:1}
.dtags{display:flex;gap:6px;flex-wrap:wrap}
.dtag{font:600 11px var(--mono);padding:4px 10px;border-radius:999px;background:var(--panel);border:1px solid var(--line);color:var(--muted)}
.dtag b{color:var(--text)}
.dkpis{display:grid;grid-template-columns:repeat(6,minmax(0,1fr));gap:12px;margin-bottom:14px}
@media(max-width:1180px){.dkpis{grid-template-columns:repeat(3,minmax(0,1fr))}}
@media(max-width:620px){.dkpis{grid-template-columns:repeat(2,minmax(0,1fr))}}
.dk{position:relative;background:var(--panel);border:1px solid var(--line);border-radius:14px;padding:15px 16px 13px;overflow:hidden;cursor:pointer;
transition:transform .12s,border-color .12s,box-shadow .12s}
.dk:hover{transform:translateY(-2px);border-color:var(--line2);box-shadow:var(--shadow)}
.dk::before{content:"";position:absolute;inset:0 0 auto 0;height:3px;background:var(--c,var(--line2))}
.dk .n{font:700 32px/1 var(--sans);letter-spacing:-.03em}
.dk .k{font:600 11px var(--mono);letter-spacing:.07em;text-transform:uppercase;color:var(--muted);margin-top:8px}
.dk .s{color:var(--faint);font-size:11.5px;margin-top:4px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.dgrid{display:grid;gap:14px;margin-bottom:14px}
.dg3{grid-template-columns:repeat(3,minmax(0,1fr))}
.dg2{grid-template-columns:minmax(0,1.35fr) minmax(0,1fr)}
.dg21{grid-template-columns:minmax(0,1fr) minmax(0,1fr) minmax(0,1fr)}
@media(max-width:1100px){.dg3,.dg2,.dg21{grid-template-columns:minmax(0,1fr)}}
.dc{background:var(--panel);border:1px solid var(--line);border-radius:14px;overflow:hidden;display:flex;flex-direction:column;min-width:0}
.dc>.h{display:flex;align-items:center;gap:8px;padding:13px 16px 0;font:600 13px var(--sans)}
.dc>.h .ct{margin-left:auto;color:var(--faint);font:600 11px var(--mono)}
.dc>.h .lnk{margin-left:auto;font:600 12px var(--sans);color:var(--signal);background:none;border:0;padding:0}
.dc>.b{padding:14px 16px 16px;flex:1;min-width:0}
.dnote{color:var(--faint);font-size:11.5px;margin-top:10px}
/* donut */
.dwrap{display:flex;align-items:center;gap:20px;flex-wrap:wrap}
.donut text{font-family:var(--sans)}
.dleg{display:flex;flex-direction:column;gap:9px;min-width:150px;flex:1}
.dleg .r{display:flex;align-items:center;gap:8px;font-size:12.5px;cursor:pointer}
.dleg .r:hover b{color:var(--signal)}
.dleg .sw{width:10px;height:10px;border-radius:3px;flex:none}
.dleg .l{color:var(--muted);flex:1}
.dleg b{font:600 13px var(--mono)}
.dleg .pc{color:var(--faint);font:11px var(--mono);width:38px;text-align:right}
/* bars */
.hb{display:flex;flex-direction:column;gap:8px}
.hb .r{display:grid;grid-template-columns:minmax(80px,38%) minmax(0,1fr) 44px;align-items:center;gap:10px;font-size:12.5px;cursor:pointer}
.hb .r .l{overflow:hidden;text-overflow:ellipsis;white-space:nowrap;color:var(--text);font-family:var(--mono);font-size:12px}
.hb .r .t{height:9px;border-radius:999px;background:var(--panel2);overflow:hidden}
.hb .r .t i{display:block;height:100%;border-radius:999px;background:var(--c,var(--observed));transform-origin:left;animation:grow .7s cubic-bezier(.2,.8,.2,1) both}
.hb .r .v{font:600 12px var(--mono);color:var(--muted);text-align:right}
.hb .r:hover .l{color:var(--signal)}
@keyframes grow{from{transform:scaleX(0)}}
@media(prefers-reduced-motion:reduce){.hb .r .t i{animation:none}.view.on{animation:none}}
.hb.sm .r{grid-template-columns:54px minmax(0,1fr) 44px}
.hb.wide .r{grid-template-columns:minmax(110px,52%) minmax(0,1fr) 40px}
.hb.wide .r .l{font-family:var(--sans);font-size:12.5px}
/* stacked */
.stk{display:flex;height:14px;border-radius:999px;overflow:hidden;background:var(--panel2)}
.stk i{display:block;height:100%}
.stkleg{display:flex;flex-wrap:wrap;gap:6px 14px;margin-top:10px;font-size:12px;color:var(--muted)}
.stkleg .k{display:inline-flex;gap:6px;align-items:center}
.stkleg .sw{width:9px;height:9px;border-radius:3px}
.stkleg b{font:600 12px var(--mono);color:var(--text)}
/* attention */
.att{display:grid;grid-template-columns:repeat(3,1fr);gap:10px}
.att .a{border:1px solid var(--line);border-radius:12px;padding:12px 12px 10px;cursor:pointer;background:var(--panel2);border-top:3px solid var(--c)}
.att .a:hover{border-color:var(--c)}
.att .a .n{font:700 28px/1 var(--sans);color:var(--c)}
.att .a .k{font:600 10px var(--mono);letter-spacing:.08em;text-transform:uppercase;color:var(--muted);margin-top:6px}
.dlist .it{display:flex;align-items:flex-start;gap:10px;padding:10px 0;border-bottom:1px solid var(--line);cursor:pointer}
.dlist .it:last-child{border-bottom:0;padding-bottom:0}
.dlist .it:first-child{padding-top:0}
.dlist .rk{font:700 12px var(--mono);color:var(--c,var(--signal));width:18px;flex:none;padding-top:2px}
.dlist .tx{min-width:0;flex:1}
.dlist .tt{display:flex;gap:8px;align-items:center;flex-wrap:wrap;font:600 13px var(--mono)}
.dlist .tt .p{overflow:hidden;text-overflow:ellipsis;white-space:nowrap;max-width:100%}
.dlist .ds{color:var(--muted);font-size:12px;margin-top:2px}
.dlist .it:hover .tt .p{color:var(--signal)}
.sevd{width:8px;height:8px;border-radius:50%;background:var(--c);flex:none;margin-top:6px}
/* layer strip */
.lstrip{display:grid;grid-template-columns:repeat(6,minmax(0,1fr));gap:0;border:1px solid var(--line);border-radius:14px;overflow:hidden;background:var(--panel);margin-bottom:14px}
@media(max-width:900px){.lstrip{grid-template-columns:repeat(2,minmax(0,1fr))}}
.ls{padding:14px 16px;border-right:1px solid var(--line);position:relative;cursor:pointer}
.ls:last-child{border-right:0}
.ls:hover{background:var(--panel2)}
.ls .ln{font:600 10px var(--mono);letter-spacing:.1em;text-transform:uppercase;color:var(--c);display:flex;align-items:center;gap:6px}
.ls .ln::before{content:"";width:8px;height:8px;border-radius:2px;background:var(--c)}
.ls .n{font:700 24px/1.1 var(--sans);margin-top:8px;letter-spacing:-.02em}
.ls .d{color:var(--faint);font-size:11.5px;margin-top:3px}
/* capture strip */
.cstrip{width:100%;height:56px;display:block}
.cstrip rect{shape-rendering:crispEdges}
.rolebar{display:flex;margin-top:6px;height:22px;border-radius:6px;overflow:hidden;font:600 10.5px var(--mono)}
.rolebar span{display:flex;align-items:center;padding:0 7px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;color:#fff;min-width:0}
.dtbl{width:100%;font-size:12.5px}
.dtbl td{padding:7px 0;border-bottom:1px solid var(--line)}
.dtbl tr:last-child td{border-bottom:0}
.dtbl td:last-child{text-align:right;font-family:var(--mono);color:var(--muted)}
.dtbl tr{cursor:pointer}.dtbl tbody tr:hover{background:none}.dtbl tr:hover td:first-child{color:var(--signal)}
.okt{color:var(--ok)}.badt{color:var(--bad)}.wrnt{color:var(--warn)}
"""

DASH_JS = r"""
/* ---------- DASHBOARD ---------- */
const EVL=Object.values(D.evidence||{}).sort((a,b)=>a.id-b.id);
const fmtN=n=>n>=10000?Math.round(n/1000)+"k":n>=1000?(n/1000).toFixed(1)+"k":String(n);
const pct=(a,b)=>b?Math.round(a/b*100)+"%":"0%";
function tally(xs,f){const m=new Map();xs.forEach(x=>{const k=f(x);if(k!=null)m.set(k,(m.get(k)||0)+1);});return [...m.entries()].sort((a,b)=>b[1]-a[1]||String(a[0]).localeCompare(String(b[0])));}
const statusClass=s=>s==null?"?":s>=500?"5xx":s>=400?"4xx":s>=300?"3xx":s>=200?"2xx":"1xx";
const SC_COL={"2xx":"var(--ok)","3xx":"var(--observed)","4xx":"var(--warn)","5xx":"var(--bad)","?":"var(--faint)","1xx":"var(--faint)"};
function donut(parts,size,thick,big,small){
  const tot=parts.reduce((a,p)=>a+p.v,0)||1,r=size/2-thick/2,C=2*Math.PI*r,h=size/2;let off=0;
  const arcs=parts.filter(p=>p.v).map(p=>{const len=C*p.v/tot;const gap=parts.filter(q=>q.v).length>1?2:0;
    const s=`<circle r="${r}" cx="${h}" cy="${h}" fill="none" stroke="${p.color}" stroke-width="${thick}" stroke-dasharray="${Math.max(0,len-gap)} ${C-len+gap}" stroke-dashoffset="${-off}" transform="rotate(-90 ${h} ${h})"><title>${esc(p.label)}: ${p.v}</title></circle>`;off+=len;return s;}).join("");
  return `<svg class="donut" viewBox="0 0 ${size} ${size}" width="${size}" height="${size}" role="img"><circle r="${r}" cx="${h}" cy="${h}" fill="none" stroke="var(--panel2)" stroke-width="${thick}"/>${arcs}
   <text x="${h}" y="${h+2}" text-anchor="middle" font-size="${size*.2}" font-weight="700" fill="var(--text)">${esc(big)}</text>
   <text x="${h}" y="${h+size*.12}" text-anchor="middle" font-size="${size*.075}" font-weight="600" fill="var(--muted)" letter-spacing=".08em">${esc(small)}</text></svg>`;
}
function hbars(rows,opt){
  opt=opt||{};const mx=Math.max(1,...rows.map(r=>r.v));
  return `<div class="hb${opt.sm?" sm":""}${opt.wide?" wide":""}">${rows.map(r=>`<div class="r" ${r.attr||""} title="${esc(r.title||r.label)}"><span class="l">${esc(r.label)}</span><span class="t"><i style="width:${Math.max(2,r.v/mx*100).toFixed(1)}%;--c:${r.color||opt.color||"var(--observed)"}"></i></span><span class="v">${r.vtxt!=null?r.vtxt:fmtN(r.v)}</span></div>`).join("")}</div>`;
}
function stacked(parts){
  const tot=parts.reduce((a,p)=>a+p.v,0)||1;
  return `<div class="stk">${parts.filter(p=>p.v).map(p=>`<i style="width:${(p.v/tot*100).toFixed(2)}%;background:${p.color}" title="${esc(p.label)}: ${p.v}"></i>`).join("")}</div>
  <div class="stkleg">${parts.filter(p=>p.v).map(p=>`<span class="k"><span class="sw" style="background:${p.color}"></span>${esc(p.label)} <b>${fmtN(p.v)}</b></span>`).join("")}</div>`;
}
function provenanceBar(){return "";}
function hostsCard(){return "";}
function osintCard(){
  const o=D.osint;if(!o)return "";
  const rows=[];
  if(o.tls&&o.tls.issuer)rows.push(["TLS",`${o.tls.issuer}${o.tls.not_after?` · expires ${o.tls.not_after}`:""}`]);
  if(o.hosting&&o.hosting.network)rows.push(["Hosting",`${o.hosting.network}${o.hosting.country?` · ${o.hosting.country}`:""}`]);
  if((o.technology||[]).length)rows.push(["Technology",o.technology.join(", ")]);
  if(o.headers_missing)rows.push(["Security headers",o.headers_missing.length?`${o.headers_missing.length} missing: ${o.headers_missing.join(", ")}`:"all common headers present"]);
  if(o.registrar)rows.push(["Registrar",o.registrar]);
  if((o.open_ports||[]).length)rows.push(["Open ports",o.open_ports.join(", ")]);
  if(o.email_security)rows.push(["Email auth",`SPF: ${o.email_security.spf_note||"?"} · DMARC: ${o.email_security.dmarc_policy||o.email_security.dmarc_note||"?"}`]);
  if(o.subdomains)rows.push(["Subdomains",`${o.subdomains} from certificate transparency`]);
  if(!rows.length)return "";
  return `<div class="dc"><div class="h">External recon <span class="ct">${esc(o.host||"")}</span></div><div class="b"><table class="dtbl"><tbody>${rows.map(([k,v])=>`<tr data-goto="infra"><td>${esc(k)}</td><td style="max-width:60%">${esc(v)}</td></tr>`).join("")}</tbody></table>
   <div class="dnote">Collected live by <span class="mono">burp2model osint</span>, not from the capture.</div></div></div>`;
}
function vMore(){
  const st=c.api_state||{},both=st.BOTH||0,rt=st.RUNTIME_ONLY||0,so=st.STATIC_ONLY||0,eptot=both+rt+so;
  const cap=D.stats||{},roles=D.roles||[];
  const reqTot=EVL.length;
  const sev={hot:0,warn:0,info:0};PRIO.forEach(p=>sev[p.sev]++);
  const topUnk=tally(D.unknowns||[],u=>u.type);
  const sigTop=tally(PRIO.flatMap(p=>p.sig.map(x=>x.ttl)),t=>t).slice(0,4);
  const tpReq=(D.third_parties||[]).reduce((a,t)=>a+(t.requests||(t.evidence||[]).length),0);
  const kpi=(n,k,sub,col,go)=>`<div class="dk" style="--c:${col}" data-goto="${go}"><div class="n">${fmtN(n)}</div><div class="k">${esc(k)}</div><div class="s">${esc(sub)}</div></div>`;

  /* methods + status mix from the evidence table */
  const meth=tally(EVL,e=>e.method||"?"), stc=tally(EVL,e=>statusClass(e.status));
  const stOrder=["2xx","3xx","4xx","5xx","?","1xx"].map(k=>({label:k==="?"?"no status":k,v:(stc.find(x=>x[0]===k)||[0,0])[1],color:SC_COL[k]}));
  /* busiest endpoints */
  const topEp=[...EP].filter(e=>e.requests>0).sort((a,b)=>b.requests-a.requests||a.label.localeCompare(b.label)).slice(0,8);
  /* where requests went by host */
  const hostN=tally(EVL,e=>e.host);
  /* roles */
  const roleN=tally(EVL,e=>e.role||null);
  const roleCol=["var(--observed)","var(--inferred)","var(--ok)","var(--signal)","var(--warn)","var(--l2)"];
  /* cookies */
  const ck=D.cookies||[],ckBad=ck.filter(x=>!x.httponly||!x.secure).length;
  const layers=[
    ["Edge","var(--l1)",c.hosts||0,"hosts"+((D.hosts||[]).some(h=>Object.keys(h.tech||{}).length)?" + tech":""),"graph"],
    ["Routes","var(--l2)",c.routes||0,"pages and states","surface"],
    ["Client code","var(--l3)",c.scripts||0,"scripts","code"],
    ["APIs","var(--l4)",(c.endpoints||0),`${c.parameters||0} parameters`,"surface"],
    ["Trust","var(--l5)",(c.third_parties||0)+(c.auth||0)+(c.cookies||0),`${c.third_parties||0} third · ${c.auth||0} auth · ${c.cookies||0} cookies`,"trust"],
    ["Unknowns","var(--l6)",c.unknowns||0,"named gaps","unknowns"]];

  return `  <div class="dgrid dg3">
   <div class="dc"><div class="h">Code vs runtime <span class="ct">${eptot} endpoints</span></div><div class="b">
    <div class="dwrap">${donut([{v:both,color:"var(--ok)",label:"seen in code and traffic"},{v:rt,color:"var(--observed)",label:"traffic only"},{v:so,color:"var(--signal)",label:"code only"}],150,20,String(eptot),"ENDPOINTS")}
     <div class="dleg">
      <div class="r" data-goto="surface"><span class="sw" style="background:var(--ok)"></span><span class="l">Code + traffic</span><b>${both}</b><span class="pc">${pct(both,eptot)}</span></div>
      <div class="r" data-goto="surface"><span class="sw" style="background:var(--observed)"></span><span class="l">Traffic only</span><b>${rt}</b><span class="pc">${pct(rt,eptot)}</span></div>
      <div class="r" data-goto="surface"><span class="sw" style="background:var(--signal)"></span><span class="l">Code only</span><b>${so}</b><span class="pc">${pct(so,eptot)}</span></div></div></div>
    <div class="dnote">Code only = named in the client code but never called in this capture.</div></div></div>

   <div class="dc"><div class="h">Traffic shape <span class="ct">${fmtN(reqTot)} requests</span></div><div class="b">
    ${stacked(stOrder)}
    <div style="height:16px"></div>
    ${hbars(meth.slice(0,6).map(([k,v])=>({label:k,v,color:k==="GET"?"var(--muted)":"var(--signal)"})),{sm:true})}</div></div>

   <div class="dc"><div class="h">Worth a look <span class="ct">${PRIO.length} item${PRIO.length===1?"":"s"}</span></div><div class="b">
    <div class="att">
     <div class="a" style="--c:var(--signal)" data-goto="priorities"><div class="n">${sev.hot}</div><div class="k">High</div></div>
     <div class="a" style="--c:var(--warn)" data-goto="priorities"><div class="n">${sev.warn}</div><div class="k">Medium</div></div>
     <div class="a" style="--c:var(--observed)" data-goto="priorities"><div class="n">${sev.info}</div><div class="k">Note</div></div></div>
    <div style="height:14px"></div>${hbars(sigTop.map(([k,v])=>({label:k,v,color:"var(--signal)",attr:'data-goto="priorities"'})),{wide:true})}
    <div class="dnote">Ranked leads to verify, not findings. Each says what to check next.</div>
    ${ckBad?`<div class="dnote" style="margin-top:6px"><span class="wrnt">●</span> ${ckBad} cookie${ckBad===1?"":"s"} missing HttpOnly or Secure</div>`:""}</div></div>
  </div>

  <div class="dc" style="margin-bottom:14px"><div class="h">Capture timeline <span class="ct">each bar is a request, in capture order</span></div><div class="b">
   ${captureStrip()}</div></div>

  <div class="dgrid dg2">
   <div class="dc"><div class="h">Start here <button class="lnk" data-goto="priorities">All ${PRIO.length} →</button></div><div class="b dlist">
    ${PRIO.slice(0,6).map((p,i)=>{const e=p.ep,l=p.sig[0];return `<div class="it" data-ep="${esc(e.id)}" style="--c:${p.sev==="hot"?"var(--signal)":p.sev==="warn"?"var(--warn)":"var(--observed)"}"><span class="rk">${i+1}</span><div class="tx"><div class="tt">${methodm(e.method)}<span class="p">${esc(e.path)}</span></div><div class="ds">${esc(l.ttl)}${p.sig.length>1?` · +${p.sig.length-1} more`:""}</div></div></div>`;}).join("")||'<div class="empty">Nothing stands out.</div>'}</div></div>
   <div class="dc"><div class="h">Busiest endpoints <button class="lnk" data-goto="surface">All →</button></div><div class="b">
    ${topEp.length?hbars(topEp.map(e=>({label:(e.method!=="*"?e.method+" ":"")+e.path,v:e.requests,attr:`data-ep="${esc(e.id)}"`,color:e.state==="STATIC_ONLY"?"var(--signal)":"var(--observed)"}))):'<div class="empty">No endpoint was requested.</div>'}</div></div>
  </div>

  <div class="dgrid dg21">
   <div class="dc"><div class="h">${roles.length>1?"Roles":"Credentials"} <span class="ct">${roles.length>1?roles.length+" roles":""}</span></div><div class="b">
    ${roles.length>1?hbars(roleN.map(([k,v],i)=>({label:k,v,color:roleCol[i%roleCol.length],attr:'data-goto="crossrole"'}))):
      ((D.auth||[]).length?`<table class="dtbl"><tbody>${D.auth.map(a=>`<tr data-goto="trust"><td>${esc(a.label)}</td><td>${a.endpoints.length} endpoint${a.endpoints.length===1?"":"s"}</td></tr>`).join("")}</tbody></table>`:'<div class="empty">No credentials observed.</div>')}
    ${roles.length>1?`<div class="dnote">Requests per role. <a href="#crossrole" data-goto="crossrole">Compare what each role reached →</a></div>`:""}</div></div>
   <div class="dc"><div class="h">Third parties <button class="lnk" data-goto="supply">All →</button></div><div class="b">
    ${(D.third_parties||[]).length?hbars([...D.third_parties].sort((a,b)=>(b.requests||(b.evidence||[]).length)-(a.requests||(a.evidence||[]).length)).slice(0,7).map(t=>({label:t.label,v:t.requests||(t.evidence||[]).length,color:"var(--l5)",attr:'data-goto="supply"'}))):'<div class="empty">No third-party hosts.</div>'}</div></div>
   <div class="dc"><div class="h">Open questions <button class="lnk" data-goto="unknowns">All →</button></div><div class="b">
    ${topUnk.length?hbars(topUnk.slice(0,6).map(([k,v])=>({label:openTitle(k),v,color:"var(--l6)",attr:'data-goto="unknowns"'})),{wide:true}):'<div class="empty">Nothing left open.</div>'}</div></div>
  </div>

  <div class="lstrip">${layers.map(([n,col,v,d,go])=>`<div class="ls" style="--c:${col}" data-goto="${go}"><div class="ln">${esc(n)}</div><div class="n">${fmtN(v)}</div><div class="d">${esc(d)}</div></div>`).join("")}</div>

  <div class="dgrid dg2">
   <div class="dc"><div class="h">Hosts <span class="ct">${(D.hosts||[]).length} first-party</span></div><div class="b">
    <table class="dtbl"><tbody>${(D.hosts||[]).map(h=>`<tr data-goto="graph"><td class="mono">${esc(h.label)}<span style="color:var(--faint)"> ${esc((h.schemes||[]).join("/"))}${(h.ports||[]).length?":"+esc(h.ports.join(",")):""}</span></td><td>${esc(Object.entries(h.tech||{}).map(([k,v])=>v?`${k}: ${v}`:k).join(" · ")||"—")}</td></tr>`).join("")||'<tr><td>—</td></tr>'}</tbody></table>
    ${hostN.length>1?`<div style="height:12px"></div>${hbars(hostN.slice(0,5).map(([k,v])=>({label:k,v,color:"var(--l1)",attr:'data-goto="inventory"'})),{sm:true})}`:""}</div></div>
   <div class="dc"><div class="h">Capture coverage</div><div class="b"><table class="dtbl"><tbody>
    <tr><td>Requests parsed</td><td>${cap.parsed??cap.exchanges??reqTot} of ${cap.items??"—"}${cap.skipped?` · <span class="wrnt">${cap.skipped} skipped</span>`:""}</td></tr>
    <tr><td>Static assets (not mapped)</td><td>${cap.static_assets??0}</td></tr>
    <tr><td>CORS preflights</td><td>${cap.preflight??0}</td></tr>
    <tr><td>Roles</td><td>${esc(roles.join(", ")||"none")}</td></tr></tbody></table>
    <div class="dnote">An absence here is an absence in the <b>capture</b>, never a statement about the target.</div></div></div>
  </div>
  ${D.osint?`<div class="dgrid" style="grid-template-columns:minmax(0,1fr)">${osintCard()}</div>`:""}`;
}


/* ---------- at a glance: screenshot, infrastructure, stack ---------- */
const STACK=D.stack||[];
const STACK_COL={"Edge & CDN":"var(--l6)","Web server":"var(--l1)","Language & framework":"var(--l4)","Frontend":"var(--l3)","CMS & platform":"var(--l2)","API":"var(--inferred)","Services":"var(--l5)"};
const STACK_SHORT={"Edge & CDN":"Edge","Web server":"Server","Language & framework":"App","Frontend":"Frontend","CMS & platform":"Platform","API":"API"};
const HDR_LABEL={"strict-transport-security":"HSTS","content-security-policy":"CSP","x-frame-options":"X-Frame-Options","x-content-type-options":"nosniff","referrer-policy":"Referrer-Policy","permissions-policy":"Permissions-Policy","cross-origin-opener-policy":"COOP","cross-origin-resource-policy":"CORP"};
/* the host the story is about: the one recon looked at, else the busiest */
function primaryFirst(){
  const rec=(D.osint||{}).host;
  return [...(D.hosts||[])].sort((a,b)=>(b.label===rec)-(a.label===rec)||(b.evidence||[]).length-(a.evidence||[]).length);
}
function techPill(t){
  const ev=(t.evidence||[])[0],how=t.how?`seen in ${t.how}`:"";
  return `<button class="tp" ${ev?`data-ev="${ev}"`:""} title="${esc(how+(ev?" · "+EVD(ev):""))}"><i style="background:${STACK_COL[t.category]||"var(--l5)"}"></i>${esc(t.name)}${t.version?`<small>${esc(t.version)}</small>`:""}</button>`;
}
function stackCard(){
  const order=["Edge & CDN","Web server","Language & framework","Frontend","CMS & platform","API"];
  const layers=order.map(c=>[c,STACK.filter(t=>t.category===c)]).filter(x=>x[1].length);
  const svc=STACK.filter(t=>t.category==="Services");
  if(!layers.length&&!svc.length)return "";
  const kinds=new Map();svc.forEach(t=>{const k=t.kind||"Other";(kinds.get(k)||kinds.set(k,[]).get(k)).push(t);});
  return `<div class="dc"><div class="h">Technology stack <span class="ct">${STACK.length} detected</span></div><div class="b">
   ${layers.length?`<div class="smap"><div class="sn you">Browser</div>${layers.map(([c,ts])=>`<div class="sa">→</div><div class="sn"><span class="sl">${esc(STACK_SHORT[c]||c)}</span>${ts.map(techPill).join("")}</div>`).join("")}</div>`:""}
   ${svc.length?`<div class="svc">${[...kinds.entries()].sort((a,b)=>a[0].localeCompare(b[0])).map(([k,ts])=>`<span class="sk">${esc(k)}</span><span class="sv">${ts.map(techPill).join("")}</span>`).join("")}</div>`:""}
   <div class="dnote">Read from headers, cookies, pages and the hosts the app talks to. Hints, not a version scan.</div></div></div>`;
}
function infraRows(){
  const rows=[],o=D.osint||{},hs=primaryFirst();
  if(hs.length){const h=hs[0],sc=(h.schemes||[]).join("/"),pt=(h.ports||[]).join(", ");
    rows.push(["Host",`${esc(h.label)}${hs.length>1?`<small>+${hs.length-1} more</small>`:""}<small>${esc([sc,pt].filter(Boolean).join(" "))}</small>`]);}
  if(o.hosting&&o.hosting.network)rows.push(["Hosting",esc(o.hosting.network+(o.hosting.country?" · "+o.hosting.country:""))]);
  if((o.ips||[]).length)rows.push(["IP",esc(o.ips.join(", "))]);
  if(o.tls&&o.tls.issuer)rows.push(["TLS",esc(o.tls.issuer)+(o.tls.days_until_expiry!=null?`<small>${o.tls.days_until_expiry} days left</small>`:"")]);
  if(o.registrar)rows.push(["Registrar",esc(o.registrar)]);
  const dn=[];if((o.nameservers||[]).length)dn.push(o.nameservers.length+" nameservers");if(o.subdomains)dn.push(o.subdomains+" subdomains");
  if(dn.length)rows.push(["DNS",esc(dn.join(" · "))]);
  const em=o.email_security||{},mail=[];if(em.spf)mail.push("SPF");if(em.dmarc_policy)mail.push("DMARC p="+em.dmarc_policy);
  if(mail.length)rows.push(["Mail auth",esc(mail.join(" · "))]);
  const hp=(o.headers_present||[]).map(h=>HDR_LABEL[h]||h);
  if(hp.length)rows.push(["Headers set",esc(hp.slice(0,4).join(", "))+(hp.length>4?`<small>+${hp.length-4}</small>`:"")]);
  return rows.slice(0,8);
}
function infraCard(){
  const rows=infraRows();if(rows.length<2)return "";
  return `<div class="dc"><div class="h">Infrastructure</div><div class="b"><div class="irows">${rows.map(([k,v])=>`<div class="k">${esc(k)}</div><div class="v">${v}</div>`).join("")}</div>${D.osint?`<div class="dnote">Hosting, TLS and DNS come from external recon.</div>`:""}</div></div>`;
}
function shotCard(){
  if(!D.screenshot)return "";
  const hs=primaryFirst(),h=hs[0];
  return `<div class="shotcard"><div class="sbar"><i></i><i></i><i></i><span>${esc(h?`${(h.schemes||["https"])[0]}://${h.label}/`:D.app)}</span></div><button class="simg" data-shot aria-label="Enlarge the screenshot"><img src="${esc(D.screenshot)}" alt="Screenshot of ${esc(h?h.label:D.app)}"></button></div>`;
}
function glance(){
  const shot=shotCard(),a=infraCard(),b=stackCard();
  if(!shot&&!a&&!b)return "";
  return `<div class="band${shot?" shot":""}">${shot}${a}${b}</div>`;
}

function leadCard(p,i){
  const e=p.ep,l=p.sig[0],col=p.sev==="hot"?"var(--signal)":p.sev==="warn"?"var(--warn)":"var(--observed)";
  return `<div class="lead" style="--c:${col}"><span class="num">${i+1}</span><div>
    <div class="t">${methodm(e.method)}<span>${esc(e.path)}</span></div>
    <div class="w">${esc(l.ttl)}${p.sig.length>1?` <span style="color:var(--faint);font-weight:500">+${p.sig.length-1} more</span>`:""}</div>
    <div class="y">${esc(l.why)}</div><div class="nx"><b>Do next</b>${esc(l.next)}</div></div>
    <div class="acts"><button class="abtn pri" data-ep="${esc(e.id)}">Open</button><button class="abtn" data-lead-map="${esc(e.id)}">On the map</button></div></div>`;
}
function vOverview(){
  const st=c.api_state||{},both=st.BOTH||0,rt=st.RUNTIME_ONLY||0,so=st.STATIC_ONLY||0,eptot=both+rt+so;
  const hot=PRIO.filter(p=>p.sev==="hot").length,roles=D.roles||[],reqTot=EVL.length;
  const sum=[`<b>${c.endpoints||0}</b> API endpoints on <b>${c.routes||0}</b> pages, from <b>${fmtN(reqTot)}</b> captured requests${roles.length>1?` as <b>${roles.length}</b> roles`:""}.`];
  if(so)sum.push(`<b>${so}</b> ${so===1?"endpoint is":"endpoints are"} named in the code but never called.`);
  sum.push(PRIO.length?`Start with the ${Math.min(5,PRIO.length)} leads below.`:"Nothing stands out. The map is the next stop.");
  const stc=tally(EVL,e=>statusClass(e.status));
  const stOrder=["2xx","3xx","4xx","5xx"].map(k=>({label:k,v:(stc.find(x=>x[0]===k)||[0,0])[1],color:SC_COL[k]}));
  const unk=c.unknowns||0;
  return `<div class="ovh"><div><h1>${esc(D.app)}</h1><p class="sum">${sum.join(" ")}</p>
    <div class="meta">scope ${esc((D.scope||[]).join(", ")||"none")} · ${esc(D.generated||"")}</div></div>
   <div class="big4">
    <button data-goto="surface"><div class="n">${c.endpoints||0}</div><div class="k">API endpoints</div></button>
    <button data-goto="inventory"><div class="n">${fmtN(reqTot)}</div><div class="k">Requests</div></button>
    <button class="${hot||weakCookies.length?"hot":""}" data-goto="priorities"><div class="n">${PRIO.length+weakCookies.length}</div><div class="k">To check</div></button>
    <button data-goto="unknowns"><div class="n">${unk}</div><div class="k">Open questions</div></button></div></div>

  ${glance()}

  <div class="ovg"><div>
    <div class="sech"><h2>Check these first</h2><span class="s">ranked leads to verify, not findings</span>${PRIO.length+weakCookies.length>5?`<button class="lnk" data-goto="priorities">All ${PRIO.length+weakCookies.length} →</button>`:""}</div>
    ${PRIO.slice(0,5).map(leadCard).join("")||'<div class="dc"><div class="b"><div class="empty">Nothing stands out in this capture.</div></div></div>'}
   </div><div class="side">
    <div class="dc"><div class="h">What the code names vs what ran</div><div class="b"><div class="dwrap">${donut([{v:both,color:"var(--ok)",label:"in code and traffic"},{v:rt,color:"var(--observed)",label:"traffic only"},{v:so,color:"var(--signal)",label:"code only"}],130,18,String(eptot),"ENDPOINTS")}
      <div class="dleg"><div class="r" data-goto="surface"><span class="sw" style="background:var(--ok)"></span><span class="l">Both</span><b>${both}</b></div>
       <div class="r" data-goto="surface"><span class="sw" style="background:var(--observed)"></span><span class="l">Traffic only</span><b>${rt}</b></div>
       <div class="r" data-goto="surface"><span class="sw" style="background:var(--signal)"></span><span class="l">Code only</span><b>${so}</b></div></div></div></div></div>
    <div class="dc"><div class="h">Responses</div><div class="b">${stacked(stOrder)}</div></div>
    ${roles.length>1?`<div class="dc"><div class="h">Roles in this capture</div><div class="b"><div class="dtags">${roles.map(r=>`<span class="dtag"><b>${esc(r)}</b></span>`).join("")}</div><div class="dnote"><a href="#crossrole" data-goto="crossrole">See what each role reached →</a></div></div></div>`:""}
   </div></div>

  <div class="sech"><h2>Explore</h2></div>
  <div class="tiles">
   <button class="tile" data-goto="graph"><b>Map</b><span>How pages, scripts and endpoints connect.</span></button>
   <button class="tile" data-goto="inventory"><b>Requests</b><span>Every request, like Burp's HTTP history.</span></button>
   <button class="tile" data-goto="ask"><b>Ask</b><span>A plain question, or a BQL query.</span></button>
   <button class="tile" data-goto="unknowns"><b>Open questions</b><span>What this capture could not show.</span></button></div>

  <details class="more"><summary>More numbers <span>timeline, busiest endpoints, third parties, hosts</span></summary><div class="inner">${vMore()}</div></details>`;
}
function initOverview(){
  $$("[data-ev]",$("#main")).forEach(b=>b.onclick=e=>{e.stopPropagation();openEv(b.dataset.ev);});
  const sh=$("[data-shot]");
  if(sh)sh.onclick=()=>{const d=document.createElement("div");d.className="lightbox";d.innerHTML=`<img src="${esc(D.screenshot)}" alt="Screenshot">`;d.onclick=()=>d.remove();document.body.append(d);};
  addEventListener("keydown",function k(e){if(e.key==="Escape"){const l=$(".lightbox");if(l)l.remove();removeEventListener("keydown",k);}});
  $$("[data-lead-map]").forEach(b=>b.onclick=e=>{e.stopPropagation();MAPS.sel=b.dataset.leadMap;MAPS.path=null;if(MAPS.mode==="focus")MAPS.focusId=MAPS.sel;view="graph";render();});
}
/* one bar per request in capture order, coloured by status class; long captures are bucketed */
function captureStrip(){
  const n=EVL.length;if(!n)return '<div class="empty">No requests.</div>';
  const W=1000,H=56,B=Math.min(n,W),per=n/B;
  let bars="",lastRole=null,runs=[];
  EVL.forEach(e=>{const r=e.role||"—";if(!runs.length||runs[runs.length-1].r!==r)runs.push({r,n:0});runs[runs.length-1].n++;});
  const worst=["5xx","4xx","3xx","2xx","?","1xx"];
  for(let i=0;i<B;i++){
    const a=Math.floor(i*per),b=Math.max(a+1,Math.floor((i+1)*per));let cls="2xx",rank=9;
    for(let k=a;k<b&&k<n;k++){const s=statusClass(EVL[k].status),rr=worst.indexOf(s);if(rr<rank){rank=rr;cls=s;}}
    const h=cls==="5xx"?H:cls==="4xx"?H*.82:cls==="3xx"?H*.62:H*.5;
    bars+=`<rect x="${(i*W/B).toFixed(2)}" y="${(H-h).toFixed(1)}" width="${B<120?(W/B*.8).toFixed(2):(W/B+.35).toFixed(2)}" height="${h.toFixed(1)}" fill="${SC_COL[cls]}" opacity=".85"/>`;
  }
  const rcol=["var(--observed)","var(--inferred)","var(--ok)","var(--signal)","var(--warn)","var(--l2)"];
  const names=[...new Set(runs.map(r=>r.r))];
  const rb=runs.length>1||runs[0].r!=="—"?`<div class="rolebar">${runs.map(r=>`<span style="flex:${r.n};background:${rcol[names.indexOf(r.r)%rcol.length]}" title="${esc(r.r)}: ${r.n} requests">${esc(r.r)}</span>`).join("")}</div>`:"";
  return `<svg class="cstrip" viewBox="0 0 ${W} ${H}" preserveAspectRatio="none" role="img" aria-label="Requests in capture order, coloured by status">${bars}</svg>${rb}
   <div class="stkleg" style="margin-top:8px"><span class="k"><span class="sw" style="background:var(--ok)"></span>2xx</span><span class="k"><span class="sw" style="background:var(--observed)"></span>3xx</span><span class="k"><span class="sw" style="background:var(--warn)"></span>4xx</span><span class="k"><span class="sw" style="background:var(--bad)"></span>5xx</span></div>`;
}
"""
