"""The request and response viewer the report uses on every page, and the code beautifiers behind it.

`rrMount(el, ids, opts)` draws the masked request and response for one or more evidence ids into `el`.
JavaScript, HTML and JSON bodies are indented and coloured; Raw shows them untouched. The same
component sits under the Requests table, the leads list, the reference details and the answers.
"""

RR_CSS = r"""
/* request / response viewer */
.rr{display:flex;flex-direction:column;min-height:0;height:100%;background:var(--panel)}
.rrbar{display:flex;align-items:center;gap:8px;flex-wrap:wrap;padding:7px 12px;border-bottom:1px solid var(--line);background:var(--panel2);flex:none}
.rrbar .rrt{font:600 12.5px var(--sans);max-width:46%;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.rrbar .rrt code{font:600 12px var(--mono)}
.rrchips{display:flex;gap:4px;flex-wrap:wrap;align-items:center}
.rrchip{font:600 11px var(--mono);padding:3px 8px;border-radius:6px;border:1px solid var(--line2);background:var(--panel);color:var(--muted)}
.rrchip.on{background:var(--text);color:var(--ink);border-color:var(--text)}
.rrchip:hover{border-color:var(--faint);color:var(--text)}
.rrbar .sp{flex:1}
.rrpanes{display:flex;flex:1;min-height:0}
.rr.vert .rrpanes{flex-direction:column}
.rrp{flex:1;min-width:0;min-height:0;display:flex;flex-direction:column;border-right:1px solid var(--line)}
.rrp:last-child{border:0}
.rr.vert .rrp{border-right:0;border-bottom:1px solid var(--line)}
.rrp .ph{display:flex;align-items:center;gap:6px;padding:5px 8px;background:var(--panel2);border-bottom:1px solid var(--line);flex:none}
.rrp .ph b{font:700 11px var(--mono);letter-spacing:.06em;text-transform:uppercase;margin-right:4px}
.rrp .ph .st{font:600 11px var(--mono);color:var(--muted)}
.rrp .ph .tag{font:600 10px var(--mono);color:var(--inferred);border:1px solid var(--inferred);border-radius:4px;padding:0 5px}
.rrp .ph .sp{flex:1}
.rrp .code{flex:1;margin:0;overflow:auto;padding:8px 0;font:12px/1.55 var(--mono);background:var(--panel);counter-reset:l}
.rrp .code .l{display:block;padding:0 12px 0 52px;position:relative;white-space:pre-wrap;word-break:break-all;min-height:1.55em}
.rrp .code .l::before{counter-increment:l;content:counter(l);position:absolute;left:0;width:40px;text-align:right;color:var(--faint);font-size:11px;user-select:none}
.rrp .code.nol .l{padding-left:12px}.rrp .code.nol .l::before{display:none}
.rrp .ln{color:var(--signal);font-weight:700}.rrp .hn{color:var(--observed)}.rrp .hv{color:var(--text)}.rrp .rd{color:var(--inferred);font-weight:700}
.rrp .tk{color:var(--signal);font-weight:600}.rrp .ts{color:var(--ok)}.rrp .tc{color:var(--faint);font-style:italic}.rrp .tn{color:var(--warn)}.rrp .tg{color:var(--observed)}.rrp .ta{color:var(--inferred)}
.rrp .jk{color:var(--observed)}.rrp .js{color:var(--ok)}.rrp .jn{color:var(--warn)}.rrp .jb{color:var(--inferred)}
.rrp .note{color:var(--faint);font-style:italic}
.rrp .gap{height:8px}
.rrempty{display:grid;place-items:center;height:100%;padding:30px;text-align:center;color:var(--faint);font-size:13px;background:var(--panel)}
.rrempty b{display:block;color:var(--muted);font:600 14px var(--sans);margin-bottom:4px}
.rrbtn{font:600 11px var(--mono);padding:3px 8px;border-radius:5px;border:1px solid var(--line2);background:var(--panel);color:var(--muted)}
.rrbtn:hover{color:var(--text)}
"""

RR_JS = r"""
/* ---------- code beautifiers (plain JS, no libraries) ---------- */
function beautifyJS(src){
  if(!src||src.length>300000)return src||"";
  const n=src.length,IND="  ";let out="",ind=0,i=0,prev="",afterBrace=false;
  const ctx=[],pstack=[];let paren=0;
  const trimEnd=()=>{out=out.replace(/[ \t]+$/,"");};
  const nl=()=>{trimEnd();out+="\n"+IND.repeat(Math.max(0,ind));};
  const space=()=>{if(out&&!/[\s(\[]$/.test(out))out+=" ";};
  const word=(j)=>{let k=j;while(k<n&&/[\w$]/.test(src[k]))k++;return src.slice(j,k);};
  const lastWord=()=>{const m=/([A-Za-z_$][\w$]*)\s*$/.exec(out);return m?m[1]:"";};
  while(i<n){
    const ch=src[i],nx=src[i+1];
    if(/\s/.test(ch)){let j=i;while(j<n&&/\s/.test(src[j]))j++;if(!afterBrace)space();i=j;continue;}
    if(afterBrace){
      afterBrace=false;
      const w=/[A-Za-z]/.test(ch)?word(i):"";
      if(ch===")"||ch===","||ch===";"||ch==="."||ch==="]"||w==="else"||w==="catch"||w==="finally"||(w==="while"&&false)){space();}
      else nl();
    }
    if(ch==="/"&&nx==="/"){let j=src.indexOf("\n",i);if(j<0)j=n;space();out+=src.slice(i,j).trimEnd();nl();i=j;continue;}
    if(ch==="/"&&nx==="*"){let j=src.indexOf("*/",i+2);j=j<0?n:j+2;if(out&&!/\n\s*$/.test(out))nl();out+=src.slice(i,j);nl();i=j;continue;}
    if(ch==='"'||ch==="'"||ch==="`"){
      let j=i+1;
      while(j<n){const c=src[j];
        if(c==="\\"){j+=2;continue;}
        if(c===ch)break;
        if(ch==="`"&&c==="$"&&src[j+1]==="{"){let d=1;j+=2;while(j<n&&d>0){if(src[j]==="{")d++;else if(src[j]==="}")d--;j++;}continue;}
        if(c==="\n"&&ch!=="`")break;
        j++;}
      out+=src.slice(i,j+1);i=j+1;prev=ch;continue;}
    if(ch==="/"&&(prev===""||/[(,=:\[!&|?{};+\-*%<>~^]/.test(prev)||/^(return|typeof|case|in|of|void|delete|throw)$/.test(lastWord()))){
      let j=i+1,cls=false;
      while(j<n){const c=src[j];if(c==="\\"){j+=2;continue;}if(c==="[")cls=true;else if(c==="]")cls=false;else if(c==="/"&&!cls)break;else if(c==="\n"){j=n;break;}j++;}
      if(j<n&&src[j]==="/"){j++;while(j<n&&/[a-z]/i.test(src[j]))j++;out+=src.slice(i,j);i=j;prev=")";continue;}
    }
    if(ch==="{"){
      let k=i+1;while(k<n&&/\s/.test(src[k]))k++;
      if(src[k]==="}"){space();out+="{}";i=k+1;prev="}";continue;}
      const lw=lastWord(),obj=/[(,=:\[?]$/.test(prev)||prev===""&&false||/^(return|case)$/.test(lw);
      ctx.push(obj?"o":"b");pstack.push(paren);paren=0;
      space();out+="{";ind++;nl();prev="{";i++;continue;}
    if(ch==="}"){
      ctx.pop();paren=pstack.length?pstack.pop():0;ind--;nl();out+="}";prev="}";afterBrace=true;i++;continue;}
    if(ch===";"){out+=";";prev=";";if(paren<=0)nl();else out+=" ";i++;continue;}
    if(ch===","){out+=",";prev=",";if(ctx[ctx.length-1]==="o"&&paren<=0)nl();else out+=" ";i++;continue;}
    if(ch==="("||ch==="["){paren++;out+=ch;prev=ch;i++;continue;}
    if(ch===")"||ch==="]"){paren--;out+=ch;prev=ch;i++;continue;}
    if(ch==="="&&nx==="="||ch==="!"&&nx==="="||ch==="="&&nx===">"||ch==="&"&&nx==="&"||ch==="|"&&nx==="|"){
      let j=i+2;while(src[j]==="=")j++;space();out+=src.slice(i,j)+" ";prev=src[j-1];i=j;continue;}
    out+=ch;prev=ch;i++;
  }
  return out.replace(/\n\s*\n\s*\n/g,"\n\n").trim();
}
const VOID=new Set(["area","base","br","col","embed","hr","img","input","link","meta","param","source","track","wbr"]);
function beautifyHTML(src){
  if(!src||src.length>300000)return src||"";
  const parts=src.split(/(<!--[\s\S]*?-->|<script\b[\s\S]*?<\/script>|<style\b[\s\S]*?<\/style>|<[^>]+>)/gi);
  const IND="  ";let d=0,out=[];
  for(const p of parts){
    if(!p||!p.trim())continue;
    if(/^<script\b/i.test(p)){
      const m=/^(<script\b[^>]*>)([\s\S]*?)(<\/script>)$/i.exec(p);
      if(m){out.push(IND.repeat(d)+m[1]);const body=m[2].trim();if(body)beautifyJS(body).split("\n").forEach(l=>out.push(IND.repeat(d+1)+l));out.push(IND.repeat(d)+m[3]);continue;}
    }
    if(/^<style\b/i.test(p)){
      const m=/^(<style\b[^>]*>)([\s\S]*?)(<\/style>)$/i.exec(p);
      if(m){out.push(IND.repeat(d)+m[1]);const body=m[2].trim().replace(/\}\s*/g,"}\n").replace(/\{\s*/g,"{\n  ").replace(/;\s*(?!\})/g,";\n  ");if(body)body.split("\n").forEach(l=>out.push(IND.repeat(d+1)+l.trim()));out.push(IND.repeat(d)+m[3]);continue;}
    }
    if(p[0]!=="<"){p.split(/\n/).map(x=>x.trim()).filter(Boolean).forEach(x=>out.push(IND.repeat(d)+x));continue;}
    if(/^<!/.test(p)||/^<\?/.test(p)){out.push(IND.repeat(d)+p);continue;}
    const close=/^<\//.test(p),name=((/^<\/?([\w:-]+)/.exec(p)||[])[1]||"").toLowerCase();
    if(close){d=Math.max(0,d-1);out.push(IND.repeat(d)+p);}
    else{out.push(IND.repeat(d)+p);if(!VOID.has(name)&&!/\/>$/.test(p))d++;}
  }
  return out.join("\n");
}
/* colouring: one regex pass per language over already-escaped text */
const JS_KW=/^(?:const|let|var|function|return|if|else|for|while|do|new|class|extends|import|export|from|async|await|try|catch|finally|throw|switch|case|break|continue|default|typeof|instanceof|in|of|this|null|undefined|true|false|void|delete|yield|static|get|set)$/;
function hlJS(text){
  const re=/(\/\/[^\n]*|\/\*[\s\S]*?\*\/)|("(?:\\.|[^"\\\n])*"|'(?:\\.|[^'\\\n])*'|`(?:\\.|[^`\\])*`)|\b([A-Za-z_$][\w$]*)\b|(\b\d[\d._]*\b)/g;
  let out="",last=0,m;
  while((m=re.exec(text))){
    out+=esc(text.slice(last,m.index));last=re.lastIndex;
    if(m[1])out+=`<span class="tc">${esc(m[1])}</span>`;
    else if(m[2])out+=`<span class="ts">${esc(m[2])}</span>`;
    else if(m[3])out+=JS_KW.test(m[3])?`<span class="tk">${m[3]}</span>`:esc(m[3]);
    else out+=`<span class="tn">${esc(m[4])}</span>`;
  }
  return out+esc(text.slice(last));
}
function hlHTML(text){
  const re=/(<!--[\s\S]*?-->)|(<\/?)([\w:-]+)((?:\s+[\w:@.-]+(?:=(?:"[^"]*"|'[^']*'|[^\s>]+))?)*)\s*(\/?>)|(<![^>]*>)/g;
  let out="",last=0,m;
  while((m=re.exec(text))){
    out+=esc(text.slice(last,m.index));last=re.lastIndex;
    if(m[1])out+=`<span class="tc">${esc(m[1])}</span>`;
    else if(m[6])out+=`<span class="tc">${esc(m[6])}</span>`;
    else{const attrs=esc(m[4]||"").replace(/([\w:@.-]+)(=)(&quot;[^&]*?&quot;|&#39;[^&]*?&#39;|[^\s&]+)/g,'<span class="ta">$1</span>$2<span class="ts">$3</span>');
      out+=`<span class="tg">${esc(m[2])}${esc(m[3])}</span>${attrs}<span class="tg">${esc(m[5])}</span>`;}
  }
  return out+esc(text.slice(last));
}
function hlJSON(text){
  try{const o=JSON.parse(text);return esc(JSON.stringify(o,null,2)).replace(/(&quot;(?:[^&]|&(?!quot;))*?&quot;)(\s*:)?|\b(true|false|null)\b|-?\b\d+(?:\.\d+)?(?:[eE][+-]?\d+)?\b/g,
    (m,s,c,b)=>s?(c?`<span class="jk">${s}</span>${c}`:`<span class="js">${s}</span>`):b?`<span class="jb">${m}</span>`:`<span class="jn">${m}</span>`);}catch(e){return null;}
}
function bodyKind(m,ev,isReq){
  const ct=((m.headers||[]).find(h=>/^content-type$/i.test(h[0]))||["",""])[1].toLowerCase();
  if(/json/.test(ct))return "json";
  if(!isReq&&(/javascript|ecmascript/.test(ct)||(ev&&ev.mime==="script")||/\.m?js(\?|$)/.test((ev&&ev.path)||"")))return "js";
  if(/html/.test(ct)||(!isReq&&ev&&ev.mime==="html"))return "html";
  if(/xml/.test(ct))return "xml";
  return "text";
}
/* turn one body into numbered, coloured lines (or plain lines when raw) */
function bodyLines(body,kind,mode){
  if(!body)return [];
  let text=body,html;
  if(mode==="pretty"){
    if(kind==="json"){const h=hlJSON(body);if(h!=null)return h.split("\n");}
    else if(kind==="js"){text=beautifyJS(body);html=hlJS(text);}
    else if(kind==="html"){text=beautifyHTML(body);html=hlHTML(text);}
  }
  return (html!=null?html:esc(text)).split("\n");
}
function rrPane(title,m,ev,isReq,mode,extra){
  const kind=m?bodyKind(m,ev,isReq):"text";
  const has=m&&(m.line||(m.headers||[]).length||m.body);
  const head=has?`<span class="l"><span class="ln">${esc(m.line||"")}</span></span>`+(m.headers||[]).map(([k,v])=>`<span class="l"><span class="hn">${esc(k)}</span>: <span class="${/\[REDACTED/i.test(v)?"rd":"hv"}">${esc(v)}</span></span>`).join(""):"";
  const lines=has?bodyLines(m.body,kind,mode):[];
  const pretty=mode==="pretty"&&(kind==="js"||kind==="html"||kind==="json")&&m&&m.body;
  const body=lines.length?`<span class="l gap"></span>`+lines.map(l=>`<span class="l">${l}</span>`).join(""):"";
  const trunc=has&&m.truncated&&m.body?`<span class="l note">... body cut here (the report keeps ${kind==="js"?"40":kind==="html"?"20":"6"} KB)</span>`:"";
  return {kind,html:has?`<div class="code${mode==="raw"?"":""}">${head}${body}${trunc}</div>`:`<div class="code nol"><span class="l note">Not captured in this export.</span></div>`,pretty};
}
const RRS={layout:"h",tab:{req:"pretty",res:"pretty"}};
try{const s=JSON.parse(localStorage.getItem("b2m-rr")||"{}");if(s.layout)RRS.layout=s.layout;if(s.tab)RRS.tab=Object.assign(RRS.tab,s.tab);}catch(e){}
const rrSave=()=>{try{localStorage.setItem("b2m-rr",JSON.stringify(RRS));}catch(e){}};
/* draw the viewer for evidence ids into el. opts: {title, sel, empty:{head,text}, actions:[[label,fn]]} */
function rrMount(el,ids,opts){
  opts=opts||{};
  /* real requests first; the page or script that merely names an endpoint comes after */
  const code=i=>{const m=(D.evidence["ev_"+i]||{}).mime;return m==="script"||m==="html"?1:0;};
  ids=(ids||[]).filter(i=>D.evidence["ev_"+i]).map((i,k)=>[i,k]).sort((a,b)=>code(a[0])-code(b[0])||a[1]-b[1]).map(x=>x[0]);
  const st=el._rr=el._rr||{};st.ids=ids;
  if(!ids.includes(st.sel))st.sel=opts.sel!=null&&ids.includes(opts.sel)?opts.sel:ids[0];
  if(!ids.length){const e=opts.empty||{};el.innerHTML=`<div class="rrempty"><div><b>${esc(e.head||"Nothing to show")}</b>${esc(e.text||"Pick something from the list to see its request and response here.")}</div></div>`;return;}
  const ev=D.evidence["ev_"+st.sel];
  const mk=(t,m,isReq,k)=>{
    const p=rrPane(t,m,ev,isReq,RRS.tab[k]);
    const stx=isReq?"":`<span class="st">${ev.status==null?"":ev.status}${ev.mime?" · "+esc(ev.mime):""}</span>`;
    return `<div class="rrp"><div class="ph"><b>${t}</b><button class="ptab${RRS.tab[k]==="pretty"?" on":""}" data-rt="${k}:pretty">${p.kind==="js"?"Beautified":"Pretty"}</button><button class="ptab${RRS.tab[k]==="raw"?" on":""}" data-rt="${k}:raw">Raw</button><span class="sp"></span>${stx}${isReq?(opts.actions||[]).map((a,i)=>`<button class="rrbtn" data-ra="${i}">${esc(a[0])}</button>`).join(""):`<button class="rrbtn" data-rcopy>Copy body</button>`}</div>${p.html}</div>`;
  };
  const chips=ids.length>1?`<div class="rrchips">${ids.slice(0,14).map(i=>`<button class="rrchip${i===st.sel?" on":""}" data-rs="${i}">${EVD(i)}</button>`).join("")}${ids.length>14?`<span style="color:var(--faint);font:11px var(--mono)">+${ids.length-14}</span>`:""}</div>`:"";
  const vert=opts.vert||RRS.layout==="v";
  el.innerHTML=`<div class="rr${vert?" vert":""}"><div class="rrbar"><span class="rrt">${opts.title&&opts.title.trim()?esc(opts.title):opts.title?"":`<code>${esc(ev.method)} ${esc(ev.host)}${esc(ev.path)}</code>`}</span>${chips}<span class="sp"></span>${opts.vert?"":`<button class="rrbtn" data-rl>${RRS.layout==="v"?"Side by side":"Stacked"}</button>`}</div>
    <div class="rrpanes">${mk("Request",ev.request,true,"req")}${mk("Response",ev.response,false,"res")}</div></div>`;
  $$("[data-rs]",el).forEach(b=>b.onclick=()=>{st.sel=+b.dataset.rs;rrMount(el,ids,opts);});
  $$("[data-rt]",el).forEach(b=>b.onclick=()=>{const [k,v]=b.dataset.rt.split(":");RRS.tab[k]=v;rrSave();rrMount(el,ids,opts);});
  $$("[data-ra]",el).forEach(b=>b.onclick=()=>{const a=(opts.actions||[])[+b.dataset.ra];if(a)a[1](st.sel,b);});
  const rl=$("[data-rl]",el);if(rl)rl.onclick=()=>{RRS.layout=RRS.layout==="v"?"h":"v";rrSave();rrMount(el,ids,opts);};
  /* code reads from its first line, not from the response headers */
  const resp=$$(".rrp",el)[1],gap=resp&&$(".code .gap",resp);
  if(gap&&ev.response&&["js","html"].includes(bodyKind(ev.response,ev,false))&&RRS.tab.res==="pretty"){const box=gap.closest(".code");box.scrollTop=Math.max(0,gap.offsetTop-6);}
  const rc=$("[data-rcopy]",el);if(rc)rc.onclick=()=>fallbackCopy(((ev.response||{}).body)||"",()=>{rc.textContent="Copied";setTimeout(()=>rc.textContent="Copy body",1200);});
}
/* evidence ids that best show an endpoint, page, script or host */
const evOf=x=>(x&&x.evidence)||[];
"""
