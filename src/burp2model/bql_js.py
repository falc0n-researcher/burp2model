"""The BQL engine for the offline report — a JavaScript port of bql.py.

The report is a single file with no server, so its query console cannot call
SQLite. This runs the same language over the data embedded in the page. It is
kept in lockstep with `bql.py` by tests/test_bql_parity.py, which runs one query
corpus through both engines and compares the answers.
"""

BQL_JS = r"""
const BQL=(function(){
const OPS=["eq","ne","cont","ncont","like","regex","gt","gte","lt","lte"];
const DEFAULT_LIMIT=100,MAX_LIMIT=5000;
class BQLError extends Error{}
const fail=m=>{throw new BQLError(m);};
const cmp=(a,b)=>a<b?-1:a>b?1:0;

/* ---- lexing ---- */
const TOKEN=/\s*(?:(\()|(\))|([A-Za-z_][\w.\-]*:(?:"(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*'|[^\s()]+))|("(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*')|([^\s()"']+))/y;
function unquote(s){return s.length>=2&&s[0]===s[s.length-1]&&(s[0]==='"'||s[0]==="'")?s.slice(1,-1).split("\\"+s[0]).join(s[0]):s;}
function lex(text){
  const toks=[];let pos=0;text=text.trim();
  while(pos<text.length){
    TOKEN.lastIndex=pos;const m=TOKEN.exec(text);
    if(!m||TOKEN.lastIndex===pos)fail("cannot read the query near "+JSON.stringify(text.slice(pos,pos+20)));
    pos=TOKEN.lastIndex;
    if(m[1])toks.push(["lp","("]);
    else if(m[2])toks.push(["rp",")"]);
    else if(m[3]){const i=m[3].indexOf(":");toks.push(["term",[m[3].slice(0,i),unquote(m[3].slice(i+1))]]);}
    else if(m[4])toks.push(["text",unquote(m[4])]);
    else if(["AND","OR","NOT"].includes(m[5].toUpperCase()))toks.push([m[5].toUpperCase(),m[5].toUpperCase()]);
    else toks.push(["word",m[5]]);
  }
  return toks;
}

/* ---- parsing ---- */
function parse(toks){
  let i=0;
  const peek=()=>i<toks.length?toks[i][0]:null;
  const take=()=>toks[i++];
  function or_(){let n=and_();while(peek()==="OR"){take();n=["or",n,and_()];}return n;}
  function and_(){let n=not_();while(["AND","term","text","lp","NOT"].includes(peek())){if(peek()==="AND")take();n=["and",n,not_()];}return n;}
  function not_(){if(peek()==="NOT"){take();return["not",not_()];}return atom();}
  function atom(){
    const k=peek();
    if(k==="lp"){take();const n=or_();if(peek()!=="rp")fail("missing )");take();return n;}
    if(k==="term"){const [,[head,raw]]=take();const parts=head.split(".");let op="eq";
      if(parts.length>1&&OPS.includes(parts[parts.length-1]))op=parts.pop();
      return["term",parts.join("."),op,raw];}
    if(k==="text")return["text",take()[1]];
    fail(k===null?"expected a term like field:value":"unexpected "+JSON.stringify(toks[i][1]));
  }
  const n=or_();
  if(i<toks.length)fail("unexpected "+JSON.stringify(toks[i][1]));
  return n;
}

/* ---- fields ---- */
const REQ={
  "req.method":[r=>r.method,"text"],"req.host":[r=>r.host,"text"],"req.path":[r=>r.path,"text"],
  "req.template":[r=>r.path_template,"text"],"req.header":[r=>r.req_headers,"text"],
  "req.body":[r=>r.req_body,"text"],"resp.code":[r=>r.status,"int"],"resp.mime":[r=>r.mime,"text"],
  "resp.header":[r=>r.resp_headers,"text"],"resp.body":[r=>r.resp_body,"text"],
  "role":[r=>r.role,"text"],"id":[r=>r.id,"int"],"source":[r=>r.source,"text"]};
const REQ_TEXT=["path","req_body","resp_body","req_headers","resp_headers","host"];
const asText=v=>v==null?null:typeof v==="boolean"?(v?"1":"0"):typeof v==="object"?JSON.stringify(v):String(v);
const NODE={
  "node.id":[n=>n.id,"text"],"node.type":[n=>n.type,"text"],"node.label":[n=>n.label,"text"],
  "node.layer":[n=>n.layer,"int"],"node.source":[n=>n.source,"text"],
  "node.state":[n=>asText(n.attrs.api_state),"text"]};
const NODE_TEXT=["label","id"];
function EDGE(ctx){
  const nd=id=>ctx.nodeById.get(id);
  return{
  "edge.type":[e=>e.type,"text"],"edge.state":[e=>e.state,"text"],"edge.src":[e=>e.src,"text"],"edge.dst":[e=>e.dst,"text"],
  "edge.src.type":[e=>(nd(e.src)||{}).type,"text"],"edge.dst.type":[e=>(nd(e.dst)||{}).type,"text"],
  "edge.src.label":[e=>(nd(e.src)||{}).label,"text"],"edge.dst.label":[e=>(nd(e.dst)||{}).label,"text"]};}
const EDGE_TEXT=["src","dst","type"];
const ATTR=/^[A-Za-z_][\w\-]*$/;

function targetOf(f,ctx){
  if(f in REQ)return"requests";
  if(f in EDGE(ctx))return"edges";
  if(f in NODE||f==="node.evidence"||f==="node.role"||f.startsWith("node.attr."))return"nodes";
  fail("unknown field "+JSON.stringify(f)+"; run `help` for the field list");
}
function targets(ast,ctx){
  if(ast[0]==="term")return new Set([targetOf(ast[1],ctx)]);
  if(ast[0]==="text")return new Set();
  const s=new Set();ast.slice(1).forEach(a=>targets(a,ctx).forEach(x=>s.add(x)));return s;
}
const escRe=s=>s.replace(/[.*+?^${}()|[\]\\]/g,"\\$&");

/* ---- compile to a row predicate ---- */
function termPred(target,f,op,value,ctx){
  let get,kind;
  if(target==="requests")[get,kind]=REQ[f];
  else if(target==="edges")[get,kind]=EDGE(ctx)[f];
  else if(f==="node.evidence"){
    const ev=parseInt(value.toLowerCase().replace(/^ev_/,""),10);
    if(!/^(ev_)?\d+$/i.test(value))fail("node.evidence needs an evidence id, got "+JSON.stringify(value));
    if(op!=="eq"&&op!=="ne")fail("node.evidence supports eq and ne");
    return n=>(n.evidence.includes(ev))===(op==="eq");
  }else if(f==="node.role"){
    if(op==="eq"||op==="ne"){const want=value.toLowerCase();
      return n=>{const has=n.roles.some(r=>JSON.stringify(r).toLowerCase().includes('"'+want+'"'));return op==="eq"?has:!has;};}
    const text=n=>JSON.stringify(n.roles);get=text;kind="text";
  }else if(f.startsWith("node.attr.")){
    const a=f.slice(10);if(!ATTR.test(a))fail("bad attribute name "+JSON.stringify(a));
    get=n=>asText(n.attrs[a]);kind="text";
  }else[get,kind]=NODE[f];

  if(kind==="int"){
    if(["cont","ncont","like","regex"].includes(op))fail(f+" is numeric; use eq ne gt gte lt lte");
    if(!/^\s*[+-]?\d+\s*$/.test(value))fail(f+" needs a number, got "+JSON.stringify(value));
    const v=parseInt(value,10);
    return r=>{const x=get(r);if(x==null)return false;
      return{eq:x===v,ne:x!==v,gt:x>v,gte:x>=v,lt:x<v,lte:x<=v}[op];};
  }
  if(["gt","gte","lt","lte"].includes(op))fail(f+" is text; "+op+" is for numbers");
  const low=value.toLowerCase();
  if(op==="eq")return r=>{const x=get(r);return x!=null&&String(x).toLowerCase()===low;};
  if(op==="ne")return r=>{const x=get(r);return x==null||String(x).toLowerCase()!==low;};
  if(op==="cont")return r=>{const x=get(r);return x!=null&&String(x).toLowerCase().includes(low);};
  if(op==="ncont")return r=>{const x=get(r);return x==null||!String(x).toLowerCase().includes(low);};
  if(op==="like"){const re=new RegExp("^"+value.split("*").map(escRe).join(".*")+"$","is");
    return r=>{const x=get(r);return x!=null&&re.test(String(x));};}
  let re;try{re=new RegExp(value,"i");}catch(e){fail("bad regex "+JSON.stringify(value)+": "+e.message);}
  return r=>{const x=get(r);return x!=null&&re.test(String(x));};
}
function compile(ast,target,ctx){
  const k=ast[0];
  if(k==="and"){const a=compile(ast[1],target,ctx),b=compile(ast[2],target,ctx);return r=>a(r)&&b(r);}
  if(k==="or"){const a=compile(ast[1],target,ctx),b=compile(ast[2],target,ctx);return r=>a(r)||b(r);}
  if(k==="not"){const a=compile(ast[1],target,ctx);return r=>!a(r);}
  if(k==="text"){const cols={requests:REQ_TEXT,nodes:NODE_TEXT,edges:EDGE_TEXT}[target],low=ast[1].toLowerCase();
    return r=>cols.some(c=>r[c]!=null&&String(r[c]).toLowerCase().includes(low));}
  return termPred(target,ast[1],ast[2],ast[3],ctx);
}

/* ---- data ---- */
function requestsFrom(evidence){
  const hs=h=>(h||[]).map(([k,v])=>k+": "+v).join("\n");
  return Object.values(evidence||{}).sort((a,b)=>a.id-b.id).map(e=>{
    const rq=e.request||{},rs=e.response||{},parts=(rq.line||"").split(" ");
    return{id:e.id,source:e.source,item:e.item,role:e.role,method:e.method,host:e.host,
      path:parts.length>=2?parts[1]:"",path_template:e.path,status:e.status,mime:e.mime,
      req_headers:hs(rq.headers),req_body:rq.body||"",resp_headers:hs(rs.headers),resp_body:rs.body||""};});
}
function context(db){
  const nodeById=new Map(db.nodes.map(n=>[n.id,n]));
  const out=new Map(),inc=new Map();
  for(const e of db.edges){
    if(!out.has(e.src))out.set(e.src,[]);out.get(e.src).push(e);
    if(!inc.has(e.dst))inc.set(e.dst,[]);inc.get(e.dst).push(e);
  }
  return{db,nodeById,out,inc};
}
const evs=a=>(a||[]).map(i=>"ev_"+i);
const plural=t=>t+(t===1?"":"es");

/* ---- filters ---- */
function runFilter(ctx,text,limit){
  const m=/\s+limit\s+(\d+)\s*$/i.exec(text);
  if(m){limit=parseInt(m[1],10);text=text.slice(0,m.index);}
  limit=Math.max(1,Math.min(limit,MAX_LIMIT));
  const ast=parse(lex(text)),ts=targets(ast,ctx);
  if(ts.size>1)fail("a query can filter one of requests, nodes or edges — this mixes "+[...ts].sort().join(", "));
  const target=ts.size?[...ts][0]:"requests";
  const pred=compile(ast,target,ctx);
  let rows,cols,out;
  if(target==="requests"){
    rows=ctx.db.requests.filter(pred);
    out=rows.slice(0,limit).map(r=>({ev:"ev_"+r.id,method:r.method,status:r.status,host:r.host,path:r.path,role:r.role||"",mime:r.mime||""}));
    cols=["ev","method","status","host","path","role"];
  }else if(target==="nodes"){
    rows=ctx.db.nodes.filter(pred).sort((a,b)=>a.layer-b.layer||cmp(a.type,b.type)||cmp(a.label,b.label));
    out=rows.slice(0,limit).map(n=>({id:n.id,type:n.type,layer:n.layer,label:n.label,source:n.source,state:n.attrs.api_state||"",roles:n.roles.join(","),evidence:evs(n.evidence)}));
    cols=["type","label","state","source","roles","evidence"];
  }else{
    rows=ctx.db.edges.filter(pred);
    const lab=id=>(ctx.nodeById.get(id)||{}).label;
    out=rows.slice(0,limit).map(e=>({src:lab(e.src),type:e.type,state:e.state,dst:lab(e.dst),evidence:evs(e.evidence)}));
    cols=["src","type","state","dst","evidence"];
  }
  const total=rows.length;
  let note=total+" match"+(total!==1?"es":"");
  if(total>out.length)note+=" (showing "+out.length+"; add `limit N`)";
  return{kind:target,columns:cols,rows:out,note,total};
}

/* ---- graph verbs ---- */
function resolve(ctx,ref){
  ref=ref.trim();
  if(ctx.nodeById.has(ref))return ref;
  const low=ref.toLowerCase();
  let hits=ctx.db.nodes.filter(n=>String(n.label).toLowerCase()===low);
  if(!hits.length)hits=ctx.db.nodes.filter(n=>String(n.label).toLowerCase().includes(low));
  if(!hits.length)fail("no node matches "+JSON.stringify(ref));
  if(hits.length>1)fail(JSON.stringify(ref)+" is ambiguous — be more specific: "+hits.slice(0,5).map(n=>n.label).join(" | "));
  return hits[0].id;
}
const label=(ctx,id)=>(ctx.nodeById.get(id)||{label:id}).label;
function walk(ctx,nid,depth,dir){
  depth=Math.max(1,Math.min(depth,8));
  const adj=dir==="out"?ctx.out:ctx.inc,res=new Map();
  let frontier=[nid];
  for(let d=1;d<=depth;d++){
    const next=[];
    for(const cur of frontier)for(const e of adj.get(cur)||[]){
      const n=dir==="out"?e.dst:e.src;
      if(!res.has(n)){res.set(n,d);next.push(n);}
    }
    frontier=next;
  }
  const rows=[...res].filter(([id])=>ctx.nodeById.has(id)).map(([id,d])=>{const n=ctx.nodeById.get(id);return{hops:d,type:n.type,label:n.label,source:n.source};})
    .sort((a,b)=>a.hops-b.hops||cmp(a.type,b.type)||cmp(a.label,b.label));
  return{kind:"nodes",columns:["hops","type","label","source"],rows,
    note:rows.length+" node(s) "+(dir==="out"?"downstream of":"upstream of")+" "+label(ctx,nid)+" (depth "+depth+")",total:rows.length};
}
function paths(ctx,start,goal,limit=3,maxDepth=8){
  const back=goal===null,found=[],seen=new Map([[start,0]]);
  const queue=[[start,[]]];
  while(queue.length&&found.length<limit){
    const [cur,trail]=queue.shift();
    if(trail.length>=maxDepth)continue;
    for(const e of ((back?ctx.inc:ctx.out).get(cur))||[]){
      const nxt=back?e.src:e.dst;
      const hop={from:e.src,to:e.dst,edge:e.type,state:e.state,evidence:evs(e.evidence)};
      const path=trail.concat([hop]);
      if(back?(ctx.nodeById.get(nxt)||{}).type==="host":nxt===goal){found.push(path);if(found.length>=limit)break;continue;}
      if(!seen.has(nxt)||seen.get(nxt)>=path.length){seen.set(nxt,path.length);queue.push([nxt,path]);}
    }
  }
  return back?found.map(p=>p.slice().reverse()):found;
}
function pathsResult(ctx,ps,title){
  const rows=[];
  ps.forEach((p,n)=>p.forEach((h,i)=>rows.push({path:n+1,hop:i+1,from:label(ctx,h.from),edge:h.edge,state:h.state,to:label(ctx,h.to),evidence:h.evidence})));
  return{kind:"paths",columns:["path","hop","from","edge","state","to","evidence"],rows,note:ps.length?ps.length+" path(s): "+title:"no path: "+title,total:ps.length};
}
const HELP="BQL — filters and graph verbs over this model. Fields: req.method req.host req.path req.template req.header req.body resp.code resp.mime resp.header resp.body role id | node.type node.label node.id node.layer node.source node.role node.state node.evidence node.attr.<name> | edge.type edge.state edge.src edge.dst edge.src.type edge.dst.type edge.src.label edge.dst.label. Operators: eq ne cont ncont like regex gt gte lt lte. Combine with AND OR NOT ( ) and end with `limit N`. Verbs: reach <node> · blast <node> [depth N] · upstream <node> · neighbors <node> · path <a> to <b> · osint [section] · unknowns · stats · help.";

function run(db,text,limit=DEFAULT_LIMIT){
  if(!db._ctx)Object.defineProperty(db,"_ctx",{value:context(db),enumerable:false});
  const ctx=db._ctx;
  text=(text||"").trim().replace(/;+\s*$/,"").trim();
  if(!text)fail("empty query — try `help`");
  const sp=text.search(/\s/),first=(sp<0?text:text.slice(0,sp)).toLowerCase(),rest=sp<0?"":text.slice(sp).trim();
  if(first==="help")return{kind:"text",columns:[],rows:[],note:HELP,total:null};
  if(first==="stats"){const s=db.stats||{};return{kind:"table",columns:["metric","value"],rows:Object.entries(s).map(([metric,value])=>({metric,value})),note:"graph.db",total:Object.keys(s).length};}
  if(first==="unknowns"){const rows=db.unknowns.map(u=>({type:u.type,entity:u.entity,we_dont_know:u.we_dont_know,next_step:u.next_step}));
    return{kind:"table",columns:["type","entity","we_dont_know","next_step"],rows,note:rows.length+" unknown(s)",total:rows.length};}
  if(first==="osint"){
    if(!db.osint)return{kind:"facts",columns:["section","key","value"],rows:[],note:"no OSINT stored yet — build with OSINT enabled (the default)",total:0};
    const sec=rest.toLowerCase(),rows=db.facts.filter(f=>!rest||f.section.toLowerCase()===sec);
    return{kind:"facts",columns:["section","key","value"],rows,note:"OSINT run #"+db.osint.id+" · "+db.osint.host+" · "+db.osint.generated_at,total:rows.length};}
  if(first==="schema"||first==="sql")fail(first+" is available in the CLI (`burp2model q`), not in the report");
  if(["reach","blast","upstream","neighbors","path"].includes(first)){
    if(!rest)fail(first+" needs a node");
    if(first==="path"){const m=rest.split(/\s+to\s+/i);if(m.length<2)fail("usage: path <a> to <b>");
      const a=resolve(ctx,unquote(m[0].trim())),b=resolve(ctx,unquote(m.slice(1).join(" to ").trim()));
      return pathsResult(ctx,paths(ctx,a,b,1),label(ctx,a)+" → "+label(ctx,b));}
    let words=rest.split(/\s+/),depth=3;
    if(words.length>=2&&words[words.length-2].toLowerCase()==="depth"&&/^\d+$/.test(words[words.length-1])){depth=parseInt(words.pop(),10);words.pop();}
    const nid=resolve(ctx,unquote(words.join(" ")));
    if(first==="reach")return pathsResult(ctx,paths(ctx,nid,null),"how "+label(ctx,nid)+" is reached");
    if(first==="blast")return walk(ctx,nid,depth,"out");
    if(first==="upstream")return walk(ctx,nid,depth,"in");
    const d=walk(ctx,nid,depth,"out"),u=walk(ctx,nid,depth,"in");
    const rows=d.rows.map(r=>Object.assign({direction:"out"},r)).concat(u.rows.map(r=>Object.assign({direction:"in"},r)));
    return{kind:"nodes",columns:["direction","hops","type","label","source"],rows,note:rows.length+" node(s) within "+depth+" hop(s) of "+label(ctx,nid),total:rows.length};
  }
  return runFilter(ctx,text,limit);
}
return{run,requestsFrom,BQLError,HELP};
})();
"""
