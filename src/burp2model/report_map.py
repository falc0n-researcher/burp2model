"""The Map view of the offline report: an interactive graph of the whole app on a canvas.

Three layouts (clustered force, layered flow, and a focus ring around one node), pan and zoom,
hover tracing, a node inspector, path tracing between two nodes, search, layer and edge filters
and a minimap. Positions are deterministic: the same model always draws the same picture.
"""

MAP_CSS = r"""
/* map */
.m-graph{padding:0!important;overflow:hidden!important}
.m-graph .view{max-width:none;height:100%}
.m-graph .foot{display:none}
.mapx{display:flex;flex-direction:column;height:100%;outline:none}
.mtop{display:flex;align-items:center;gap:10px;flex-wrap:wrap;padding:9px 14px;border-bottom:1px solid var(--line);background:var(--panel)}
.mtop h1{font:700 15px var(--sans);margin:0 4px 0 0}
.msearch{position:relative;flex:0 1 250px;min-width:170px}
.msearch input{width:100%;height:32px;padding:0 10px 0 30px;border:1px solid var(--line2);border-radius:7px;background:var(--panel2);color:var(--text);font:12.5px var(--sans)}
.msearch input:focus{border-color:var(--signal);outline:none}
.msearch svg{position:absolute;left:9px;top:8px;width:15px;height:15px;color:var(--faint)}
.msug{position:absolute;left:0;right:0;top:36px;background:var(--panel);border:1px solid var(--line2);border-radius:9px;box-shadow:var(--shadow);z-index:40;max-height:260px;overflow:auto;padding:3px}
.msug button{display:flex;gap:8px;align-items:center;width:100%;text-align:left;padding:6px 8px;border:0;background:none;border-radius:6px;font:12px var(--mono);color:var(--text)}
.msug button:hover,.msug button.on{background:var(--signal-soft)}
.msug .k{font:600 9.5px var(--mono);color:var(--faint);margin-left:auto;text-transform:uppercase}
.mchips{display:flex;gap:5px;flex-wrap:wrap;align-items:center;flex-basis:100%;order:9}
.mchip{display:inline-flex;gap:6px;align-items:center;font:600 11px var(--mono);padding:4px 9px;border-radius:7px;border:1px solid var(--line2);background:var(--panel);color:var(--text)}
.mchip .sw{width:9px;height:9px;border-radius:2px;flex:none}
.mchip .c{color:var(--faint)}
.mchip.off{opacity:.42;text-decoration:line-through}
.mchip:hover{border-color:var(--faint)}
.mchips .div{width:1px;height:20px;background:var(--line2);margin:0 4px}
.mseg{display:inline-flex;border:1px solid var(--line2);border-radius:8px;overflow:hidden}
.mseg button{font:600 11.5px var(--sans);padding:5px 11px;border:0;background:var(--panel);color:var(--muted)}
.mseg button+button{border-left:1px solid var(--line2)}
.mseg button.on{background:var(--text);color:var(--ink)}
.mbtn{font:600 12px var(--sans);padding:5px 10px;border:1px solid var(--line2);border-radius:8px;background:var(--panel);color:var(--muted)}
.mbtn:hover{color:var(--text)}
.mbody{display:flex;flex:1;min-height:0}
.mcv{position:relative;flex:1;min-width:0;background:radial-gradient(1200px 700px at 50% 40%,var(--panel2),var(--ink))}
.mcv canvas.main{position:absolute;inset:0;width:100%;height:100%;display:block;cursor:grab;touch-action:none}
.mcv canvas.main.drag{cursor:grabbing}.mcv canvas.main.hit{cursor:pointer}
.mcv canvas.mini{position:absolute;right:14px;bottom:14px;width:170px;height:110px;border:1px solid var(--line2);border-radius:10px;background:var(--panel);opacity:.94;cursor:pointer;box-shadow:var(--shadow)}
.mhud{position:absolute;left:14px;bottom:14px;color:var(--muted);font:11.5px var(--mono);background:var(--panel);border:1px solid var(--line);border-radius:8px;padding:5px 10px;pointer-events:none}
.mtip{position:absolute;pointer-events:none;z-index:5;background:var(--panel);border:1px solid var(--line2);border-radius:9px;box-shadow:var(--shadow);padding:7px 10px;font:12px var(--mono);max-width:340px;display:none}
.mtip b{display:block;font:700 12.5px var(--mono);word-break:break-all}
.mtip span{color:var(--muted);font-size:11px}
.mzoom{position:absolute;right:14px;top:14px;display:flex;flex-direction:column;gap:6px}
.mzoom button{width:32px;height:32px;border:1px solid var(--line2);border-radius:8px;background:var(--panel);font:700 15px var(--sans);color:var(--muted)}
.mzoom button:hover{color:var(--text)}
.minsp{width:330px;flex:none;border-left:1px solid var(--line);background:var(--panel);overflow:auto;padding:16px 16px 30px}
@media(max-width:1000px){.minsp{display:none}}
.minsp h3{font:700 11px var(--mono);letter-spacing:.12em;text-transform:uppercase;color:var(--faint);margin:18px 0 8px}
.minsp h3:first-child{margin-top:0}
.nh{display:flex;align-items:center;gap:10px;margin-bottom:6px}
.nh .ic{width:30px;height:30px;border-radius:9px;display:grid;place-items:center;flex:none;background:var(--panel2)}
.nh .ic svg{width:16px;height:16px}
.nh .kind{font:600 10.5px var(--mono);letter-spacing:.09em;text-transform:uppercase;color:var(--muted)}
.nlabel{font:700 14px/1.35 var(--mono);word-break:break-all;margin:2px 0 10px}
.nrows{display:grid;grid-template-columns:90px 1fr;gap:6px 10px;font-size:12.5px}
.nrows .k{color:var(--muted)}.nrows .v{word-break:break-word;font-family:var(--mono);font-size:12px}
.nact{display:flex;gap:6px;flex-wrap:wrap;margin:14px 0 4px}
.conn{display:flex;gap:8px;align-items:center;padding:6px 8px;border-radius:7px;cursor:pointer;font:12px var(--mono);border:1px solid transparent}
.conn:hover{background:var(--panel2);border-color:var(--line)}
.conn .a{color:var(--faint);flex:none;width:14px}
.conn .t{overflow:hidden;text-overflow:ellipsis;white-space:nowrap;flex:1;min-width:0}
.conn .e{font:600 9.5px var(--mono);color:var(--muted);flex:none}
.conn .s{width:8px;height:8px;border-radius:2px;flex:none}
.ghd{font:600 11px var(--mono);color:var(--muted);margin:10px 0 3px;display:flex;gap:6px;align-items:center}
.ghd .st{font-size:9.5px;border:1px solid currentColor;border-radius:4px;padding:0 4px}
.ghd .st.ob{color:var(--observed)}.ghd .st.in{color:var(--inferred)}.ghd .st.ex{color:var(--l6)}
.pathbox{border:1px solid var(--signal);background:var(--signal-soft);border-radius:10px;padding:10px 12px;margin-top:12px}
.pathbox .pt{font:700 11px var(--mono);letter-spacing:.08em;text-transform:uppercase;color:var(--signal);margin-bottom:6px}
.hubrow{display:flex;gap:8px;align-items:center;padding:6px 0;border-bottom:1px solid var(--line);cursor:pointer;font:12px var(--mono)}
.hubrow:hover .t{color:var(--signal)}
.hubrow .t{flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.hubrow .d{color:var(--faint)}
.tips{color:var(--muted);font-size:12px;line-height:1.75}
.tips kbd{font:600 10.5px var(--mono);border:1px solid var(--line2);border-bottom-width:2px;border-radius:4px;padding:0 5px;background:var(--panel2);color:var(--text)}
"""

MAP_JS = r"""
/* ---------- MAP (canvas, deterministic layouts, inspector) ---------- */
const CAT=[
  {id:"infra",label:"Infrastructure",short:"Infra",types:["infra"],color:"var(--l6)",shape:"square"},
  {id:"host",label:"Hosts",short:"Hosts",types:["host"],color:"var(--l1)",shape:"rsquare"},
  {id:"tech",label:"Technology",short:"Tech",types:["tech"],color:"var(--l5)",shape:"hex"},
  {id:"route",label:"Pages / routes",short:"Pages",types:["route"],color:"var(--l2)",shape:"circle"},
  {id:"script",label:"Scripts",short:"Scripts",types:["script"],color:"var(--l3)",shape:"diamond"},
  {id:"endpoint",label:"API endpoints",short:"Endpoints",types:["endpoint"],color:"var(--l4)",shape:"circle"},
  {id:"param",label:"Parameters",short:"Params",types:["parameter","operation"],color:"var(--inferred)",shape:"dot"},
  {id:"trust",label:"Trust & third parties",short:"Trust",types:["third_party","auth","cookie","role"],color:"var(--l5)",shape:"tri"},
];
function catOf(t){for(let i=0;i<CAT.length;i++)if(CAT[i].types.includes(t))return i;return CAT.length-1;}
function shapePath(shape,r){
  const s=r*1.15;
  switch(shape){
    case "square":return `M${-s} ${-s}H${s}V${s}H${-s}Z`;
    case "rsquare":{const k=s*.45;return `M${-s+k} ${-s}H${s-k}Q${s} ${-s} ${s} ${-s+k}V${s-k}Q${s} ${s} ${s-k} ${s}H${-s+k}Q${-s} ${s} ${-s} ${s-k}V${-s+k}Q${-s} ${-s} ${-s+k} ${-s}Z`;}
    case "diamond":return `M0 ${-s*1.2}L${s*1.2} 0L0 ${s*1.2}L${-s*1.2} 0Z`;
    case "hex":return [0,1,2,3,4,5].map(i=>{const a=Math.PI/3*i;return (i?"L":"M")+(s*Math.cos(a)).toFixed(2)+" "+(s*Math.sin(a)).toFixed(2);}).join("")+"Z";
    case "tri":return `M0 ${-s*1.15}L${s*1.1} ${s*.75}L${-s*1.1} ${s*.75}Z`;
    case "dot":{const d=Math.max(3,r*.7);return `M${-d} 0a${d} ${d} 0 1 0 ${2*d} 0a${d} ${d} 0 1 0 ${-2*d} 0`;}
    default:return `M${-r} 0a${r} ${r} 0 1 0 ${2*r} 0a${r} ${r} 0 1 0 ${-2*r} 0`;
  }
}
const ACCESS=new Set(["REACHED","SENT_CREDENTIAL"]);
const MAPS=(function(){
  const base={mode:"force",hidden:new Set((D.graph.nodes||[]).length>140?["param"]:[]),edgeOff:new Set((D.graph.edges||[]).length>300?["ACCESS"]:[]),sel:null,path:null,focusId:null};
  try{const s=JSON.parse(localStorage.getItem("b2m-map2")||"null");if(s){base.mode=s.mode||base.mode;base.hidden=new Set(s.hidden||[...base.hidden]);base.edgeOff=new Set(s.edgeOff||[]);}}catch(e){}
  return base;
})();
function mapSave(){try{localStorage.setItem("b2m-map2",JSON.stringify({mode:MAPS.mode,hidden:[...MAPS.hidden],edgeOff:[...MAPS.edgeOff]}));}catch(e){}}
const ICON={host:"M4 6h16v5H4zM4 13h16v5H4z",route:"M5 4h9l5 5v11H5z",script:"M8 7l-5 5 5 5M16 7l5 5-5 5",endpoint:"M4 12h6m4 0h6M10 8l4 4-4 4",
  parameter:"M5 8h14M5 16h14",third_party:"M12 3l9 16H3z",auth:"M7 11V8a5 5 0 0 1 10 0v3M5 11h14v9H5z",cookie:"M12 3a9 9 0 1 0 9 9 4 4 0 0 1-4-4 4 4 0 0 1-5-5z",
  role:"M12 12a4 4 0 1 0 0-8 4 4 0 0 0 0 8zM4 21a8 8 0 0 1 16 0",tech:"M12 3l8 4.5v9L12 21l-8-4.5v-9z",infra:"M3 12h18M12 3a14 14 0 0 1 0 18M12 3a14 14 0 0 0 0 18M12 3a9 9 0 1 0 0 18 9 9 0 0 0 0-18z",operation:"M5 8h14M5 16h14"};
const KIND_LABEL={infra:"Infrastructure",host:"Host",tech:"Technology",route:"Page / route",script:"Script",endpoint:"API endpoint",parameter:"Parameter",operation:"GraphQL operation",third_party:"Third party",auth:"Auth scheme",cookie:"Cookie",role:"Role"};

const AREA_SKIP=new Set(["api","rest","v1","v2","v3","v4","graphql","gql","apis","public","internal","www"]);
function areaOf(n){
  let p;
  if(n.type==="endpoint"){const m=/^\S+\s+(.*)$/.exec(n.label);p=m?m[1]:n.label;}
  else if(n.type==="route")p=n.label;else return null;
  p=p.replace(/^[^/]*/,"");
  const segs=p.split("?")[0].split("/").filter(x=>x&&!AREA_SKIP.has(x.toLowerCase())&&!/^\{.*\}$/.test(x)&&!/^[\d.]+$/.test(x)&&!/^[a-f0-9-]{16,}$/i.test(x));
  const a=(segs[0]||"root").toLowerCase().replace(/[^a-z0-9_.-]/g,"").replace(/\.[a-z0-9]{1,5}$/,"")||"root";
  return a.length>4&&a.endsWith("s")&&!a.endsWith("ss")?a.slice(0,-1):a;
}
function vGraph(){
  const present=CAT.map((cat,i)=>({cat,i,n:(D.graph.nodes||[]).filter(x=>catOf(x.type)===i).length})).filter(x=>x.n);
  const states=["OBSERVED","INFERRED","EXTERNAL"].filter(s=>(D.graph.edges||[]).some(e=>e.state===s)).concat((D.graph.edges||[]).some(e=>ACCESS.has(e.type))?["ACCESS"]:[]);
  const SN={OBSERVED:"seen in traffic",INFERRED:"found in code",EXTERNAL:"recon",ACCESS:"who reached what"};
  return `<div class="mapx" id="mapx" tabindex="-1"><div class="mtop"><h1>Map</h1>
    <div class="msearch"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="11" cy="11" r="7"/><path d="M21 21l-4.3-4.3"/></svg><input id="msq" placeholder="Find a node…" autocomplete="off" spellcheck="false"><div class="msug" id="msug" hidden></div></div>
    <span style="flex:1"></span>
    <div class="mseg" id="mmode"><button data-mode="force" class="${MAPS.mode==="force"?"on":""}" title="Clusters by kind, springs along edges">Cluster</button><button data-mode="flow" class="${MAPS.mode==="flow"?"on":""}" title="Layers left to right">Flow</button><button data-mode="focus" class="${MAPS.mode==="focus"?"on":""}" title="The selected node and what surrounds it">Focus</button></div>
    <button class="mbtn" id="mpng" title="Download the map as a PNG">PNG</button><div class="mchips" id="mlayers">${present.map(x=>`<button class="mchip${MAPS.hidden.has(x.cat.id)?" off":""}" data-layer="${x.cat.id}" title="Show or hide"><span class="sw" style="background:${x.cat.color}"></span>${esc(x.cat.short)} <span class="c">${x.n}</span></button>`).join("")}
     <span class="div"></span>${states.map(s=>`<button class="mchip${MAPS.edgeOff.has(s)?" off":""}" data-es="${s}" title="Show or hide these edges"><span class="sw" style="background:none;border-top:2px ${s==="INFERRED"?"dashed":s==="EXTERNAL"?"dotted":"solid"} ${s==="INFERRED"?"var(--inferred)":s==="EXTERNAL"?"var(--l6)":s==="ACCESS"?"var(--faint)":"var(--observed)"};border-radius:0;height:0;margin-top:1px"></span>${SN[s]}</button>`).join("")}</div></div>
   <div class="mbody"><div class="mcv" id="mcv"><canvas class="main" id="mc"></canvas><canvas class="mini" id="mm" width="340" height="220"></canvas><div class="mhud" id="mhud"></div><div class="mtip" id="mtip"></div>
     <div class="mzoom"><button data-z="in" aria-label="Zoom in">+</button><button data-z="out" aria-label="Zoom out">−</button><button data-z="fit" aria-label="Fit" style="font-size:11px">Fit</button></div></div>
    <aside class="minsp" id="minsp"></aside></div></div>`;
}

function initGraph(){
  const cv=$("#mc");if(!cv)return;
  const wrap=$("#mcv"),ctx=cv.getContext("2d"),mini=$("#mm"),mctx=mini.getContext("2d"),tip=$("#mtip");
  if(MAPS.raf)cancelAnimationFrame(MAPS.raf);
  MAPS.sim=null;
  /* ---- data ---- */
  const all=D.graph.nodes.map(n=>({...n,cat:catOf(n.type),x:0,y:0,tx:0,ty:0,vx:0,vy:0,deg:0,fx:null,fy:null}));
  const byId=new Map(all.map(n=>[n.id,n]));
  const vis=n=>!MAPS.hidden.has(CAT[n.cat].id);
  let nodes=all.filter(vis);
  const nset=new Set(nodes.map(n=>n.id));
  let edges=D.graph.edges.filter(e=>nset.has(e.s)&&nset.has(e.d)&&!MAPS.edgeOff.has(e.state)&&!(MAPS.edgeOff.has("ACCESS")&&ACCESS.has(e.type))).map(e=>({s:byId.get(e.s),d:byId.get(e.d),type:e.type,state:e.state}));
  nodes.forEach(n=>n.deg=0);edges.forEach(e=>{e.s.deg++;e.d.deg++;});
  const adj=new Map(nodes.map(n=>[n.id,[]]));edges.forEach(e=>{adj.get(e.s.id).push({n:e.d,e,out:true});adj.get(e.d.id).push({n:e.s,e,out:false});});
  const EPBY=Object.fromEntries(EP.map(e=>[e.id,e]));
  const R=n=>(n.cat===1?9:n.cat===5?5:4.5)+Math.min(8,Math.sqrt(n.deg)*1.6);
  const cs=getComputedStyle(document.documentElement);
  const col=v=>{const m=/^var\((--[\w-]+)\)$/.exec(v);return m?cs.getPropertyValue(m[1]).trim():v;};
  let C={};const readTheme=()=>{["text","muted","faint","line","line2","panel","panel2","ink","signal","observed","inferred","ok","warn","bad","l6"].forEach(k=>C[k]=cs.getPropertyValue("--"+k).trim());CAT.forEach(c=>c._c=col(c.color));};
  readTheme();
  const themeObs=new MutationObserver(()=>{readTheme();dirty=true;});themeObs.observe(document.documentElement,{attributes:true,attributeFilter:["data-theme"]});
  const pathCache={};const P2=(shape,r)=>{const k=shape+Math.round(r*2);return pathCache[k]||(pathCache[k]=new Path2D(shapePath(shape,Math.round(r*2)/2)));};

  /* ---- layouts (all deterministic) ---- */
  function layoutFlow(){
    const cols=CAT.map((_,i)=>i).filter(i=>nodes.some(n=>n.cat===i)),ROWH=26,SUB=30,COLW=210;
    const by={};cols.forEach(ci=>by[ci]=nodes.filter(n=>n.cat===ci).sort((a,b)=>String(a.label).localeCompare(String(b.label))));
    const rank={};cols.forEach(ci=>by[ci].forEach((n,r)=>rank[n.id]=r));
    for(let sw=0;sw<6;sw++){(sw%2?cols.slice().reverse():cols).forEach(ci=>{
      const bary=n=>{const ns=adj.get(n.id).map(x=>rank[x.n.id]).filter(v=>v!=null);return ns.length?ns.reduce((a,b)=>a+b,0)/ns.length:rank[n.id];};
      by[ci].sort((a,b)=>bary(a)-bary(b)||String(a.label).localeCompare(String(b.label)));by[ci].forEach((n,r)=>rank[n.id]=r);});}
    let x=0;const maxRows=Math.max(1,...cols.map(ci=>Math.min(SUB,by[ci].length)));
    cols.forEach(ci=>{const nsub=Math.max(1,Math.ceil(by[ci].length/SUB)),off=(maxRows-Math.min(SUB,by[ci].length))*ROWH/2;
      by[ci].forEach((n,r)=>{n.tx=x+Math.floor(r/SUB)*COLW;n.ty=off+(r%SUB)*ROWH;});x+=nsub*COLW+60;});
  }
  function layoutForce(){
    /* every (kind, feature area) is a bubble. Bubbles are packed without overlap, grouped by kind around a ring,
       so the picture reads as neighbourhoods. Nodes then relax inside their bubble. */
    const groups=new Map();
    nodes.forEach(n=>{n.area=areaOf(n);const k=n.cat+"|"+(n.area||"");(groups.get(k)||groups.set(k,{cat:n.cat,name:n.area||CAT[n.cat].short,g:[]}).get(k)).g.push(n);});
    const bub=[...groups.values()].sort((x,y)=>x.cat-y.cat||y.g.length-x.g.length||x.name.localeCompare(y.name));
    bub.forEach(b=>{b.r=16+9.5*Math.sqrt(b.g.length);});
    const regions=[];
    CAT.forEach((c,ci)=>{const bs=bub.filter(b=>b.cat===ci);if(!bs.length)return;
      const placed=[];
      bs.forEach((b,i)=>{
        if(!i){b.x=0;b.y=0;placed.push(b);return;}
        for(let rad=0,ang=0;;ang+=.55,rad+=.9){const x=Math.cos(ang)*rad*3.2,y=Math.sin(ang)*rad*3.2;
          if(placed.every(q=>Math.hypot(q.x-x,q.y-y)>=q.r+b.r+34)){b.x=x;b.y=y;placed.push(b);break;}if(rad>4000){b.x=rad;b.y=0;placed.push(b);break;}}});
      let mx=0,my=0;placed.forEach(b=>{mx+=b.x*b.g.length;my+=b.y*b.g.length;});const tot=placed.reduce((a,b)=>a+b.g.length,0);mx/=tot;my/=tot;
      placed.forEach(b=>{b.x-=mx;b.y-=my;});
      regions.push({ci,bs:placed,R:Math.max(...placed.map(b=>Math.hypot(b.x,b.y)+b.r))});});
    /* regions along a ring, spaced by their own size */
    const need=regions.reduce((a,r)=>a+2*r.R+90,0),RING=Math.max(regions.length>1?need/(2*Math.PI):0,regions.length>1?Math.max(...regions.map(r=>r.R))+80:0);
    let ang=-Math.PI/2;
    regions.forEach(r=>{const share=(2*r.R+90)/Math.max(1,need)*2*Math.PI;ang+=share/2;
      const cx=regions.length>1?Math.cos(ang)*RING:0,cy=regions.length>1?Math.sin(ang)*RING*.82:0;ang+=share/2;
      r.bs.forEach(b=>{b.ax=cx+b.x;b.ay=cy+b.y;b.g.forEach(n=>{n.ax=b.ax;n.ay=b.ay;});});});
    MAPS.clusters=bub.filter(b=>b.g.length>=2||b.g[0].cat===1).map(b=>({g:b.g,name:b.name,cat:b.cat,r:b.r}));
    const cnt={};
    nodes.slice().sort((a,b)=>a.cat-b.cat||String(a.label).localeCompare(String(b.label))).forEach(n=>{
      const k=n.ax+","+n.ay,i=cnt[k]=(cnt[k]||0)+1,a=i*2.399963,r=9*Math.sqrt(i);
      n.x=n.ax+Math.cos(a)*r;n.y=n.ay+Math.sin(a)*r;n.vx=n.vy=0;});
    const sim={anchor:{},alpha:1};MAPS.sim=sim;
    const steps=nodes.length>1500?60:nodes.length>600?140:240;
    for(let i=0;i<steps;i++)tick(sim,true);
    nodes.forEach(n=>{n.tx=n.x;n.ty=n.y;});
    sim.alpha=0;
  }
  function tick(sim,pre){
    const a=sim.alpha,N=nodes,CELL=60,grid=new Map();
    N.forEach(n=>{const k=Math.floor(n.x/CELL)+","+Math.floor(n.y/CELL);(grid.get(k)||grid.set(k,[]).get(k)).push(n);});
    N.forEach(n=>{const cx=Math.floor(n.x/CELL),cy=Math.floor(n.y/CELL);
      for(let gx=cx-2;gx<=cx+2;gx++)for(let gy=cy-2;gy<=cy+2;gy++){const g=grid.get(gx+","+gy);if(!g)continue;
        for(const m of g){if(m===n||m.id<n.id)continue;let dx=m.x-n.x,dy=m.y-n.y,d2=dx*dx+dy*dy;if(d2<.01){dx=(n.deg%7-3)*.1+.05;dy=(m.deg%5-2)*.1+.05;d2=dx*dx+dy*dy;}
          if(d2>120*120)continue;const d=Math.sqrt(Math.max(d2,36)),f=Math.min(30,700/(d*d)+(d<R(n)+R(m)+5?3:0))*a,fx=dx/Math.sqrt(d2)*f,fy=dy/Math.sqrt(d2)*f;n.vx-=fx;n.vy-=fy;m.vx+=fx;m.vy+=fy;}}});
    edges.forEach(e=>{if(ACCESS.has(e.type)||e.s.deg>24||e.d.deg>24||e.s.ax!==e.d.ax||e.s.ay!==e.d.ay)return;const dx=e.d.x-e.s.x,dy=e.d.y-e.s.y,d=Math.max(1,Math.sqrt(dx*dx+dy*dy)),rest=e.type==="USES_PARAMETER"?30:60,f=(d-rest)/d*.03*a/Math.sqrt(Math.max(1,Math.max(e.s.deg,e.d.deg)));
      e.s.vx+=dx*f;e.s.vy+=dy*f;e.d.vx-=dx*f;e.d.vy-=dy*f;});
    N.forEach(n=>{n.vx+=(n.ax-n.x)*.09*a;n.vy+=(n.ay-n.y)*.09*a;
      if(n.fx!=null){n.x=n.fx;n.y=n.fy;n.vx=n.vy=0;return;}
      const sp=Math.hypot(n.vx,n.vy);if(sp>24){n.vx*=24/sp;n.vy*=24/sp;}
      n.x+=n.vx;n.y+=n.vy;n.vx*=.58;n.vy*=.58;if(!isFinite(n.x)||!isFinite(n.y)){n.x=n.ax;n.y=n.ay;n.vx=n.vy=0;}});
    sim.alpha=pre?a*.985:a*.965;
  }
  function layoutFocus(){
    const c=byId.get(MAPS.focusId||MAPS.sel)&&nset.has(MAPS.focusId||MAPS.sel)?byId.get(MAPS.focusId||MAPS.sel):nodes.filter(n=>(n.cat===3||n.cat===5)&&n.deg<60).sort((a,b)=>b.deg-a.deg||String(a.label).localeCompare(String(b.label)))[0]||nodes.slice().sort((a,b)=>b.deg-a.deg)[0];
    if(!c)return;MAPS.focusId=c.id;
    const dist=new Map([[c.id,0]]),q=[c];
    while(q.length){const n=q.shift(),d=dist.get(n.id);if(d>=3)continue;adj.get(n.id).forEach(x=>{if(!dist.has(x.n.id)){dist.set(x.n.id,d+1);q.push(x.n);}});}
    const rings=[[],[],[],[]];dist.forEach((d,id)=>rings[d].push(byId.get(id)));
    nodes.forEach(n=>{n.focusOut=!dist.has(n.id);});
    rings.forEach((rg,d)=>{if(!d){c.tx=0;c.ty=0;return;}
      rg.sort((a,b)=>a.cat-b.cat||String(a.label).localeCompare(String(b.label)));
      const rad=Math.max(130*d,rg.length*(d===1?15:11)/(2*Math.PI)+60*d);
      rg.forEach((n,i)=>{const a=-Math.PI/2+i*2*Math.PI/rg.length;n.tx=Math.cos(a)*rad;n.ty=Math.sin(a)*rad;});});
    /* everything beyond three hops parks far out, faded */
    nodes.filter(n=>n.focusOut).forEach((n,i,arr)=>{const a=i*2*Math.PI/arr.length,r=520+Math.sqrt(arr.length)*12;n.tx=Math.cos(a)*r;n.ty=Math.sin(a)*r;});
  }
  function layout(){
    nodes.forEach(n=>{n.focusOut=false;});
    if(MAPS.mode==="flow")layoutFlow();else if(MAPS.mode==="focus")layoutFocus();else layoutForce();
  }

  /* ---- camera ---- */
  let W=1,H=1,dpr=window.devicePixelRatio||1,T={x:0,y:0,k:1},dirty=true,anim=null;
  const resize=()=>{const r=wrap.getBoundingClientRect();W=Math.max(200,r.width);H=Math.max(200,r.height);dpr=window.devicePixelRatio||1;cv.width=W*dpr;cv.height=H*dpr;dirty=true;};
  const bounds=()=>{let a=1e9,b=1e9,c2=-1e9,d=-1e9;const list=MAPS.mode==="focus"?nodes.filter(n=>!n.focusOut):nodes;list.forEach(n=>{a=Math.min(a,n.tx);b=Math.min(b,n.ty);c2=Math.max(c2,n.tx);d=Math.max(d,n.ty);});return list.length?{x0:a,y0:b,x1:c2,y1:d}:{x0:-100,y0:-100,x1:100,y1:100};};
  function fit(animate){
    const b=bounds(),pad=80,sw=Math.max(1,b.x1-b.x0),sh=Math.max(1,b.y1-b.y0);
    const k=Math.max(.05,Math.min(2.2,Math.min((W-pad*2)/sw,(H-pad*2)/sh)));
    const to={k,x:W/2-(b.x0+sw/2)*k,y:H/2-(b.y0+sh/2)*k};
    if(animate){anim={from:{...T},to,t0:performance.now(),dur:420};}else{T=to;}dirty=true;
  }
  const toWorld=(px,py)=>({x:(px-T.x)/T.k,y:(py-T.y)/T.k});
  function zoomAt(f,px,py){const k=Math.max(.05,Math.min(6,T.k*f)),w=toWorld(px,py);T={k,x:px-w.x*k,y:py-w.y*k};dirty=true;}
  function flyTo(n){const k=Math.max(T.k,1.2);anim={from:{...T},to:{k,x:W/2-n.tx*k,y:H/2-n.ty*k},t0:performance.now(),dur:480};dirty=true;}

  /* ---- highlight state ---- */
  let hover=null,hl=null,pathSet=null,pathEdges=null,dash=0;
  function nbrSet(id){const s=new Set([id]);(adj.get(id)||[]).forEach(x=>s.add(x.n.id));return s;}
  function setPath(a,b){
    if(!a||!b||a===b){MAPS.path=null;return;}
    const prev=new Map([[a,null]]),q=[a];
    while(q.length&&!prev.has(b)){const id=q.shift();(adj.get(id)||[]).forEach(x=>{if(!prev.has(x.n.id)){prev.set(x.n.id,id);q.push(x.n.id);}});}
    if(!prev.has(b)){MAPS.path={from:a,to:b,ids:null};return;}
    const ids=[];for(let c=b;c!=null;c=prev.get(c))ids.push(c);ids.reverse();MAPS.path={from:a,to:b,ids};
  }
  function recompute(){
    const q=((($("#msq")||{}).value)||"").trim().toLowerCase();
    hl=q?new Set(nodes.filter(n=>String(n.label).toLowerCase().includes(q)).map(n=>n.id)):null;
    pathSet=null;pathEdges=null;
    if(MAPS.path&&MAPS.path.ids){pathSet=new Set(MAPS.path.ids);pathEdges=new Set();for(let i=0;i<MAPS.path.ids.length-1;i++){pathEdges.add(MAPS.path.ids[i]+">"+MAPS.path.ids[i+1]);pathEdges.add(MAPS.path.ids[i+1]+">"+MAPS.path.ids[i]);}}
  }

  /* ---- drawing ---- */
  function draw(now){
    ctx.setTransform(dpr,0,0,dpr,0,0);ctx.clearRect(0,0,W,H);
    const focusId=hover||MAPS.sel,fs=pathSet||(focusId?nbrSet(focusId):null);
    const dimmed=(id)=>(hl&&!hl.has(id))||(fs&&!fs.has(id)&&!hl)||(MAPS.mode==="focus"&&byId.get(id).focusOut&&!hl);
    const sx=n=>n.x*T.k+T.x,sy=n=>n.y*T.k+T.y;
    /* edges */
    const vx0=-40,vy0=-40,vx1=W+40,vy1=H+40;
    for(const pass of [0,1]){
      for(const e of edges){
        const hi=pathEdges?pathEdges.has(e.s.id+">"+e.d.id):(focusId&&(e.s.id===focusId||e.d.id===focusId));
        if((pass===1)!==!!hi)continue;
        const ax=sx(e.s),ay=sy(e.s),bx=sx(e.d),by=sy(e.d);
        if((ax<vx0&&bx<vx0)||(ax>vx1&&bx>vx1)||(ay<vy0&&by<vy0)||(ay>vy1&&by>vy1))continue;
        const dim=!hi&&(dimmed(e.s.id)||dimmed(e.d.id));
        const base=e.state==="INFERRED"?C.inferred:e.state==="EXTERNAL"?C.l6:C.observed;
        ctx.globalAlpha=hi?1:dim?.04:Math.max(.035,(e.state==="OBSERVED"?.38:.42)*Math.pow(Math.min(1,3.2/Math.sqrt(Math.max(e.s.deg,e.d.deg))),1.5));
        ctx.strokeStyle=hi?(pathEdges?C.signal:base):base;ctx.lineWidth=hi?(pathEdges?2.6:1.9):1;
        ctx.setLineDash(e.state==="INFERRED"?[5,4]:e.state==="EXTERNAL"?[1.5,4]:hi?[7,5]:[]);
        if(hi)ctx.lineDashOffset=-dash;else ctx.lineDashOffset=0;
        ctx.beginPath();
        if(MAPS.mode==="flow"){const sg=bx>=ax?1:-1,dx=Math.max(30,Math.abs(bx-ax)*.4);ctx.moveTo(ax,ay);ctx.bezierCurveTo(ax+sg*dx,ay,bx-sg*dx,by,bx,by);}
        else{const mx=(ax+bx)/2,my=(ay+by)/2,nx=-(by-ay)*.09,ny=(bx-ax)*.09;ctx.moveTo(ax,ay);ctx.quadraticCurveTo(mx+nx,my+ny,bx,by);}
        ctx.stroke();
        if(hi||T.k>1.4){ /* direction */
          const ang=Math.atan2(by-ay,bx-ax),rr=R(e.d)*T.k+3;
          if(Math.hypot(bx-ax,by-ay)>rr*2.5){const px=bx-Math.cos(ang)*rr,py=by-Math.sin(ang)*rr;ctx.setLineDash([]);ctx.fillStyle=ctx.strokeStyle;
            ctx.beginPath();ctx.moveTo(px,py);ctx.lineTo(px-Math.cos(ang-.45)*8,py-Math.sin(ang-.45)*8);ctx.lineTo(px-Math.cos(ang+.45)*8,py-Math.sin(ang+.45)*8);ctx.closePath();ctx.fill();}}
      }
    }
    ctx.setLineDash([]);ctx.globalAlpha=1;
    /* neighbourhoods: a soft bubble and a name behind each group */
    if(MAPS.mode==="force"&&MAPS.clusters&&!hl){
      ctx.textAlign="center";ctx.textBaseline="middle";const lb=[];
      for(const c of MAPS.clusters.slice().sort((x,y)=>y.g.length-x.g.length)){let mx=0,my=0;for(const n of c.g){mx+=n.x;my+=n.y;}mx/=c.g.length;my/=c.g.length;
        let rad=0;for(const n of c.g)rad=Math.max(rad,Math.hypot(n.x-mx,n.y-my)+R(n)+10);
        const cx=mx*T.k+T.x,cy=my*T.k+T.y,rr=rad*T.k;
        if(cx+rr<0||cy+rr<0||cx-rr>W||cy-rr>H)continue;
        if(c.g.length>=2){ctx.globalAlpha=fs?.5:1;ctx.beginPath();ctx.arc(cx,cy,rr,0,7);ctx.fillStyle=CAT[c.cat]._c;ctx.globalAlpha=(fs?.03:.075);ctx.fill();ctx.globalAlpha=fs?.12:.28;ctx.lineWidth=1;ctx.strokeStyle=CAT[c.cat]._c;ctx.setLineDash([2,5]);ctx.stroke();ctx.setLineDash([]);}
        const fs2=Math.max(10,Math.min(18,9+rr/16));
        const txt=c.name.toUpperCase()+(c.g.length>1?"  "+c.g.length:"");ctx.font=`700 ${fs2}px Inter,system-ui,sans-serif`;
        const w=ctx.measureText(txt).width,bx=[cx-w/2-3,cy-rr-fs2*.9-fs2/2,cx+w/2+3,cy-rr-fs2*.9+fs2/2];
        if(lb.some(q=>!(bx[2]<q[0]||bx[0]>q[2]||bx[3]<q[1]||bx[1]>q[3])))continue;lb.push(bx);
        ctx.globalAlpha=fs?.14:.75;ctx.fillStyle=CAT[c.cat]._c;ctx.fillText(txt,cx,cy-rr-fs2*.9);}
      ctx.textAlign="start";ctx.globalAlpha=1;
    }
    /* nodes */
    const order=nodes.slice().sort((a,b)=>(dimmed(a.id)?0:1)-(dimmed(b.id)?0:1)||a.deg-b.deg);
    const labels=[];
    for(const n of order){
      const x=sx(n),y=sy(n);if(x<-30||y<-30||x>W+30||y>H+30)continue;
      const r=R(n)*T.k,dim=dimmed(n.id),isSel=MAPS.sel===n.id,isHov=hover===n.id,match=hl&&hl.has(n.id);
      const cat=CAT[n.cat],ep=EPBY[n.id],ghost=ep&&ep.state==="STATIC_ONLY";
      ctx.globalAlpha=dim?.14:1;
      ctx.save();ctx.translate(x,y);
      if(isSel||isHov||match){ctx.beginPath();ctx.arc(0,0,r*1.15+7,0,7);ctx.fillStyle=cat._c;ctx.globalAlpha=(dim?.14:1)*.22;ctx.fill();ctx.globalAlpha=dim?.14:1;}
      const p=P2(cat.shape,Math.max(2.5,r));
      if(ghost){ctx.fillStyle=C.panel;ctx.fill(p);ctx.setLineDash([3,2.5]);ctx.lineWidth=1.8;ctx.strokeStyle=C.signal;ctx.stroke(p);ctx.setLineDash([]);}
      else{ctx.fillStyle=cat._c;ctx.fill(p);ctx.lineWidth=isSel?3:1.6;ctx.strokeStyle=isSel||match?C.signal:C.panel;ctx.stroke(p);}
      if(ep&&ep.privileged&&!ghost){ctx.beginPath();ctx.arc(r*.9,-r*.9,Math.max(2.2,r*.32),0,7);ctx.fillStyle=C.signal;ctx.fill();}
      ctx.restore();
      if(!dim||match)labels.push({n,x,y,r,pri:(isSel?1e6:isHov?9e5:match?8e5:fs&&fs.has(n.id)?5e5:0)+n.deg});
    }
    ctx.globalAlpha=1;
    /* labels: busiest first, never overlapping */
    labels.sort((a,b)=>b.pri-a.pri);
    const placed=[],showAll=T.k>=(MAPS.mode==="flow"?.42:1.05),hubCut=Math.max(4,nodes.map(n=>n.deg).sort((a,b)=>b-a)[Math.floor(nodes.length*.08)]||4);
    ctx.font=`${T.k>2?12:11}px ui-monospace,SFMono-Regular,Menlo,Consolas,monospace`;ctx.textBaseline="middle";
    for(const L of labels){
      const force=L.pri>=1e5;if(!force&&!showAll&&L.n.deg<hubCut)continue;
      let t=String(L.n.label||"");if(t.length>(force?60:30))t=t.slice(0,(force?59:29))+"…";
      const w=ctx.measureText(t).width,x0=L.x+L.r+5,y0=L.y-7,box=[x0-2,y0,x0+w+2,y0+14];
      if(!force&&placed.some(b=>!(box[2]<b[0]||box[0]>b[2]||box[3]<b[1]||box[1]>b[3])))continue;
      placed.push(box);
      ctx.lineWidth=3.5;ctx.strokeStyle=C.ink;ctx.lineJoin="round";ctx.strokeText(t,x0,L.y);
      ctx.fillStyle=L.pri>=5e5?C.text:C.muted;ctx.fillText(t,x0,L.y);
    }
    $("#mhud").textContent=`${nodes.length} nodes · ${edges.length} edges · ${Math.round(T.k*100)}%`;
    drawMini();
  }
  function drawMini(){
    const mw=mini.width,mh=mini.height;mctx.clearRect(0,0,mw,mh);
    const b=bounds(),pad=14,sw=Math.max(1,b.x1-b.x0),sh=Math.max(1,b.y1-b.y0),k=Math.min((mw-pad*2)/sw,(mh-pad*2)/sh);
    const ox=(mw-sw*k)/2-b.x0*k,oy=(mh-sh*k)/2-b.y0*k;mini._m={k,ox,oy};
    nodes.forEach(n=>{mctx.fillStyle=CAT[n.cat]._c;mctx.globalAlpha=.85;mctx.fillRect(n.tx*k+ox-1.5,n.ty*k+oy-1.5,3,3);});
    mctx.globalAlpha=1;
    const a=toWorld(0,0),c2=toWorld(W,H);
    mctx.strokeStyle=C.signal;mctx.lineWidth=2;mctx.strokeRect(a.x*k+ox,a.y*k+oy,(c2.x-a.x)*k,(c2.y-a.y)*k);
  }
  /* ---- frame loop: only runs while something moves ---- */
  function frame(now){
    if(!document.body.contains(cv)){themeObs.disconnect();return;}
    let moving=false;
    if(anim){const t=Math.min(1,(now-anim.t0)/anim.dur),e=1-Math.pow(1-t,3);T={k:anim.from.k+(anim.to.k-anim.from.k)*e,x:anim.from.x+(anim.to.x-anim.from.x)*e,y:anim.from.y+(anim.to.y-anim.from.y)*e};if(t>=1)anim=null;moving=true;}
    if(MAPS.sim&&MAPS.sim.alpha>.02){tick(MAPS.sim,false);nodes.forEach(n=>{n.tx=n.x;n.ty=n.y;});moving=true;}
    else for(const n of nodes){if(n.fx!=null)continue;const dx=n.tx-n.x,dy=n.ty-n.y;if(Math.abs(dx)>.15||Math.abs(dy)>.15){n.x+=dx*.22;n.y+=dy*.22;moving=true;}else{n.x=n.tx;n.y=n.ty;}}
    const animating=!!(pathEdges||MAPS.sel||hover);
    if(animating){dash=(dash+.35)%24;}
    if(dirty||moving||animating){draw(now);dirty=false;}
    MAPS.raf=requestAnimationFrame(frame);
  }

  /* ---- picking and interaction ---- */
  function pick(px,py){
    let best=null,bd=1e9;
    for(const n of nodes){if(MAPS.mode==="focus"&&n.focusOut)continue;const dx=n.x*T.k+T.x-px,dy=n.y*T.k+T.y-py,d=dx*dx+dy*dy,r=Math.max(7,R(n)*T.k+3);if(d<r*r&&d<bd){bd=d;best=n;}}
    return best;
  }
  let down=null,dragN=null,moved=false;
  cv.addEventListener("pointerdown",ev=>{const r=cv.getBoundingClientRect(),px=ev.clientX-r.left,py=ev.clientY-r.top,n=pick(px,py);
    down={px,py,tx:T.x,ty:T.y,n};moved=false;cv.setPointerCapture(ev.pointerId);anim=null;
    if(n){dragN=n;}else cv.classList.add("drag");});
  cv.addEventListener("pointermove",ev=>{const r=cv.getBoundingClientRect(),px=ev.clientX-r.left,py=ev.clientY-r.top;
    if(down){const dx=px-down.px,dy=py-down.py;if(Math.abs(dx)+Math.abs(dy)>3)moved=true;
      if(dragN&&moved){const w=toWorld(px,py);dragN.x=dragN.tx=w.x;dragN.y=dragN.ty=w.y;if(MAPS.mode==="force"&&MAPS.sim){dragN.fx=w.x;dragN.fy=w.y;MAPS.sim.alpha=Math.max(MAPS.sim.alpha,.25);}dirty=true;}
      else if(!dragN&&moved){T.x=down.tx+dx;T.y=down.ty+dy;dirty=true;}
      return;}
    const n=pick(px,py);if((n&&n.id)!==hover){hover=n?n.id:null;dirty=true;cv.classList.toggle("hit",!!n);}
    if(n){const ep=EPBY[n.id];tip.style.display="block";tip.style.left=Math.min(W-300,px+14)+"px";tip.style.top=Math.min(H-70,py+14)+"px";
      tip.innerHTML=`<b>${esc(n.label)}</b><span>${esc(KIND_LABEL[n.type]||humanize(n.type))}${ep?" · "+esc(ep.state||""):""}${n.deg?" · "+n.deg+" link"+(n.deg===1?"":"s"):""}</span>`;}
    else tip.style.display="none";});
  cv.addEventListener("pointerup",ev=>{
    if(dragN){dragN.fx=dragN.fy=null;if(!moved){if(ev.shiftKey&&MAPS.sel&&MAPS.sel!==dragN.id){setPath(MAPS.sel,dragN.id);}else{MAPS.path=null;MAPS.sel=dragN.id;if(MAPS.mode==="focus"){MAPS.focusId=dragN.id;layout();fit(true);}}recompute();inspector();dirty=true;}}
    else if(down&&!moved){MAPS.sel=null;MAPS.path=null;recompute();inspector();dirty=true;}
    down=null;dragN=null;cv.classList.remove("drag");});
  cv.addEventListener("pointerleave",()=>{hover=null;tip.style.display="none";dirty=true;});
  cv.addEventListener("wheel",ev=>{ev.preventDefault();const r=cv.getBoundingClientRect();zoomAt(ev.deltaY<0?1.15:1/1.15,ev.clientX-r.left,ev.clientY-r.top);},{passive:false});
  cv.addEventListener("dblclick",ev=>{const r=cv.getBoundingClientRect(),n=pick(ev.clientX-r.left,ev.clientY-r.top);if(n){MAPS.mode="focus";MAPS.focusId=n.id;MAPS.sel=n.id;mapSave();render();}else fit(true);});
  mini.addEventListener("pointerdown",ev=>{const r=mini.getBoundingClientRect(),m=mini._m;if(!m)return;const mx=(ev.clientX-r.left)*(mini.width/r.width),my=(ev.clientY-r.top)*(mini.height/r.height);
    const wx=(mx-m.ox)/m.k,wy=(my-m.oy)/m.k;anim={from:{...T},to:{k:T.k,x:W/2-wx*T.k,y:H/2-wy*T.k},t0:performance.now(),dur:300};dirty=true;});
  $$("[data-z]",wrap).forEach(b=>b.onclick=()=>{const k=b.dataset.z;if(k==="fit")fit(true);else zoomAt(k==="in"?1.3:1/1.3,W/2,H/2);});
  $("#mapx").addEventListener("keydown",ev=>{if(ev.target.tagName==="INPUT")return;
    if(ev.key==="f"||ev.key==="F")fit(true);else if(ev.key==="Escape"){MAPS.sel=null;MAPS.path=null;recompute();inspector();dirty=true;}
    else if(ev.key==="+"||ev.key==="=")zoomAt(1.2,W/2,H/2);else if(ev.key==="-")zoomAt(1/1.2,W/2,H/2);});

  /* ---- toolbar ---- */
  $$("[data-layer]").forEach(b=>b.onclick=()=>{const k=b.dataset.layer;MAPS.hidden.has(k)?MAPS.hidden.delete(k):MAPS.hidden.add(k);mapSave();MAPS.sel=MAPS.path=null;render();});
  $$("[data-es]").forEach(b=>b.onclick=()=>{const k=b.dataset.es;MAPS.edgeOff.has(k)?MAPS.edgeOff.delete(k):MAPS.edgeOff.add(k);mapSave();render();});
  $$("[data-mode]").forEach(b=>b.onclick=()=>{if(MAPS.mode!==b.dataset.mode){MAPS.mode=b.dataset.mode;if(MAPS.mode==="focus"&&MAPS.sel)MAPS.focusId=MAPS.sel;mapSave();render();}});
  $("#mpng").onclick=()=>{const c=document.createElement("canvas");c.width=cv.width*2;c.height=cv.height*2;const x=c.getContext("2d");x.fillStyle=C.ink;x.fillRect(0,0,c.width,c.height);x.drawImage(cv,0,0,c.width,c.height);c.toBlob(b=>{const u=URL.createObjectURL(b),a=document.createElement("a");a.href=u;a.download=(D.app||"model")+".map.png";a.click();URL.revokeObjectURL(u);});};
  /* search with suggestions */
  const sq=$("#msq"),sg=$("#msug");let sgi=0,sgl=[];
  function suggest(){const q=sq.value.trim().toLowerCase();recompute();dirty=true;if(!q){sg.hidden=true;return;}
    sgl=nodes.filter(n=>String(n.label).toLowerCase().includes(q)).sort((a,b)=>String(a.label).toLowerCase().indexOf(q)-String(b.label).toLowerCase().indexOf(q)||b.deg-a.deg).slice(0,8);sgi=0;
    sg.hidden=!sgl.length;sg.innerHTML=sgl.map((n,i)=>`<button data-i="${i}" class="${i?"":"on"}"><span class="sw" style="width:8px;height:8px;border-radius:2px;background:${CAT[n.cat]._c}"></span><span style="overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${esc(n.label)}</span><span class="k">${esc(n.type)}</span></button>`).join("");
    $$("button",sg).forEach(b=>b.onmousedown=e=>{e.preventDefault();choose(sgl[+b.dataset.i]);});}
  function choose(n){if(!n)return;sg.hidden=true;MAPS.sel=n.id;MAPS.path=null;if(MAPS.mode==="focus"){MAPS.focusId=n.id;layout();fit(true);}else flyTo(n);recompute();inspector();dirty=true;}
  sq.addEventListener("input",suggest);sq.addEventListener("blur",()=>setTimeout(()=>sg.hidden=true,120));
  sq.addEventListener("keydown",e=>{if(e.key==="Enter"){e.preventDefault();choose(sgl[sgi]);}else if(e.key==="ArrowDown"||e.key==="ArrowUp"){e.preventDefault();sgi=(sgi+(e.key==="ArrowDown"?1:-1)+sgl.length)%Math.max(1,sgl.length);$$("button",sg).forEach((b,i)=>b.classList.toggle("on",i===sgi));}else if(e.key==="Escape"){sq.value="";suggest();}});

  /* ---- inspector ---- */
  const invKey=n=>{const ep=EPBY[n.id];if(ep&&ep.state!=="STATIC_ONLY")return(ep.host||"")+(ep.path||"").replace(/\/$/,"");if(n.type==="route")return n.id.replace(/^route:/,"").replace(/\/$/,"");if(n.type==="host")return n.label;return null;};
  function inspector(){
    const el=$("#minsp"),n=MAPS.sel?byId.get(MAPS.sel):null;
    if(!n||!nset.has(n.id)){
      const hubs=nodes.slice().sort((a,b)=>b.deg-a.deg).slice(0,8);
      const cnt=CAT.map((c,i)=>[c,nodes.filter(x=>x.cat===i).length]).filter(x=>x[1]);
      el.innerHTML=`<h3>This map</h3><div class="nrows"><div class="k">Nodes</div><div class="v">${nodes.length}</div><div class="k">Edges</div><div class="v">${edges.length}</div>
        <div class="k">Seen in traffic</div><div class="v">${edges.filter(e=>e.state==="OBSERVED").length}</div><div class="k">Found in code</div><div class="v">${edges.filter(e=>e.state==="INFERRED").length}</div>
        ${edges.some(e=>e.state==="EXTERNAL")?`<div class="k">From recon</div><div class="v">${edges.filter(e=>e.state==="EXTERNAL").length}</div>`:""}</div>
       <h3>Most connected</h3>${hubs.map(h=>`<div class="hubrow" data-pick="${esc(h.id)}"><span class="s" style="width:9px;height:9px;border-radius:2px;background:${CAT[h.cat]._c};flex:none"></span><span class="t">${esc(h.label)}</span><span class="d">${h.deg}</span></div>`).join("")}
       <h3>How to read it</h3><div class="tips">Hover a node to trace what it touches. <b>Click</b> to inspect it. <kbd>Shift</kbd>+click a second node to trace the shortest path between them. <b>Double-click</b> a node to focus on it. Drag a node to move it. Scroll to zoom, <kbd>F</kbd> to fit.<br>Solid lines were seen in traffic, dashed lines were found in the code, dotted lines come from recon. A dashed hollow node is an endpoint the code names but no request reached.</div>`;
      $$("[data-pick]",el).forEach(r=>r.onclick=()=>choose(byId.get(r.dataset.pick)));return;
    }
    const ep=EPBY[n.id],cat=CAT[n.cat];
    const groups={};(adj.get(n.id)||[]).forEach(x=>{const k=(x.out?"→ ":"← ")+x.e.type+"|"+x.e.state;(groups[k]=groups[k]||[]).push(x.n);});
    const rows=[];
    if(ep){rows.push(["State",ep.state==="BOTH"?"seen in code and traffic":ep.state==="STATIC_ONLY"?"in code, never called":"traffic only"]);if(ep.statuses.length)rows.push(["Statuses",ep.statuses.join(", ")]);rows.push(["Requests",ep.requests]);if(ep.params.length)rows.push(["Parameters",ep.params.length]);if(ep.roles.length)rows.push(["Roles",ep.roles.join(", ")]);if(ep.credentials.length)rows.push(["Credentials",ep.credentials.join(", ")]);if(ep.privileged)rows.push(["Note","privileged-looking path"]);}
    else if(n.state)rows.push(["State",n.state]);
    if((n.evidence||[]).length)rows.push(["Evidence",n.evidence.slice(0,4).map(EVD).join(", ")+(n.evidence.length>4?" …":"")]);
    if(n.detail)rows.push(["Detail",n.detail]);
    const path=MAPS.path;
    el.innerHTML=`<div class="nh"><span class="ic" style="color:${cat._c}"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="${ICON[n.type]||ICON.endpoint}"/></svg></span><span class="kind">${esc(KIND_LABEL[n.type]||humanize(n.type))}</span></div>
      <div class="nlabel">${esc(n.label)}</div>
      <div class="nrows">${rows.map(([k,v])=>`<div class="k">${esc(k)}</div><div class="v">${esc(v)}</div>`).join("")}<div class="k">Links</div><div class="v">${n.deg}</div></div>
      <div class="nact"><button class="mbtn" id="nfocus">Focus</button>${ep||(n.evidence||[]).length?`<button class="mbtn" id="ndet">Details</button>`:""}${BQLDB?`<button class="mbtn" id="nreach">Query reach</button>`:""}${invKey(n)!=null?`<button class="mbtn" id="ninv">Inventory</button>`:""}</div>
      ${path?`<div class="pathbox"><div class="pt">Shortest path</div>${path.ids?path.ids.map((id,i)=>`<div class="conn" data-pick="${esc(id)}"><span class="a">${i?"↳":"●"}</span><span class="t">${esc((byId.get(id)||{}).label||id)}</span></div>`).join(""):`<span style="font-size:12.5px;color:var(--muted)">No path between these two nodes with the current filters.</span>`}</div>`:""}
      ${Object.keys(groups).sort().map(k=>{const [lab,st]=k.split("|");const cls=st==="INFERRED"?"in":st==="EXTERNAL"?"ex":"ob";return `<div class="ghd"><span>${esc(lab.replace(/_/g," ").toLowerCase())}</span><span class="st ${cls}">${st==="INFERRED"?"code":st==="EXTERNAL"?"recon":"traffic"}</span><span>${groups[k].length}</span></div>${groups[k].slice(0,30).map(m=>`<div class="conn" data-pick="${esc(m.id)}"><span class="s" style="background:${CAT[m.cat]._c}"></span><span class="t">${esc(m.label)}</span></div>`).join("")}${groups[k].length>30?`<div class="conn"><span class="t" style="color:var(--faint)">+${groups[k].length-30} more</span></div>`:""}`;}).join("")}`;
    $$("[data-pick]",el).forEach(r=>r.onclick=()=>choose(byId.get(r.dataset.pick)));
    const f=$("#nfocus");if(f)f.onclick=()=>{MAPS.mode="focus";MAPS.focusId=n.id;mapSave();render();};
    const d=$("#ndet");if(d)d.onclick=()=>openNode(n.id);
    const r=$("#nreach");if(r)r.onclick=()=>{if(BQLDB){qRun(`reach "${n.label.replace(/"/g,'\\"')}"`);view="query";render();}};
    const iv=$("#ninv");if(iv)iv.onclick=()=>{INV.node=invKey(n);INV.q="";INV.sel=null;view="inventory";render();};
  }

  /* ---- go ---- */
  resize();layout();
  nodes.forEach(n=>{n.x=n.tx;n.y=n.ty;});
  if(MAPS.mode==="focus"&&!MAPS.sel&&MAPS.focusId==null){}
  fit(false);recompute();inspector();
  if(MAPS.sel&&nset.has(MAPS.sel)&&MAPS.mode!=="focus"){}
  new ResizeObserver(()=>{resize();}).observe(wrap);
  MAPS.dbg=()=>({T,nodes,W,H});
  MAPS.raf=requestAnimationFrame(frame);
  if(!nodes.length){$("#mhud").textContent="Every layer is hidden. Turn one back on above.";}
}
"""
