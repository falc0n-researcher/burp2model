/* burp2model site — theme, copy buttons, terminal, scrollspy. No dependencies. */
(function () {
  "use strict";
  var root = document.documentElement;
  root.classList.remove("no-js");
  var reduced = window.matchMedia && window.matchMedia("(prefers-reduced-motion: reduce)").matches;

  function store(k, v) { try { if (v === undefined) return localStorage.getItem(k); localStorage.setItem(k, v); } catch (e) { return null; } }

  /* ---- theme ---- */
  var saved = store("b2m-theme");
  if (saved === "light" || saved === "dark") root.setAttribute("data-theme", saved);
  document.querySelectorAll(".theme-toggle").forEach(function (btn) {
    btn.addEventListener("click", function () {
      var cur = root.getAttribute("data-theme");
      if (!cur) cur = window.matchMedia("(prefers-color-scheme: light)").matches ? "light" : "dark";
      var next = cur === "light" ? "dark" : "light";
      root.setAttribute("data-theme", next);
      store("b2m-theme", next);
    });
  });

  /* ---- copy buttons ---- */
  document.querySelectorAll("[data-copy]").forEach(function (btn) {
    btn.addEventListener("click", function () {
      var sel = btn.getAttribute("data-copy");
      var src = sel ? document.querySelector(sel) : btn.parentElement.querySelector("pre, code");
      var text = src ? src.innerText.replace(/^\$ /gm, "") : "";
      var done = function () {
        btn.classList.add("done");
        btn.setAttribute("aria-label", "Copied");
        setTimeout(function () { btn.classList.remove("done"); btn.setAttribute("aria-label", "Copy"); }, 1400);
      };
      if (navigator.clipboard) navigator.clipboard.writeText(text).then(done, function () {});
    });
  });

  /* ---- reveal on scroll ---- */
  var reveals = document.querySelectorAll(".reveal");
  if ("IntersectionObserver" in window && !reduced) {
    var io = new IntersectionObserver(function (entries) {
      entries.forEach(function (e) { if (e.isIntersecting) { e.target.classList.add("in"); io.unobserve(e.target); } });
    }, { rootMargin: "0px 0px -8% 0px" });
    reveals.forEach(function (el) { io.observe(el); });
  } else {
    reveals.forEach(function (el) { el.classList.add("in"); });
  }

  /* ---- hero terminal: a real build of samples/burp-history-sample.xml ---- */
  var term = document.getElementById("term-out");
  if (term) {
    var script = [
      ["cmd", "burp2model user.xml  -w shop --role user"],
      ["cmd", "burp2model admin.xml -w shop --role admin"],
      ["line", "  <span class=c-dim>▸</span> parsing burp export   <span class=c-dim>stream + base64-decode</span>"],
      ["line", "  <span class=c-dim>▸</span> redacting values      <span class=c-dim>values → fingerprints</span>"],
      ["line", "  <span class=c-dim>▸</span> typing assets         <span class=c-dim>routes · scripts · APIs</span>"],
      ["line", "  <span class=c-dim>▸</span> relating nodes        <span class=c-dim>OBSERVED vs INFERRED</span>"],
      ["line", "  <span class=c-dim>▸</span> reconciling           <span class=c-dim>code vs runtime</span>"],
      ["line", "  <span class=c-dim>▸</span> naming unknowns       <span class=c-dim>what we can't see</span>"],
      ["gap"],
      ["line", "  <span class=c-cyan>routes 3 · APIs 10 · edges 71</span>"],
      ["line", "  <span class=c-cyan>6 both · 3 runtime-only ·</span> <span class=c-brand>1 static-only ← look here</span>"],
      ["line", "  <span class=c-vio>11 named unknowns</span>  <span class=c-dim>absence = a gap in observation</span>"],
      ["gap"],
      ["cmd", "burp2model cross-role shop --low user --high admin"],
      ["line", "'user' reached privileged-looking endpoints (1)"],
      ["line", "  <span class=c-brand>GET /api/admin/users</span>   user=<span class=c-brand>[403]</span> admin=<span class=c-ok>[200]</span>"],
      ["line", "'admin' reached, 'user' never tried (2)"],
      ["line", "  <span class=c-brand>GET /api/admin/audit</span>   admin=[200]  <span class=c-dim>← the static-only one</span>"],
      ["line", "<span class=c-dim>Each is a hypothesis, not a finding.</span>"]
    ];
    var out = "";
    var render = function (extra) { term.innerHTML = out + (extra || "") + '<span class="cursor"></span>'; };
    if (reduced) {
      script.forEach(function (s) {
        if (s[0] === "cmd") out += '<span class="c-prompt">$</span> ' + s[1] + "\n";
        else if (s[0] === "line") out += s[1] + "\n";
        else out += "\n";
      });
      render();
    } else {
      var i = 0;
      var next = function () {
        if (i >= script.length) {
          setTimeout(function () { out = ""; i = 0; next(); }, 6000);
          return;
        }
        var s = script[i++];
        if (s[0] === "cmd") {
          var j = 0, text = s[1];
          var type = function () {
            render('<span class="c-prompt">$</span> ' + text.slice(0, j));
            if (j++ < text.length) setTimeout(type, 26 + Math.random() * 30);
            else { out += '<span class="c-prompt">$</span> ' + text + "\n"; setTimeout(next, 380); }
          };
          type();
        } else {
          out += s[0] === "line" ? s[1] + "\n" : "\n";
          render();
          setTimeout(next, s[0] === "gap" ? 120 : 190);
        }
      };
      var started = false;
      var start = function () { if (!started) { started = true; next(); } };
      if ("IntersectionObserver" in window) {
        var tio = new IntersectionObserver(function (e) { if (e[0].isIntersecting) { start(); tio.disconnect(); } });
        tio.observe(term);
      } else start();
    }
  }

  /* ---- docs: scrollspy + mobile sidebar ---- */
  var links = document.querySelectorAll(".sidebar a[href^='#']");
  if (links.length && "IntersectionObserver" in window) {
    var map = {};
    links.forEach(function (a) { map[a.getAttribute("href").slice(1)] = a; });
    var visible = {};
    var spy = new IntersectionObserver(function (entries) {
      entries.forEach(function (e) { visible[e.target.id] = e.isIntersecting; });
      var first = null;
      document.querySelectorAll(".doc-section[id]").forEach(function (s) { if (!first && visible[s.id]) first = s.id; });
      if (first && map[first]) {
        links.forEach(function (a) { a.classList.remove("active"); a.removeAttribute("aria-current"); });
        map[first].classList.add("active");
        map[first].setAttribute("aria-current", "true");
      }
    }, { rootMargin: "-80px 0px -55% 0px" });
    document.querySelectorAll(".doc-section[id]").forEach(function (s) { spy.observe(s); });
  }
  var st = document.querySelector(".side-toggle");
  if (st) {
    st.addEventListener("click", function () {
      var sb = document.querySelector(".sidebar");
      var open = sb.classList.toggle("open");
      st.setAttribute("aria-expanded", open ? "true" : "false");
    });
    document.querySelectorAll(".sidebar a").forEach(function (a) {
      a.addEventListener("click", function () {
        var sb = document.querySelector(".sidebar");
        if (window.innerWidth <= 880) { sb.classList.remove("open"); st.setAttribute("aria-expanded", "false"); }
      });
    });
  }

  /* ---- year ---- */
  document.querySelectorAll("[data-year]").forEach(function (el) { el.textContent = new Date().getFullYear(); });
})();
