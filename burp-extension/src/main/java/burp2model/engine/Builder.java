package burp2model.engine;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/** Builds the model from redacted exchanges: a port of model.build(). */
public final class Builder {
    private Builder() {}

    static final Pattern API_HINT = Pattern.compile("/(api|v\\d+|graphql|rest|gql)(/|$)", Pattern.CASE_INSENSITIVE);
    public static final Pattern PRIV_RE = Pattern.compile(
            "/(admin|administrator|internal|manage|management|config|privileged|superuser|staff|root|debug|actuator|console|backoffice|ops)(/|$)",
            Pattern.CASE_INSENSITIVE);
    /** Beacons and analytics calls: real traffic, but not a lead. */
    public static final Pattern TELEMETRY_RE = Pattern.compile(
            "/(collect|track|tracking|trackevents?|beacon|pixel|analytics|telemetry|gtag|gtm|ping|rum|csp-report)(/|$)", Pattern.CASE_INSENSITIVE);
    private static final Pattern STATIC_EXT = Pattern.compile(
            "\\.(?:png|jpe?g|gif|svg|ico|webp|avif|bmp|css|woff2?|ttf|otf|eot|map|mp4|webm|mp3|wav|pdf|zip)$", Pattern.CASE_INSENSITIVE);
    private static final Pattern PLACEHOLDER = Pattern.compile("\\{[^/{}]*\\}");
    private static final Pattern PROBE_PATH = Pattern.compile(
            "(?:\\.\\.[/\\\\]|\\.\\.%2f|\\.\\.%5c|%2e%2e|%252e|%00|%c0%ae|%c0%af|%0d%0a|%0a[a-z0-9]|\\\\x00"
                    + "|%2a%7e1|\\*~1|~1[/\\\\]"
                    + "|%25%7b|%24%7b|\\$\\{|%23_?member|ognl|jndi:"
                    + "|%3cscript|<script|union(?:%20|\\+|\\s)select"
                    + "|\\.(?:js|css|png|jpe?g|svg|ico|woff2?|map)/)", Pattern.CASE_INSENSITIVE);
    private static final Set<String> PROBE_METHODS = Set.of("TRACE", "DEBUG", "TRACK");
    private static final Pattern FILE_SEG = Pattern.compile("\\.[A-Za-z0-9]{1,6}$");
    private static final int SIBLING_STEM = 8;
    private static final int SIBLING_SHAPE = 12;

    // ------------------------------------------------------------------ scope

    static String bareHost(String host) {
        String h = host.toLowerCase().strip();
        if (h.startsWith("[")) {
            int e = h.indexOf(']');
            return e >= 0 ? h.substring(1, e) : h.substring(1);
        }
        if (h.chars().filter(c -> c == ':').count() > 1) {
            return h;
        }
        return h.split(":", 2)[0];
    }

    public static boolean inScope(String host, List<String> scope) {
        String h = bareHost(host);
        for (String s0 : scope) {
            String s = bareHost(s0);
            while (s.startsWith("*")) {
                s = s.substring(1);
            }
            while (s.startsWith(".")) {
                s = s.substring(1);
            }
            if (h.equals(s) || h.endsWith("." + s)) {
                return true;
            }
        }
        return false;
    }

    public static String matchKey(String path) {
        String key = PLACEHOLDER.matcher(path).replaceAll("{}");
        while (key.endsWith("/")) {
            key = key.substring(0, key.length() - 1);
        }
        return key.isEmpty() ? "/" : key;
    }

    // --------------------------------------------------------------- classify

    private static boolean isJs(Exchange ex) {
        String m = ex.mime.toLowerCase();
        return m.contains("script") || m.contains("ecmascript") || ex.pathTemplate.endsWith(".js") || ex.pathTemplate.endsWith(".mjs");
    }

    private static boolean isHtml(Exchange ex) {
        return ex.mime.toLowerCase().contains("html");
    }

    private static boolean isStaticAsset(Exchange ex) {
        String m = ex.mime.toLowerCase();
        return STATIC_EXT.matcher(ex.pathTemplate).find()
                || Set.of("css", "image", "gif", "jpeg", "png", "svg", "font", "woff", "woff2", "ico").contains(m);
    }

    private static boolean isApi(Exchange ex) {
        if (API_HINT.matcher(ex.pathTemplate).find()) {
            return true;
        }
        String m = ex.mime.toLowerCase();
        return m.equals("json") || m.equals("xml") || m.contains("json");
    }

    private static boolean isRedirect(Exchange ex) {
        return ex.status != null && ex.status >= 300 && ex.status < 400;
    }

    static String classify(Exchange ex) {
        if (ex.preflight) {
            return "preflight";
        }
        if (isJs(ex)) {
            return "script";
        }
        if (isStaticAsset(ex) && (ex.method.equals("GET") || ex.method.equals("HEAD"))) {
            return "asset";
        }
        if (!ex.method.equals("GET") && !ex.method.equals("HEAD")) {
            return "endpoint";
        }
        if (isHtml(ex)) {
            return "route";
        }
        if (isApi(ex) || (!ex.queryParams.isEmpty() && !isHtml(ex) && !isRedirect(ex))) {
            return "endpoint";
        }
        return "route";
    }

    public static boolean isProbe(Exchange ex) {
        if (ex.probe == null) {
            ex.probe = PROBE_METHODS.contains(ex.method) || PROBE_PATH.matcher(ex.path == null ? "" : ex.path).find();
        }
        return ex.probe;
    }

    // ------------------------------------------------------ slug collapsing

    private record Key(String host, String path) {}

    static int collapseSiblings(List<Exchange> exchanges) {
        Map<Key, Boolean> seen = new LinkedHashMap<>();
        for (Exchange ex : exchanges) {
            String last = ex.pathTemplate.substring(ex.pathTemplate.lastIndexOf('/') + 1);
            if (ex.method.equals("OPTIONS") || isProbe(ex) || FILE_SEG.matcher(last).find()) {
                continue;
            }
            seen.putIfAbsent(new Key(ex.host, ex.pathTemplate.split("\\?", 2)[0]), true);
        }
        Map<Key, List<String>> templates = new LinkedHashMap<>();
        int depth = 0;
        for (Key k : seen.keySet()) {
            List<String> segs = new ArrayList<>();
            for (String x : k.path().replaceAll("^/+|/+$", "").split("/")) {
                if (!x.isEmpty()) {
                    segs.add(x);
                }
            }
            templates.put(k, segs);
            depth = Math.max(depth, segs.size());
        }
        Map<Key, List<String>> cur = new LinkedHashMap<>();
        templates.forEach((k, v) -> cur.put(k, new ArrayList<>(v)));
        for (int d = 0; d < depth; d++) {
            Map<String, Set<String>> groups = new LinkedHashMap<>();       // host \0 prefix -> values
            // the paths in each group: a group's prefix (segments before d) is fixed while depth d is folded,
            // so looking a value's paths up here is the same as scanning every path, without the n^2
            Map<String, List<List<String>>> members = new HashMap<>();
            for (Map.Entry<Key, List<String>> e : cur.entrySet()) {
                List<String> segs = e.getValue();
                if (segs.size() > d) {
                    String gk = e.getKey().host() + "\u0000" + String.join("/", segs.subList(0, d));
                    groups.computeIfAbsent(gk, x -> new LinkedHashSet<>()).add(segs.get(d));
                    members.computeIfAbsent(gk, x -> new ArrayList<>()).add(segs);
                }
            }
            for (Map.Entry<String, Set<String>> g : groups.entrySet()) {
                List<List<String>> inGroup = members.get(g.getKey());
                Set<String> plain = new LinkedHashSet<>();
                for (String v : g.getValue()) {
                    if (!v.contains("{") && !FILE_SEG.matcher(v).find()) {
                        plain.add(v);
                    }
                }
                if (plain.size() < SIBLING_STEM) {
                    continue;
                }
                Map<String, String> fold = new LinkedHashMap<>();
                Map<String, List<String>> stems = new LinkedHashMap<>();
                for (String v : plain) {
                    if (v.contains("-")) {
                        stems.computeIfAbsent(v.substring(0, v.lastIndexOf('-')) + "-", x -> new ArrayList<>()).add(v);
                    }
                }
                for (Map.Entry<String, List<String>> s : stems.entrySet()) {
                    if (s.getValue().size() >= SIBLING_STEM && s.getKey().length() >= 6) {
                        for (String v : s.getValue()) {
                            fold.put(v, s.getKey() + "{slug}");
                        }
                    }
                }
                Set<String> rest = new LinkedHashSet<>(plain);
                rest.removeAll(fold.keySet());
                if (rest.size() >= SIBLING_SHAPE) {
                    Map<String, Set<String>> kidsOf = new HashMap<>();
                    for (List<String> segs : inGroup) {
                        if (segs.size() > d + 1) {
                            kidsOf.computeIfAbsent(segs.get(d), x -> new TreeSet<>()).add(segs.get(d + 1));
                        }
                    }
                    Map<String, Set<String>> shaped = new LinkedHashMap<>();
                    for (String v : rest) {
                        Set<String> kids = kidsOf.get(v);
                        if (kids != null) {
                            shaped.put(v, kids);
                        }
                    }
                    if (!shaped.isEmpty()) {
                        Map<Set<String>, Integer> counts = new LinkedHashMap<>();
                        shaped.values().forEach(ks -> counts.merge(ks, 1, Integer::sum));
                        Set<String> modal = null;
                        int best = -1;
                        for (Map.Entry<Set<String>, Integer> c : counts.entrySet()) {
                            if (c.getValue() > best) {
                                best = c.getValue();
                                modal = c.getKey();
                            }
                        }
                        List<String> same = new ArrayList<>();
                        for (Map.Entry<String, Set<String>> e : shaped.entrySet()) {
                            if (e.getValue().equals(modal)) {
                                same.add(e.getKey());
                            }
                        }
                        if (same.size() >= SIBLING_SHAPE && same.size() >= 0.8 * shaped.size()) {
                            same.forEach(v -> fold.put(v, "{slug}"));
                        }
                    }
                }
                if (fold.isEmpty()) {
                    continue;
                }
                for (List<String> segs : inGroup) {
                    String to = fold.get(segs.get(d));
                    if (to != null) {
                        segs.set(d, to);
                    }
                }
            }
        }
        Map<Key, String> mapping = new LinkedHashMap<>();
        for (Map.Entry<Key, List<String>> e : cur.entrySet()) {
            List<String> segs = e.getValue();
            String nw = segs.isEmpty() ? "/" : "/" + String.join("/", segs);
            List<String> old = templates.get(e.getKey());
            if (!old.isEmpty() && !nw.equals("/" + String.join("/", old))) {
                mapping.put(e.getKey(), nw);
            }
        }
        if (mapping.isEmpty()) {
            return 0;
        }
        java.util.function.BiFunction<String, String, String> rewrite = (host, template) -> {
            int q = template.indexOf('?');
            String base = q < 0 ? template : template.substring(0, q);
            String qs = q < 0 ? "" : template.substring(q);
            String nw = mapping.get(new Key(host, base));
            if (nw == null) {
                return template;
            }
            String trail = base.endsWith("/") && base.length() > 1 ? "/" : "";
            return nw + trail + qs;
        };
        for (Exchange ex : exchanges) {
            ex.pathTemplate = rewrite.apply(ex.host, ex.pathTemplate);
            if (ex.refererHost != null && ex.refererPath != null) {
                ex.refererPath = rewrite.apply(ex.refererHost, ex.refererPath);
            }
        }
        return mapping.size();
    }

    // ------------------------------------------------------------------ build

    private static String nodeFor(Model m, Exchange ex, String kind) {
        String nid;
        if ("script".equals(kind)) {
            nid = "script:" + ex.host + ex.pathTemplate;
        } else if ("route".equals(kind)) {
            nid = "route:" + ex.host + ex.pathTemplate;
        } else if ("endpoint".equals(kind)) {
            nid = "endpoint:" + ex.method + ":" + ex.host + ":" + ex.pathTemplate;
        } else {
            return null;
        }
        return m.nodes.containsKey(nid) ? nid : null;
    }

    @SuppressWarnings("unchecked")
    private static void addStatus(Model.Node node, Integer status) {
        List<Object> st = node.list("statuses");
        if (status != null && !st.contains((long) status)) {
            st.add((long) status);
            st.sort(Comparator.comparingLong(o -> (Long) o));
        }
    }

    private static int sameSiteRank(String v) {
        return v.equals("lax") ? 1 : v.equals("strict") ? 2 : 0;
    }

    private static String authLabel(String cred) {
        if (cred.startsWith("cookie:")) {
            return "session cookie " + cred.substring(7);
        }
        if (cred.startsWith("header:")) {
            return "credential header " + cred.substring(7);
        }
        if (cred.startsWith("query:")) {
            return "credential in query " + cred.substring(6);
        }
        return "Authorization: " + cred;
    }

    @SuppressWarnings("unchecked")
    private static void addSecret(Model m, Map<String, Object> s, int idx) {
        String key = s.get("kind") + "\u0000" + s.get("hmac_12");
        Map<String, Object> ex = m.secretIndex.get(key);
        if (ex != null) {
            ex.put("count", ((Long) ex.get("count")) + 1);
            List<Object> ev = (List<Object>) ex.get("evidence");
            if (!ev.contains((long) idx) && ev.size() < 10) {
                ev.add((long) idx);
            }
            return;
        }
        Map<String, Object> entry = new LinkedHashMap<>(s);
        entry.put("count", 1L);
        List<Object> ev = new ArrayList<>();
        ev.add((long) idx);
        entry.put("evidence", ev);
        m.secretIndex.put(key, entry);
        m.secrets.add(entry);
    }

    @SuppressWarnings("unchecked")
    public static Model build(List<Exchange> exchanges, String name, String seedHost, List<String> scopeIn, Map<String, Object> stats) {
        Model m = new Model(name);
        m.stats = new LinkedHashMap<>(stats == null ? Map.of() : stats);
        m.stats.putIfAbsent("exchanges", (long) exchanges.size());
        for (String k : new String[] {"static_assets", "preflight", "third_party_requests"}) {
            m.stats.put(k, 0L);
        }
        java.util.Set<Integer> idxs = new HashSet<>();
        for (Exchange ex : exchanges) {
            idxs.add(ex.index);
        }
        if (idxs.size() != exchanges.size()) {
            for (int n = 0; n < exchanges.size(); n++) {
                exchanges.get(n).index = n + 1;
            }
        }
        m.stats.put("slug_templates_folded", (long) collapseSiblings(exchanges));
        if (seedHost == null && !exchanges.isEmpty()) {
            Map<String, Integer> hosts = new LinkedHashMap<>();
            for (Exchange ex : exchanges) {
                hosts.merge(ex.host, 1, Integer::sum);
            }
            List<String> pool = new ArrayList<>();
            if (scopeIn != null && !scopeIn.isEmpty()) {
                for (String h : hosts.keySet()) {
                    if (inScope(h, scopeIn)) {
                        pool.add(h);
                    }
                }
            }
            if (pool.isEmpty()) {
                pool.addAll(hosts.keySet());
            }
            java.util.Collections.sort(pool);
            String best = null;
            for (String h : pool) {
                if (best == null || hosts.get(h) >= hosts.get(best)) {
                    best = h;                       // max(sorted(pool), key=count): the last of equals wins
                }
            }
            seedHost = best;
        }
        if (scopeIn != null && !scopeIn.isEmpty()) {
            m.scope = new ArrayList<>(scopeIn);
        } else {
            m.scope = new ArrayList<>();
            if (seedHost != null) {
                m.scope.add(Domains.registrableDomain(seedHost));
            }
        }
        final String primary = seedHost;

        Set<String> runtimeSeen = new LinkedHashSet<>();
        Set<String> referenced = new LinkedHashSet<>();
        Map<String, String> routeOfPage = new HashMap<>();

        // ---- pass 1: observed traffic
        for (Exchange ex : exchanges) {
            int i = ex.index;
            String role = ex.role;
            Map<String, Object> ev = new LinkedHashMap<>();
            ev.put("id", (long) i);
            ev.put("source", ex.source);
            ev.put("item", (long) ex.item);
            ev.put("method", ex.method);
            ev.put("host", ex.host);
            ev.put("path", ex.pathTemplate);
            ev.put("status", ex.status == null ? null : (Object) (long) ex.status);
            ev.put("mime", ex.mime);
            ev.put("role", role);
            m.evidenceLog.add(ev, ex.evZ, ex.reqPath);
            for (Redact.Fingerprint s : ex.secrets) {
                addSecret(m, s.asMap(), i);
            }
            if (isProbe(ex)) {
                m.stats.merge("probe_requests", 1L, (a, b) -> (Long) a + 1);
                continue;
            }
            if (role != null) {
                m.roles.add(role);
                m.addNode("role:" + role, "role", 5, "role: " + role);
                m.evidence("role:" + role, i);
            }
            boolean firstParty = inScope(ex.host, m.scope);
            if (!firstParty) {
                String tpId = "host:" + ex.host;
                Model.Node tp = m.addNode(tpId, "third_party", 5, ex.host, "scope", "external", "requests", 0L);
                tp.attrs.put("requests", ((Number) tp.attrs.getOrDefault("requests", 0L)).longValue() + 1);
                m.evidence(tpId, i);
                m.stats.merge("third_party_requests", 1L, (a, b) -> (Long) a + 1);
                if (isJs(ex)) {
                    String sid = "script:" + ex.host + ex.pathTemplate;
                    String last = ex.pathTemplate.substring(ex.pathTemplate.lastIndexOf('/') + 1);
                    m.addNode(sid, "script", 3, last.isEmpty() ? "script.js" : last, "host", ex.host, "scope", "external");
                    m.evidence(sid, i);
                    m.addEdge(tpId, sid, "LOADS", "OBSERVED", i);
                }
                continue;
            }
            String hostId = "host:" + ex.host;
            Model.Node h = m.addNode(hostId, "host", 1, ex.host, "scope", "first-party", "schemes", new ArrayList<>(),
                    "ports", new ArrayList<>(), "tech", new LinkedHashMap<String, Object>());
            m.evidence(hostId, i);
            List<Object> schemes = h.list("schemes");
            if (ex.scheme != null && !ex.scheme.isEmpty() && !schemes.contains(ex.scheme)) {
                schemes.add(ex.scheme);
            }
            List<Object> ports = h.list("ports");
            if (ex.port != 0 && !ports.contains((long) ex.port)) {
                ports.add((long) ex.port);
            }
            Map<String, Object> techMap = (Map<String, Object>) h.attrs.get("tech");
            for (String[] kv : ex.tech) {
                techMap.putIfAbsent(kv[0], kv[1]);
                String tid = "tech:" + kv[1];
                m.addNode(tid, "tech", 1, kv[1], "header", kv[0]);
                m.evidence(tid, i);
                m.addEdge(hostId, tid, "RUNS", "OBSERVED", i);
            }
            for (Map<String, Object> c : ex.setCookies) {
                String cid = "cookie:" + c.get("name");
                Model.Node cn = m.addNode(cid, "cookie", 5, (String) c.get("name"), "httponly", c.get("httponly"),
                        "secure", c.get("secure"), "samesite", c.get("samesite"));
                m.evidence(cid, i);
                m.addEdge(hostId, cid, "SETS_COOKIE", "OBSERVED", i);
                cn.attrs.put("httponly", (Boolean) cn.attrs.get("httponly") && (Boolean) c.get("httponly"));
                cn.attrs.put("secure", (Boolean) cn.attrs.get("secure") && (Boolean) c.get("secure"));
                String old = cn.attrs.get("samesite") == null ? "" : ((String) cn.attrs.get("samesite")).toLowerCase();
                String nw = c.get("samesite") == null ? "" : ((String) c.get("samesite")).toLowerCase();
                if (sameSiteRank(nw) < sameSiteRank(old)) {
                    cn.attrs.put("samesite", c.get("samesite"));
                }
            }
            String kind = classify(ex);
            if (kind.equals("asset")) {
                m.stats.merge("static_assets", 1L, (a, b) -> (Long) a + 1);
                continue;
            }
            if (kind.equals("preflight")) {
                m.stats.merge("preflight", 1L, (a, b) -> (Long) a + 1);
                continue;
            }
            String labelPrefix = ex.host.equals(primary) ? "" : ex.host;
            Model.Node node;
            if (kind.equals("script")) {
                String sid = "script:" + ex.host + ex.pathTemplate;
                String last = ex.pathTemplate.substring(ex.pathTemplate.lastIndexOf('/') + 1);
                m.addNode(sid, "script", 3, last.isEmpty() ? "script.js" : last, "host", ex.host, "scope", "first-party");
                m.evidence(sid, i);
                m.addEdge(hostId, sid, "LOADS", "OBSERVED", i);
                node = m.nodes.get(sid);
            } else if (kind.equals("route")) {
                String rid = "route:" + ex.host + ex.pathTemplate;
                node = m.addNode(rid, "route", 2, labelPrefix + ex.pathTemplate, "host", ex.host, "path", ex.pathTemplate,
                        "statuses", new ArrayList<>());
                m.evidence(rid, i);
                m.addEdge(hostId, rid, "SERVES", "OBSERVED", i);
                routeOfPage.put(ex.host + "\u0000" + ex.pathTemplate, rid);
                addStatus(node, ex.status);
            } else {
                String eid = "endpoint:" + ex.method + ":" + ex.host + ":" + ex.pathTemplate;
                runtimeSeen.add(eid);
                node = m.addNode(eid, "endpoint", 4, ex.method + " " + labelPrefix + ex.pathTemplate, "method", ex.method,
                        "host", ex.host, "path", ex.pathTemplate, "status", ex.status == null ? null : (Object) (long) ex.status,
                        "statuses", new ArrayList<>(), "status_by_role", new LinkedHashMap<String, Object>(),
                        "credentials", new ArrayList<>(), "anonymous_requests", 0L, "requests", 0L);
                m.evidence(eid, i);
                m.addEdge(hostId, eid, "EXPOSES", "OBSERVED", i);
                addStatus(node, ex.status);
                node.attrs.put("requests", ((Long) node.attrs.get("requests")) + 1);
                if (role != null) {
                    Map<String, Object> sbr = (Map<String, Object>) node.attrs.get("status_by_role");
                    List<Object> l = (List<Object>) sbr.computeIfAbsent(role, x -> new ArrayList<>());
                    if (ex.status != null && !l.contains((long) ex.status)) {
                        l.add((long) ex.status);
                        l.sort(Comparator.comparingLong(o -> (Long) o));
                    }
                }
                if (!ex.credentials.isEmpty()) {
                    for (String cred : ex.credentials) {
                        List<Object> cl = node.list("credentials");
                        if (!cl.contains(cred)) {
                            cl.add(cred);
                        }
                        String aid = "auth:" + cred;
                        m.addNode(aid, "auth", 5, authLabel(cred));
                        m.evidence(aid, i);
                        m.addEdge(eid, aid, "SENT_CREDENTIAL", "OBSERVED", i);
                    }
                } else {
                    node.attrs.put("anonymous_requests", ((Long) node.attrs.get("anonymous_requests")) + 1);
                }
                for (String op : ex.gqlOps) {
                    String oid = "op:" + eid + ":" + op;
                    m.addNode(oid, "operation", 4, op);
                    m.evidence(oid, i);
                    m.addEdge(eid, oid, "USES_OPERATION", "OBSERVED", i);
                    if (role != null && !m.nodes.get(oid).roles.contains(role)) {
                        m.nodes.get(oid).roles.add(role);
                    }
                }
            }
            if (role != null && !node.roles.contains(role)) {
                node.roles.add(role);
            }
            if (role != null) {
                m.addEdge("role:" + role, node.id, "REACHED", "OBSERVED", i);
            }
            if (kind.equals("route") || kind.equals("endpoint")) {
                for (Object[] loc : new Object[][] {{"query", ex.queryParams}, {"body", ex.bodyParams}}) {
                    for (Redact.Pair p : (List<Redact.Pair>) loc[1]) {
                        String pid = "param:" + node.id + ":" + p.name();
                        m.addNode(pid, "parameter", 4, p.name(), "location", loc[0]);
                        m.evidence(pid, i);
                        m.addEdge(node.id, pid, "USES_PARAMETER", "OBSERVED", i);
                    }
                }
            }
        }

        // A path that only ever answered 404/410 is not part of the app.
        List<String> gone = new ArrayList<>();
        for (Map.Entry<String, Model.Node> e : m.nodes.entrySet()) {
            Model.Node n = e.getValue();
            if ((n.type.equals("route") || n.type.equals("endpoint")) && n.attrs.get("statuses") instanceof List<?> sl
                    && !sl.isEmpty() && sl.stream().allMatch(s -> ((Long) s) == 404 || ((Long) s) == 410)) {
                gone.add(e.getKey());
            }
        }
        for (String nid : gone) {
            m.nodes.remove(nid);
            runtimeSeen.remove(nid);
        }
        if (!gone.isEmpty()) {
            Set<String> dead = new HashSet<>(gone);
            m.edges = new ArrayList<>(m.edges.stream().filter(e -> !dead.contains(e.src) && !dead.contains(e.dst)).toList());
            m.edgeIndex = new LinkedHashMap<>();
            for (Model.Edge e : m.edges) {
                m.edgeIndex.put(Model.edgeKey(e.src, e.dst, e.type), e);
            }
            for (String k : new ArrayList<>(m.nodes.keySet())) {
                // "param:<gone node id>:<name>": try each ':' as the end of the node id instead of every gone id
                if (k.startsWith("param:")) {
                    for (int c = k.indexOf(':', 6); c > 0; c = k.indexOf(':', c + 1)) {
                        if (dead.contains(k.substring(6, c))) {
                            m.nodes.remove(k);
                            break;
                        }
                    }
                }
            }
            routeOfPage.values().removeIf(dead::contains);
        }
        m.stats.put("not_found_paths_dropped", (long) gone.size());

        // ---- pass 2: referer edges and static references
        Map<String, List<String>> byKey = new LinkedHashMap<>();
        for (String nid : new TreeSet<>(runtimeSeen)) {
            byKey.computeIfAbsent(matchKey((String) m.nodes.get(nid).attrs.get("path")), x -> new ArrayList<>()).add(nid);
        }
        for (Exchange ex : exchanges) {
            int i = ex.index;
            if (!inScope(ex.host, m.scope)) {
                continue;
            }
            String kind = classify(ex);
            String src = nodeFor(m, ex, kind);
            if (src != null && ex.refererHost != null && inScope(ex.refererHost, m.scope)) {
                String page = routeOfPage.get(ex.refererHost + "\u0000" + ex.refererPath);
                if (page != null && !page.equals(src)) {
                    String etype = kind.equals("endpoint") ? "CALLS" : kind.equals("script") ? "INCLUDES" : "NAVIGATES_TO";
                    m.addEdge(page, src, etype, "OBSERVED", i);
                }
            }
        }
        for (Exchange ex : exchanges) {
            if (ex.jsRefs.isEmpty() || isProbe(ex)) {
                continue;
            }
            int i = ex.index;
            boolean firstParty = inScope(ex.host, m.scope);
            String kind = firstParty ? classify(ex) : (isJs(ex) ? "script" : null);
            String src = kind != null ? nodeFor(m, ex, kind) : null;
            if (src == null) {
                continue;
            }
            String baseHost = ex.host;
            if (!inScope(baseHost, m.scope) || "script".equals(kind)) {
                baseHost = ex.refererHost != null && inScope(ex.refererHost, m.scope) ? ex.refererHost : primary;
            }
            for (Extract.Ref ref : ex.jsRefs) {
                String method = ref.method();
                String host = ref.host();
                String path = ref.path();
                if (host != null && !inScope(host, m.scope)) {
                    String tpId = "host:" + host;
                    m.addNode(tpId, "third_party", 5, host, "scope", "external", "requests", 0L);
                    m.evidence(tpId, i);
                    m.addEdge(src, tpId, "REFERENCES", "INFERRED", i);
                    continue;
                }
                if (host == null && !firstParty) {
                    continue;
                }
                List<String> cands = new ArrayList<>();
                for (String nid : byKey.getOrDefault(matchKey(path), List.of())) {
                    Model.Node n = m.nodes.get(nid);
                    if ((host == null || host.equals(n.attrs.get("host"))) && (method == null || method.equals(n.attrs.get("method")))) {
                        cands.add(nid);
                    }
                }
                if (!cands.isEmpty()) {
                    for (String nid : cands) {
                        referenced.add(nid);
                        m.evidence(nid, i);
                        m.addEdge(src, nid, "REFERENCES", "INFERRED", i);
                    }
                    continue;
                }
                String targetHost = host != null ? host : baseHost;
                String meth = method != null ? method : "*";
                String eid = "endpoint:" + meth + ":" + targetHost + ":" + path;
                String prefix = targetHost != null && targetHost.equals(primary) ? "" : targetHost;
                m.addNode(eid, "endpoint", 4, meth + " " + prefix + path, "method", method, "host", targetHost, "path", path,
                        "method_known", method != null, "statuses", new ArrayList<>(), "status_by_role", new LinkedHashMap<String, Object>(),
                        "credentials", new ArrayList<>(), "anonymous_requests", 0L, "requests", 0L);
                m.evidence(eid, i);
                referenced.add(eid);
                m.addEdge(src, eid, "REFERENCES", "INFERRED", i);
            }
        }
        linkScriptAssets(m, exchanges);
        m.stack = buildStack(m, exchanges);
        reconcile(m, referenced, runtimeSeen);
        emitUnknowns(m, exchanges);
        for (Model.Node n : m.nodes.values()) {
            java.util.Collections.sort(n.evidence);
        }
        for (Model.Edge e : m.edges) {
            java.util.Collections.sort(e.evidence);
        }
        return m;
    }

    private static void linkScriptAssets(Model m, List<Exchange> exchanges) {
        Set<String> seen = new HashSet<>();
        for (Exchange ex : exchanges) {
            if (ex.status != null && ex.status < 400 && !isProbe(ex)) {
                seen.add(ex.host + "\u0000" + ex.pathTemplate);
            }
        }
        for (Exchange ex : exchanges) {
            if (ex.jsAssets.isEmpty() || isProbe(ex) || !inScope(ex.host, m.scope)) {
                continue;
            }
            String src = "script:" + ex.host + ex.pathTemplate;
            if (!m.nodes.containsKey(src)) {
                continue;
            }
            for (Extract.Asset a : ex.jsAssets) {
                if (!inScope(a.host(), m.scope)) {
                    continue;
                }
                if (a.kind().equals("sourcemap")) {
                    boolean captured = seen.contains(a.host() + "\u0000" + a.path());
                    Map<String, Object> sm = new LinkedHashMap<>();
                    sm.put("host", a.host());
                    sm.put("path", a.path());
                    sm.put("captured", captured);
                    m.nodes.get(src).attrs.put("sourcemap", sm);
                    m.evidence(src, ex.index);
                    if (!captured) {
                        m.unknowns.add(new Model.Unknown("SOURCE_MAP_NOT_CAPTURED", src,
                                List.of("the script names a source map (" + a.path() + ") that is not in the capture"),
                                "original source file names and structure",
                                "request the .map file in an authorized session and re-capture"));
                    }
                    continue;
                }
                String wid = "script:" + a.host() + a.path();
                String last = a.path().substring(a.path().lastIndexOf('/') + 1);
                Model.Node node = m.addNode(wid, "script", 3, last.isEmpty() ? "worker.js" : last, "host", a.host(), "scope", "first-party");
                node.attrs.putIfAbsent("worker", a.kind());
                m.evidence(wid, ex.index);
                m.addEdge(src, wid, "SPAWNS", "INFERRED", ex.index);
            }
        }
    }

    @SuppressWarnings("unchecked")
    private static List<Map<String, Object>> buildStack(Model m, List<Exchange> exchanges) {
        Map<String, Map<String, Object>> agg = new LinkedHashMap<>();
        java.util.function.Function<String[], Map<String, Object>> entry = a -> {
            Map<String, Object> e = agg.computeIfAbsent(a[1] + "\u0000" + a[0], k -> {
                Map<String, Object> x = new LinkedHashMap<>();
                x.put("name", a[0]);
                x.put("category", a[1]);
                x.put("kind", a[4]);
                x.put("version", "");
                x.put("how", a[2]);
                x.put("evidence", new ArrayList<Object>());
                return x;
            });
            if (!a[3].isEmpty() && ((String) e.get("version")).isEmpty()) {
                e.put("version", a[3]);
            }
            return e;
        };
        for (Exchange ex : exchanges) {
            if (isProbe(ex) || !inScope(ex.host, m.scope)) {
                continue;
            }
            for (Stack.Hit h : ex.stack) {
                Map<String, Object> e = entry.apply(new String[] {h.name(), h.category(), h.how(), h.version(), Stack.serviceKind(h.name())});
                List<Object> ev = (List<Object>) e.get("evidence");
                if (!ev.contains((long) ex.index) && ev.size() < 10) {
                    ev.add((long) ex.index);
                }
            }
        }
        Map<String, Model.Node> byHost = new LinkedHashMap<>();
        for (Model.Node n : m.nodes.values()) {
            if (n.type.equals("third_party")) {
                byHost.put(n.label, n);
            }
        }
        List<String> hosts = new ArrayList<>(byHost.keySet());
        java.util.Collections.sort(hosts);
        for (Stack.Vendor v : Stack.vendorsFor(hosts)) {
            String cat = v.kind().equals("Edge & CDN") ? "Edge & CDN" : "Services";
            Map<String, Object> e = entry.apply(new String[] {v.vendor(), cat, "third-party host", "", cat.equals("Edge & CDN") ? "" : v.kind()});
            List<Object> ev = (List<Object>) e.get("evidence");
            List<Integer> src = byHost.get(v.host()).evidence;
            for (int i = 0; i < Math.min(10, src.size()); i++) {
                if (!ev.contains((long) src.get(i)) && ev.size() < 10) {
                    ev.add((long) src.get(i));
                }
            }
        }
        List<String> cats = Stack.categories();
        List<Map<String, Object>> out = new ArrayList<>(agg.values());
        out.sort(Comparator.<Map<String, Object>>comparingInt(e -> {
            int r = cats.indexOf(e.get("category"));
            return r < 0 ? 99 : r;
        }).thenComparing(e -> ((String) e.get("name")).toLowerCase()));
        for (Map<String, Object> e : out) {
            ((List<Object>) e.get("evidence")).sort(Comparator.comparingLong(o -> (Long) o));
        }
        return out;
    }

    private static void reconcile(Model m, Set<String> referenced, Set<String> runtimeSeen) {
        for (Model.Node node : m.nodes.values()) {
            if (!node.type.equals("endpoint")) {
                continue;
            }
            boolean inJs = referenced.contains(node.id);
            boolean inRt = runtimeSeen.contains(node.id);
            node.attrs.put("api_state", inJs && inRt ? "BOTH" : inJs ? "STATIC_ONLY" : "RUNTIME_ONLY");
        }
    }

    private static void emitUnknowns(Model m, List<Exchange> exchanges) {
        boolean credsSeen = exchanges.stream().anyMatch(e -> !e.credentials.isEmpty());
        if (m.roles.isEmpty() && !credsSeen) {
            m.unknowns.add(new Model.Unknown("AUTHENTICATED_STATE_NOT_OBSERVED", "app:" + m.name,
                    List.of("no credentials were sent in the capture", "capture had no role tag"),
                    "how the app behaves for a logged-in user", "re-ingest an authenticated capture with a role"));
        } else if (m.roles.isEmpty()) {
            m.unknowns.add(new Model.Unknown("ROLE_NOT_TAGGED", "app:" + m.name,
                    List.of("credentials were sent", "capture had no role tag"),
                    "which user/role the traffic belongs to, so access cannot be compared",
                    "re-ingest each account's capture with a role name"));
        }
        Object skipped = m.stats.get("skipped");
        if (skipped instanceof Number n && n.longValue() > 0) {
            m.unknowns.add(new Model.Unknown("CAPTURE_ITEMS_SKIPPED", "app:" + m.name,
                    List.of(n.longValue() + " export item(s) could not be parsed"), "what those requests contained",
                    "re-export the history; check for truncated or non-Burp XML"));
        }
        Set<String> truncated = new TreeSet<>();
        for (Exchange ex : exchanges) {
            if (ex.scanTruncated) {
                truncated.add("script:" + ex.host + ex.pathTemplate);
            }
        }
        for (String sid : truncated) {
            if (m.nodes.containsKey(sid)) {
                m.unknowns.add(new Model.Unknown("SCRIPT_PARTIALLY_SCANNED", sid, List.of("script body exceeded the scan cap"),
                        "endpoints referenced past the cap", "extract the bundle and scan it separately"));
            }
        }
        for (Model.Node node : m.nodes.values()) {
            if (!node.type.equals("endpoint")) {
                continue;
            }
            Object state = node.attrs.get("api_state");
            if ("STATIC_ONLY".equals(state)) {
                List<String> know = new ArrayList<>(List.of("referenced in code", "never observed at runtime"));
                if (Boolean.FALSE.equals(node.attrs.getOrDefault("method_known", true))) {
                    know.add("HTTP method not determinable from the reference");
                }
                m.unknowns.add(new Model.Unknown("API_PURPOSE_UNKNOWN", node.id, know,
                        "what this endpoint does and whether it is reachable", "request it directly in an authorised session"));
            }
            List<Object> st = node.list("statuses");
            if (st != null && !st.isEmpty() && st.stream().allMatch(s -> ((Long) s) >= 400)) {
                String codes = String.join(", ", st.stream().map(String::valueOf).toList());
                m.unknowns.add(new Model.Unknown("ENDPOINT_ONLY_ERRORED", node.id, List.of("observed statuses: " + codes),
                        "how it behaves with valid input and authorization", "exercise the feature normally in an authorised session"));
            }
        }
    }
}
