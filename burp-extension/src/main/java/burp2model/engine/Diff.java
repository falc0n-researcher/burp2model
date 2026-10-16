package burp2model.engine;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.TreeMap;
import java.util.TreeSet;

/** What changed between two builds of one app, grouped so a release reads as a handful of lines. A port of diff.py. */
public final class Diff {
    private Diff() {}

    private static final Map<String, Integer> ORDER = new HashMap<>();
    private static final List<String> HEAD = List.of("host", "route", "endpoint", "script", "third_party", "tech", "cookie", "auth", "role", "operation", "parameter");

    static {
        String[] o = {"host", "route", "script", "endpoint", "operation", "parameter", "third_party", "auth", "cookie", "role", "tech"};
        for (int i = 0; i < o.length; i++) {
            ORDER.put(o[i], i);
        }
    }

    private static int ord(String type) {
        return ORDER.getOrDefault(type, 99);
    }

    private static final java.util.regex.Pattern INTEGER = java.util.regex.Pattern.compile("-?\\d+");

    @SuppressWarnings("unchecked")
    private static List<Object> sortedList(Object v) {
        List<Object> l = v instanceof List<?> x ? new ArrayList<>((List<Object>) x) : new ArrayList<>();
        l.sort(Comparator.comparing(String::valueOf, (a, b) -> {
            boolean na = INTEGER.matcher(a).matches(), nb = INTEGER.matcher(b).matches();
            if (na && nb) {
                return Long.compare(Long.parseLong(a), Long.parseLong(b));
            }
            return a.compareTo(b);
        }));
        return l;
    }

    /** The facts about a node that can move without it being a different node. */
    @SuppressWarnings("unchecked")
    static Map<String, Object> fp(Model.Node n) {
        Map<String, Object> a = n.attrs;
        Map<String, Object> out = new LinkedHashMap<>();
        switch (n.type) {
            case "endpoint" -> {
                out.put("state", a.get("api_state"));
                out.put("statuses", sortedList(a.get("statuses")));
                Map<String, Object> byRole = new TreeMap<>();
                if (a.get("status_by_role") instanceof Map<?, ?> sbr) {
                    ((Map<String, Object>) sbr).forEach((r, v) -> byRole.put(r, sortedList(v)));
                }
                out.put("by role", byRole);
                out.put("credentials", sortedList(a.get("credentials")));
                out.put("roles", sortedList(n.roles));
            }
            case "route" -> {
                out.put("statuses", sortedList(a.get("statuses")));
                out.put("roles", sortedList(n.roles));
            }
            case "host" -> {
                out.put("header", a.get("tech") instanceof Map<?, ?> t ? new TreeMap<>((Map<String, Object>) t) : new TreeMap<>());
                out.put("schemes", sortedList(a.get("schemes")));
                out.put("ports", sortedList(a.get("ports")));
            }
            case "cookie" -> {
                out.put("HttpOnly", a.get("httponly"));
                out.put("Secure", a.get("secure"));
                out.put("SameSite", a.get("samesite"));
            }
            case "script" -> {
                Object sm = a.get("sourcemap");
                out.put("source map captured", sm instanceof Map<?, ?> s && !s.isEmpty() ? s.get("captured") : null);
                out.put("worker kind", a.get("worker"));
            }
            default -> {
            }
        }
        return out;
    }

    @SuppressWarnings("unchecked")
    static String show(Object v) {
        if (v instanceof List<?> l) {
            return l.isEmpty() ? "none" : String.join(", ", l.stream().map(String::valueOf).toList());
        }
        if (v instanceof Map<?, ?> m) {
            if (m.isEmpty()) {
                return "none";
            }
            List<String> parts = new ArrayList<>();
            ((Map<String, Object>) m).forEach((k, x) -> parts.add(k + ": " + show(x)));
            return String.join("; ", parts);
        }
        return v == null ? "none" : String.valueOf(v);
    }

    @SuppressWarnings("unchecked")
    static String summarise(String field, Object a, Object b) {
        if (a instanceof List<?> la && b instanceof List<?> lb) {
            List<Object> gone = new ArrayList<>();
            List<Object> neu = new ArrayList<>();
            for (Object x : la) {
                if (!lb.contains(x)) {
                    gone.add(x);
                }
            }
            for (Object x : lb) {
                if (!la.contains(x)) {
                    neu.add(x);
                }
            }
            if (gone.size() == 1 && neu.size() == 1) {
                return field + " " + gone.get(0) + " → " + neu.get(0);
            }
            List<String> parts = new ArrayList<>();
            neu.forEach(x -> parts.add("+" + x));
            gone.forEach(x -> parts.add("−" + x));
            return field + " " + String.join(" ", parts);
        }
        if (a instanceof Map<?, ?> ma && b instanceof Map<?, ?> mb) {
            Set<String> keys = new TreeSet<>();
            keys.addAll((Set<String>) ma.keySet());
            keys.addAll((Set<String>) mb.keySet());
            List<String> parts = new ArrayList<>();
            for (String k : keys) {
                Object x = ma.get(k);
                Object y = mb.get(k);
                if (!Objects.equals(x, y)) {
                    if (x instanceof List<?> && y instanceof List<?>) {
                        parts.add(summarise(field + " " + k + ":", x, y));
                    } else {
                        parts.add(field + " " + k + ": " + show(x) + " → " + show(y));
                    }
                }
            }
            return String.join("; ", parts);
        }
        return field + " " + show(a) + " → " + show(b);
    }

    private static List<Object> changes(Model.Node a, Model.Node b) {
        Map<String, Object> fa = fp(a);
        Map<String, Object> fb = fp(b);
        List<Object> out = new ArrayList<>();
        for (Map.Entry<String, Object> e : fa.entrySet()) {
            if (!Objects.equals(e.getValue(), fb.get(e.getKey()))) {
                Map<String, Object> c = new LinkedHashMap<>();
                c.put("field", e.getKey());
                c.put("from", e.getValue());
                c.put("to", fb.get(e.getKey()));
                c.put("summary", summarise(e.getKey(), e.getValue(), fb.get(e.getKey())));
                out.add(c);
            }
        }
        return out;
    }

    private static List<List<String>> components(Set<String> ids, List<Model.Edge> edges) {
        Map<String, String> parent = new HashMap<>();
        ids.forEach(i -> parent.put(i, i));
        java.util.function.Function<String, String> find = new java.util.function.Function<>() {
            @Override
            public String apply(String x) {
                while (!parent.get(x).equals(x)) {
                    parent.put(x, parent.get(parent.get(x)));
                    x = parent.get(x);
                }
                return x;
            }
        };
        for (Model.Edge e : edges) {
            if (ids.contains(e.src) && ids.contains(e.dst)) {
                parent.put(find.apply(e.src), find.apply(e.dst));
            }
        }
        Map<String, List<String>> groups = new LinkedHashMap<>();
        for (String i : new TreeSet<>(ids)) {
            groups.computeIfAbsent(find.apply(i), k -> new ArrayList<>()).add(i);
        }
        return new ArrayList<>(groups.values());
    }

    private static String labelOf(Model m, String id) {
        Model.Node n = m.nodes.get(id);
        if (n != null) {
            return n.label;
        }
        int i = id.indexOf(':');
        return i < 0 ? id : id.substring(i + 1);
    }

    private static List<Object> evs(List<Integer> ids, int cap) {
        List<Object> out = new ArrayList<>();
        List<Integer> sorted = new ArrayList<>(new TreeSet<>(ids));
        for (int i = 0; i < Math.min(cap, sorted.size()); i++) {
            out.add((long) sorted.get(i));
        }
        return out;
    }

    private static Map<String, Object> workflow(String kind, Model m, List<String> idsList, List<Model.Edge> edges, Map<String, List<Integer>> incident,
                                                Model other) {
        Set<String> ids = new HashSet<>(idsList);
        List<Model.Node> nodes = new ArrayList<>();
        idsList.forEach(i -> nodes.add(m.nodes.get(i)));
        nodes.sort(Comparator.comparingInt((Model.Node n) -> ord(n.type)).thenComparing(n -> n.label));
        Model.Node head = null;
        for (String t : HEAD) {
            for (Model.Node n : nodes) {
                if (n.type.equals(t)) {
                    head = n;
                    break;
                }
            }
            if (head != null) {
                break;
            }
        }
        if (head == null) {
            head = nodes.get(0);
        }
        Map<String, Integer> counts = new TreeMap<>();
        for (Model.Node n : nodes) {
            counts.merge(n.type, 1, Integer::sum);
        }
        final Model.Node h = head;
        List<String[]> restPairs = new ArrayList<>();
        counts.forEach((t, c) -> {
            if (!t.equals(h.type) || c > 1) {
                restPairs.add(new String[] {t, String.valueOf(c)});
            }
        });
        restPairs.sort(Comparator.comparingInt(x -> ord(x[0])));
        List<String> rest = new ArrayList<>();
        for (String[] r : restPairs) {
            rest.add(r[1] + " " + r[0].replace('_', ' ') + (!r[1].equals("1") ? "s" : ""));
        }
        List<Object> links = new ArrayList<>();
        // only the edges touching this workflow, in list order (scanning every edge per workflow was n^2)
        Set<Integer> touching = new TreeSet<>();
        for (String id : idsList) {
            touching.addAll(incident.getOrDefault(id, List.of()));
        }
        for (int at : touching) {
            Model.Edge e = edges.get(at);
            boolean aIn = ids.contains(e.src);
            boolean bIn = ids.contains(e.dst);
            if (aIn != bIn) {
                String outside = aIn ? e.dst : e.src;
                Model.Node on = m.nodes.containsKey(outside) ? m.nodes.get(outside) : other.nodes.get(outside);
                if ((other.nodes.containsKey(outside) || m.nodes.containsKey(outside)) && on != null && !on.type.equals("host") && !on.type.equals("tech")) {
                    Map<String, Object> l = new LinkedHashMap<>();
                    l.put(bIn ? "from" : "to", labelOf(m, outside));
                    l.put("edge", e.type.toLowerCase());
                    l.put("node", labelOf(m, bIn ? e.dst : e.src));
                    links.add(l);
                }
            }
        }
        Set<Integer> evAll = new TreeSet<>();
        nodes.forEach(n -> evAll.addAll(n.evidence));
        List<Object> nodeList = new ArrayList<>();
        List<Object> chain = new ArrayList<>();
        long params = 0;
        for (Model.Node n : nodes) {
            Map<String, Object> nm = new LinkedHashMap<>();
            nm.put("id", n.id);
            nm.put("type", n.type);
            nm.put("label", n.label);
            nodeList.add(nm);
            if (n.type.equals("parameter")) {
                params++;
            } else if (chain.size() < 8) {
                chain.add(n.label);
            }
        }
        if (params > 0) {
            chain.add("+" + params + " parameters");
        }
        Map<String, Object> w = new LinkedHashMap<>();
        w.put("kind", kind);
        w.put("title", head.type.replace('_', ' ') + " " + head.label);
        w.put("head", head.label);
        w.put("summary", String.join(", ", rest));
        w.put("nodes", nodeList);
        w.put("chain", chain);
        w.put("links", links.subList(0, Math.min(3, links.size())));
        w.put("evidence", evs(new ArrayList<>(evAll), 8));
        return w;
    }

    private static Map<String, Map<String, Object>> stackIndex(Model m) {
        Map<String, Map<String, Object>> idx = new TreeMap<>();
        for (Map<String, Object> t : m.stack) {
            idx.put(t.get("category") + "\u0000" + t.get("name"), t);
        }
        return idx;
    }

    private static Map<String, Object> map(Object... kv) {
        Map<String, Object> m = new LinkedHashMap<>();
        for (int i = 0; i + 1 < kv.length; i += 2) {
            m.put((String) kv[i], kv[i + 1]);
        }
        return m;
    }

    @SuppressWarnings("unchecked")
    public static Map<String, Object> diff(Model old, Model neu, Map<String, Object> oldMeta, Map<String, Object> newMeta,
                                           java.util.function.BiFunction<String, String, Map<String, Object>> hist) {
        Map<String, Model.Node> on = old.nodes;
        Map<String, Model.Node> nn = neu.nodes;
        Set<String> newIds = new TreeSet<>();
        Set<String> goneIds = new TreeSet<>();
        for (String i : nn.keySet()) {
            if (!on.containsKey(i) && !nn.get(i).type.equals("tech")) {
                newIds.add(i);
            }
        }
        for (String i : on.keySet()) {
            if (!nn.containsKey(i) && !on.get(i).type.equals("tech")) {
                goneIds.add(i);
            }
        }
        Map<String, String> closed = new TreeMap<>();
        Map<String, String> walked = new HashMap<>();
        for (Model.Node n : nn.values()) {
            if (n.type.equals("endpoint") && !Boolean.FALSE.equals(n.attrs.getOrDefault("method_known", true))) {
                walked.put(n.attrs.get("host") + "\u0000" + Builder.matchKey(String.valueOf(n.attrs.getOrDefault("path", ""))), n.id);
            }
        }
        for (String gid : goneIds) {
            Model.Node n = on.get(gid);
            if (n.type.equals("endpoint") && Boolean.FALSE.equals(n.attrs.getOrDefault("method_known", true))) {
                String hit = walked.get(n.attrs.get("host") + "\u0000" + Builder.matchKey(String.valueOf(n.attrs.getOrDefault("path", ""))));
                if (hit != null && newIds.contains(hit)) {
                    closed.put(gid, hit);
                }
            }
        }
        closed.forEach((g, h) -> {
            goneIds.remove(g);
            newIds.remove(h);
        });

        List<Map<String, Object>> changed = new ArrayList<>();
        for (String nid : new TreeSet<>(on.keySet())) {
            if (!nn.containsKey(nid)) {
                continue;
            }
            List<Object> ch = changes(on.get(nid), nn.get(nid));
            if (!ch.isEmpty()) {
                changed.add(map("kind", nn.get(nid).type, "id", nid, "label", nn.get(nid).label, "changes", ch, "evidence", evs(nn.get(nid).evidence, 3)));
            }
        }
        closed.forEach((g, h) -> {
            Map<String, Object> c = map("field", "state", "from", "STATIC_ONLY", "to", nn.get(h).attrs.get("api_state"),
                    "summary", "named in code before, now walked in traffic (" + on.get(g).label + " → " + nn.get(h).label + ")");
            changed.add(map("kind", "endpoint", "id", h, "label", nn.get(h).label, "changes", List.of(c), "evidence", evs(nn.get(h).evidence, 3)));
        });

        // the technology stack
        Map<String, Map<String, Object>> so = stackIndex(old);
        Map<String, Map<String, Object>> sn = stackIndex(neu);
        List<Map<String, Object>> stackNew = new ArrayList<>();
        List<Map<String, Object>> stackGone = new ArrayList<>();
        for (Map.Entry<String, Map<String, Object>> e : sn.entrySet()) {
            if (!so.containsKey(e.getKey())) {
                Map<String, Object> v = e.getValue();
                String ver = String.valueOf(v.getOrDefault("version", ""));
                List<Object> ev = (List<Object>) v.getOrDefault("evidence", List.of());
                stackNew.add(map("kind", "stack", "label", v.get("name") + (!ver.isEmpty() ? " " + ver : ""), "category", v.get("category"),
                        "evidence", ev.subList(0, Math.min(3, ev.size()))));
            }
        }
        for (Map.Entry<String, Map<String, Object>> e : so.entrySet()) {
            if (!sn.containsKey(e.getKey())) {
                Map<String, Object> v = e.getValue();
                String ver = String.valueOf(v.getOrDefault("version", ""));
                stackGone.add(map("kind", "stack", "label", v.get("name") + (!ver.isEmpty() ? " " + ver : ""), "category", v.get("category")));
            }
        }
        for (String k : sn.keySet()) {
            if (so.containsKey(k)) {
                String a = String.valueOf(so.get(k).getOrDefault("version", ""));
                String b = String.valueOf(sn.get(k).getOrDefault("version", ""));
                if (!a.equals(b)) {
                    List<Object> ev = (List<Object>) sn.get(k).getOrDefault("evidence", List.of());
                    Map<String, Object> c = map("field", "version", "from", a, "to", b,
                            "summary", "version " + (a.isEmpty() ? "none" : a) + " → " + (b.isEmpty() ? "none" : b));
                    changed.add(map("kind", "stack", "id", "stack:" + sn.get(k).get("category") + ":" + sn.get(k).get("name"), "label", sn.get(k).get("name"),
                            "category", sn.get(k).get("category"), "changes", List.of(c), "evidence", ev.subList(0, Math.min(3, ev.size()))));
                }
            }
        }
        for (String cat : new String[] {"Edge & CDN", "Web server", "Language & framework"}) {
            List<Map<String, Object>> g = stackGone.stream().filter(x -> x.get("category").equals(cat)).toList();
            List<Map<String, Object>> a = stackNew.stream().filter(x -> x.get("category").equals(cat)).toList();
            if (g.size() == 1 && a.size() == 1) {
                Map<String, Object> c = map("field", "technology", "from", g.get(0).get("label"), "to", a.get(0).get("label"),
                        "summary", cat.toLowerCase() + " " + g.get(0).get("label") + " → " + a.get(0).get("label"));
                changed.add(map("kind", "stack", "id", "stack:" + cat, "label", cat, "category", cat, "changes", List.of(c), "evidence", a.get(0).getOrDefault("evidence", List.of())));
                stackGone.remove(g.get(0));
                stackNew.remove(a.get(0));
            }
        }

        Map<String, Model.Edge> oldE = new TreeMap<>();
        Map<String, Model.Edge> newE = new TreeMap<>();
        old.edges.forEach(e -> oldE.put(e.src + "\u0000" + e.type + "\u0000" + e.dst, e));
        neu.edges.forEach(e -> newE.put(e.src + "\u0000" + e.type + "\u0000" + e.dst, e));
        List<Model.Edge> added = new ArrayList<>();
        List<Model.Edge> removed = new ArrayList<>();
        newE.forEach((k, e) -> {
            if (!oldE.containsKey(k)) {
                added.add(e);
            }
        });
        oldE.forEach((k, e) -> {
            if (!newE.containsKey(k)) {
                removed.add(e);
            }
        });

        List<Map<String, Object>> newWf = new ArrayList<>();
        List<String> newSingle = new ArrayList<>();
        splitWorkflows("new_workflow", neu, newIds, added, old, newWf, newSingle);
        List<Map<String, Object>> goneWf = new ArrayList<>();
        List<String> goneSingle = new ArrayList<>();
        splitWorkflows("gone_workflow", old, goneIds, removed, neu, goneWf, goneSingle);
        Set<String> inWfNew = new HashSet<>(newSingle);
        newWf.forEach(w -> ((List<Map<String, Object>>) w.get("nodes")).forEach(n -> inWfNew.add((String) n.get("id"))));
        Set<String> inWfGone = new HashSet<>(goneSingle);
        goneWf.forEach(w -> ((List<Map<String, Object>>) w.get("nodes")).forEach(n -> inWfGone.add((String) n.get("id"))));

        List<Map<String, Object>> newNodes = new ArrayList<>();
        for (String i : newSingle) {
            newNodes.add(single(neu, i, "new", hist));
        }
        List<Map<String, Object>> goneNodes = new ArrayList<>();
        for (String i : goneSingle) {
            goneNodes.add(single(old, i, "gone", hist));
        }
        Comparator<Map<String, Object>> byKind = Comparator.comparingInt((Map<String, Object> d) -> ord((String) d.get("kind"))).thenComparing(d -> (String) d.get("label"));
        newNodes.sort(byKind);
        goneNodes.sort(byKind);
        List<Object> newEdges = looseEdges(added, neu, inWfNew);
        List<Object> goneEdges = looseEdges(removed, old, inWfGone);

        Map<String, Object> summary = new LinkedHashMap<>();
        summary.put("new", (long) (newSingle.size() + stackNew.size() + newEdges.size()));
        summary.put("changed", (long) changed.size());
        summary.put("gone", (long) (goneSingle.size() + stackGone.size() + goneEdges.size()));
        summary.put("new_workflows", (long) newWf.size());
        summary.put("gone_workflows", (long) goneWf.size());
        long total = 0;
        for (String k : new String[] {"new", "changed", "gone", "new_workflows", "gone_workflows"}) {
            total += (Long) summary.get(k);
        }
        summary.put("total", total);
        changed.sort(Comparator.comparingInt((Map<String, Object> c) -> ord((String) c.get("kind"))).thenComparing(c -> String.valueOf(c.get("label"))));
        List<Object> workflows = new ArrayList<>(newWf);
        workflows.addAll(goneWf);
        Map<String, Object> r = new LinkedHashMap<>();
        r.put("app", neu.name);
        r.put("from", oldMeta == null ? Map.of() : oldMeta);
        r.put("to", newMeta == null ? Map.of() : newMeta);
        r.put("same", total == 0);
        r.put("summary", summary);
        r.put("workflows", workflows);
        r.put("new", map("nodes", newNodes, "stack", stackNew, "edges", newEdges));
        r.put("changed", changed);
        r.put("gone", map("nodes", goneNodes, "stack", stackGone, "edges", goneEdges));
        r.put("note", "Drift between two builds. Each line is a change in the attack surface to understand, never a finding. "
                + "Evidence ids are from the newer build for new and changed things, the older build for gone ones.");
        return r;
    }

    private static void splitWorkflows(String kind, Model model, Set<String> ids, List<Model.Edge> edges, Model other,
                                       List<Map<String, Object>> wf, List<String> singles) {
        Map<String, List<Integer>> incident = new HashMap<>();
        for (int i = 0; i < edges.size(); i++) {
            Model.Edge e = edges.get(i);
            incident.computeIfAbsent(e.src, x -> new ArrayList<>()).add(i);
            if (!e.dst.equals(e.src)) {
                incident.computeIfAbsent(e.dst, x -> new ArrayList<>()).add(i);
            }
        }
        for (List<String> comp : components(ids, edges)) {
            if (comp.size() >= 2) {
                wf.add(workflow(kind, model, comp, edges, incident, other));
            } else {
                singles.add(comp.get(0));
            }
        }
        wf.sort(Comparator.comparingInt((Map<String, Object> w) -> -((List<?>) w.get("nodes")).size()).thenComparing(w -> (String) w.get("title")));
    }

    private static Map<String, Object> single(Model model, String nid, String side, java.util.function.BiFunction<String, String, Map<String, Object>> hist) {
        Model.Node n = model.nodes.get(nid);
        Map<String, Object> d = map("kind", n.type, "label", n.label, "state", n.attrs.get("api_state"), "evidence", evs(n.evidence, 3));
        if (hist != null) {
            Map<String, Object> h = hist.apply("node", nid);
            if (h != null) {
                String key = side.equals("new") ? "first_seen" : "last_seen";
                d.put(key, h.get(key));
            }
        }
        return d;
    }

    private static List<Object> looseEdges(List<Model.Edge> edges, Model model, Set<String> touched) {
        List<Object> out = new ArrayList<>();
        for (Model.Edge e : edges) {
            if (touched.contains(e.src) || touched.contains(e.dst)) {
                continue;
            }
            boolean tech = false;
            for (String x : new String[] {e.src, e.dst}) {
                Model.Node n = model.nodes.get(x);
                if (n != null && n.type.equals("tech")) {
                    tech = true;
                }
            }
            if (tech) {
                continue;
            }
            out.add(map("from", labelOf(model, e.src), "edge", e.type.toLowerCase(), "to", labelOf(model, e.dst), "state", e.state, "evidence", evs(e.evidence, 3)));
        }
        return out;
    }

    private static String ev(List<Object> ids) {
        if (ids == null || ids.isEmpty()) {
            return "";
        }
        List<String> p = new ArrayList<>();
        ids.forEach(i -> p.add("ev_" + i));
        return "  " + String.join(", ", p);
    }

    private static String evNoPad(List<Object> ids) {
        List<String> p = new ArrayList<>();
        ids.forEach(i -> p.add("ev_" + i));
        return String.join(", ", p);
    }

    private static String tag(Map<String, Object> m) {
        if (m == null || m.isEmpty()) {
            return "?";
        }
        String s = "build " + m.get("id");
        Object at = m.get("built_at");
        if (at != null && !String.valueOf(at).isEmpty()) {
            String t = String.valueOf(at);
            s += " (" + t.substring(0, Math.min(10, t.length())) + ")";
        }
        return s;
    }

    @SuppressWarnings("unchecked")
    public static String formatText(Map<String, Object> d) {
        Map<String, Object> s = (Map<String, Object>) d.get("summary");
        List<String> out = new ArrayList<>();
        out.add(d.get("app") + ": " + tag((Map<String, Object>) d.get("from")) + " → " + tag((Map<String, Object>) d.get("to")));
        if (Boolean.TRUE.equals(d.get("same"))) {
            out.add("No drift between these two builds.");
            return String.join("\n", out);
        }
        out.add("  " + s.get("new_workflows") + " new workflow(s) · " + s.get("new") + " new · " + s.get("changed") + " changed · " + s.get("gone") + " gone"
                + ((Long) s.get("gone_workflows") > 0 ? " · " + s.get("gone_workflows") + " removed workflow(s)" : ""));
        List<Map<String, Object>> wfNew = new ArrayList<>();
        List<Map<String, Object>> wfGone = new ArrayList<>();
        for (Object o : (List<Object>) d.get("workflows")) {
            Map<String, Object> w = (Map<String, Object>) o;
            (w.get("kind").equals("new_workflow") ? wfNew : wfGone).add(w);
        }
        if (!wfNew.isEmpty()) {
            out.add("");
            out.add("NEW WORKFLOWS (connected additions, one line each)");
            for (Map<String, Object> w : wfNew) {
                out.add("  ▸ " + w.get("title") + "  (" + ((List<?>) w.get("nodes")).size() + " things: " + w.get("summary") + ")");
                out.add("      " + String.join(" → ", ((List<Object>) w.get("chain")).stream().map(String::valueOf).toList()));
                for (Object lo : (List<Object>) w.get("links")) {
                    Map<String, Object> l = (Map<String, Object>) lo;
                    out.add("      " + l.get("node") + " " + l.get("edge") + " " + (l.get("from") != null ? l.get("from") : l.get("to")));
                }
                if (!((List<?>) w.get("evidence")).isEmpty()) {
                    out.add("      " + evNoPad((List<Object>) w.get("evidence")));
                }
            }
        }
        List<Object> changed = (List<Object>) d.get("changed");
        if (!changed.isEmpty()) {
            out.add("");
            out.add("CHANGED");
            for (Object co : changed) {
                Map<String, Object> c = (Map<String, Object>) co;
                out.add("  ~ " + c.get("label") + "  [" + c.get("kind") + "]");
                for (Object xo : (List<Object>) c.get("changes")) {
                    out.add("      " + ((Map<String, Object>) xo).get("summary"));
                }
                if (!((List<?>) c.get("evidence")).isEmpty()) {
                    out.add("      " + evNoPad((List<Object>) c.get("evidence")));
                }
            }
        }
        Map<String, Object> n = (Map<String, Object>) d.get("new");
        if (!((List<?>) n.get("nodes")).isEmpty() || !((List<?>) n.get("stack")).isEmpty() || !((List<?>) n.get("edges")).isEmpty()) {
            out.add("");
            out.add("NEW");
            for (Object xo : (List<Object>) n.get("nodes")) {
                Map<String, Object> x = (Map<String, Object>) xo;
                out.add("  + " + x.get("label") + "  [" + x.get("kind") + "]" + ev((List<Object>) x.get("evidence")));
            }
            for (Object xo : (List<Object>) n.get("stack")) {
                Map<String, Object> x = (Map<String, Object>) xo;
                out.add("  + " + x.get("label") + "  [" + x.get("category") + "]" + ev((List<Object>) x.get("evidence")));
            }
            for (Object xo : (List<Object>) n.get("edges")) {
                Map<String, Object> x = (Map<String, Object>) xo;
                out.add("  + " + x.get("from") + " " + x.get("edge") + " " + x.get("to") + ev((List<Object>) x.get("evidence")));
            }
        }
        Map<String, Object> g = (Map<String, Object>) d.get("gone");
        if (!((List<?>) g.get("nodes")).isEmpty() || !((List<?>) g.get("stack")).isEmpty() || !((List<?>) g.get("edges")).isEmpty() || !wfGone.isEmpty()) {
            out.add("");
            out.add("GONE (evidence is from the older build)");
            for (Map<String, Object> w : wfGone) {
                out.add("  - " + w.get("title") + "  (" + ((List<?>) w.get("nodes")).size() + " things: " + w.get("summary") + ")");
            }
            for (Object xo : (List<Object>) g.get("nodes")) {
                Map<String, Object> x = (Map<String, Object>) xo;
                String seen = x.get("last_seen") != null ? "  last seen " + String.valueOf(x.get("last_seen")).substring(0, 10) : "";
                out.add("  - " + x.get("label") + "  [" + x.get("kind") + "]" + seen);
            }
            for (Object xo : (List<Object>) g.get("stack")) {
                Map<String, Object> x = (Map<String, Object>) xo;
                out.add("  - " + x.get("label") + "  [" + x.get("category") + "]");
            }
            for (Object xo : (List<Object>) g.get("edges")) {
                Map<String, Object> x = (Map<String, Object>) xo;
                out.add("  - " + x.get("from") + " " + x.get("edge") + " " + x.get("to"));
            }
        }
        return String.join("\n", out);
    }
}
