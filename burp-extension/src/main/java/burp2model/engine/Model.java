package burp2model.engine;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;

/** The six-layer model: nodes, edges, unknowns, evidence. A port of model.py's data structures. */
public final class Model {
    public static final int SCHEMA = 2;

    public static final class Node {
        public final String id;
        public final String type;
        public final int layer;
        public final String label;
        public final Map<String, Object> attrs = new LinkedHashMap<>();
        public final List<Integer> evidence = new ArrayList<>();
        public final List<String> roles = new ArrayList<>();
        private java.util.Set<Integer> evSet;

        /** Add an evidence id once; a set alongside the list keeps this fast for nodes with thousands of requests. */
        boolean addEvidence(int idx) {
            if (evSet == null) {
                evSet = new java.util.HashSet<>(evidence);
            }
            if (!evSet.add(idx)) {
                return false;
            }
            evidence.add(idx);
            return true;
        }

        Node(String id, String type, int layer, String label) {
            this.id = id;
            this.type = type;
            this.layer = layer;
            this.label = label;
        }

        /** A node that is not part of any model: the map's stand-in for a group of nodes. */
        public static Node standIn(String id, String type, int layer, String label) {
            return new Node(id, type, layer, label);
        }

        @SuppressWarnings("unchecked")
        public List<Object> list(String key) {
            return (List<Object>) attrs.get(key);
        }

        public String str(String key) {
            Object v = attrs.get(key);
            return v == null ? null : String.valueOf(v);
        }

        public Map<String, Object> toMap() {
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("id", id);
            m.put("type", type);
            m.put("layer", (long) layer);
            m.put("label", label);
            m.put("attrs", attrs);
            m.put("evidence", evidence);
            m.put("roles", roles);
            return m;
        }
    }

    public static final class Edge {
        public final String src;
        public final String dst;
        public final String type;
        public final String state;
        public final List<Integer> evidence = new ArrayList<>();
        private java.util.Set<Integer> evSet;

        boolean addEvidence(int idx) {
            if (evSet == null) {
                evSet = new java.util.HashSet<>(evidence);
            }
            if (!evSet.add(idx)) {
                return false;
            }
            evidence.add(idx);
            return true;
        }

        Edge(String src, String dst, String type, String state) {
            this.src = src;
            this.dst = dst;
            this.type = type;
            this.state = state;
        }

        public Map<String, Object> toMap() {
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("src", src);
            m.put("dst", dst);
            m.put("type", type);
            m.put("state", state);
            m.put("evidence", evidence);
            return m;
        }
    }

    public record Unknown(String type, String entity, List<String> weKnow, String weDontKnow, String nextStep) {
        public Map<String, Object> toMap() {
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("type", type);
            m.put("entity", entity);
            m.put("we_know", weKnow);
            m.put("we_dont_know", weDontKnow);
            m.put("next_step", nextStep);
            return m;
        }
    }

    public String name;
    public final Map<String, Node> nodes = new LinkedHashMap<>();
    public List<Edge> edges = new ArrayList<>();
    public final List<Unknown> unknowns = new ArrayList<>();
    public final Set<String> roles = new TreeSet<>();
    public final List<Map<String, Object>> secrets = new ArrayList<>();
    public List<String> scope = new ArrayList<>();
    public Map<String, Object> stats = new LinkedHashMap<>();
    public List<Map<String, Object>> stack = new ArrayList<>();
    public final EvidenceLog evidenceLog = new EvidenceLog();
    Map<String, Edge> edgeIndex = new LinkedHashMap<>();
    final Map<String, Map<String, Object>> secretIndex = new LinkedHashMap<>();
    /** Builder's answer to "is this host in scope" for each host, for this model's scope; never saved. */
    final Map<String, Boolean> scopeCache = new java.util.HashMap<>();

    public Model(String name) {
        this.name = name;
    }

    /**
     * A deep copy of what pass 1 of a build fills in (nodes, edges, roles, secrets, scope, the evidence log), so the
     * later passes can work on the copy while the original takes the next requests. Evidence entries are shared:
     * nothing changes them once logged.
     */
    Model copyObserved() {
        Model c = new Model(name);
        for (Node n : nodes.values()) {
            Node d = new Node(n.id, n.type, n.layer, n.label);
            n.attrs.forEach((k, v) -> d.attrs.put(k, deepCopy(v)));
            d.evidence.addAll(n.evidence);
            d.roles.addAll(n.roles);
            c.nodes.put(d.id, d);
        }
        for (Edge e : edges) {
            Edge d = new Edge(e.src, e.dst, e.type, e.state);
            d.evidence.addAll(e.evidence);
            c.edges.add(d);
            c.edgeIndex.put(edgeKey(d.src, d.dst, d.type), d);
        }
        c.roles.addAll(roles);
        for (Map<String, Object> s : secrets) {
            @SuppressWarnings("unchecked")
            Map<String, Object> d = (Map<String, Object>) deepCopy(s);
            c.secrets.add(d);
            c.secretIndex.put(d.get("kind") + "\u0000" + d.get("hmac_12"), d);
        }
        c.scope = new ArrayList<>(scope);
        c.stats = new LinkedHashMap<>(stats);
        c.evidenceLog.share(evidenceLog);
        c.unknowns.addAll(unknowns);
        c.stack = new ArrayList<>(stack);
        return c;
    }

    private static Object deepCopy(Object v) {
        if (v instanceof Map<?, ?> m) {
            Map<Object, Object> out = new LinkedHashMap<>();
            m.forEach((k, x) -> out.put(k, deepCopy(x)));
            return out;
        }
        if (v instanceof List<?> l) {
            List<Object> out = new ArrayList<>(l.size());
            l.forEach(x -> out.add(deepCopy(x)));
            return out;
        }
        return v;
    }

    public Node addNode(String id, String type, int layer, String label, Object... attrKv) {
        Node n = nodes.get(id);
        if (n == null) {
            n = new Node(id, type, layer, label);
            for (int i = 0; i + 1 < attrKv.length; i += 2) {
                n.attrs.put((String) attrKv[i], attrKv[i + 1]);
            }
            nodes.put(id, n);
        }
        return n;
    }

    public void evidence(String nodeId, int idx) {
        Node n = nodes.get(nodeId);
        if (n != null) {
            n.addEvidence(idx);
        }
    }

    static String edgeKey(String src, String dst, String type) {
        return src + "\u0000" + dst + "\u0000" + type;
    }

    public void addEdge(String src, String dst, String type, String state, Integer idx) {
        String key = edgeKey(src, dst, type);
        Edge e = edgeIndex.get(key);
        if (e != null) {
            if (idx != null) {
                e.addEvidence(idx);
            }
            return;
        }
        e = new Edge(src, dst, type, state);
        if (idx != null) {
            e.evidence.add(idx);
        }
        edgeIndex.put(key, e);
        edges.add(e);
    }

    public Map<String, Object> counts() {
        Map<String, Integer> byType = new LinkedHashMap<>();
        Map<String, Integer> states = new LinkedHashMap<>();
        for (Node n : nodes.values()) {
            byType.merge(n.type, 1, Integer::sum);
            if (n.type.equals("endpoint")) {
                String st = n.str("api_state");
                states.merge(st == null ? "UNKNOWN" : st, 1, Integer::sum);
            }
        }
        Map<String, Object> c = new LinkedHashMap<>();
        c.put("nodes", (long) nodes.size());
        c.put("edges", (long) edges.size());
        for (String[] kv : new String[][] {{"hosts", "host"}, {"routes", "route"}, {"scripts", "script"},
            {"endpoints", "endpoint"}, {"parameters", "parameter"}, {"operations", "operation"},
            {"third_parties", "third_party"}, {"auth", "auth"}, {"cookies", "cookie"}, {"tech", "tech"}}) {
            c.put(kv[0], (long) byType.getOrDefault(kv[1], 0));
        }
        c.put("roles", (long) roles.size());
        c.put("unknowns", (long) unknowns.size());
        Map<String, Object> st = new LinkedHashMap<>();
        states.forEach((k, v) -> st.put(k, (long) v));
        c.put("api_state", st);
        c.put("secrets", (long) secrets.size());
        return c;
    }

    public Map<String, Object> toMap() {
        Map<String, Object> d = new LinkedHashMap<>();
        d.put("tool", "burp2model");
        d.put("schema", (long) SCHEMA);
        d.put("app", name);
        d.put("scope", scope);
        d.put("counts", counts());
        d.put("stats", stats);
        List<Object> ns = new ArrayList<>();
        nodes.values().forEach(n -> ns.add(n.toMap()));
        d.put("nodes", ns);
        List<Object> es = new ArrayList<>();
        edges.forEach(e -> es.add(e.toMap()));
        d.put("edges", es);
        List<Object> us = new ArrayList<>();
        unknowns.forEach(u -> us.add(u.toMap()));
        d.put("unknowns", us);
        d.put("roles", new ArrayList<>(roles));
        d.put("secrets", secrets);
        d.put("evidence", evidenceLog);
        d.put("stack", stack);
        return d;
    }

    /** Rebuild a model from model.json data (used to load saved builds). */
    @SuppressWarnings("unchecked")
    public static Model fromMap(Map<String, Object> d) {
        Model m = new Model((String) d.get("app"));
        for (Object o : (List<Object>) d.get("nodes")) {
            Map<String, Object> nd = (Map<String, Object>) o;
            Node n = new Node((String) nd.get("id"), (String) nd.get("type"), ((Number) nd.get("layer")).intValue(), (String) nd.get("label"));
            n.attrs.putAll((Map<String, Object>) nd.get("attrs"));
            for (Object e : (List<Object>) nd.get("evidence")) {
                n.evidence.add(((Number) e).intValue());
            }
            for (Object r : (List<Object>) nd.get("roles")) {
                n.roles.add((String) r);
            }
            m.nodes.put(n.id, n);
        }
        for (Object o : (List<Object>) d.get("edges")) {
            Map<String, Object> ed = (Map<String, Object>) o;
            Edge e = new Edge((String) ed.get("src"), (String) ed.get("dst"), (String) ed.get("type"), (String) ed.get("state"));
            for (Object x : (List<Object>) ed.get("evidence")) {
                e.evidence.add(((Number) x).intValue());
            }
            m.edges.add(e);
            m.edgeIndex.put(edgeKey(e.src, e.dst, e.type), e);
        }
        for (Object o : (List<Object>) d.get("unknowns")) {
            Map<String, Object> u = (Map<String, Object>) o;
            List<String> know = new ArrayList<>();
            for (Object k : (List<Object>) u.get("we_know")) {
                know.add((String) k);
            }
            m.unknowns.add(new Unknown((String) u.get("type"), (String) u.get("entity"), know, (String) u.get("we_dont_know"), (String) u.get("next_step")));
        }
        for (Object r : (List<Object>) d.get("roles")) {
            m.roles.add((String) r);
        }
        m.secrets.addAll((List<Map<String, Object>>) d.get("secrets"));
        m.scope = new ArrayList<>((List<String>) d.get("scope"));
        m.stats = (Map<String, Object>) d.get("stats");
        m.evidenceLog.addAll((List<Map<String, Object>>) d.get("evidence"));
        m.stack = new ArrayList<>((List<Map<String, Object>>) d.get("stack"));
        return m;
    }

    static Set<String> set() {
        return new LinkedHashSet<>();
    }
}
