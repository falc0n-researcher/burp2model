package burp2model.ui;

import burp2model.engine.Model;
import burp2model.ui.GraphPanel.E;
import burp2model.ui.GraphPanel.V;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * What the map draws for a model: the nodes the toggles show, a large map's path areas folded into groups, and one
 * edge per kind of link between what is drawn. No Swing and no layout: the positions come from MapLayout.
 */
final class GraphData {
    private GraphData() {}

    /** Large maps (over this many shown nodes) show each host's path areas as groups. */
    static final int GROUP_ABOVE = 150;

    /** The graph to draw. byId maps every shown node's id (members of closed groups too) to what draws it. */
    record Graph(List<V> vs, List<E> es, Map<String, V> byId, Map<String, List<Model.Node>> groupMembers, Map<String, String> openGroupOf,
                 int shown) {}

    /**
     * Build the graph: `types` are the node types switched on, `codeOnly` keeps endpoints the code names but nothing
     * called (and what names them), `group` folds large maps into groups except the `expanded` ones.
     */
    static Graph build(Model model, Set<String> types, boolean codeOnly, boolean group, Set<String> expanded) {
        List<V> vs = new ArrayList<>();
        List<E> es = new ArrayList<>();
        Map<String, V> byId = new HashMap<>();
        Map<String, List<Model.Node>> groupMembers = new HashMap<>();
        Map<String, String> openGroupOf = new HashMap<>();
        Set<String> keep = codeOnly ? codeNamed(model) : null;
        List<Model.Node> shown = new ArrayList<>();
        for (Model.Node n : model.nodes.values()) {
            if (types.contains(n.type) && (keep == null || keep.contains(n.id))) {
                shown.add(n);
            }
        }
        boolean grouping = group && keep == null && shown.size() > GROUP_ABOVE;
        Map<String, List<Model.Node>> groups = new LinkedHashMap<>();
        if (grouping) {
            for (Model.Node n : shown) {
                String k = groupKey(n, model);
                if (k != null) {
                    groups.computeIfAbsent(k, x -> new ArrayList<>()).add(n);
                }
            }
        }
        for (Model.Node n : shown) {
            String k = grouping ? groupKey(n, model) : null;
            List<Model.Node> g = k == null ? null : groups.get(k);
            if (g != null && g.size() > 1 && !expanded.contains(k)) {
                String gid = "group:" + k;
                V gv = byId.get(gid);
                if (gv == null) {
                    gv = standIn(gid, k, g);
                    vs.add(gv);
                    byId.put(gid, gv);
                    groupMembers.put(gid, g);
                }
                byId.put(n.id, gv);                       // edges to a member go to its group
                continue;
            }
            if (g != null && g.size() > 1) {
                openGroupOf.put(n.id, k);
            }
            V v = new V(n);
            vs.add(v);
            byId.put(n.id, v);
        }
        Set<String> edgeSeen = new HashSet<>();
        for (Model.Edge e : model.edges) {
            V a = byId.get(e.src);
            V b = byId.get(e.dst);
            // inside one group there is nothing to draw; between groups, one line per kind of link
            if (a != null && b != null && a != b && edgeSeen.add(a.node.id + "\u0000" + b.node.id + "\u0000" + e.state + "\u0000" + e.type)) {
                E ed = new E(a, b, e.state, e.type);
                es.add(ed);
                a.edges.add(ed);
                b.edges.add(ed);
                a.degree++;
                b.degree++;
                a.nbrs.add(b);
                b.nbrs.add(a);
            }
        }
        for (V v : vs) {
            v.r = v.members > 0 ? 7 + Math.min(9, Math.sqrt(v.members) * 1.2) : 4 + Math.min(10, Math.sqrt(v.degree) * 1.6);
        }
        return new Graph(vs, es, byId, groupMembers, openGroupOf, shown.size());
    }

    /** Endpoints named in code and never called, and whatever references them. */
    private static Set<String> codeNamed(Model model) {
        Set<String> keep = new HashSet<>();
        for (Model.Node n : model.nodes.values()) {
            if ("STATIC_ONLY".equals(n.attrs.get("api_state"))) {
                keep.add(n.id);
            }
        }
        for (Model.Edge e : model.edges) {
            if (keep.contains(e.dst) && e.type.equals("REFERENCES")) {
                keep.add(e.src);
            }
        }
        return keep;
    }

    /** The model's nodes and edges as a fingerprint: the same structure needs no new layout. */
    static long structureOf(Model m) {
        long h = 0xcbf29ce484222325L;
        for (Model.Node n : m.nodes.values()) {
            h = (h ^ n.id.hashCode()) * 0x100000001b3L;
            h = (h ^ n.type.hashCode()) * 0x100000001b3L;
            h = (h ^ String.valueOf(n.attrs.get("api_state")).hashCode()) * 0x100000001b3L;
        }
        for (Model.Edge e : m.edges) {
            h = (h ^ e.src.hashCode()) * 0x100000001b3L;
            h = (h ^ e.dst.hashCode()) * 0x100000001b3L;
            h = (h ^ e.type.hashCode()) * 0x100000001b3L;
            h = (h ^ String.valueOf(e.state).hashCode()) * 0x100000001b3L;
        }
        return h ^ ((long) m.nodes.size() << 32) ^ m.edges.size();
    }

    /**
     * Which group a node belongs to on a large map: endpoints, pages and their parameters by host and first path
     * segment, scripts by host. Hosts, third parties, tech, roles and the rest stay on their own (null).
     */
    static String groupKey(Model.Node n, Model m) {
        switch (n.type) {
            case "endpoint", "route", "operation" -> {
                String host = String.valueOf(n.attrs.getOrDefault("host", ""));
                String path = String.valueOf(n.attrs.getOrDefault("path", "/"));
                int q = path.indexOf('?');
                path = q < 0 ? path : path.substring(0, q);
                String[] segs = path.split("/");
                String first = "";
                for (String s : segs) {
                    if (!s.isEmpty()) {
                        first = s;
                        break;
                    }
                }
                return host + " /" + first;
            }
            case "parameter" -> {
                // "param:<endpoint id>:<name>": with its endpoint's group
                int c = n.id.lastIndexOf(':');
                Model.Node owner = c > 6 ? m.nodes.get(n.id.substring(6, c)) : null;
                return owner == null || owner.type.equals("parameter") ? null : groupKey(owner, m);
            }
            case "script" -> {
                Object h = n.attrs.get("host");
                if (h == null && n.id.startsWith("script:")) {
                    int slash = n.id.indexOf('/', 7);              // "script:<host><path>"
                    h = slash > 7 ? n.id.substring(7, slash) : n.id.substring(7);
                }
                return (h == null ? "" : h) + " scripts";
            }
            default -> {
                return null;
            }
        }
    }

    /** The stand-in drawn for a closed group: its name, size, and the evidence of its first members. */
    private static V standIn(String gid, String key, List<Model.Node> members) {
        Map<String, Integer> kinds = new HashMap<>();
        int layer = Integer.MAX_VALUE;
        for (Model.Node n : members) {
            kinds.merge(n.type, 1, Integer::sum);
            layer = Math.min(layer, n.layer);
        }
        String kind = kinds.entrySet().stream().max(Map.Entry.comparingByValue()).map(Map.Entry::getKey).orElse("endpoint");
        Model.Node n = Model.Node.standIn(gid, "group", layer, key + "  (" + members.size() + ")");
        n.attrs.put("members", (long) members.size());
        n.attrs.put("kind", kind);
        Set<Integer> ev = new java.util.TreeSet<>();
        for (Model.Node x : members) {
            ev.addAll(x.evidence);
            if (ev.size() > 300) {
                break;
            }
        }
        n.evidence.addAll(ev);
        V v = new V(n);
        v.color = Theme.type(kind);
        v.members = members.size();
        return v;
    }

    /** How much room an opened group of n members takes: a disc that fits them about 26 apart. */
    static double openRadius(int n) {
        return 30 + 15 * Math.sqrt(n);
    }
}
