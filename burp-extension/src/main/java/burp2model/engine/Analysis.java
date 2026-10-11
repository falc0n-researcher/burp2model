package burp2model.engine;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/** Ranked leads and role comparison: ports of the report's "To check" scoring and model.cross_role. */
public final class Analysis {
    private Analysis() {}

    public record Signal(String sev, String title, String why, String next) {}

    /** One endpoint with every reason it is worth a look; `sev` is the strongest signal's. */
    public record Lead(String sev, Model.Node endpoint, List<Signal> signals) {}

    private static int rank(String sev) {
        return sev.equals("hot") ? 0 : sev.equals("warn") ? 1 : 2;
    }

    @SuppressWarnings("unchecked")
    public static List<Lead> leads(Model m) {
        List<Model.Node> eps = new ArrayList<>();
        for (Model.Node n : m.nodes.values()) {
            if (n.type.equals("endpoint")) {
                eps.add(n);
            }
        }
        long staticN = eps.stream().filter(n -> "STATIC_ONLY".equals(n.attrs.get("api_state"))).count();
        List<Lead> out = new ArrayList<>();
        for (Model.Node e : eps) {
            List<Signal> sig = new ArrayList<>();
            String path = String.valueOf(e.attrs.getOrDefault("path", ""));
            boolean privileged = Builder.PRIV_RE.matcher(path).find();
            if (!privileged && Builder.TELEMETRY_RE.matcher(path).find()) {
                continue;                                  // a beacon is traffic, not a lead
            }
            long requests = ((Number) e.attrs.getOrDefault("requests", 0L)).longValue();
            List<Object> creds = (List<Object>) e.attrs.getOrDefault("credentials", List.of());
            List<Object> statuses = (List<Object>) e.attrs.getOrDefault("statuses", List.of());
            String method = String.valueOf(e.attrs.getOrDefault("method", "*"));
            if ("STATIC_ONLY".equals(e.attrs.get("api_state"))) {
                sig.add(new Signal(staticN > 12 && !privileged ? "info" : "hot", "Referenced in code, never called",
                        "The client code names this endpoint but no request to it was captured, so nobody has walked this path.",
                        "Request it directly in an authorised session and observe the response."));
            }
            if (privileged && requests > 0) {
                sig.add(new Signal("hot", "Privileged-looking path was reached",
                        "The path matches an admin/internal pattern and appears in the capture"
                                + (e.roles.isEmpty() ? "" : " (roles: " + String.join(", ", e.roles) + ")") + ".",
                        "Confirm the response was meant for the caller; replay across accounts."));
            } else if (privileged) {
                sig.add(new Signal("hot", "Privileged-looking path referenced",
                        "The path matches an admin/internal pattern; it was only referenced in code, never requested.",
                        "Request it in an authorised session and observe who is allowed in."));
            }
            if (!statuses.isEmpty() && statuses.stream().allMatch(s -> ((Number) s).longValue() >= 400)) {
                sig.add(new Signal("warn", "Only ever returned errors",
                        "Every observed status was " + String.join(", ", statuses.stream().map(String::valueOf).toList())
                                + " so behaviour with valid input or auth has not been seen.",
                        "Exercise the feature normally in an authorised session."));
            }
            if (((Number) e.attrs.getOrDefault("anonymous_requests", 0L)).longValue() > 0 && !creds.isEmpty()) {
                sig.add(new Signal("warn", "Seen with and without credentials",
                        "Some requests carried a credential and some did not, so it is unclear whether auth is required.",
                        "Replay it unauthenticated and compare the response."));
            }
            if (requests > 0 && !method.equals("*") && !method.equals("GET") && !method.equals("HEAD") && !method.equals("null") && creds.isEmpty()) {
                sig.add(new Signal("info", "State-changing call without an observed credential",
                        "A " + method + " request with no credential seen on it.", "Check whether it is meant to require authentication."));
            }
            if (sig.isEmpty()) {
                continue;
            }
            sig.sort(Comparator.comparingInt(s -> rank(s.sev())));
            out.add(new Lead(sig.get(0).sev(), e, sig));
        }
        out.sort(Comparator.comparingInt((Lead l) -> rank(l.sev())).thenComparing((Lead l) -> -l.signals().size())
                .thenComparing(l -> ((Number) l.endpoint().attrs.getOrDefault("requests", 0L)).longValue() > 0 ? 0 : 1)
                .thenComparing(l -> l.endpoint().label));
        return out;
    }

    private static boolean ok(Object statuses) {
        if (statuses instanceof List<?> l) {
            return l.stream().anyMatch(s -> ((Number) s).longValue() >= 200 && ((Number) s).longValue() < 300);
        }
        return false;
    }

    /** Compare what a low and a high role reached. Output is hypotheses, never findings. */
    @SuppressWarnings("unchecked")
    public static Map<String, Object> crossRole(Model m, String low, String high) {
        Map<Integer, String> evRole = new LinkedHashMap<>();
        for (Map<String, Object> e : m.evidenceLog.metas()) {
            evRole.put(((Number) e.get("id")).intValue(), (String) e.get("role"));
        }
        List<Map<String, Object>> highOnly = new ArrayList<>();
        List<Map<String, Object>> lowPriv = new ArrayList<>();
        List<Map<String, Object>> shared = new ArrayList<>();
        for (Model.Node node : m.nodes.values()) {
            if (!node.type.equals("endpoint") && !node.type.equals("operation")) {
                continue;
            }
            boolean rl = node.roles.contains(low);
            boolean rh = node.roles.contains(high);
            String path = String.valueOf(node.attrs.getOrDefault("path", node.label));
            Map<String, Object> sbr = node.attrs.get("status_by_role") instanceof Map<?, ?> x ? (Map<String, Object>) x : Map.of();
            String prefer = rl ? low : high;
            List<Integer> ids = new ArrayList<>();
            for (int i : node.evidence) {
                if (prefer.equals(evRole.get(i))) {
                    ids.add(i);
                }
            }
            List<Integer> use = ids.isEmpty() ? node.evidence : ids;
            Map<String, Object> entry = new LinkedHashMap<>();
            entry.put("endpoint", node.label);
            entry.put("id", node.id);
            entry.put("evidence", new ArrayList<>(use.subList(0, Math.min(3, use.size()))));
            Map<String, Object> st = new LinkedHashMap<>();
            for (String r : new String[] {low, high}) {
                if (sbr.containsKey(r)) {
                    st.put(r, sbr.get(r));
                }
            }
            entry.put("statuses", st);
            if (rh && !rl) {
                entry.put("kind", "high_only");
                entry.put("unknown", "whether '" + low + "' can reach it");
                entry.put("next", "replay as '" + low + "' and compare with '" + high + "'");
                highOnly.add(entry);
            } else if (rl && Builder.PRIV_RE.matcher(path).find()) {
                entry.put("kind", "low_reached_privileged");
                entry.put("unknown", "whether the low-role response was authorised or a leak");
                entry.put("next", "compare '" + low + "' and '" + high + "' response bodies");
                lowPriv.add(entry);
            } else if (rl && rh && ok(sbr.get(low)) && ok(sbr.get(high))) {
                entry.put("kind", "shared_same_success");
                entry.put("unknown", "whether both roles see the same data");
                entry.put("next", "diff the two responses for role-specific fields");
                shared.add(entry);
            }
        }
        Comparator<Map<String, Object>> byName = Comparator.comparing(e -> (String) e.get("endpoint"));
        highOnly.sort(byName);
        lowPriv.sort(byName);
        shared.sort(byName);
        Map<String, Object> r = new LinkedHashMap<>();
        r.put("low", low);
        r.put("high", high);
        r.put("roles_present", new ArrayList<>(m.roles));
        r.put("low_reached_privileged", lowPriv);
        r.put("high_only", highOnly);
        r.put("shared_same_success", shared);
        return r;
    }

    private static final Map<String, Integer> GAP_WEIGHT = Map.of("AUTHENTICATED_STATE_NOT_OBSERVED", 5, "API_PURPOSE_UNKNOWN", 4,
            "ROLE_NOT_TAGGED", 4, "AUTHORIZATION_UNKNOWN", 3, "ENDPOINT_ONLY_ERRORED", 2, "SCRIPT_PARTIALLY_SCANNED", 2, "CAPTURE_ITEMS_SKIPPED", 1);

    /** The model's unknowns ranked by how much resolving each improves the picture, each with the smallest next step. */
    public static List<Map<String, Object>> gaps(Model m) {
        java.util.Set<String> priv = new java.util.HashSet<>();
        for (Model.Node n : m.nodes.values()) {
            if (n.type.equals("endpoint") && Builder.PRIV_RE.matcher(String.valueOf(n.attrs.getOrDefault("path", ""))).find()) {
                priv.add(n.label);
            }
        }
        List<Map<String, Object>> out = new ArrayList<>();
        for (Model.Unknown u : m.unknowns) {
            Model.Node en = m.nodes.get(u.entity());
            String ent = en != null ? en.label : u.entity().substring(u.entity().lastIndexOf(':') + 1);
            int w = GAP_WEIGHT.getOrDefault(u.type(), 1) + (priv.contains(ent) ? 1 : 0);
            Map<String, Object> g = new LinkedHashMap<>();
            g.put("leverage", (long) w);
            g.put("type", u.type());
            g.put("entity", ent);
            g.put("unknown", u.weDontKnow());
            g.put("we_know", u.weKnow());
            g.put("next", u.nextStep());
            out.add(g);
        }
        out.sort(Comparator.comparingLong((Map<String, Object> g) -> -((Long) g.get("leverage"))).thenComparing(g -> (String) g.get("type"))
                .thenComparing(g -> (String) g.get("entity")));
        return out;
    }

    /** The most connected nodes: the load-bearing parts of the app. */
    public static List<Map<String, Object>> hubs(Model m, int top) {
        Map<String, Integer> deg = new java.util.HashMap<>();
        for (Model.Edge e : m.edges) {
            deg.merge(e.src, 1, Integer::sum);
            deg.merge(e.dst, 1, Integer::sum);
        }
        List<Map<String, Object>> out = new ArrayList<>();
        deg.entrySet().stream().filter(e -> m.nodes.containsKey(e.getKey()) && !m.nodes.get(e.getKey()).type.equals("host"))
                .sorted((a, b) -> b.getValue() - a.getValue()).limit(top).forEach(e -> {
                    Model.Node n = m.nodes.get(e.getKey());
                    Map<String, Object> h = new LinkedHashMap<>();
                    h.put("degree", (long) e.getValue());
                    h.put("type", n.type);
                    h.put("label", n.label);
                    h.put("id", n.id);
                    out.add(h);
                });
        return out;
    }
}
