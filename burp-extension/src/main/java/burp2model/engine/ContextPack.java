package burp2model.engine;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.TreeSet;

/**
 * "Copy for AI": the model as a rules-first package for a language model of your own, plus the prompt around it.
 * Structure, not bytes: every id the package cites resolves in its evidence table. A port of context_package().
 */
public final class ContextPack {
    private ContextPack() {}

    static final List<String> RULES = List.of(
            "Cite an evidence id (ev_N) for every claim; each id is resolved in `evidence`.",
            "Never name an endpoint, route or parameter that is not in this package.",
            "State unknowns explicitly; do not guess authorization behaviour.",
            "Output hypotheses and the evidence needed to test them, never findings or payloads.",
            "Treat an absence in this package as an absence in the capture, never in the target.",
            "REFERENCES edges are INFERRED from code; only OBSERVED facts happened in traffic.");

    private static int priority(Model.Node n) {
        String path = String.valueOf(n.attrs.getOrDefault("path", ""));
        if ("STATIC_ONLY".equals(n.attrs.get("api_state"))) {
            return 0;
        }
        if (Builder.PRIV_RE.matcher(path).find()) {
            return 1;
        }
        if (!n.roles.isEmpty()) {
            return 2;
        }
        List<?> creds = n.attrs.get("credentials") instanceof List<?> l ? l : List.of();
        if (!creds.isEmpty() && ((Number) n.attrs.getOrDefault("anonymous_requests", 0L)).longValue() > 0) {
            return 3;
        }
        Object method = n.attrs.get("method");
        if (method != null && !method.equals("GET") && !method.equals("HEAD")) {
            return 4;
        }
        return 5;
    }

    private static List<Object> evList(Model.Node n, int k, Set<Integer> cited) {
        List<Object> out = new ArrayList<>();
        for (int i = 0; i < Math.min(k, n.evidence.size()); i++) {
            cited.add(n.evidence.get(i));
            out.add("ev_" + n.evidence.get(i));
        }
        return out;
    }

    private static Map<String, Object> map(Object... kv) {
        Map<String, Object> m = new LinkedHashMap<>();
        for (int i = 0; i + 1 < kv.length; i += 2) {
            m.put((String) kv[i], kv[i + 1]);
        }
        return m;
    }

    private static String cov(int shown, int total) {
        return shown + "/" + total + (total > shown ? " (capped)" : "");
    }

    @SuppressWarnings("unchecked")
    public static Map<String, Object> pack(Model m, String lens, int cap) {
        Set<Integer> cited = new TreeSet<>();
        List<Model.Node> eps = new ArrayList<>();
        List<Model.Node> routes = new ArrayList<>();
        List<Model.Node> scripts = new ArrayList<>();
        List<Model.Node> tps = new ArrayList<>();
        for (Model.Node n : m.nodes.values()) {
            switch (n.type) {
                case "endpoint" -> eps.add(n);
                case "route" -> routes.add(n);
                case "script" -> scripts.add(n);
                case "third_party" -> tps.add(n);
                default -> {
                }
            }
        }
        if (lens.equals("auth")) {
            eps.removeIf(n -> n.roles.isEmpty() && (!(n.attrs.get("credentials") instanceof List<?> l) || l.isEmpty()));
        }
        if (!lens.equals("all")) {
            eps.sort(Comparator.comparingInt(ContextPack::priority).thenComparing(n -> n.label));
        }
        tps.sort(Comparator.comparingLong((Model.Node n) -> -((Number) n.attrs.getOrDefault("requests", 0L)).longValue()));

        Map<String, Map<String, List<String>>> rels = new LinkedHashMap<>();
        Map<String, Integer> refsOut = new LinkedHashMap<>();
        Map<String, List<String>> paramsOf = new LinkedHashMap<>();
        for (Model.Edge e : m.edges) {
            if (e.type.equals("REFERENCES")) {
                refsOut.merge(e.src, 1, Integer::sum);
            } else if (e.type.equals("USES_PARAMETER") && m.nodes.containsKey(e.dst)) {
                paramsOf.computeIfAbsent(e.src, k -> new ArrayList<>()).add(m.nodes.get(e.dst).label);
            }
            if (e.type.equals("REFERENCES") || e.type.equals("CALLS")) {
                Model.Node src = m.nodes.get(e.src);
                if (src != null) {
                    rels.computeIfAbsent(e.dst, k -> new LinkedHashMap<>())
                            .computeIfAbsent(e.type.equals("REFERENCES") ? "referenced_by" : "called_from", k -> new ArrayList<>()).add(src.label);
                }
            }
        }

        List<Object> endpoints = new ArrayList<>();
        for (Model.Node n : eps.subList(0, Math.min(cap, eps.size()))) {
            Map<String, Object> v = map("id", n.id, "type", n.type, "label", n.label, "api_state", n.attrs.get("api_state"), "evidence", evList(n, 3, cited));
            if (n.attrs.get("statuses") instanceof List<?> l && !l.isEmpty()) {
                v.put("statuses", l);
            }
            List<String> params = new ArrayList<>(new TreeSet<>(paramsOf.getOrDefault(n.id, List.of())));
            if (!params.isEmpty()) {
                v.put("params", params.subList(0, Math.min(12, params.size())));
            }
            if (!n.roles.isEmpty()) {
                v.put("reached_by", n.roles);
                v.put("status_by_role", n.attrs.getOrDefault("status_by_role", Map.of()));
            }
            if (n.attrs.get("credentials") instanceof List<?> l && !l.isEmpty()) {
                v.put("credentials", l);
                if (((Number) n.attrs.getOrDefault("anonymous_requests", 0L)).longValue() > 0) {
                    v.put("also_seen_without_credentials", true);
                }
            }
            rels.getOrDefault(n.id, Map.of()).forEach((k, vals) -> {
                List<String> u = new ArrayList<>(new TreeSet<>(vals));
                v.put(k, u.subList(0, Math.min(5, u.size())));
            });
            if (Boolean.FALSE.equals(n.attrs.get("method_known"))) {
                v.put("method", "unknown (static reference)");
            }
            endpoints.add(v);
        }
        List<Object> routeList = new ArrayList<>();
        for (Model.Node n : routes.subList(0, Math.min(cap, routes.size()))) {
            routeList.add(map("id", n.id, "type", n.type, "label", n.label, "evidence", evList(n, 3, cited)));
        }
        List<Object> scriptList = new ArrayList<>();
        for (Model.Node n : scripts.subList(0, Math.min(cap, scripts.size()))) {
            scriptList.add(map("id", n.id, "type", n.type, "label", n.label, "evidence", evList(n, 3, cited), "references", (long) refsOut.getOrDefault(n.id, 0)));
        }
        List<Object> tpList = new ArrayList<>();
        for (Model.Node n : tps.subList(0, Math.min(cap, tps.size()))) {
            tpList.add(map("id", n.id, "type", n.type, "label", n.label, "evidence", evList(n, 3, cited)));
        }
        List<Model.Unknown> us = new ArrayList<>(m.unknowns);
        us.sort(Comparator.comparing(u -> u.type().equals("AUTHORIZATION_UNKNOWN")));
        List<Object> unknowns = new ArrayList<>();
        for (Model.Unknown u : us.subList(0, Math.min(cap, us.size()))) {
            Model.Node en = m.nodes.get(u.entity());
            unknowns.add(map("type", u.type(), "entity", en != null ? en.label : u.entity().substring(u.entity().lastIndexOf(':') + 1),
                    "we_know", u.weKnow(), "we_dont_know", u.weDontKnow(), "next", u.nextStep()));
        }
        List<Object> auth = new ArrayList<>();
        List<Object> cookies = new ArrayList<>();
        for (Model.Node n : m.nodes.values()) {
            if (n.type.equals("auth")) {
                auth.add(map("id", n.id, "type", n.type, "label", n.label, "evidence", evList(n, 3, cited)));
            } else if (n.type.equals("cookie")) {
                cookies.add(map("id", n.id, "type", n.type, "label", n.label, "evidence", evList(n, 3, cited), "httponly", n.attrs.get("httponly"),
                        "secure", n.attrs.get("secure"), "samesite", n.attrs.get("samesite")));
            }
        }
        List<Object> stack = new ArrayList<>();
        for (Map<String, Object> t : m.stack.subList(0, Math.min(cap, m.stack.size()))) {
            List<Object> ids = (List<Object>) t.getOrDefault("evidence", List.of());
            List<Object> shown = new ArrayList<>();
            for (int i = 0; i < Math.min(2, ids.size()); i++) {
                cited.add(((Number) ids.get(i)).intValue());
                shown.add("ev_" + ids.get(i));
            }
            Map<String, Object> s = map("name", t.get("name"), "category", t.get("category"));
            if (!String.valueOf(t.getOrDefault("kind", "")).isEmpty()) {
                s.put("kind", t.get("kind"));
            }
            if (!String.valueOf(t.getOrDefault("version", "")).isEmpty()) {
                s.put("version", t.get("version"));
            }
            s.put("evidence", shown);
            stack.add(s);
        }
        List<Map<String, Object>> sec = new ArrayList<>(m.secrets);
        sec.sort(Comparator.comparingLong((Map<String, Object> s) -> -((Number) s.get("count")).longValue()).thenComparing(s -> String.valueOf(s.get("kind"))));
        List<Object> secrets = new ArrayList<>();
        for (Map<String, Object> s : sec.subList(0, Math.min(20, sec.size()))) {
            List<Object> ids = (List<Object>) s.get("evidence");
            List<Object> shown = new ArrayList<>();
            for (int i = 0; i < Math.min(3, ids.size()); i++) {
                cited.add(((Number) ids.get(i)).intValue());
                shown.add("ev_" + ids.get(i));
            }
            secrets.add(map("kind", s.get("kind"), "length", s.get("length"), "entropy", s.get("entropy"), "count", s.get("count"), "evidence", shown));
        }

        Map<String, Object> pkg = new LinkedHashMap<>();
        pkg.put("tool", "burp2model");
        pkg.put("app", m.name);
        pkg.put("lens", lens);
        pkg.put("rules", RULES);
        pkg.put("scope", m.scope);
        pkg.put("roles", new ArrayList<>(m.roles));
        pkg.put("shape", m.counts());
        pkg.put("routes", routeList);
        pkg.put("endpoints", endpoints);
        pkg.put("scripts", scriptList);
        pkg.put("third_parties", tpList);
        pkg.put("stack", stack);
        pkg.put("trust", map("auth", auth, "cookies", cookies));
        pkg.put("secrets", secrets);
        pkg.put("unknowns", unknowns);
        pkg.put("coverage", map("routes", cov(routeList.size(), routes.size()), "endpoints", cov(endpoints.size(), eps.size()),
                "scripts", cov(scriptList.size(), scripts.size()), "third_parties", cov(tpList.size(), tps.size()),
                "unknowns", cov(unknowns.size(), m.unknowns.size()), "capture", new TreeMap<>(m.stats),
                "note", lens.equals("all") ? "model order" : "endpoints are ordered by the lens, so capping drops the least interesting ones first"));
        Map<String, Object> evidence = new LinkedHashMap<>();
        Map<Integer, Map<String, Object>> byId = new java.util.HashMap<>();
        for (Map<String, Object> e : m.evidenceLog.metas()) {
            byId.put(((Number) e.get("id")).intValue(), e);
        }
        for (int i : cited) {
            Map<String, Object> e = byId.get(i);
            if (e != null) {
                Map<String, Object> row = new LinkedHashMap<>();
                for (String k : new String[] {"method", "host", "path", "status", "role", "source", "item"}) {
                    row.put(k, e.get(k));
                }
                evidence.put("ev_" + i, row);
            }
        }
        pkg.put("evidence", evidence);
        pkg.put("token_estimate", (long) (Json.write(pkg).length() / 4));
        return pkg;
    }

    private static final String WHOLE = String.join("\n",
            "You are a senior application-security researcher. Below is an evidence-backed model of a single web application, built from traffic that was actually captured. It is structure, not raw bytes. Reason only from it.",
            "",
            "Ground rules:",
            "- Cite the evidence id(s) — ev_N — for every claim. The `evidence` map resolves each one to a real request.",
            "- Never name an endpoint, parameter, route, host or cookie that is not in the model.",
            "- Everything you produce is a hypothesis to verify safely, never a finding, an exploit or a payload.",
            "- An absence in the model is an absence in the capture, not proof of absence in the target. `inferred` means found in code, not confirmed called.",
            "",
            "Do this:",
            "1. ATTACK SURFACE — group the endpoints by function (authentication, payments, account, admin, catalog, config...). For each: method + path, parameters, whether a credential was seen, statuses observed, and which host it sits behind. Flag anything reached without a credential and anything on a privileged-looking path.",
            "2. WHERE TO HUNT — a prioritised list, highest value first: the endpoint or parameter, the evidence that makes it interesting, the issue class worth checking, and the single next request or two-account comparison that would confirm or kill it.",
            "3. OPEN QUESTIONS — restate each unknown and the exact capture or request needed to close it.",
            "4. WHAT STAYS UNCERTAIN — and why this capture cannot answer it.");

    private static final String METHODOLOGY = String.join("\n",
            "You are a senior application-security researcher planning how to investigate ONE web application you are authorised to test. Below is an evidence-backed model of it, built from captured traffic. Every item cites evidence ids (ev_N) that resolve to real requests.",
            "",
            "Produce a RECON AND HUNTING METHODOLOGY specific to THIS application, not a generic checklist.",
            "- Sequence it: recon first (close the blind spots the unknowns name), then mapping, then focused investigation per feature area, ordered by where understanding pays off most.",
            "- Ground every step in this model: reference the actual endpoints, roles and unknowns by name, and cite the ev_N behind each. Never introduce an endpoint, parameter or edge the model does not contain.",
            "- For each line of inquiry state what the evidence shows, what is unknown, the specific question worth answering, and the single next observation or two-account comparison that would answer it.",
            "- Everything is a hypothesis to verify safely in an authorised session. No payloads, no exploits.",
            "",
            "Structure your answer as: (1) What this app is, in three sentences. (2) Recon. (3) A prioritised set of lines of inquiry, one per feature area. (4) What stays uncertain and the capture that would resolve it.");

    /** The text to put on the clipboard: the prompt, then the package as JSON. scope: whole | endpoints | open | methodology. */
    public static String forAi(Model m, String scope) {
        Map<String, Object> p = pack(m, "attention", 60);
        Map<String, Object> obj = new LinkedHashMap<>();
        String prompt = WHOLE;
        String note = "whole model";
        switch (scope) {
            case "endpoints" -> {
                for (String k : new String[] {"app", "scope", "endpoints", "evidence"}) {
                    obj.put(k, p.get(k));
                }
                note = "endpoints and evidence only";
            }
            case "open" -> {
                for (String k : new String[] {"app", "unknowns", "endpoints", "evidence"}) {
                    obj.put(k, p.get(k));
                }
                note = "open questions, with endpoints for context";
            }
            case "methodology" -> {
                for (String k : new String[] {"app", "scope", "roles", "shape", "endpoints", "unknowns", "evidence"}) {
                    obj.put(k, p.get(k));
                }
                prompt = METHODOLOGY;
                note = "model for a methodology";
            }
            default -> obj.putAll(p);
        }
        return prompt + "\n\nMODEL (" + note + ", JSON):\n```json\n" + Json.pretty(obj) + "\n```";
    }

    /** Roughly how many tokens the whole package is. */
    public static int tokens(Model m) {
        return ((Number) pack(m, "attention", 60).get("token_estimate")).intValue();
    }
}
