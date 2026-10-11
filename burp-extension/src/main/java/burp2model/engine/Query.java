package burp2model.engine;

import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Comparator;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.TreeSet;
import java.util.function.Function;
import java.util.function.Predicate;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * The query engine: BQL (HTTPQL-style filters and graph verbs) plus the plain intents, over one in-memory
 * model. A port of bql.py / bql_js.py. Every row carries the evidence ids behind it; no network, no AI.
 */
public final class Query {
    public static final int DEFAULT_LIMIT = 100;
    public static final int MAX_LIMIT = 5000;

    public static final class QueryError extends RuntimeException {
        public QueryError(String m) {
            super(m);
        }
    }

    /** kind: requests | nodes | edges | paths | table | text. */
    public record Result(String kind, List<String> columns, List<Map<String, Object>> rows, String note, int total) {}

    private final Model m;
    private final Map<String, List<Model.Edge>> out = new HashMap<>();
    private final Map<String, List<Model.Edge>> inc = new HashMap<>();
    private final List<Map<String, Object>> requests = new ArrayList<>();
    /** Optional: first and last build of a node, for the history fields. */
    public Function<String, int[]> history = id -> null;
    /** Optional: the text of what changed since a build reference. */
    public Function<String, String> changedSince = ref -> {
        throw new QueryError("no build history yet");
    };

    public Query(Model m) {
        this.m = m;
        for (Model.Edge e : m.edges) {
            out.computeIfAbsent(e.src, k -> new ArrayList<>()).add(e);
            inc.computeIfAbsent(e.dst, k -> new ArrayList<>()).add(e);
        }
        for (int i = 0; i < m.evidenceLog.size(); i++) {
            requests.add(new ReqRow(i));
        }
    }

    // ------------------------------------------------------------ the requests table

    @SuppressWarnings("unchecked")
    private static String headersText(Object hs) {
        if (!(hs instanceof List<?> l)) {
            return "";
        }
        List<String> lines = new ArrayList<>();
        for (Object h : l) {
            List<Object> kv = (List<Object>) h;
            lines.add(kv.get(0) + ": " + kv.get(1));
        }
        return String.join("\n", lines);
    }

    private static final java.util.Set<String> HEAVY = java.util.Set.of("req_headers", "req_body", "resp_headers", "resp_body");
    private int cachedIdx = -1;
    private Map<String, Object> cachedFull;

    /** The unpacked request and response text of entry i; the last one is kept, so a filter that reads several fields unpacks once. */
    @SuppressWarnings("unchecked")
    private synchronized Map<String, Object> heavy(int i) {
        if (cachedIdx != i) {
            Map<String, Object> ev = m.evidenceLog.get(i);
            Map<String, Object> rq = ev.get("request") instanceof Map<?, ?> r ? (Map<String, Object>) r : Map.of();
            Map<String, Object> rs = ev.get("response") instanceof Map<?, ?> r ? (Map<String, Object>) r : Map.of();
            Map<String, Object> full = new HashMap<>();
            full.put("req_headers", headersText(rq.get("headers")));
            full.put("req_body", rq.getOrDefault("body", ""));
            full.put("resp_headers", headersText(rs.get("headers")));
            full.put("resp_body", rs.getOrDefault("body", ""));
            cachedFull = full;
            cachedIdx = i;
        }
        return cachedFull;
    }

    /** One captured request as a table row. The small fields are held; the request and response text is unpacked when a filter asks for it. */
    private final class ReqRow extends HashMap<String, Object> {
        private static final long serialVersionUID = 1L;
        private final int idx;

        ReqRow(int idx) {
            this.idx = idx;
            Map<String, Object> meta = m.evidenceLog.meta(idx);
            put("id", meta.get("id"));
            put("source", meta.get("source"));
            put("item", meta.get("item"));
            put("role", meta.get("role"));
            put("method", meta.get("method"));
            put("host", meta.get("host"));
            put("path", m.evidenceLog.path(idx));
            put("path_template", meta.get("path"));
            put("status", meta.get("status"));
            put("mime", meta.get("mime"));
        }

        @Override
        public Object get(Object key) {
            if (HEAVY.contains(key)) {
                return heavy(idx).get(key);
            }
            return super.get(key);
        }
    }

    // ------------------------------------------------------------------ lexing

    private static final List<String> OPS = List.of("eq", "ne", "cont", "ncont", "like", "regex", "gt", "gte", "lt", "lte");
    private static final Pattern TOKEN = Pattern.compile(
            "\\s*(?:(\\()|(\\))|([A-Za-z_][\\w.\\-]*:(?:\"(?:[^\"\\\\]|\\\\.)*\"|'(?:[^'\\\\]|\\\\.)*'|[^\\s()]+))|(\"(?:[^\"\\\\]|\\\\.)*\"|'(?:[^'\\\\]|\\\\.)*')|([^\\s()\"']+))");

    private record Tok(String kind, String a, String b) {}

    private static String unquote(String s) {
        if (s.length() >= 2 && s.charAt(0) == s.charAt(s.length() - 1) && (s.charAt(0) == '"' || s.charAt(0) == '\'')) {
            return s.substring(1, s.length() - 1).replace("\\" + s.charAt(0), String.valueOf(s.charAt(0)));
        }
        return s;
    }

    private static List<Tok> lex(String text) {
        List<Tok> toks = new ArrayList<>();
        text = text.strip();
        int pos = 0;
        while (pos < text.length()) {
            Matcher mt = TOKEN.matcher(text);
            mt.region(pos, text.length());
            if (!mt.lookingAt() || mt.end() == pos) {
                throw new QueryError("cannot read the query near '" + text.substring(pos, Math.min(text.length(), pos + 20)) + "'");
            }
            pos = mt.end();
            if (mt.group(1) != null) {
                toks.add(new Tok("lp", "(", null));
            } else if (mt.group(2) != null) {
                toks.add(new Tok("rp", ")", null));
            } else if (mt.group(3) != null) {
                String v = mt.group(3);
                int i = v.indexOf(':');
                toks.add(new Tok("term", v.substring(0, i), unquote(v.substring(i + 1))));
            } else if (mt.group(4) != null) {
                toks.add(new Tok("text", unquote(mt.group(4)), null));
            } else {
                String w = mt.group(5);
                String up = w.toUpperCase();
                if (up.equals("AND") || up.equals("OR") || up.equals("NOT")) {
                    toks.add(new Tok(up, up, null));
                } else {
                    toks.add(new Tok("word", w, null));
                }
            }
        }
        return toks;
    }

    // ------------------------------------------------------------------ parsing

    private sealed interface Ast permits And, Or, Not, Term, Text {}

    private record And(Ast a, Ast b) implements Ast {}

    private record Or(Ast a, Ast b) implements Ast {}

    private record Not(Ast a) implements Ast {}

    private record Term(String field, String op, String value) implements Ast {}

    private record Text(String value) implements Ast {}

    private static final class Parser {
        final List<Tok> t;
        int i;

        Parser(List<Tok> t) {
            this.t = t;
        }

        String peek() {
            return i < t.size() ? t.get(i).kind() : null;
        }

        Tok take() {
            return t.get(i++);
        }

        Ast parse() {
            Ast n = or();
            if (i < t.size()) {
                throw new QueryError("unexpected '" + t.get(i).a() + "'");
            }
            return n;
        }

        Ast or() {
            Ast n = and();
            while ("OR".equals(peek())) {
                take();
                n = new Or(n, and());
            }
            return n;
        }

        Ast and() {
            Ast n = not();
            while (Set.of("AND", "term", "text", "lp", "NOT").contains(String.valueOf(peek()))) {
                if ("AND".equals(peek())) {
                    take();
                }
                n = new And(n, not());
            }
            return n;
        }

        Ast not() {
            if ("NOT".equals(peek())) {
                take();
                return new Not(not());
            }
            return atom();
        }

        Ast atom() {
            String k = peek();
            if ("lp".equals(k)) {
                take();
                Ast n = or();
                if (!"rp".equals(peek())) {
                    throw new QueryError("missing )");
                }
                take();
                return n;
            }
            if ("term".equals(k)) {
                Tok tk = take();
                List<String> parts = new ArrayList<>(Arrays.asList(tk.a().split("\\.")));
                String op = "eq";
                if (parts.size() > 1 && OPS.contains(parts.get(parts.size() - 1))) {
                    op = parts.remove(parts.size() - 1);
                }
                return new Term(String.join(".", parts), op, tk.b());
            }
            if ("text".equals(k)) {
                return new Text(take().a());
            }
            throw new QueryError(k == null ? "expected a term like field:value" : "unexpected '" + t.get(i).a() + "'");
        }
    }

    // ------------------------------------------------------------------ fields

    private interface Getter {
        Object get(Object row);
    }

    private record Field(Getter get, String kind) {}

    private static final Map<String, Field> REQ = new LinkedHashMap<>();
    private static final Map<String, Field> NODE = new LinkedHashMap<>();
    private static final List<String> REQ_TEXT = List.of("path", "req_body", "resp_body", "req_headers", "resp_headers", "host");
    private static final List<String> NODE_TEXT = List.of("label", "id");
    private static final List<String> EDGE_TEXT = List.of("src", "dst", "type");
    private static final Pattern ATTR = Pattern.compile("^[A-Za-z_][\\w\\-]*$");

    @SuppressWarnings("unchecked")
    private static Getter req(String key) {
        return row -> ((Map<String, Object>) row).get(key);
    }

    static {
        REQ.put("req.method", new Field(req("method"), "text"));
        REQ.put("req.host", new Field(req("host"), "text"));
        REQ.put("req.path", new Field(req("path"), "text"));
        REQ.put("req.template", new Field(req("path_template"), "text"));
        REQ.put("req.header", new Field(req("req_headers"), "text"));
        REQ.put("req.body", new Field(req("req_body"), "text"));
        REQ.put("resp.code", new Field(req("status"), "int"));
        REQ.put("resp.mime", new Field(req("mime"), "text"));
        REQ.put("resp.header", new Field(req("resp_headers"), "text"));
        REQ.put("resp.body", new Field(req("resp_body"), "text"));
        REQ.put("role", new Field(req("role"), "text"));
        REQ.put("id", new Field(req("id"), "int"));
        REQ.put("source", new Field(req("source"), "text"));
        NODE.put("node.id", new Field(n -> ((Model.Node) n).id, "text"));
        NODE.put("node.type", new Field(n -> ((Model.Node) n).type, "text"));
        NODE.put("node.label", new Field(n -> ((Model.Node) n).label, "text"));
        NODE.put("node.layer", new Field(n -> (long) ((Model.Node) n).layer, "int"));
        NODE.put("node.source", new Field(n -> "traffic", "text"));
        NODE.put("node.state", new Field(n -> ((Model.Node) n).attrs.get("api_state"), "text"));
    }

    private Map<String, Field> edgeFields() {
        Map<String, Field> f = new LinkedHashMap<>();
        f.put("edge.type", new Field(e -> ((Model.Edge) e).type, "text"));
        f.put("edge.state", new Field(e -> ((Model.Edge) e).state, "text"));
        f.put("edge.src", new Field(e -> ((Model.Edge) e).src, "text"));
        f.put("edge.dst", new Field(e -> ((Model.Edge) e).dst, "text"));
        f.put("edge.src.type", new Field(e -> nodeProp(((Model.Edge) e).src, true), "text"));
        f.put("edge.dst.type", new Field(e -> nodeProp(((Model.Edge) e).dst, true), "text"));
        f.put("edge.src.label", new Field(e -> nodeProp(((Model.Edge) e).src, false), "text"));
        f.put("edge.dst.label", new Field(e -> nodeProp(((Model.Edge) e).dst, false), "text"));
        return f;
    }

    private Object nodeProp(String id, boolean type) {
        Model.Node n = m.nodes.get(id);
        return n == null ? null : type ? n.type : n.label;
    }

    private String targetOf(String f) {
        if (REQ.containsKey(f)) {
            return "requests";
        }
        if (edgeFields().containsKey(f)) {
            return "edges";
        }
        if (NODE.containsKey(f) || f.equals("node.evidence") || f.equals("node.role") || f.startsWith("node.attr.")
                || f.equals("node.first_build") || f.equals("node.last_build")) {
            return "nodes";
        }
        throw new QueryError("unknown field '" + f + "'; run `help` for the field list");
    }

    private Set<String> targets(Ast a) {
        Set<String> s = new TreeSet<>();
        if (a instanceof Term t) {
            s.add(targetOf(t.field()));
        } else if (a instanceof And x) {
            s.addAll(targets(x.a()));
            s.addAll(targets(x.b()));
        } else if (a instanceof Or x) {
            s.addAll(targets(x.a()));
            s.addAll(targets(x.b()));
        } else if (a instanceof Not x) {
            s.addAll(targets(x.a()));
        }
        return s;
    }

    private static String asText(Object v) {
        if (v == null) {
            return null;
        }
        if (v instanceof Boolean b) {
            return b ? "1" : "0";
        }
        if (v instanceof Map || v instanceof List) {
            return Json.write(v);
        }
        return String.valueOf(v);
    }

    private Predicate<Object> termPred(String target, Term t) {
        String f = t.field();
        String op = t.op();
        String value = t.value();
        Getter get;
        String kind;
        if (target.equals("requests")) {
            Field fd = REQ.get(f);
            get = fd.get();
            kind = fd.kind();
        } else if (target.equals("edges")) {
            Field fd = edgeFields().get(f);
            get = fd.get();
            kind = fd.kind();
        } else if (f.equals("node.evidence")) {
            Matcher em = Pattern.compile("^(?:ev_|evd[ _]?)?(\\d+)$", Pattern.CASE_INSENSITIVE).matcher(value.strip());
            if (!em.find()) {
                throw new QueryError("node.evidence needs an evidence id, got '" + value + "'");
            }
            if (!op.equals("eq") && !op.equals("ne")) {
                throw new QueryError("node.evidence supports eq and ne");
            }
            int ev = Integer.parseInt(em.group(1));
            return n -> ((Model.Node) n).evidence.contains(ev) == op.equals("eq");
        } else if (f.equals("node.role")) {
            if (op.equals("eq") || op.equals("ne")) {
                String want = value.toLowerCase();
                return n -> {
                    boolean has = ((Model.Node) n).roles.stream().anyMatch(r -> r.toLowerCase().contains(want));
                    return op.equals("eq") == has;
                };
            }
            get = n -> Json.write(((Model.Node) n).roles);
            kind = "text";
        } else if (f.equals("node.first_build") || f.equals("node.last_build")) {
            boolean first = f.equals("node.first_build");
            get = n -> {
                int[] h = history.apply(((Model.Node) n).id);
                return h == null ? null : (long) (first ? h[0] : h[1]);
            };
            kind = "int";
        } else if (f.startsWith("node.attr.")) {
            String a = f.substring("node.attr.".length());
            if (!ATTR.matcher(a).find()) {
                throw new QueryError("bad attribute name '" + a + "'");
            }
            get = n -> asText(((Model.Node) n).attrs.get(a));
            kind = "text";
        } else {
            Field fd = NODE.get(f);
            get = fd.get();
            kind = fd.kind();
        }
        final Getter g = get;
        if (kind.equals("int")) {
            if (Set.of("cont", "ncont", "like", "regex").contains(op)) {
                throw new QueryError(f + " is numeric; use eq ne gt gte lt lte");
            }
            if (!value.strip().matches("[+-]?\\d+")) {
                throw new QueryError(f + " needs a number, got '" + value + "'");
            }
            long v = Long.parseLong(value.strip().replace("+", ""));
            return r -> {
                Object x = g.get(r);
                if (!(x instanceof Number n)) {
                    return false;
                }
                long y = n.longValue();
                return switch (op) {
                    case "eq" -> y == v;
                    case "ne" -> y != v;
                    case "gt" -> y > v;
                    case "gte" -> y >= v;
                    case "lt" -> y < v;
                    default -> y <= v;
                };
            };
        }
        if (Set.of("gt", "gte", "lt", "lte").contains(op)) {
            throw new QueryError(f + " is text; " + op + " is for numbers");
        }
        String low = value.toLowerCase();
        switch (op) {
            case "eq":
                return r -> {
                    Object x = g.get(r);
                    return x != null && asText(x).toLowerCase().equals(low);
                };
            case "ne":
                return r -> {
                    Object x = g.get(r);
                    return x == null || !asText(x).toLowerCase().equals(low);
                };
            case "cont":
                return r -> {
                    Object x = g.get(r);
                    return x != null && asText(x).toLowerCase().contains(low);
                };
            case "ncont":
                return r -> {
                    Object x = g.get(r);
                    return x == null || !asText(x).toLowerCase().contains(low);
                };
            case "like": {
                StringBuilder sb = new StringBuilder("^");
                String[] parts = value.split("\\*", -1);
                for (int i = 0; i < parts.length; i++) {
                    if (i > 0) {
                        sb.append(".*");
                    }
                    sb.append(Pattern.quote(parts[i]));
                }
                Pattern re = Pattern.compile(sb.append("$").toString(), Pattern.CASE_INSENSITIVE | Pattern.DOTALL);
                return r -> {
                    Object x = g.get(r);
                    return x != null && re.matcher(asText(x)).find();
                };
            }
            default: {
                Pattern re;
                try {
                    re = Pattern.compile(value, Pattern.CASE_INSENSITIVE);
                } catch (Exception e) {
                    throw new QueryError("bad regex '" + value + "': " + e.getMessage());
                }
                return r -> {
                    Object x = g.get(r);
                    return x != null && re.matcher(asText(x)).find();
                };
            }
        }
    }

    @SuppressWarnings("unchecked")
    private Predicate<Object> compile(Ast a, String target) {
        if (a instanceof And x) {
            Predicate<Object> p = compile(x.a(), target);
            Predicate<Object> q = compile(x.b(), target);
            return r -> p.test(r) && q.test(r);
        }
        if (a instanceof Or x) {
            Predicate<Object> p = compile(x.a(), target);
            Predicate<Object> q = compile(x.b(), target);
            return r -> p.test(r) || q.test(r);
        }
        if (a instanceof Not x) {
            Predicate<Object> p = compile(x.a(), target);
            return r -> !p.test(r);
        }
        if (a instanceof Text x) {
            String low = x.value().toLowerCase();
            return r -> {
                if (target.equals("requests")) {
                    Map<String, Object> row = (Map<String, Object>) r;
                    return REQ_TEXT.stream().anyMatch(c -> row.get(c) != null && String.valueOf(row.get(c)).toLowerCase().contains(low));
                }
                if (target.equals("nodes")) {
                    Model.Node n = (Model.Node) r;
                    return n.label.toLowerCase().contains(low) || n.id.toLowerCase().contains(low);
                }
                Model.Edge e = (Model.Edge) r;
                return e.src.toLowerCase().contains(low) || e.dst.toLowerCase().contains(low) || e.type.toLowerCase().contains(low);
            };
        }
        return termPred(target, (Term) a);
    }

    private static List<String> evs(List<Integer> l) {
        List<String> out = new ArrayList<>();
        new TreeSet<>(l).forEach(i -> out.add("ev_" + i));
        return out;
    }

    private static Map<String, Object> row(Object... kv) {
        Map<String, Object> r = new LinkedHashMap<>();
        for (int i = 0; i + 1 < kv.length; i += 2) {
            r.put((String) kv[i], kv[i + 1]);
        }
        return r;
    }

    private static final Pattern LIMIT = Pattern.compile("\\s+limit\\s+(\\d+)\\s*$", Pattern.CASE_INSENSITIVE);

    private Result runFilter(String text, int limit) {
        Matcher lm = LIMIT.matcher(text);
        if (lm.find()) {
            limit = Integer.parseInt(lm.group(1));
            text = text.substring(0, lm.start());
        }
        limit = Math.max(1, Math.min(limit, MAX_LIMIT));
        Ast ast = new Parser(lex(text)).parse();
        Set<String> ts = targets(ast);
        if (ts.size() > 1) {
            throw new QueryError("a query can filter one of requests, nodes or edges — this mixes " + String.join(", ", ts));
        }
        String target = ts.isEmpty() ? "requests" : ts.iterator().next();
        Predicate<Object> pred = compile(ast, target);
        List<Map<String, Object>> rows = new ArrayList<>();
        List<String> cols;
        int total;
        if (target.equals("requests")) {
            List<Map<String, Object>> hits = new ArrayList<>();
            for (Map<String, Object> r : requests) {
                if (pred.test(r)) {
                    hits.add(r);
                }
            }
            total = hits.size();
            for (Map<String, Object> r : hits.subList(0, Math.min(limit, hits.size()))) {
                rows.add(row("ev", "ev_" + r.get("id"), "method", r.get("method"), "status", r.get("status"), "host", r.get("host"),
                        "path", r.get("path"), "role", r.get("role") == null ? "" : r.get("role"),
                        "mime", r.get("mime") == null ? "" : r.get("mime")));
            }
            cols = List.of("ev", "method", "status", "host", "path", "role");
        } else if (target.equals("nodes")) {
            List<Model.Node> hits = new ArrayList<>();
            for (Model.Node n : m.nodes.values()) {
                if (pred.test(n)) {
                    hits.add(n);
                }
            }
            hits.sort(Comparator.comparingInt((Model.Node n) -> n.layer).thenComparing(n -> n.type).thenComparing(n -> n.label));
            total = hits.size();
            for (Model.Node n : hits.subList(0, Math.min(limit, hits.size()))) {
                Object st = n.attrs.get("api_state");
                rows.add(row("id", n.id, "type", n.type, "layer", (long) n.layer, "label", n.label, "source", "traffic",
                        "state", st == null ? "" : st, "roles", String.join(",", n.roles), "evidence", evs(n.evidence)));
            }
            cols = List.of("type", "label", "state", "source", "roles", "evidence");
        } else {
            List<Model.Edge> hits = new ArrayList<>();
            for (Model.Edge e : m.edges) {
                if (pred.test(e)) {
                    hits.add(e);
                }
            }
            total = hits.size();
            for (Model.Edge e : hits.subList(0, Math.min(limit, hits.size()))) {
                rows.add(row("src", label(e.src), "type", e.type, "state", e.state, "dst", label(e.dst), "evidence", evs(e.evidence)));
            }
            cols = List.of("src", "type", "state", "dst", "evidence");
        }
        String note = total + " match" + (total != 1 ? "es" : "");
        if (total > rows.size()) {
            note += " (showing " + rows.size() + "; add `limit N`)";
        }
        return new Result(target, cols, rows, note, total);
    }

    // ------------------------------------------------------------------ graph verbs

    String label(String id) {
        Model.Node n = m.nodes.get(id);
        return n == null ? id : n.label;
    }

    public String resolve(String ref) {
        ref = ref.strip();
        if (m.nodes.containsKey(ref)) {
            return ref;
        }
        String low = ref.toLowerCase();
        List<Model.Node> hits = new ArrayList<>();
        for (Model.Node n : m.nodes.values()) {
            if (n.label.toLowerCase().equals(low)) {
                hits.add(n);
            }
        }
        if (hits.isEmpty()) {
            for (Model.Node n : m.nodes.values()) {
                if (n.label.toLowerCase().contains(low)) {
                    hits.add(n);
                }
            }
            hits.sort(Comparator.comparingInt(n -> n.layer));
        }
        if (hits.isEmpty()) {
            throw new QueryError("no node matches '" + ref + "'");
        }
        if (hits.size() > 1) {
            List<String> labels = new ArrayList<>();
            hits.stream().limit(5).forEach(n -> labels.add(n.label));
            throw new QueryError("'" + ref + "' is ambiguous — be more specific: " + String.join(" | ", labels));
        }
        return hits.get(0).id;
    }

    private Result walk(String nid, int depth, boolean forward) {
        depth = Math.max(1, Math.min(depth, 8));
        Map<String, List<Model.Edge>> adj = forward ? out : inc;
        Map<String, Integer> res = new LinkedHashMap<>();
        List<String> frontier = List.of(nid);
        for (int d = 1; d <= depth; d++) {
            List<String> next = new ArrayList<>();
            for (String cur : frontier) {
                for (Model.Edge e : adj.getOrDefault(cur, List.of())) {
                    String n = forward ? e.dst : e.src;
                    if (!res.containsKey(n) && !n.equals(nid)) {
                        res.put(n, d);
                        next.add(n);
                    }
                }
            }
            frontier = next;
        }
        List<Map<String, Object>> rows = new ArrayList<>();
        for (Map.Entry<String, Integer> e : res.entrySet()) {
            Model.Node n = m.nodes.get(e.getKey());
            if (n != null) {
                rows.add(row("hops", (long) e.getValue(), "type", n.type, "label", n.label, "source", "traffic"));
            }
        }
        rows.sort(Comparator.comparingLong((Map<String, Object> r) -> (Long) r.get("hops"))
                .thenComparing(r -> (String) r.get("type")).thenComparing(r -> (String) r.get("label")));
        return new Result("nodes", List.of("hops", "type", "label", "source"), rows,
                rows.size() + " node(s) " + (forward ? "downstream of" : "upstream of") + " " + label(nid) + " (depth " + depth + ")", rows.size());
    }

    private record Hop(Model.Edge e) {}

    private List<List<Hop>> paths(String start, String goal, int limit, int maxDepth) {
        boolean back = goal == null;
        List<List<Hop>> found = new ArrayList<>();
        Map<String, Integer> seen = new HashMap<>();
        seen.put(start, 0);
        ArrayDeque<Object[]> queue = new ArrayDeque<>();
        queue.add(new Object[] {start, new ArrayList<Hop>()});
        while (!queue.isEmpty() && found.size() < limit) {
            Object[] cur = queue.poll();
            String node = (String) cur[0];
            @SuppressWarnings("unchecked")
            List<Hop> trail = (List<Hop>) cur[1];
            if (trail.size() >= maxDepth) {
                continue;
            }
            for (Model.Edge e : (back ? inc : out).getOrDefault(node, List.of())) {
                String nxt = back ? e.src : e.dst;
                List<Hop> path = new ArrayList<>(trail);
                path.add(new Hop(e));
                Model.Node nn = m.nodes.get(nxt);
                if (back ? (nn != null && nn.type.equals("host")) : nxt.equals(goal)) {
                    found.add(path);
                    if (found.size() >= limit) {
                        break;
                    }
                    continue;
                }
                if (!seen.containsKey(nxt) || seen.get(nxt) >= path.size()) {
                    seen.put(nxt, path.size());
                    queue.add(new Object[] {nxt, path});
                }
            }
        }
        if (back) {
            found.forEach(java.util.Collections::reverse);
        }
        return found;
    }

    private Result pathsResult(List<List<Hop>> ps, String title) {
        List<Map<String, Object>> rows = new ArrayList<>();
        for (int n = 0; n < ps.size(); n++) {
            for (int i = 0; i < ps.get(n).size(); i++) {
                Model.Edge e = ps.get(n).get(i).e();
                rows.add(row("path", (long) (n + 1), "hop", (long) (i + 1), "from", label(e.src), "edge", e.type, "state", e.state,
                        "to", label(e.dst), "evidence", evs(e.evidence)));
            }
        }
        return new Result("paths", List.of("path", "hop", "from", "edge", "state", "to", "evidence"), rows,
                ps.isEmpty() ? "no path: " + title : ps.size() + " path(s): " + title, ps.size());
    }

    private static Object[] depthArg(String[] words) {
        if (words.length >= 2 && words[words.length - 2].equalsIgnoreCase("depth") && words[words.length - 1].matches("\\d+")) {
            return new Object[] {Arrays.copyOf(words, words.length - 2), Integer.parseInt(words[words.length - 1])};
        }
        return new Object[] {words, 3};
    }

    // ------------------------------------------------------------------ the other verbs

    private Result provenance(String nid) {
        Model.Node n = m.nodes.get(nid);
        List<Map<String, Object>> rows = new ArrayList<>();
        for (int ev : n.evidence) {
            Map<String, Object> r = requests.stream().filter(x -> ((Number) x.get("id")).intValue() == ev).findFirst().orElse(null);
            if (r != null) {
                rows.add(row("ev", "ev_" + ev, "role", r.get("role") == null ? "" : r.get("role"), "method", r.get("method"),
                        "url", r.get("host") + String.valueOf(r.get("path")), "status", r.get("status")));
            }
        }
        return new Result("table", List.of("ev", "role", "method", "url", "status"), rows,
                rows.size() + " request(s) behind " + n.label, rows.size());
    }

    private Result staticOnly() {
        List<Map<String, Object>> rows = new ArrayList<>();
        List<Model.Node> eps = new ArrayList<>(m.nodes.values());
        eps.sort(Comparator.comparing(n -> n.label));
        for (Model.Node n : eps) {
            if (!n.type.equals("endpoint") || !"STATIC_ONLY".equals(n.attrs.get("api_state"))) {
                continue;
            }
            List<String> by = new ArrayList<>();
            for (Model.Edge e : inc.getOrDefault(n.id, List.of())) {
                if (e.type.equals("REFERENCES")) {
                    by.add(label(e.src));
                }
            }
            java.util.Collections.sort(by);
            rows.add(row("endpoint", n.label, "named_in", String.join(", ", by), "evidence", evs(n.evidence)));
        }
        return new Result("table", List.of("endpoint", "named_in", "evidence"), rows,
                rows.size() + " endpoint(s) in code, never seen in traffic", rows.size());
    }

    private Result reachesPrivileged(String role) {
        List<Map<String, Object>> rows = new ArrayList<>();
        List<Model.Node> eps = new ArrayList<>(m.nodes.values());
        eps.sort(Comparator.comparing(n -> n.label));
        for (Model.Node n : eps) {
            if (!n.type.equals("endpoint") || n.roles.stream().noneMatch(r -> r.equalsIgnoreCase(role))) {
                continue;
            }
            if (!Builder.PRIV_RE.matcher(String.valueOf(n.attrs.getOrDefault("path", ""))).find()) {
                continue;
            }
            Object sbr = List.of();
            for (Map.Entry<?, ?> e : ((Map<?, ?>) n.attrs.getOrDefault("status_by_role", Map.of())).entrySet()) {
                if (String.valueOf(e.getKey()).equalsIgnoreCase(role)) {
                    sbr = e.getValue();
                }
            }
            List<List<Hop>> p = paths(n.id, null, 1, 8);
            String via = "";
            if (!p.isEmpty()) {
                List<String> parts = new ArrayList<>();
                parts.add(label(p.get(0).get(0).e().src));
                p.get(0).forEach(h -> parts.add(label(h.e().dst)));
                via = String.join(" → ", parts);
            }
            rows.add(row("endpoint", n.label, "statuses", String.valueOf(sbr), "via", via, "evidence", evs(n.evidence.subList(0, Math.min(3, n.evidence.size())))));
        }
        return new Result("table", List.of("endpoint", "statuses", "via", "evidence"), rows,
                rows.size() + " privileged-looking endpoint(s) reached as " + role + "; check each response was meant for that role", rows.size());
    }

    private Result unknowns() {
        List<Map<String, Object>> rows = new ArrayList<>();
        for (Model.Unknown u : m.unknowns) {
            rows.add(row("type", u.type(), "entity", u.entity(), "we_dont_know", u.weDontKnow(), "next_step", u.nextStep()));
        }
        return new Result("table", List.of("type", "entity", "we_dont_know", "next_step"), rows, rows.size() + " unknown(s)", rows.size());
    }

    private Result stats() {
        Map<String, Object> c = m.counts();
        List<Map<String, Object>> rows = new ArrayList<>();
        c.forEach((k, v) -> rows.add(row("metric", k, "value", String.valueOf(v))));
        rows.add(row("metric", "requests", "value", String.valueOf(m.evidenceLog.size())));
        return new Result("table", List.of("metric", "value"), rows, "model " + m.name, rows.size());
    }

    // ------------------------------------------------------------------ plain intents

    private Result listApis() {
        List<Map<String, Object>> rows = new ArrayList<>();
        List<Model.Node> eps = new ArrayList<>();
        for (Model.Node n : m.nodes.values()) {
            if (n.type.equals("endpoint")) {
                eps.add(n);
            }
        }
        eps.sort(Comparator.comparing(n -> n.label));
        for (Model.Node n : eps) {
            rows.add(row("endpoint", n.label, "state", n.attrs.get("api_state"), "statuses", String.valueOf(n.attrs.get("statuses")),
                    "roles", String.join(",", n.roles), "evidence", evs(n.evidence)));
        }
        return new Result("table", List.of("endpoint", "state", "statuses", "roles", "evidence"), rows, rows.size() + " endpoints", rows.size());
    }

    private Result listRoutes() {
        List<Map<String, Object>> rows = new ArrayList<>();
        m.nodes.values().stream().filter(n -> n.type.equals("route")).sorted(Comparator.comparing(n -> n.label)).forEach(n ->
                rows.add(row("route", n.label, "statuses", String.valueOf(n.attrs.get("statuses")), "evidence", evs(n.evidence))));
        return new Result("table", List.of("route", "statuses", "evidence"), rows, rows.size() + " routes", rows.size());
    }

    private Result reconcile() {
        Map<String, Integer> states = new TreeMap<>();
        List<Map<String, Object>> rows = new ArrayList<>();
        for (Model.Node n : m.nodes.values()) {
            if (n.type.equals("endpoint")) {
                states.merge(String.valueOf(n.attrs.get("api_state")), 1, Integer::sum);
            }
        }
        states.forEach((k, v) -> rows.add(row("state", k, "endpoints", (long) v)));
        return new Result("table", List.of("state", "endpoints"), rows, "code vs runtime", rows.size());
    }

    private Result thirdParties() {
        List<Map<String, Object>> rows = new ArrayList<>();
        m.nodes.values().stream().filter(n -> n.type.equals("third_party")).sorted(Comparator.comparing(n -> n.label)).forEach(n ->
                rows.add(row("host", n.label, "requests", n.attrs.get("requests"), "evidence", evs(n.evidence))));
        return new Result("table", List.of("host", "requests", "evidence"), rows, rows.size() + " third parties", rows.size());
    }

    private Result authSurface() {
        List<Map<String, Object>> rows = new ArrayList<>();
        for (Model.Node n : m.nodes.values()) {
            if (n.type.equals("auth")) {
                rows.add(row("kind", "credential", "what", n.label, "evidence", evs(n.evidence)));
            } else if (n.type.equals("cookie")) {
                boolean http = Boolean.TRUE.equals(n.attrs.get("httponly"));
                boolean sec = Boolean.TRUE.equals(n.attrs.get("secure"));
                rows.add(row("kind", "cookie", "what", n.label + "  " + (http ? "HttpOnly" : "missing HttpOnly") + " · "
                        + (sec ? "Secure" : "missing Secure") + " · SameSite=" + n.attrs.get("samesite"), "evidence", evs(n.evidence)));
            }
        }
        return new Result("table", List.of("kind", "what", "evidence"), rows, "roles: " + (m.roles.isEmpty() ? "none tagged" : String.join(", ", m.roles)), rows.size());
    }

    private Result parameters() {
        List<Map<String, Object>> rows = new ArrayList<>();
        for (Model.Node n : m.nodes.values()) {
            if (n.type.equals("endpoint") || n.type.equals("route")) {
                List<String> ps = new ArrayList<>();
                for (Model.Edge e : out.getOrDefault(n.id, List.of())) {
                    if (e.type.equals("USES_PARAMETER")) {
                        ps.add(label(e.dst));
                    }
                }
                if (!ps.isEmpty()) {
                    rows.add(row("endpoint", n.label, "parameters", String.join(", ", ps), "evidence", evs(n.evidence)));
                }
            }
        }
        return new Result("table", List.of("endpoint", "parameters", "evidence"), rows, "parameter names only; values are never stored", rows.size());
    }

    @SuppressWarnings("unchecked")
    private Result secrets() {
        List<Map<String, Object>> rows = new ArrayList<>();
        for (Map<String, Object> s : m.secrets) {
            List<String> ev = new ArrayList<>();
            ((List<Object>) s.get("evidence")).forEach(x -> ev.add("ev_" + x));
            rows.add(row("kind", s.get("kind"), "length", s.get("length"), "entropy", s.get("entropy"), "seen", s.get("count"), "evidence", ev));
        }
        return new Result("table", List.of("kind", "length", "entropy", "seen", "evidence"), rows,
                rows.size() + " distinct masked values; values are never stored, fingerprints are keyed hashes", rows.size());
    }

    private Result privileged() {
        List<Map<String, Object>> rows = new ArrayList<>();
        m.nodes.values().stream().filter(n -> n.type.equals("endpoint")
                && Builder.PRIV_RE.matcher(String.valueOf(n.attrs.getOrDefault("path", ""))).find()).sorted(Comparator.comparing(n -> n.label))
                .forEach(n -> rows.add(row("endpoint", n.label, "state", n.attrs.get("api_state"), "roles", String.join(",", n.roles), "evidence", evs(n.evidence))));
        return new Result("table", List.of("endpoint", "state", "roles", "evidence"), rows, rows.size() + " privileged-looking endpoints (path heuristic)", rows.size());
    }

    @SuppressWarnings("unchecked")
    private Result errors() {
        List<Map<String, Object>> rows = new ArrayList<>();
        m.nodes.values().stream().filter(n -> n.type.equals("endpoint")).forEach(n -> {
            List<Object> st = (List<Object>) n.attrs.get("statuses");
            if (st != null && !st.isEmpty() && st.stream().allMatch(s -> ((Long) s) >= 400)) {
                rows.add(row("endpoint", n.label, "statuses", String.valueOf(st), "evidence", evs(n.evidence)));
            }
        });
        return new Result("table", List.of("endpoint", "statuses", "evidence"), rows, rows.size() + " endpoints only ever returned errors", rows.size());
    }

    private Result routeApis(String arg) {
        String id = resolve(arg);
        Set<String> seen = new TreeSet<>();
        List<Map<String, Object>> rows = new ArrayList<>();
        ArrayDeque<String> q = new ArrayDeque<>(List.of(id));
        Set<String> visited = new java.util.HashSet<>(List.of(id));
        while (!q.isEmpty()) {
            String cur = q.poll();
            for (Model.Edge e : out.getOrDefault(cur, List.of())) {
                Model.Node d = m.nodes.get(e.dst);
                if (d != null && d.type.equals("endpoint") && seen.add(d.id)) {
                    rows.add(row("endpoint", d.label, "state", d.attrs.get("api_state"), "via", label(cur) + " -" + e.type + "->", "evidence", evs(e.evidence)));
                }
                if (d != null && (d.type.equals("script") || d.type.equals("route")) && visited.add(d.id)) {
                    q.add(d.id);
                }
            }
        }
        return new Result("table", List.of("endpoint", "state", "via", "evidence"), rows, rows.size() + " API(s) reached from " + label(id), rows.size());
    }

    public static final String HELP = """
            Type a question or a BQL query. Every answer cites evidence (ev_N) and runs offline.

            Intents:  list-apis · reconcile · list-routes · third-parties · auth-surface · parameters · secrets ·
                      privileged · errors · unknowns · shape · route-apis /x · provenance /api/x · entity-evidence <name>
            Filters:  req.method:POST AND resp.code.gte:400
                      req.host.cont:"api." AND NOT role:admin
                      resp.body.regex:"stack ?trace"
                      node.type:endpoint AND node.state:STATIC_ONLY
                      edge.state:EXTERNAL     ·    "login"  (free text)
            Fields:   req.method req.host req.path req.template req.header req.body resp.code resp.mime resp.header
                      resp.body role id source | node.type node.label node.id node.layer node.state node.role
                      node.evidence node.first_build node.last_build node.attr.<name> | edge.type edge.state edge.src
                      edge.dst edge.src.type edge.dst.type edge.src.label edge.dst.label
            Operators: eq ne cont ncont like regex gt gte lt lte    ·   combine with AND OR NOT ( ) and end with `limit N`
            Verbs:    reach <node> · blast <node> [depth N] · upstream <node> · neighbors <node> · path <a> to <b>
                      provenance <node> · static-only · changed-since <build> · reaches-privileged <role> · unknowns · stats · help
            """;

    // ------------------------------------------------------------------ entry

    private static final Map<String, String> INTENTS = Map.ofEntries(
            Map.entry("list-apis", "list-apis"), Map.entry("apis", "list-apis"), Map.entry("endpoints", "list-apis"),
            Map.entry("list-routes", "list-routes"), Map.entry("routes", "list-routes"), Map.entry("pages", "list-routes"),
            Map.entry("reconcile", "reconcile"), Map.entry("code-vs-runtime", "reconcile"), Map.entry("third-parties", "third-parties"),
            Map.entry("auth-surface", "auth-surface"), Map.entry("auth", "auth-surface"), Map.entry("parameters", "parameters"),
            Map.entry("secrets", "secrets"), Map.entry("privileged", "privileged"), Map.entry("errors", "errors"),
            Map.entry("shape", "stats"));

    public Result run(String text) {
        text = text == null ? "" : text.strip();
        while (text.endsWith(";")) {
            text = text.substring(0, text.length() - 1).strip();
        }
        if (text.isEmpty()) {
            throw new QueryError("empty query — try `help`");
        }
        String[] sp = text.split("\\s+", 2);
        String verb = sp[0].toLowerCase();
        String rest = sp.length > 1 ? sp[1].strip() : "";
        String intent = INTENTS.get(text.toLowerCase().replace(' ', '-').replace('_', '-'));
        if (intent != null) {
            return switch (intent) {
                case "list-apis" -> listApis();
                case "list-routes" -> listRoutes();
                case "reconcile" -> reconcile();
                case "third-parties" -> thirdParties();
                case "auth-surface" -> authSurface();
                case "parameters" -> parameters();
                case "secrets" -> secrets();
                case "privileged" -> privileged();
                case "errors" -> errors();
                default -> stats();
            };
        }
        switch (verb) {
            case "help":
                return new Result("text", List.of(), List.of(), HELP, 0);
            case "stats":
                return stats();
            case "unknowns":
                return unknowns();
            case "static-only":
                return staticOnly();
            case "changed-since":
                return new Result("text", List.of(), List.of(), changedSince.apply(rest.isEmpty() ? "previous" : unquote(rest)), 0);
            case "reaches-privileged":
                if (rest.isEmpty()) {
                    throw new QueryError("reaches-privileged needs a role");
                }
                return reachesPrivileged(unquote(rest));
            case "route-apis":
                return routeApis(unquote(rest));
            case "entity-evidence":
            case "provenance":
                if (rest.isEmpty()) {
                    throw new QueryError(verb + " needs a node, e.g. " + verb + " /api/orders");
                }
                return provenance(resolve(unquote(rest)));
            case "reach":
            case "blast":
            case "upstream":
            case "neighbors":
            case "path": {
                if (rest.isEmpty()) {
                    throw new QueryError(verb + " needs a node");
                }
                if (verb.equals("path")) {
                    String[] ab = rest.split("(?i)\\s+to\\s+", 2);
                    if (ab.length != 2) {
                        throw new QueryError("usage: path <a> to <b>");
                    }
                    String a = resolve(unquote(ab[0].strip()));
                    String b = resolve(unquote(ab[1].strip()));
                    return pathsResult(paths(a, b, 1, 8), label(a) + " → " + label(b));
                }
                Object[] da = depthArg(rest.split("\\s+"));
                String nid = resolve(unquote(String.join(" ", (String[]) da[0])));
                int depth = (Integer) da[1];
                if (verb.equals("reach")) {
                    return pathsResult(paths(nid, null, 3, 8), "how " + label(nid) + " is reached");
                }
                if (verb.equals("blast")) {
                    return walk(nid, depth, true);
                }
                if (verb.equals("upstream")) {
                    return walk(nid, depth, false);
                }
                Result down = walk(nid, depth, true);
                Result up = walk(nid, depth, false);
                List<Map<String, Object>> rows = new ArrayList<>();
                down.rows().forEach(r -> {
                    Map<String, Object> x = new LinkedHashMap<>(r);
                    x.put("direction", "out");
                    rows.add(x);
                });
                up.rows().forEach(r -> {
                    Map<String, Object> x = new LinkedHashMap<>(r);
                    x.put("direction", "in");
                    rows.add(x);
                });
                return new Result("nodes", List.of("direction", "hops", "type", "label", "source"), rows,
                        rows.size() + " node(s) within " + depth + " hop(s) of " + label(nid), rows.size());
            }
            default:
                return runFilter(text, DEFAULT_LIMIT);
        }
    }
}
