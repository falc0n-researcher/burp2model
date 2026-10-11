package burp2model.engine;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/** One redacted request and response pair. Values are masked before an Exchange exists. */
public final class Exchange {
    public int index;
    public String method;
    public String scheme;
    public String host;
    public int port;
    public String path;            // redacted path including redacted query
    public String pathTemplate;    // /api/users/{id}
    /** What the path looked like before slug folding; every rebuild starts from it, so folding never compounds. */
    public String rawTemplate;
    public String rawRefererPath;
    public Integer status;
    public String mime = "";
    public List<Redact.Pair> queryParams = new ArrayList<>();
    public List<Redact.Pair> bodyParams = new ArrayList<>();
    public String role;
    public List<Redact.Fingerprint> secrets = new ArrayList<>();
    public String source = "";
    public int item = -1;
    public String refererHost;
    public String refererPath;
    public List<String> cookieNames = new ArrayList<>();
    public List<Map<String, Object>> setCookies = new ArrayList<>();
    public List<String> credentials = new ArrayList<>();
    public List<String[]> tech = new ArrayList<>();
    public List<Extract.Ref> jsRefs = new ArrayList<>();
    public List<Extract.Asset> jsAssets = new ArrayList<>();
    public List<Stack.Hit> stack = new ArrayList<>();
    public boolean scanTruncated;
    public List<String> gqlOps = new ArrayList<>();
    public boolean preflight;
    /** The redacted request and response panes: {request:{line,headers,body,truncated}, response:{...}}. */
    public Map<String, Object> ev = new LinkedHashMap<>();

    // ---- persistence: names, shapes and the redacted panes; never a raw value

    public Map<String, Object> toMap() {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("index", (long) index);
        m.put("source", source);
        m.put("item", (long) item);
        m.put("method", method);
        m.put("scheme", scheme);
        m.put("host", host);
        m.put("port", (long) port);
        m.put("path", path);
        m.put("path_template", pathTemplate);
        m.put("raw_template", rawTemplate);
        m.put("raw_referer_path", rawRefererPath);
        m.put("status", status == null ? null : (Object) (long) status);
        m.put("mime", mime);
        m.put("role", role);
        List<Object> qp = new ArrayList<>();
        queryParams.forEach(p -> qp.add(p.name()));
        m.put("query_params", qp);
        List<Object> bp = new ArrayList<>();
        bodyParams.forEach(p -> bp.add(p.name()));
        m.put("body_params", bp);
        List<Object> sec = new ArrayList<>();
        secrets.forEach(f -> sec.add(f.asMap()));
        m.put("secrets", sec);
        m.put("referer_host", refererHost);
        m.put("referer_path", refererPath);
        m.put("cookie_names", cookieNames);
        m.put("set_cookies", setCookies);
        m.put("credentials", credentials);
        List<Object> t = new ArrayList<>();
        tech.forEach(x -> t.add(new ArrayList<>(List.of(x[0], x[1]))));
        m.put("tech", t);
        List<Object> jr = new ArrayList<>();
        jsRefs.forEach(r -> {
            List<Object> x = new ArrayList<>();
            x.add(r.method());
            x.add(r.host());
            x.add(r.path());
            x.add(r.kind());
            jr.add(x);
        });
        m.put("js_refs", jr);
        List<Object> ja = new ArrayList<>();
        jsAssets.forEach(r -> ja.add(new ArrayList<>(List.of(r.kind(), r.host(), r.path()))));
        m.put("js_assets", ja);
        List<Object> st = new ArrayList<>();
        stack.forEach(h -> st.add(new ArrayList<>(List.of(h.name(), h.category(), h.how(), h.version()))));
        m.put("stack", st);
        m.put("scan_truncated", scanTruncated);
        m.put("gql_ops", gqlOps);
        m.put("preflight", preflight);
        m.put("ev", ev);
        return m;
    }

    @SuppressWarnings("unchecked")
    public static Exchange fromMap(Map<String, Object> r) {
        Exchange e = new Exchange();
        e.index = ((Number) r.get("index")).intValue();
        e.source = (String) r.getOrDefault("source", "");
        e.item = ((Number) r.getOrDefault("item", -1L)).intValue();
        e.method = (String) r.get("method");
        e.scheme = (String) r.get("scheme");
        e.host = (String) r.get("host");
        e.port = ((Number) r.get("port")).intValue();
        e.path = (String) r.get("path");
        e.pathTemplate = (String) r.get("path_template");
        e.rawTemplate = (String) r.getOrDefault("raw_template", e.pathTemplate);
        e.rawRefererPath = (String) r.getOrDefault("raw_referer_path", r.get("referer_path"));
        e.status = r.get("status") == null ? null : ((Number) r.get("status")).intValue();
        e.mime = (String) r.getOrDefault("mime", "");
        e.role = (String) r.get("role");
        for (Object n : (List<Object>) r.getOrDefault("query_params", List.of())) {
            e.queryParams.add(new Redact.Pair((String) n, ""));
        }
        for (Object n : (List<Object>) r.getOrDefault("body_params", List.of())) {
            e.bodyParams.add(new Redact.Pair((String) n, ""));
        }
        for (Object o : (List<Object>) r.getOrDefault("secrets", List.of())) {
            Map<String, Object> s = (Map<String, Object>) o;
            e.secrets.add(new Redact.Fingerprint((String) s.get("kind"), (String) s.get("hmac_12"), ((Number) s.get("length")).intValue(),
                    ((Number) s.get("entropy")).doubleValue()));
        }
        e.refererHost = (String) r.get("referer_host");
        e.refererPath = (String) r.get("referer_path");
        e.cookieNames = new ArrayList<>((List<String>) r.getOrDefault("cookie_names", List.of()));
        e.setCookies = new ArrayList<>((List<Map<String, Object>>) r.getOrDefault("set_cookies", List.of()));
        e.credentials = new ArrayList<>((List<String>) r.getOrDefault("credentials", List.of()));
        for (Object o : (List<Object>) r.getOrDefault("tech", List.of())) {
            List<Object> x = (List<Object>) o;
            e.tech.add(new String[] {(String) x.get(0), (String) x.get(1)});
        }
        for (Object o : (List<Object>) r.getOrDefault("js_refs", List.of())) {
            List<Object> x = (List<Object>) o;
            e.jsRefs.add(new Extract.Ref((String) x.get(0), (String) x.get(1), (String) x.get(2), (String) x.get(3)));
        }
        for (Object o : (List<Object>) r.getOrDefault("js_assets", List.of())) {
            List<Object> x = (List<Object>) o;
            e.jsAssets.add(new Extract.Asset((String) x.get(0), (String) x.get(1), (String) x.get(2)));
        }
        for (Object o : (List<Object>) r.getOrDefault("stack", List.of())) {
            List<Object> x = (List<Object>) o;
            e.stack.add(new Stack.Hit((String) x.get(0), (String) x.get(1), (String) x.get(2), (String) x.get(3)));
        }
        e.scanTruncated = Boolean.TRUE.equals(r.get("scan_truncated"));
        e.gqlOps = new ArrayList<>((List<String>) r.getOrDefault("gql_ops", List.of()));
        e.preflight = Boolean.TRUE.equals(r.get("preflight"));
        e.ev = (Map<String, Object>) r.getOrDefault("ev", new LinkedHashMap<>());
        return e;
    }
}
