package burp2model.engine;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Static endpoint extraction from JavaScript and HTML bodies (a port of extract.py). A reference found in
 * code is a claim that the app may call an endpoint, so everything here becomes an INFERRED edge.
 */
public final class Extract {
    private Extract() {}

    public static final int MAX_SCAN_BYTES = 10 * 1024 * 1024;

    /** method (or null), host (or null), templated path, kind: call | string | form. */
    public record Ref(String method, String host, String path, String kind) {}

    /** kind: sourcemap | worker | service_worker | import_scripts. */
    public record Asset(String kind, String host, String path) {}

    static final Pattern API_HINT = Pattern.compile("/(api|v\\d+|graphql|rest|gql)(/|$)", Pattern.CASE_INSENSITIVE);
    private static final Pattern TEMPLATE_EXPR = Pattern.compile("\\$\\{[^{}`]{0,120}\\}");
    private static final String URL_BODY = "(?:\\{param\\})?(?:https?:)?/[^\\s\"'`<>\\\\]{0,300}?";
    private static final Pattern VERB_CALL = Pattern.compile("\\.(get|post|put|patch|delete|head)\\s*\\(\\s*([\"'`])(" + URL_BODY + ")\\2", Pattern.CASE_INSENSITIVE);
    private static final Pattern FETCH = Pattern.compile("(?:\\b(?:fetch|axios|ajax|request)|\\$http)\\s*\\(\\s*([\"'`])(" + URL_BODY + ")\\1");
    private static final Pattern XHR_OPEN = Pattern.compile("\\.open\\s*\\(\\s*[\"'](GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)[\"']\\s*,\\s*([\"'`])(" + URL_BODY + ")\\2", Pattern.CASE_INSENSITIVE);
    private static final Pattern METHOD_NEAR = Pattern.compile("method\\s*:\\s*[\"'`](GET|POST|PUT|PATCH|DELETE|HEAD)[\"'`]", Pattern.CASE_INSENSITIVE);
    private static final Pattern STRING = Pattern.compile("([\"'`])(" + URL_BODY + ")\\1");
    private static final Pattern FORM = Pattern.compile("<form\\b([^>]*)>", Pattern.CASE_INSENSITIVE);
    private static final Pattern ATTR = Pattern.compile("\\b(action|method)\\s*=\\s*(?:\"([^\"]*)\"|'([^']*)'|([^\\s>]+))", Pattern.CASE_INSENSITIVE);
    private static final Pattern STATIC_EXT = Pattern.compile(
            "\\.(?:png|jpe?g|gif|svg|ico|webp|avif|css|woff2?|ttf|otf|eot|map|mp4|webm|mp3|html?|js|mjs|json|txt|md)$", Pattern.CASE_INSENSITIVE);

    private record HostPath(String host, String path) {}

    /** The host and path of an absolute URL; null for a malformed authority (such as `https://[{x}]/`). */
    static String[] splitAbsolute(String raw) {
        int i = raw.indexOf("//");
        String rest = raw.substring(i + 2);
        int end = rest.length();
        for (char c : new char[] {'/', '?', '#'}) {
            int j = rest.indexOf(c);
            if (j >= 0 && j < end) {
                end = j;
            }
        }
        String auth = rest.substring(0, end);
        String tail = rest.substring(end);
        int at = auth.lastIndexOf('@');
        String hostport = at >= 0 ? auth.substring(at + 1) : auth;
        String host;
        if (hostport.startsWith("[")) {
            int rb = hostport.indexOf(']');
            if (rb < 0 || !hostport.substring(1, rb).matches("[0-9a-fA-F:.]+")) {
                return null;
            }
            host = hostport.substring(1, rb);
        } else {
            host = hostport.split(":", 2)[0];
        }
        String path = tail;
        int cut = path.length();
        for (char c : new char[] {'?', '#'}) {
            int j = path.indexOf(c);
            if (j >= 0 && j < cut) {
                cut = j;
            }
        }
        path = path.substring(0, cut);
        return new String[] {host.toLowerCase(), path};
    }

    private static HostPath normalize(String raw) {
        raw = raw.strip();
        if (raw.startsWith("{param}")) {
            raw = raw.substring("{param}".length());
        }
        if (raw.startsWith("//")) {
            raw = "https:" + raw;
        }
        String host = null;
        String path;
        String low = raw.toLowerCase();
        if (low.startsWith("http://") || low.startsWith("https://")) {
            String[] hp = splitAbsolute(raw);
            if (hp == null) {
                return null;
            }
            host = hp[0].isEmpty() ? null : hp[0];
            path = hp[1].isEmpty() ? "/" : hp[1];
        } else {
            if (!raw.startsWith("/")) {
                return null;
            }
            path = raw.split("\\?", 2)[0].split("#", 2)[0];
        }
        if (path.contains("//") || path.length() > 200) {
            return null;
        }
        if (path.length() > 1 && path.endsWith("/")) {
            path = path + "{param}";
        }
        return new HostPath(host, Redact.templatePath(path));
    }

    private static void ref(String method, String raw, String kind, Set<Ref> out) {
        HostPath n = normalize(raw);
        if (n == null) {
            return;
        }
        if (n.path().equals("/") && n.host() == null) {
            return;
        }
        if (n.host() == null && n.path().startsWith("/{param}") && !API_HINT.matcher(n.path()).find()) {
            return;
        }
        out.add(new Ref(method == null ? null : method.toUpperCase(), n.host(), n.path(), kind));
    }

    private static String span(Matcher m, int g) {
        return m.start(g) + ":" + m.end(g);
    }

    public static Set<Ref> jsRefs(String body) {
        Set<Ref> out = new HashSet<>();
        if (body == null || body.isEmpty()) {
            return out;
        }
        body = TEMPLATE_EXPR.matcher(body).replaceAll("{param}");
        Set<String> called = new HashSet<>();

        Matcher m = XHR_OPEN.matcher(body);
        while (m.find()) {
            ref(m.group(1), m.group(3), "call", out);
            called.add(span(m, 3));
        }
        m = VERB_CALL.matcher(body);
        while (m.find()) {
            ref(m.group(1), m.group(3), "call", out);
            called.add(span(m, 3));
        }
        m = FETCH.matcher(body);
        while (m.find()) {
            int e = m.end();
            String window = body.substring(e, Math.min(body.length(), e + 200));
            int stop = window.length();
            for (String tok : new String[] {";", "fetch(", "axios", ".open(", ".then(", "\n\n"}) {
                int i = window.indexOf(tok);
                if (i != -1) {
                    stop = Math.min(stop, i);
                }
            }
            Matcher near = METHOD_NEAR.matcher(window.substring(0, stop));
            ref(near.find() ? near.group(1) : null, m.group(2), "call", out);
            called.add(span(m, 2));
        }
        m = STRING.matcher(body);
        while (m.find()) {
            if (called.contains(span(m, 2))) {
                continue;
            }
            String raw = m.group(2);
            HostPath n = normalize(raw);
            if (n == null) {
                continue;
            }
            if (API_HINT.matcher(n.path()).find() && !STATIC_EXT.matcher(n.path()).find()) {
                ref(null, raw, "string", out);
            }
        }
        return out;
    }

    public static Set<Ref> htmlRefs(String body) {
        Set<Ref> out = new HashSet<>();
        if (body == null || body.isEmpty()) {
            return out;
        }
        Matcher fm = FORM.matcher(body);
        while (fm.find()) {
            String action = "";
            String method = "GET";
            Matcher am = ATTR.matcher(fm.group(1));
            while (am.find()) {
                String val = am.group(2) != null ? am.group(2) : am.group(3) != null ? am.group(3) : am.group(4) != null ? am.group(4) : "";
                if (am.group(1).equalsIgnoreCase("action")) {
                    action = val;
                } else {
                    method = val;
                }
            }
            action = action.strip();
            if (action.isEmpty() || action.startsWith("#") || action.startsWith("javascript:") || action.startsWith("mailto:")) {
                continue;
            }
            method = method.isEmpty() ? "GET" : method.toUpperCase();
            ref(method.equals("GET") || method.equals("POST") ? method : "GET", action, "form", out);
        }
        out.addAll(jsRefs(body));
        return out;
    }

    // ---- source maps and workers

    private static final Pattern SOURCEMAP = Pattern.compile("//[#@]\\s*sourceMappingURL=([^\\s'\"]+)");
    private static final String[] WORKER_KINDS = {"worker", "service_worker", "import_scripts"};
    private static final Pattern[] WORKER_RES = {
        Pattern.compile("new\\s+(?:Shared)?Worker\\s*\\(\\s*([\"'`])([^\"'`\\s]{1,200})\\1"),
        Pattern.compile("serviceWorker\\s*\\.\\s*register\\s*\\(\\s*([\"'`])([^\"'`\\s]{1,200})\\1"),
        Pattern.compile("importScripts\\s*\\(\\s*([\"'`])([^\"'`\\s]{1,200})\\1"),
    };

    /** Resolve `rel` against a script path the way urljoin would (path part only). */
    static String joinPath(String scriptPath, String rel) {
        String p = rel.split("[?#]", 2)[0];
        if (!p.startsWith("/")) {
            int slash = scriptPath.lastIndexOf('/');
            p = (slash >= 0 ? scriptPath.substring(0, slash + 1) : "/") + p;
        }
        List<String> out = new ArrayList<>();
        for (String seg : p.split("/", -1)) {
            if (seg.equals("..")) {
                if (out.size() > 1) {
                    out.remove(out.size() - 1);
                }
            } else if (!seg.equals(".")) {
                out.add(seg);
            }
        }
        return String.join("/", out);
    }

    private static HostPath resolveAsset(String raw, String scriptHost, String scriptPath) {
        raw = raw.strip();
        if (raw.isEmpty() || raw.startsWith("data:") || raw.startsWith("blob:") || raw.startsWith("{param}") || raw.contains("{param}")) {
            return null;
        }
        String host;
        String path;
        if (raw.contains("://") || raw.startsWith("//")) {
            String abs = raw.startsWith("//") ? "https:" + raw : raw;
            String[] hp = splitAbsolute(abs);
            if (hp == null) {
                return null;
            }
            host = hp[0].isEmpty() ? scriptHost : hp[0];
            path = hp[1];
        } else {
            host = scriptHost;
            path = joinPath(scriptPath, raw);
        }
        if (!path.startsWith("/") || path.contains("//") || path.length() > 200) {
            return null;
        }
        return new HostPath(host, Redact.templatePath(path));
    }

    public static Set<Asset> scriptAssets(String body, String host, String path, String headerMap) {
        Set<Asset> out = new HashSet<>();
        List<String[]> refs = new ArrayList<>();
        Matcher sm = SOURCEMAP.matcher(body == null ? "" : body);
        while (sm.find()) {
            refs.add(new String[] {"sourcemap", sm.group(1)});
        }
        if (headerMap != null) {
            refs.add(new String[] {"sourcemap", headerMap});
        }
        for (int i = 0; i < WORKER_RES.length; i++) {
            Matcher wm = WORKER_RES[i].matcher(body == null ? "" : body);
            while (wm.find()) {
                refs.add(new String[] {WORKER_KINDS[i], wm.group(2)});
            }
        }
        for (String[] r : refs) {
            HostPath hp = resolveAsset(r[1], host, path);
            if (hp != null) {
                out.add(new Asset(r[0], hp.host(), hp.path()));
            }
        }
        return out;
    }
}
