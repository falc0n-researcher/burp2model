package burp2model.engine;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.zip.GZIPInputStream;
import java.util.zip.Inflater;

/**
 * One captured request and response, from raw bytes to a redacted Exchange (a port of parse.py's item
 * parsing). Everything the model needs from a body is read from the full body; what is kept is the masked,
 * capped excerpt.
 */
public final class Parse {
    private Parse() {}

    static final int BODY_KEEP = 20000;
    static final int CODE_KEEP = 40000;
    private static final int MAX_DECOMPRESS = 50 * 1024 * 1024;
    private static final String[] SESSION_COOKIE_HINTS = {"sess", "sid", "auth", "token", "jwt", "remember", "login", "user"};
    private static final String[] CREDENTIAL_HEADER_HINTS = {"api-key", "apikey", "auth-token", "access-token", "x-token"};
    private static final Set<String> TECH_HEADERS = Set.of("server", "x-powered-by", "x-aspnet-version",
            "x-aspnetmvc-version", "x-generator", "x-runtime", "x-framework");

    /** Raw inputs for one item. */
    public record Raw(String method, String host, int port, String protocol, String path, Integer status, String mime,
                      byte[] request, byte[] response, boolean truncated) {}

    private static String latin1(byte[] b, int from, int to) {
        return new String(b, from, to - from, StandardCharsets.ISO_8859_1);
    }

    private static int find(byte[] b, byte[] pat) {
        outer:
        for (int i = 0; i + pat.length <= b.length; i++) {
            for (int j = 0; j < pat.length; j++) {
                if (b[i + j] != pat[j]) {
                    continue outer;
                }
            }
            return i;
        }
        return -1;
    }

    private record Msg(String head, byte[] body) {}

    private static Msg splitHttp(byte[] raw) {
        int sep = find(raw, new byte[] {13, 10, 13, 10});
        if (sep >= 0) {
            return new Msg(latin1(raw, 0, sep), java.util.Arrays.copyOfRange(raw, sep + 4, raw.length));
        }
        sep = find(raw, new byte[] {10, 10});
        if (sep >= 0) {
            return new Msg(latin1(raw, 0, sep), java.util.Arrays.copyOfRange(raw, sep + 2, raw.length));
        }
        return new Msg(latin1(raw, 0, raw.length), new byte[0]);
    }

    private record Head(String start, List<Redact.Pair> headers) {}

    private static Head parseHeaders(String head) {
        String[] lines = head.split("\n", -1);
        String start = lines.length > 0 ? lines[0].strip() : "";
        List<Redact.Pair> hs = new ArrayList<>();
        for (int i = 1; i < lines.length; i++) {
            String line = lines[i];
            while (line.endsWith("\r")) {
                line = line.substring(0, line.length() - 1);
            }
            int c = line.indexOf(':');
            if (line.isEmpty() || c < 0) {
                continue;
            }
            hs.add(new Redact.Pair(line.substring(0, c).strip(), line.substring(c + 1).strip()));
        }
        return new Head(start, hs);
    }

    private static String header(List<Redact.Pair> hs, String name) {
        for (Redact.Pair h : hs) {
            if (h.name().equalsIgnoreCase(name)) {
                return h.value();
            }
        }
        return "";
    }

    private static byte[] dechunk(byte[] body) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        try {
            int pos = 0;
            while (pos < body.length) {
                int eol = -1;
                for (int i = pos; i + 1 < body.length; i++) {
                    if (body[i] == 13 && body[i + 1] == 10) {
                        eol = i;
                        break;
                    }
                }
                if (eol < 0) {
                    return body;
                }
                String sizeTxt = latin1(body, pos, eol).split(";", 2)[0].strip();
                int size = Integer.parseInt(sizeTxt, 16);
                if (size == 0) {
                    break;
                }
                if (eol + 2 + size > body.length) {
                    return body;
                }
                out.write(body, eol + 2, size);
                pos = eol + 2 + size + 2;
                if (out.size() > MAX_DECOMPRESS) {
                    break;
                }
            }
            return out.toByteArray();
        } catch (Exception e) {
            return body;
        }
    }

    private record Dec(byte[] body, boolean ok) {}

    private static byte[] readBounded(java.io.InputStream in) throws java.io.IOException {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        byte[] buf = new byte[8192];
        int n;
        while ((n = in.read(buf)) > 0) {
            out.write(buf, 0, n);
            if (out.size() > MAX_DECOMPRESS) {
                break;
            }
        }
        return out.toByteArray();
    }

    private static Dec decompress(byte[] body, String encoding) {
        String enc = encoding.toLowerCase();
        try {
            if (body.length > 2 && (body[0] & 0xff) == 0x1f && (body[1] & 0xff) == 0x8b) {
                try (GZIPInputStream g = new GZIPInputStream(new java.io.ByteArrayInputStream(body))) {
                    return new Dec(readBounded(g), true);
                }
            }
            if (enc.contains("deflate")) {
                for (boolean nowrap : new boolean[] {false, true}) {
                    Inflater inf = new Inflater(nowrap);
                    try {
                        inf.setInput(body);
                        ByteArrayOutputStream out = new ByteArrayOutputStream();
                        byte[] buf = new byte[8192];
                        while (!inf.finished() && out.size() <= MAX_DECOMPRESS) {
                            int n = inf.inflate(buf);
                            if (n == 0 && (inf.needsInput() || inf.needsDictionary())) {
                                break;
                            }
                            out.write(buf, 0, n);
                        }
                        return new Dec(out.toByteArray(), true);
                    } catch (java.util.zip.DataFormatException e) {
                        // try the raw form next
                    } finally {
                        inf.end();
                    }
                }
                return new Dec(body, true);
            }
            if (enc.contains("br") || enc.contains("zstd")) {
                return new Dec(body, body.length == 0);
            }
        } catch (Exception e) {
            return new Dec(body, true);
        }
        return new Dec(body, true);
    }

    // ---- small parsers

    private static List<Redact.Pair> parseQuery(String path) {
        int q = path.indexOf('?');
        if (q < 0) {
            return new ArrayList<>();
        }
        return Url.parseQsl(path.substring(q + 1).split("#", 2)[0]);
    }

    private static List<Redact.Pair> parseBodyParams(String body, String contentType) {
        String ct = contentType.toLowerCase();
        if (ct.contains("application/x-www-form-urlencoded")) {
            return Url.parseQsl(body);
        }
        if (ct.contains("json")) {
            Object data;
            try {
                data = Json.parse(body);
            } catch (Exception e) {
                return new ArrayList<>();
            }
            List<Redact.Pair> out = new ArrayList<>();
            walk(data, "$", 0, out);
            return out;
        }
        return new ArrayList<>();
    }

    @SuppressWarnings("unchecked")
    private static void walk(Object obj, String prefix, int depth, List<Redact.Pair> out) {
        if (depth > 12) {
            return;
        }
        if (obj instanceof Map<?, ?> m) {
            for (Map.Entry<String, Object> e : ((Map<String, Object>) m).entrySet()) {
                String k = e.getKey().length() > 200 ? e.getKey().substring(0, 200) : e.getKey();
                String c = Redact.classifySegment(k);
                walk(e.getValue(), prefix + "." + (c != null ? c : k), depth + 1, out);
            }
        } else if (obj instanceof List<?> l) {
            for (int i = 0; i < Math.min(5, l.size()); i++) {
                walk(l.get(i), prefix + "[" + i + "]", depth + 1, out);
            }
        } else {
            String v = obj == null ? "None" : obj instanceof Boolean b ? (b ? "True" : "False") : String.valueOf(obj);
            out.add(new Redact.Pair(prefix, v));
        }
    }

    private static final Pattern GQL_OP = Pattern.compile("^\\s*(query|mutation|subscription)\\s+([A-Za-z_][A-Za-z0-9_]*)");
    private static final Pattern GQL_NAME = Pattern.compile("^[A-Za-z_][A-Za-z0-9_]{0,80}$");

    @SuppressWarnings("unchecked")
    private static List<String> gqlOps(String pathTemplate, String body, String ct) {
        String low = pathTemplate.toLowerCase();
        List<String> ops = new ArrayList<>();
        if (!low.contains("graphql") && !low.contains("gql")) {
            return ops;
        }
        Object data = null;
        try {
            if (body != null && !body.isEmpty() && ct.toLowerCase().contains("json")) {
                data = Json.parse(body);
            }
        } catch (Exception e) {
            data = null;
        }
        List<Object> items = data instanceof List<?> l ? (List<Object>) l : java.util.Collections.singletonList(data);
        for (Object o : items) {
            if (!(o instanceof Map<?, ?> m)) {
                continue;
            }
            Object name = m.get("operationName");
            if (name == null || (name instanceof String s && s.isEmpty())) {
                Object q = m.get("query");
                if (q instanceof String qs) {
                    Matcher g = GQL_OP.matcher(qs);
                    name = g.find() ? g.group(2) : null;
                }
            }
            if (name instanceof String s && GQL_NAME.matcher(s).find()) {
                ops.add(s);
            }
        }
        return ops;
    }

    private static List<String> credentials(List<Redact.Pair> reqHeaders, List<String> cookieNames, List<Redact.Pair> query) {
        Set<String> creds = new java.util.TreeSet<>();
        String auth = header(reqHeaders, "authorization");
        if (!auth.isEmpty()) {
            String scheme = auth.strip().contains(" ") ? auth.split(" ", 2)[0].toLowerCase() : "custom";
            creds.add(scheme.matches("^[a-z0-9-]{2,30}$") ? scheme : "custom");
        }
        for (Redact.Pair h : reqHeaders) {
            String low = h.name().toLowerCase();
            if (!low.equals("authorization")) {
                for (String hint : CREDENTIAL_HEADER_HINTS) {
                    if (low.contains(hint)) {
                        creds.add("header:" + low);
                        break;
                    }
                }
            }
        }
        for (String c : cookieNames) {
            for (String hint : SESSION_COOKIE_HINTS) {
                if (c.toLowerCase().contains(hint)) {
                    creds.add("cookie:" + c);
                    break;
                }
            }
        }
        for (Redact.Pair q : query) {
            String low = q.name().toLowerCase();
            if (Set.of("api_key", "apikey", "access_token", "token", "key", "auth").contains(low)) {
                creds.add("query:" + low);
            }
        }
        return new ArrayList<>(creds);
    }

    private static final Pattern COOKIE_NAME = Pattern.compile("^[!#$%&'*+\\-.^_`|~0-9A-Za-z]{1,100}$");

    private static List<String> cookieNames(String cookieHeader) {
        List<String> names = new ArrayList<>();
        for (String part : cookieHeader.split(";", -1)) {
            String name = part.split("=", 2)[0].strip();
            if (!name.isEmpty() && COOKIE_NAME.matcher(name).find()) {
                names.add(name);
            }
        }
        return names;
    }

    private static List<Map<String, Object>> setCookies(List<Redact.Pair> respHeaders) {
        List<Map<String, Object>> out = new ArrayList<>();
        for (Redact.Pair h : respHeaders) {
            if (!h.name().equalsIgnoreCase("set-cookie") || !h.value().contains("=")) {
                continue;
            }
            String[] parts = h.value().split(";", -1);
            String name = parts[0].split("=", 2)[0].strip();
            if (name.isEmpty()) {
                continue;
            }
            Map<String, String> flags = new LinkedHashMap<>();
            for (int i = 1; i < parts.length; i++) {
                String a = parts[i].strip();
                flags.put(a.split("=", 2)[0].toLowerCase(), a);
            }
            String samesite = flags.getOrDefault("samesite", "");
            Map<String, Object> c = new LinkedHashMap<>();
            c.put("name", name.length() > 100 ? name.substring(0, 100) : name);
            c.put("httponly", flags.containsKey("httponly"));
            c.put("secure", flags.containsKey("secure"));
            c.put("samesite", samesite.contains("=") ? samesite.split("=", 2)[1].strip() : null);
            out.add(c);
        }
        return out;
    }

    private record Referer(String host, String path) {}

    private static Referer referer(List<Redact.Pair> reqHeaders) {
        String ref = header(reqHeaders, "referer");
        if (ref.isEmpty()) {
            return new Referer(null, null);
        }
        String low = ref.toLowerCase();
        if (!low.startsWith("http://") && !low.startsWith("https://")) {
            return new Referer(null, null);
        }
        String[] hp = Extract.splitAbsolute(ref);
        if (hp == null || hp[0].isEmpty()) {
            return new Referer(null, null);
        }
        String query = "";
        int q = ref.indexOf('?');
        if (q >= 0) {
            query = ref.substring(q + 1).split("#", 2)[0];
        }
        String path = (hp[1].isEmpty() ? "/" : hp[1]) + (query.isEmpty() ? "" : "?" + query);
        String red = Redact.redactPath(path).value();
        return new Referer(hp[0], Redact.routeTemplate(red, Redact.templatePath(hp[1].isEmpty() ? "/" : hp[1])));
    }

    private static boolean isJsResponse(String mime, String pathTemplate, String ct) {
        String m = (mime + " " + ct).toLowerCase();
        return m.contains("script") || m.contains("ecmascript") || pathTemplate.endsWith(".js") || pathTemplate.endsWith(".mjs");
    }

    private static boolean isHtmlResponse(String mime, String ct) {
        return (mime + " " + ct).toLowerCase().contains("html");
    }

    /** The first n code points (Python slices by code point, and so must we to keep the same text). */
    static String trunc(String s, int n) {
        if (s.length() <= n) {
            return s;
        }
        if (s.codePointCount(0, s.length()) <= n) {
            return s;
        }
        return s.substring(0, s.offsetByCodePoints(0, n));
    }

    /** Length in code points. */
    static int len(String s) {
        return s.codePointCount(0, s.length());
    }

    private static String utf8(byte[] b) {
        return new String(b, StandardCharsets.UTF_8);
    }

    // ---- body analysis, cached by content: the same bundle loaded again costs a hash, not another scan

    private record BodyScan(String full, List<Redact.Fingerprint> prints, List<Extract.Ref> refs, List<String[]> assetRefs, List<Stack.Hit> hits, String evText) {}

    /** Scans by content, least recently used dropped first once they hold SCAN_CACHE_CHARS (it used to stop caching when full). */
    private static final java.util.LinkedHashMap<String, BodyScan> SCANS = new java.util.LinkedHashMap<>(256, 0.75f, true);
    private static final java.util.concurrent.atomic.AtomicLong SCAN_CHARS = new java.util.concurrent.atomic.AtomicLong();
    private static final long SCAN_CACHE_CHARS = 48L * 1024 * 1024;

    private static String contentKey(byte[] b, boolean js) {
        try {
            java.security.MessageDigest md = java.security.MessageDigest.getInstance("SHA-1");
            md.update((byte) (js ? 1 : 0));
            md.update(b);
            return b.length + ":" + java.util.HexFormat.of().formatHex(md.digest());
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    private static BodyScan scanBody(byte[] bytes, boolean js) {
        String key = bytes.length > 2048 ? contentKey(bytes, js) : null;
        if (key != null) {
            BodyScan hit;
            synchronized (SCANS) {
                hit = SCANS.get(key);
            }
            if (hit != null) {
                return hit;
            }
        }
        Redact.Redacted<String> red = Redact.redactBody(utf8(bytes));
        String full = red.value();
        Set<Extract.Ref> refs = js ? Extract.jsRefs(full) : Extract.htmlRefs(full);
        List<Extract.Ref> sorted = new ArrayList<>(refs);
        BodyScan scan = new BodyScan(full, red.prints(), sorted, js ? Extract.scriptAssetRefs(full) : List.of(), Stack.bodyHits(full),
                Redact.redactNamed(trunc(trunc(full, js ? CODE_KEEP : BODY_KEEP), js ? CODE_KEEP : BODY_KEEP)));
        if (key != null && full.length() < SCAN_CACHE_CHARS / 4) {
            synchronized (SCANS) {
                if (SCANS.put(key, scan) == null) {
                    SCAN_CHARS.addAndGet(full.length());
                }
                var it = SCANS.entrySet().iterator();
                while (SCAN_CHARS.get() > SCAN_CACHE_CHARS && it.hasNext()) {
                    SCAN_CHARS.addAndGet(-it.next().getValue().full().length());
                    it.remove();
                }
            }
        }
        return scan;
    }

    /** Drop the cached scans (when a session is cleared, so memory does not linger). */
    public static void clearCache() {
        synchronized (SCANS) {
            SCANS.clear();
            SCAN_CHARS.set(0);
        }
    }

    // ---- the item

    public static Exchange item(int idx, Raw r, String role, String source, int itemNo) {
        String method = (r.method() == null || r.method().isBlank() ? "GET" : r.method()).strip().toUpperCase();
        String host = r.host() == null ? "" : r.host().strip().toLowerCase();
        String protocol = r.protocol() == null || r.protocol().isBlank() ? "https" : r.protocol().strip().toLowerCase();
        String path = r.path() == null ? "" : r.path().strip();
        Integer status = r.status();
        String mime = r.mime() == null ? "" : r.mime().strip();
        if (host.isEmpty() || !host.matches("^[a-z0-9.\\-:\\[\\]]{1,255}$")) {
            return null;
        }
        if (!method.matches("^[A-Z]{1,20}$")) {
            return null;
        }
        byte[] reqRaw = r.request() == null ? new byte[0] : r.request();
        byte[] respRaw = r.response() == null ? new byte[0] : r.response();
        Msg req = reqRaw.length > 0 ? splitHttp(reqRaw) : new Msg("", new byte[0]);
        Msg resp = respRaw.length > 0 ? splitHttp(respRaw) : new Msg("", new byte[0]);
        Head reqH = parseHeaders(req.head());
        Head respH = parseHeaders(resp.head());
        List<Redact.Pair> reqHeaders = reqH.headers();
        List<Redact.Pair> respHeaders = respH.headers();
        String respStart = respH.start();
        if (status == null && respStart.startsWith("HTTP/") && respStart.contains(" ")) {
            String[] sp = respStart.split(" ");
            if (sp.length > 1 && sp[1].matches("\\d+")) {
                status = Integer.parseInt(sp[1]);
            }
        }
        byte[] reqBody = req.body();
        byte[] respBody = resp.body();
        if (header(reqHeaders, "transfer-encoding").toLowerCase().contains("chunked")) {
            reqBody = dechunk(reqBody);
        }
        if (header(respHeaders, "transfer-encoding").toLowerCase().contains("chunked")) {
            respBody = dechunk(respBody);
        }
        reqBody = decompress(reqBody, header(reqHeaders, "content-encoding")).body();
        Dec respDec = decompress(respBody, header(respHeaders, "content-encoding"));
        respBody = respDec.body();
        String reqCt = header(reqHeaders, "content-type");
        String respCt = header(respHeaders, "content-type");
        String reqBodyText = utf8(reqBody);

        List<String> cookieNames = cookieNames(header(reqHeaders, "cookie"));
        List<Map<String, Object>> setCookies = setCookies(respHeaders);
        List<Redact.Pair> rawQuery = parseQuery(path);
        List<String> credentials = credentials(reqHeaders, cookieNames, rawQuery);
        Referer referer = referer(reqHeaders);
        boolean preflight = method.equals("OPTIONS") && !header(reqHeaders, "access-control-request-method").isEmpty();

        List<Redact.Fingerprint> secrets = new ArrayList<>();
        Redact.Redacted<String> rp = Redact.redactPath(path);
        String redPath = rp.value();
        String ptemplate = Redact.routeTemplate(redPath, Redact.templatePath(redPath));
        List<String[]> tech = new ArrayList<>();
        for (Redact.Pair h : respHeaders) {
            if (TECH_HEADERS.contains(h.name().toLowerCase()) && !h.value().isEmpty()) {
                tech.add(new String[] {h.name().toLowerCase(), trunc(h.value(), 80)});
            }
        }
        Redact.Redacted<List<Redact.Pair>> reqHr = Redact.redactHeaders(reqHeaders);
        Redact.Redacted<List<Redact.Pair>> respHr = Redact.redactHeaders(respHeaders);
        Redact.Redacted<List<Redact.Pair>> queryR = Redact.redactParams(rawQuery);
        Redact.Redacted<List<Redact.Pair>> bodyR = Redact.redactParams(parseBodyParams(reqBodyText, reqCt));
        Redact.Redacted<String> reqBodyR = Redact.redactBody(trunc(reqBodyText, BODY_KEEP));
        List<String> gql = gqlOps(ptemplate, reqBodyR.value(), reqCt);
        List<String[]> techR = new ArrayList<>();
        for (String[] kv : tech) {
            Redact.Redacted<String> m = Redact.redactBody(kv[1]);
            secrets.addAll(m.prints());
            techR.add(new String[] {kv[0], m.value()});
        }

        boolean isJs = isJsResponse(mime, ptemplate, respCt);
        boolean isHtml = isHtmlResponse(mime, respCt);
        boolean scanTruncated = (isJs || isHtml) && (!respDec.ok() || r.truncated());
        Set<Extract.Ref> jsRefs = new LinkedHashSet<>();
        Set<Extract.Asset> jsAssets = new LinkedHashSet<>();
        List<Stack.Hit> bodyHits = List.of();
        String evBodyText = null;
        String respBodyR;
        Redact.Redacted<String> s6;
        if (isJs || isHtml) {
            byte[] scan = respBody;
            if (scan.length > Extract.MAX_SCAN_BYTES) {
                scan = java.util.Arrays.copyOf(scan, Extract.MAX_SCAN_BYTES);
                scanTruncated = true;
            }
            BodyScan bs = scanBody(scan, isJs);
            s6 = new Redact.Redacted<>(bs.full(), bs.prints());
            String full = bs.full();
            jsRefs = new LinkedHashSet<>(bs.refs());
            if (isJs) {
                List<String[]> arefs = new ArrayList<>(bs.assetRefs());
                for (Redact.Pair h : respHeaders) {
                    String n = h.name().toLowerCase();
                    if (n.equals("sourcemap") || n.equals("x-sourcemap")) {
                        arefs.add(new String[] {"sourcemap", h.value()});
                        break;
                    }
                }
                jsAssets = Extract.resolveAssets(arefs, host, ptemplate);
            }
            respBodyR = trunc(full, isJs ? CODE_KEEP : BODY_KEEP);
            bodyHits = bs.hits();
            evBodyText = bs.evText();
        } else {
            byte[] head = respBody.length > BODY_KEEP * 5 ? java.util.Arrays.copyOf(respBody, BODY_KEEP * 5) : respBody;
            s6 = Redact.redactBody(utf8(head));
            respBodyR = trunc(s6.value(), BODY_KEEP);
        }

        List<String> allCookies = new ArrayList<>();
        for (Map<String, Object> c : setCookies) {
            allCookies.add((String) c.get("name"));
        }
        allCookies.addAll(cookieNames);
        Map<String, String> lowHeaders = new LinkedHashMap<>();
        for (Redact.Pair h : respHeaders) {
            lowHeaders.put(h.name().toLowerCase(), h.value());
        }
        List<Stack.Hit> stack = Stack.detect(lowHeaders, allCookies, bodyHits, redPath);

        secrets.addAll(rp.prints());
        secrets.addAll(reqHr.prints());
        secrets.addAll(respHr.prints());
        secrets.addAll(queryR.prints());
        secrets.addAll(bodyR.prints());
        secrets.addAll(reqBodyR.prints());
        secrets.addAll(s6.prints());

        String[] startParts = reqH.start().split(" ", -1);
        String ver = reqH.start().chars().filter(c -> c == ' ').count() >= 2 ? startParts[startParts.length - 1] : "HTTP/1.1";
        int evBody = isJs ? CODE_KEEP : isHtml ? BODY_KEEP : 6000;
        Map<String, Object> reqEv = new LinkedHashMap<>();
        reqEv.put("line", Redact.redactNamed((method + " " + redPath + " " + ver).strip()));
        reqEv.put("headers", headerList(reqHr.value()));
        reqEv.put("body", Redact.redactNamed(trunc(reqBodyR.value(), 6000)));
        reqEv.put("truncated", len(reqBodyR.value()) > 6000);
        Map<String, Object> respEv = new LinkedHashMap<>();
        String line = !respStart.isEmpty() ? respStart : (status != null ? "HTTP/1.1 " + status : "");
        respEv.put("line", line.strip());
        respEv.put("headers", headerList(respHr.value()));
        respEv.put("body", evBodyText != null ? evBodyText : Redact.redactNamed(trunc(respBodyR, evBody)));
        respEv.put("truncated", len(respBodyR) > evBody || scanTruncated);
        Map<String, Object> ev = new LinkedHashMap<>();
        ev.put("request", reqEv);
        ev.put("response", respEv);

        Exchange ex = new Exchange();
        ex.index = idx;
        ex.method = method;
        ex.scheme = protocol;
        ex.host = host;
        ex.port = r.port();
        ex.path = redPath;
        ex.pathTemplate = ptemplate;
        ex.rawTemplate = ptemplate;
        ex.status = status;
        ex.mime = mime;
        ex.queryParams = queryR.value();
        ex.bodyParams = bodyR.value();
        ex.role = role;
        ex.secrets = secrets;
        ex.source = source == null ? "" : source;
        ex.item = itemNo;
        ex.refererHost = referer.host();
        ex.refererPath = referer.path();
        ex.rawRefererPath = referer.path();
        ex.cookieNames = cookieNames;
        ex.setCookies = setCookies;
        ex.credentials = credentials;
        ex.tech = techR;
        List<Extract.Ref> refs = new ArrayList<>(jsRefs);
        refs.sort(Comparator.comparing((Extract.Ref x) -> x.path()).thenComparing(x -> x.method() == null ? "" : x.method())
                .thenComparing(x -> x.host() == null ? "" : x.host()).thenComparing(Extract.Ref::kind));
        ex.jsRefs = refs;
        List<Extract.Asset> assets = new ArrayList<>(jsAssets);
        assets.sort(Comparator.comparing(Extract.Asset::kind).thenComparing(Extract.Asset::host).thenComparing(Extract.Asset::path));
        ex.jsAssets = assets;
        ex.stack = stack;
        ex.scanTruncated = scanTruncated;
        ex.gqlOps = gql;
        ex.preflight = preflight;
        ex.setEv(ev);
        ex.reqPath = redPath;
        return ex;
    }

    private static List<Object> headerList(List<Redact.Pair> hs) {
        List<Object> out = new ArrayList<>();
        for (Redact.Pair h : hs) {
            out.add(new ArrayList<>(List.of(h.name(), Redact.redactNamed(h.value()))));
        }
        return out;
    }

    static List<Object> unused() {
        return Collections.emptyList();
    }
}
