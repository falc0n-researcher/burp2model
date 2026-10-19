package burp2model.engine;

import java.io.File;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.Set;

/** Reads a HAR file (browser DevTools, Hetty, mitmproxy, ZAP, Charles ...) as if it were a Burp export. A port of parse.py's HAR reader. */
public final class Har {
    private Har() {}

    private static final Set<String> DROP = Set.of("content-encoding", "transfer-encoding", "content-length");

    @SuppressWarnings("unchecked")
    private static List<String[]> headers(Object hs) {
        List<String[]> out = new ArrayList<>();
        if (hs instanceof List<?> l) {
            for (Object o : l) {
                if (o instanceof Map<?, ?> m) {
                    String name = String.valueOf(((Map<String, Object>) m).getOrDefault("name", "")).strip();
                    if (!name.isEmpty() && !name.startsWith(":")) {
                        out.add(new String[] {name, String.valueOf(((Map<String, Object>) m).getOrDefault("value", ""))});
                    }
                }
            }
        }
        return out;
    }

    private static byte[] latin1(String s) {
        return s.getBytes(StandardCharsets.ISO_8859_1);
    }

    private static byte[] concat(byte[]... parts) {
        int n = 0;
        for (byte[] p : parts) {
            n += p.length;
        }
        byte[] out = new byte[n];
        int at = 0;
        for (byte[] p : parts) {
            System.arraycopy(p, 0, out, at, p.length);
            at += p.length;
        }
        return out;
    }

    private static String urlencode(List<String[]> pairs) {
        List<String> parts = new ArrayList<>();
        for (String[] p : pairs) {
            parts.add(Url.quotePlus(p[0], "") + "=" + Url.quotePlus(p[1], ""));
        }
        return String.join("&", parts);
    }

    @SuppressWarnings("unchecked")
    static Parse.Raw entry(Map<String, Object> e) {
        Map<String, Object> rq = e.get("request") instanceof Map<?, ?> m ? (Map<String, Object>) m : Map.of();
        Map<String, Object> rs = e.get("response") instanceof Map<?, ?> m ? (Map<String, Object>) m : Map.of();
        String url = String.valueOf(rq.getOrDefault("url", ""));
        String host;
        String scheme;
        int port;
        String path;
        String netloc;
        try {
            URI u = new URI(url);
            host = u.getHost() == null ? "" : u.getHost().toLowerCase();
            scheme = u.getScheme() == null ? "https" : u.getScheme().toLowerCase();
            port = u.getPort() > 0 ? u.getPort() : scheme.equals("https") ? 443 : 80;
            String rawPath = u.getRawPath() == null || u.getRawPath().isEmpty() ? "/" : u.getRawPath();
            path = rawPath + (u.getRawQuery() == null || u.getRawQuery().isEmpty() ? "" : "?" + u.getRawQuery());
            netloc = u.getRawAuthority() == null ? host : u.getRawAuthority();
        } catch (Exception ex) {
            return null;
        }
        int status = rs.get("status") instanceof Number n ? n.intValue() : 0;
        if (host.isEmpty() || status == 0) {
            return null;
        }
        String method = String.valueOf(rq.getOrDefault("method", "GET")).toUpperCase();
        String ver = String.valueOf(rq.getOrDefault("httpVersion", "HTTP/1.1"));
        if (!ver.toUpperCase().startsWith("HTTP/") || !ver.contains(".")) {
            ver = "HTTP/1.1";
        }
        List<String[]> rqh = headers(rq.get("headers"));
        if (rqh.stream().noneMatch(h -> h[0].equalsIgnoreCase("host"))) {
            int at = netloc.lastIndexOf('@');
            rqh.add(0, new String[] {"Host", at >= 0 ? netloc.substring(at + 1) : netloc});
        }
        Map<String, Object> post = rq.get("postData") instanceof Map<?, ?> m ? (Map<String, Object>) m : Map.of();
        String bodyText = post.get("text") == null ? null : String.valueOf(post.get("text"));
        if (bodyText == null && post.get("params") instanceof List<?> ps && !ps.isEmpty()) {
            List<String[]> pairs = new ArrayList<>();
            for (Object o : ps) {
                Map<String, Object> p = (Map<String, Object>) o;
                pairs.add(new String[] {String.valueOf(p.getOrDefault("name", "")), String.valueOf(p.getOrDefault("value", ""))});
            }
            bodyText = urlencode(pairs);
        }
        StringBuilder head = new StringBuilder(method + " " + path + " " + ver + "\r\n");
        for (String[] h : rqh) {
            String low = h[0].toLowerCase();
            if (!DROP.contains(low) || low.equals("content-length")) {
                head.append(h[0]).append(": ").append(h[1]).append("\r\n");
            }
        }
        byte[] rawRq = concat(latin1(head.toString()), latin1("\r\n"), (bodyText == null ? "" : bodyText).getBytes(StandardCharsets.UTF_8));

        Map<String, Object> content = rs.get("content") instanceof Map<?, ?> m ? (Map<String, Object>) m : Map.of();
        StringBuilder rhead = new StringBuilder("HTTP/1.1 " + status + " " + (rs.get("statusText") == null || rs.get("statusText").equals("") ? "" : rs.get("statusText")) + "\r\n");
        for (String[] h : headers(rs.get("headers"))) {
            if (!DROP.contains(h[0].toLowerCase())) {
                rhead.append(h[0]).append(": ").append(h[1]).append("\r\n");
            }
        }
        byte[] rsBody = new byte[0];
        if (content.get("text") != null) {
            String t = String.valueOf(content.get("text"));
            if ("base64".equals(content.get("encoding"))) {
                try {
                    rsBody = Base64.getMimeDecoder().decode(t);
                } catch (IllegalArgumentException ex) {
                    rsBody = new byte[0];
                }
            } else {
                rsBody = t.getBytes(StandardCharsets.UTF_8);
            }
        }
        byte[] rawRs = concat(latin1(rhead.toString()), latin1("\r\n"), rsBody);
        return new Parse.Raw(method, host, port, scheme, path, status, content.get("mimeType") == null ? "" : String.valueOf(content.get("mimeType")), rawRq, rawRs, false);
    }

    /** True when the file looks like a HAR (by extension or by its first bytes). */
    public static boolean looksLike(File f) {
        String n = f.getName().toLowerCase();
        if (n.endsWith(".har")) {
            return true;
        }
        if (!n.endsWith(".json")) {
            return false;
        }
        try {
            byte[] head;
            try (var in = Files.newInputStream(f.toPath())) {
                head = in.readNBytes(4096);                     // the start is enough; a HAR can be hundreds of MB
            }
            String s = new String(head, StandardCharsets.UTF_8).stripLeading();
            return s.startsWith("{") && s.contains("\"log\"");
        } catch (Exception e) {
            return false;
        }
    }

    /**
     * The responses a HAR holds, as raw items; entries without a response are left out. The file is read as a
     * stream: only one entry is held as text at a time, so a capture of hundreds of MB does not sit in memory twice.
     */
    @SuppressWarnings("unchecked")
    public static List<Parse.Raw> readRaw(File f) throws Exception {
        List<Parse.Raw> out = new ArrayList<>();
        try (java.io.Reader in = new java.io.BufferedReader(new java.io.InputStreamReader(Files.newInputStream(f.toPath()), StandardCharsets.UTF_8), 1 << 16)) {
            Stream st = new Stream(in);
            boolean found = st.entries(text -> {
                Object o = Json.parse(text);
                out.add(o instanceof Map<?, ?> m ? entry((Map<String, Object>) m) : null);   // null stays, so the item count is the file's
            });
            if (!found) {
                throw new IllegalArgumentException("not a HAR file (no log.entries)");
            }
        }
        return out;
    }

    /** Just enough of a streaming JSON reader to walk to log.entries and hand out each entry's text. */
    static final class Stream {
        private final java.io.Reader in;
        private int peeked = -2;

        Stream(java.io.Reader in) {
            this.in = in;
        }

        private int peek() throws java.io.IOException {
            if (peeked == -2) {
                peeked = in.read();
                if (peeked == 0xFEFF) {
                    peeked = in.read();                       // a byte order mark before the JSON
                }
            }
            return peeked;
        }

        private int next() throws java.io.IOException {
            int c = peek();
            peeked = in.read();
            return c;
        }

        private int skipWs() throws java.io.IOException {
            while (peek() == ' ' || peek() == '\n' || peek() == '\r' || peek() == '\t') {
                next();
            }
            return peek();
        }

        private void expect(char ch) throws java.io.IOException {
            int c = skipWs();
            if (c != ch) {
                throw new IllegalArgumentException("not a HAR file (expected '" + ch + "', found " + (c < 0 ? "the end" : "'" + (char) c + "'") + ")");
            }
            next();
        }

        /** A JSON string (positioned at its opening quote), decoded through the ordinary parser. */
        private String string() throws java.io.IOException {
            StringBuilder raw = new StringBuilder();
            copyString(raw);
            return (String) Json.parse(raw.toString());
        }

        private void copyString(StringBuilder sb) throws java.io.IOException {
            sb.append((char) next());                          // the opening quote
            while (true) {
                int c = next();
                if (c < 0) {
                    throw new IllegalArgumentException("not a HAR file (cut off inside a string)");
                }
                if (sb != null) {
                    sb.append((char) c);
                }
                if (c == '\\') {
                    int e = next();
                    if (e < 0) {
                        throw new IllegalArgumentException("not a HAR file (cut off inside a string)");
                    }
                    sb.append((char) e);
                } else if (c == '"') {
                    return;
                }
            }
        }

        /** Copy one value (object, array, string or literal) into sb, or skip it when sb is null. */
        private void value(StringBuilder sb) throws java.io.IOException {
            int c = skipWs();
            if (c == '"') {
                copyString(sb == null ? new StringBuilder() : sb);
                return;
            }
            if (c == '{' || c == '[') {
                int depth = 0;
                while (true) {
                    c = peek();
                    if (c < 0) {
                        throw new IllegalArgumentException("not a HAR file (cut off)");
                    }
                    if (c == '"') {
                        copyString(sb == null ? new StringBuilder() : sb);
                        continue;
                    }
                    next();
                    if (sb != null) {
                        sb.append((char) c);
                    }
                    if (c == '{' || c == '[') {
                        depth++;
                    } else if (c == '}' || c == ']') {
                        if (--depth == 0) {
                            return;
                        }
                    }
                }
            }
            while (true) {                                     // number, true, false, null
                c = peek();
                if (c < 0 || c == ',' || c == '}' || c == ']' || c == ' ' || c == '\n' || c == '\r' || c == '\t') {
                    return;
                }
                next();
                if (sb != null) {
                    sb.append((char) c);
                }
            }
        }

        /** Walk the object at the cursor, calling onKey for each key with the cursor on its value. */
        private void object(KeyHandler onKey) throws java.io.IOException {
            expect('{');
            if (skipWs() == '}') {
                next();
                return;
            }
            while (true) {
                if (skipWs() != '"') {
                    throw new IllegalArgumentException("not a HAR file (expected a key)");
                }
                String key = string();
                expect(':');
                onKey.value(key);
                int c = skipWs();
                next();
                if (c == '}') {
                    return;
                }
                if (c != ',') {
                    throw new IllegalArgumentException("not a HAR file (expected ',' or '}')");
                }
            }
        }

        private interface KeyHandler {
            void value(String key) throws java.io.IOException;
        }

        /** Hand each element of log.entries to sink as JSON text; false when the file has no log.entries. */
        boolean entries(java.util.function.Consumer<String> sink) throws java.io.IOException {
            boolean[] found = {false};
            object(key -> {
                if (!key.equals("log") || skipWs() != '{') {
                    value(null);
                    return;
                }
                object(k2 -> {
                    if (!k2.equals("entries") || skipWs() != '[') {
                        value(null);
                        return;
                    }
                    found[0] = true;
                    expect('[');
                    if (skipWs() == ']') {
                        next();
                        return;
                    }
                    while (true) {
                        StringBuilder one = new StringBuilder();
                        value(one);
                        sink.accept(one.toString());
                        int c = skipWs();
                        next();
                        if (c == ']') {
                            return;
                        }
                        if (c != ',') {
                            throw new IllegalArgumentException("not a HAR file (expected ',' or ']' between entries)");
                        }
                    }
                });
            });
            return found[0];
        }
    }

    public static List<Exchange> read(File f, String role) throws Exception {
        List<Exchange> out = new ArrayList<>();
        int i = 1;
        int item = 0;
        for (Parse.Raw r : readRaw(f)) {
            Exchange ex = null;
            if (r != null) {
                try {
                    ex = Parse.item(i, r, role, f.getName(), item);
                } catch (RuntimeException e) {
                    ex = null;
                }
            }
            if (ex != null) {
                out.add(ex);
                i++;
            }
            item++;
        }
        return out;
    }

    static URI unused() {
        return null;
    }
}
