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
            byte[] head = Files.readAllBytes(f.toPath());
            String s = new String(head, 0, Math.min(head.length, 4096), StandardCharsets.UTF_8).stripLeading();
            return s.startsWith("{") && s.contains("\"log\"");
        } catch (Exception e) {
            return false;
        }
    }

    /** The responses a HAR holds, as raw items; entries without a response are left out. */
    @SuppressWarnings("unchecked")
    public static List<Parse.Raw> readRaw(File f) throws Exception {
        Object doc = Json.parse(Files.readString(f.toPath(), StandardCharsets.UTF_8));
        Object entries = doc instanceof Map<?, ?> m && m.get("log") instanceof Map<?, ?> l ? l.get("entries") : null;
        if (!(entries instanceof List<?> list)) {
            throw new IllegalArgumentException("not a HAR file (no log.entries)");
        }
        List<Parse.Raw> out = new ArrayList<>();
        for (Object o : list) {
            Parse.Raw r = o instanceof Map<?, ?> m ? entry((Map<String, Object>) m) : null;
            out.add(r);                       // null stays, so the item count is the file's
        }
        return out;
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
