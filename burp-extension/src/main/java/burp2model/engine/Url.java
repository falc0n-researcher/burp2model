package burp2model.engine;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

/** The few urllib.parse behaviours the engine relies on. */
final class Url {
    private Url() {}

    static String unquote(String s) {
        if (s.indexOf('%') < 0) {
            return s;
        }
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        byte[] b = s.getBytes(StandardCharsets.UTF_8);
        for (int i = 0; i < b.length; i++) {
            if (b[i] == '%' && i + 2 < b.length && hex(b[i + 1]) >= 0 && hex(b[i + 2]) >= 0) {
                out.write(hex(b[i + 1]) * 16 + hex(b[i + 2]));
                i += 2;
            } else {
                out.write(b[i]);
            }
        }
        return new String(out.toByteArray(), StandardCharsets.UTF_8);
    }

    private static int hex(byte c) {
        return Character.digit((char) c, 16);
    }

    static String unquotePlus(String s) {
        return unquote(s.replace('+', ' '));
    }

    /** parse_qsl(keep_blank_values=True). */
    static List<Redact.Pair> parseQsl(String q) {
        List<Redact.Pair> out = new ArrayList<>();
        if (q == null || q.isEmpty()) {
            return out;
        }
        for (String part : q.split("&", -1)) {
            if (part.isEmpty()) {
                continue;
            }
            int eq = part.indexOf('=');
            String k = eq < 0 ? part : part.substring(0, eq);
            String v = eq < 0 ? "" : part.substring(eq + 1);
            out.add(new Redact.Pair(unquotePlus(k), unquotePlus(v)));
        }
        return out;
    }

    /** quote_plus(s, safe). */
    static String quotePlus(String s, String safe) {
        StringBuilder sb = new StringBuilder();
        for (byte raw : s.getBytes(StandardCharsets.UTF_8)) {
            int c = raw & 0xff;
            if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_' || c == '.'
                    || c == '-' || c == '~' || safe.indexOf(c) >= 0) {
                sb.append((char) c);
            } else if (c == ' ') {
                sb.append('+');
            } else {
                sb.append('%').append(String.format("%02X", c));
            }
        }
        return sb.toString();
    }

    static String urlencode(List<Redact.Pair> pairs, String safe) {
        List<String> parts = new ArrayList<>();
        for (Redact.Pair p : pairs) {
            parts.add(quotePlus(p.name(), safe) + "=" + quotePlus(p.value(), safe));
        }
        return String.join("&", parts);
    }
}
