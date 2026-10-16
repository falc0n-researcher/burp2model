package burp2model.engine;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/** A small JSON reader and writer: objects are LinkedHashMap, arrays ArrayList, numbers Long or Double. */
public final class Json {
    private Json() {}

    /** A value that writes its own JSON (a large log that is kept compressed, for instance). */
    public interface Writable {
        void writeTo(StringBuilder sb, int indent, int depth);
    }

    static void writeIterable(StringBuilder sb, Iterable<?> it, int indent, int depth) {
        boolean first = true;
        sb.append('[');
        boolean any = false;
        for (Object o : it) {
            any = true;
            if (!first) {
                sb.append(',');
            }
            first = false;
            nl(sb, indent, depth + 1);
            write(sb, o, indent, depth + 1);
        }
        if (any) {
            nl(sb, indent, depth);
        }
        sb.append(']');
    }

    public static String write(Object v) {
        StringBuilder sb = new StringBuilder();
        write(sb, v, -1, 0);
        return sb.toString();
    }

    public static String pretty(Object v) {
        StringBuilder sb = new StringBuilder();
        write(sb, v, 2, 0);
        return sb.toString();
    }

    @SuppressWarnings("unchecked")
    private static void write(StringBuilder sb, Object v, int indent, int depth) {
        if (v == null) {
            sb.append("null");
        } else if (v instanceof Writable w) {
            w.writeTo(sb, indent, depth);
        } else if (v instanceof String s) {
            quote(sb, s);
        } else if (v instanceof Boolean || v instanceof Integer || v instanceof Long) {
            sb.append(v);
        } else if (v instanceof Number n) {
            double d = n.doubleValue();
            if (Double.isNaN(d) || Double.isInfinite(d)) {
                sb.append("null");
            } else {
                sb.append(n instanceof Double || n instanceof Float ? Double.toString(d) : n.toString());
            }
        } else if (v instanceof Map<?, ?> m) {
            if (m.isEmpty()) {
                sb.append("{}");
                return;
            }
            sb.append('{');
            boolean first = true;
            for (Map.Entry<String, Object> e : ((Map<String, Object>) m).entrySet()) {
                if (!first) {
                    sb.append(',');
                }
                first = false;
                nl(sb, indent, depth + 1);
                quote(sb, e.getKey());
                sb.append(indent >= 0 ? ": " : ":");
                write(sb, e.getValue(), indent, depth + 1);
            }
            nl(sb, indent, depth);
            sb.append('}');
        } else if (v instanceof Iterable<?> it) {
            boolean first = true;
            sb.append('[');
            boolean any = false;
            for (Object o : it) {
                any = true;
                if (!first) {
                    sb.append(',');
                }
                first = false;
                nl(sb, indent, depth + 1);
                write(sb, o, indent, depth + 1);
            }
            if (any) {
                nl(sb, indent, depth);
            }
            sb.append(']');
        } else {
            quote(sb, String.valueOf(v));
        }
    }

    private static void nl(StringBuilder sb, int indent, int depth) {
        if (indent >= 0) {
            sb.append('\n').append(" ".repeat(indent * depth));
        }
    }

    private static void quote(StringBuilder sb, String s) {
        sb.append('"');
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            switch (c) {
                case '"' -> sb.append("\\\"");
                case '\\' -> sb.append("\\\\");
                case '\n' -> sb.append("\\n");
                case '\r' -> sb.append("\\r");
                case '\t' -> sb.append("\\t");
                default -> {
                    if (c < 0x20) {
                        sb.append(String.format("\\u%04x", (int) c));
                    } else if (Character.isHighSurrogate(c) && i + 1 < s.length() && Character.isLowSurrogate(s.charAt(i + 1))) {
                        sb.append(c).append(s.charAt(++i));
                    } else if (Character.isSurrogate(c)) {
                        // a lone surrogate has no UTF-8 form and would be saved as '?': keep it as an escape
                        sb.append(String.format("\\u%04x", (int) c));
                    } else {
                        sb.append(c);
                    }
                }
            }
        }
        sb.append('"');
    }

    // ------------------------------------------------------------------ parse

    /** Malformed or truncated JSON, with the offset where reading stopped. */
    public static final class JsonError extends IllegalArgumentException {
        private static final long serialVersionUID = 1L;
        public final int offset;

        JsonError(String what, int offset) {
            super(what + " at " + offset);
            this.offset = offset;
        }
    }

    public static Object parse(String s) {
        P p = new P(s);
        p.ws();
        Object v = p.value();
        p.ws();
        if (p.i != s.length()) {
            throw new JsonError("trailing data", p.i);
        }
        return v;
    }

    private static final class P {
        final String s;
        int i;

        P(String s) {
            this.s = s;
        }

        void ws() {
            while (i < s.length() && Character.isWhitespace(s.charAt(i))) {
                i++;
            }
        }

        char peek() {
            if (i >= s.length()) {
                throw new JsonError("unexpected end", i);
            }
            return s.charAt(i);
        }

        char next() {
            char c = peek();
            i++;
            return c;
        }

        void expect(char want) {
            ws();
            char c = next();
            if (c != want) {
                throw new JsonError("expected '" + want + "' but found '" + c + "'", i - 1);
            }
        }

        Object value() {
            ws();
            if (i >= s.length()) {
                throw new JsonError("unexpected end", i);
            }
            char c = s.charAt(i);
            if (c == '{') {
                return object();
            }
            if (c == '[') {
                return array();
            }
            if (c == '"') {
                return string();
            }
            if (s.startsWith("true", i)) {
                i += 4;
                return Boolean.TRUE;
            }
            if (s.startsWith("false", i)) {
                i += 5;
                return Boolean.FALSE;
            }
            if (s.startsWith("null", i)) {
                i += 4;
                return null;
            }
            return number();
        }

        Map<String, Object> object() {
            Map<String, Object> m = new LinkedHashMap<>();
            i++;
            ws();
            if (peek() == '}') {
                i++;
                return m;
            }
            while (true) {
                ws();
                if (peek() != '"') {
                    throw new JsonError("expected a key", i);
                }
                String k = string();
                expect(':');
                m.put(k, value());
                ws();
                char c = next();
                if (c == '}') {
                    return m;
                }
                if (c != ',') {
                    throw new JsonError("expected ',' or '}' but found '" + c + "'", i - 1);
                }
            }
        }

        List<Object> array() {
            List<Object> l = new ArrayList<>();
            i++;
            ws();
            if (peek() == ']') {
                i++;
                return l;
            }
            while (true) {
                l.add(value());
                ws();
                char c = next();
                if (c == ']') {
                    return l;
                }
                if (c != ',') {
                    throw new JsonError("expected ',' or ']' but found '" + c + "'", i - 1);
                }
            }
        }

        String string() {
            StringBuilder sb = new StringBuilder();
            i++;
            while (true) {
                char c = next();
                if (c == '"') {
                    return sb.toString();
                }
                if (c == '\\') {
                    char e = next();
                    switch (e) {
                        case 'n' -> sb.append('\n');
                        case 'r' -> sb.append('\r');
                        case 't' -> sb.append('\t');
                        case 'b' -> sb.append('\b');
                        case 'f' -> sb.append('\f');
                        case 'u' -> {
                            if (i + 4 > s.length()) {
                                throw new JsonError("unexpected end", s.length());
                            }
                            try {
                                sb.append((char) Integer.parseInt(s.substring(i, i + 4), 16));
                            } catch (NumberFormatException bad) {
                                throw new JsonError("bad \\u escape", i);
                            }
                            i += 4;
                        }
                        default -> sb.append(e);
                    }
                } else {
                    sb.append(c);
                }
            }
        }

        Object number() {
            int st = i;
            while (i < s.length() && "+-0123456789.eE".indexOf(s.charAt(i)) >= 0) {
                i++;
            }
            String t = s.substring(st, i);
            if (t.isEmpty()) {
                throw new JsonError("bad json", st);
            }
            try {
                if (t.contains(".") || t.contains("e") || t.contains("E")) {
                    return Double.parseDouble(t);
                }
                return Long.parseLong(t);
            } catch (NumberFormatException bad) {
                throw new JsonError("bad number", st);
            }
        }
    }
}
