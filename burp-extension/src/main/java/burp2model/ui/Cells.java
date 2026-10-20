package burp2model.ui;

import java.util.List;
import java.util.Map;

/** Values as a person reads them in a table cell: lists as "a, b", maps as "user 403 · admin 200", nothing as blank. */
final class Cells {
    private Cells() {}

    static String text(Object v) {
        if (v == null) {
            return "";
        }
        if (v instanceof List<?> l) {
            StringBuilder sb = new StringBuilder();
            for (Object o : l) {
                String s = text(o);
                if (!s.isEmpty()) {
                    sb.append(sb.length() > 0 ? ", " : "").append(s);
                }
            }
            return sb.toString();
        }
        if (v instanceof Map<?, ?> m) {
            StringBuilder sb = new StringBuilder();
            m.forEach((k, x) -> sb.append(sb.length() > 0 ? " · " : "").append(k).append(' ').append(text(x)));
            return sb.toString();
        }
        return String.valueOf(v);
    }

    /**
     * A list that arrived already written out ("[200, 403]", "user,admin", as some query answers give them), read
     * the same way as a real list.
     */
    static String listText(Object v) {
        if (!(v instanceof String s)) {
            return text(v);
        }
        String t = s.strip();
        if (t.startsWith("[") && t.endsWith("]")) {
            t = t.substring(1, t.length() - 1);
        }
        return t.replaceAll("\\s*,\\s*", ", ");
    }
}
