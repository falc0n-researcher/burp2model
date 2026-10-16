package burp2model.engine;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/** What an app is built on, read from the capture (a port of stack.py). Hints, never a version scan. */
public final class Stack {
    private Stack() {}

    public record Hit(String name, String category, String how, String version) {}

    private record HeadSign(String header, Pattern rx, String name, String category) {}

    private record Sign(Pattern rx, String name, String category) {}

    /** A body sign plus the lowercase literals one of which any match must contain (null: no cheap test, always run). */
    private record BodySign(Sign sign, String[] needles) {}

    private static final List<BodySign> BODY_FAST = new ArrayList<>();

    private static final List<HeadSign> HEAD = new ArrayList<>();
    private static final List<Sign> COOK = new ArrayList<>();
    private static final List<Sign> BODY = new ArrayList<>();
    private static final List<Sign> PATH = new ArrayList<>();
    private static final Pattern GENERATOR = Pattern.compile(StackData.GENERATOR, Pattern.CASE_INSENSITIVE);
    private static final Pattern RECAPTCHA = Pattern.compile(StackData.RECAPTCHA, Pattern.CASE_INSENSITIVE);
    private static final Pattern GEN_NAME = Pattern.compile("^([A-Za-z][\\w .+-]*?)(?:\\s+([\\d][\\w.]*))?$");
    private static final int SCAN_CAP = 400_000;

    static {
        for (String[] r : StackData.HEADER_SIGNS) {
            HEAD.add(new HeadSign(r[0], Pattern.compile(r[1], Pattern.CASE_INSENSITIVE), r[2], r[3]));
        }
        for (String[] r : StackData.COOKIE_SIGNS) {
            COOK.add(new Sign(Pattern.compile(r[0], Pattern.CASE_INSENSITIVE), r[1], r[2]));
        }
        for (String[] r : StackData.BODY_SIGNS) {
            Sign s = new Sign(Pattern.compile(r[0], Pattern.CASE_INSENSITIVE), r[1], r[2]);
            BODY.add(s);
            BODY_FAST.add(new BodySign(s, needles(r[0])));
        }
        for (String[] r : StackData.PATH_SIGNS) {
            PATH.add(new Sign(Pattern.compile(r[0], Pattern.CASE_INSENSITIVE), r[1], r[2]));
        }
    }

    private static boolean containsAny(String text, String[] needles) {
        for (String n : needles) {
            if (text.contains(n)) {
                return true;
            }
        }
        return false;
    }

    /**
     * For a pattern made of top-level alternatives, the longest literal each alternative must contain, lowercased.
     * Groups, classes and optional characters are skipped, so a literal found is always required. If any
     * alternative has no literal of 3 characters or more there is no cheap test: null.
     */
    static String[] needles(String rx) {
        List<String> alts = new ArrayList<>();
        int depth = 0;
        int start = 0;
        for (int i = 0; i < rx.length(); i++) {
            char c = rx.charAt(i);
            if (c == '\\') {
                i++;
            } else if (c == '[') {
                i = classEnd(rx, i);
            } else if (c == '(') {
                depth++;
            } else if (c == ')') {
                depth--;
            } else if (c == '|' && depth == 0) {
                alts.add(rx.substring(start, i));
                start = i + 1;
            }
        }
        alts.add(rx.substring(start));
        String[] out = new String[alts.size()];
        for (int k = 0; k < alts.size(); k++) {
            String lit = longestLiteral(alts.get(k));
            if (lit.length() < 3) {
                return null;
            }
            out[k] = lit.toLowerCase(java.util.Locale.ROOT);
        }
        return out;
    }

    private static int classEnd(String rx, int open) {
        int i = open + 1;
        if (i < rx.length() && rx.charAt(i) == '^') {
            i++;
        }
        if (i < rx.length() && rx.charAt(i) == ']') {
            i++;
        }
        for (; i < rx.length(); i++) {
            char c = rx.charAt(i);
            if (c == '\\') {
                i++;
            } else if (c == ']') {
                return i;
            }
        }
        return rx.length();
    }

    private static String longestLiteral(String alt) {
        String best = "";
        StringBuilder run = new StringBuilder();
        for (int i = 0; i < alt.length(); i++) {
            char c = alt.charAt(i);
            Character lit = null;
            int next = i + 1;
            if (c == '\\' && i + 1 < alt.length()) {
                char e = alt.charAt(i + 1);
                next = i + 2;
                if (!Character.isLetterOrDigit(e)) {
                    lit = e;                                   // \. \/ \" and the like are the character itself
                }
            } else if (c == '[') {
                next = classEnd(alt, i) + 1;
            } else if (c == '(') {
                int d = 1;
                int j = i + 1;
                for (; j < alt.length() && d > 0; j++) {
                    char x = alt.charAt(j);
                    if (x == '\\') {
                        j++;
                    } else if (x == '[') {
                        j = classEnd(alt, j);
                    } else if (x == '(') {
                        d++;
                    } else if (x == ')') {
                        d--;
                    }
                }
                next = j;
            } else if (".^$|)?*+{}".indexOf(c) < 0) {
                lit = c;
            }
            // a character followed by ?, * or {0 may be absent: it cannot be part of a required literal
            boolean optional = next < alt.length() && (alt.charAt(next) == '?' || alt.charAt(next) == '*' || alt.startsWith("{0", next));
            if (lit != null && !optional) {
                run.append(lit);
            } else {
                if (run.length() > best.length()) {
                    best = run.toString();
                }
                run.setLength(0);
                if (lit != null && optional) {
                    // nothing: the optional character ends the run
                }
            }
            boolean quantified = next < alt.length() && "?*+{".indexOf(alt.charAt(next)) >= 0;
            if (quantified) {
                if (run.length() > best.length()) {
                    best = run.toString();
                }
                run.setLength(0);
                if (alt.charAt(next) == '{') {
                    int close = alt.indexOf('}', next);
                    next = close < 0 ? alt.length() : close + 1;
                } else {
                    next++;
                }
                if (next < alt.length() && (alt.charAt(next) == '?' || alt.charAt(next) == '+')) {
                    next++;                                    // lazy or possessive
                }
            }
            i = next - 1;
        }
        return run.length() > best.length() ? run.toString() : best;
    }

    public static List<String> categories() {
        return List.of(StackData.CATEGORIES);
    }

    public static String serviceKind(String name) {
        return name.equals("reCAPTCHA") ? "Bot protection" : "";
    }

    private static String ver(Matcher m) {
        if (m.groupCount() >= 1 && m.group(1) != null && !m.group(1).isEmpty()) {
            String v = m.group(1);
            return v.length() > 20 ? v.substring(0, 20) : v;
        }
        return "";
    }

    private static void add(Map<String, String[]> found, String name, String cat, String how, String ver) {
        String k = name + "\0" + cat;
        String[] cur = found.get(k);
        if (cur == null || (!ver.isEmpty() && cur[1].isEmpty())) {
            found.put(k, new String[] {how, !ver.isEmpty() ? ver : (cur != null ? cur[1] : "")});
        }
    }

    private static List<Hit> toHits(Map<String, String[]> found) {
        List<Hit> out = new ArrayList<>();
        for (Map.Entry<String, String[]> e : found.entrySet()) {
            String[] k = e.getKey().split("\0", 2);
            out.add(new Hit(k[0], k[1], e.getValue()[0], e.getValue()[1]));
        }
        return out;
    }

    /** What the markup or script text itself shows (the part that depends only on the body, so it can be cached by content). */
    public static List<Hit> bodyHits(String body) {
        Map<String, String[]> found = new LinkedHashMap<>();
        if (body == null || body.isEmpty()) {
            return List.of();
        }
        String text = body.length() > SCAN_CAP ? body.substring(0, SCAN_CAP) : body;
        // one lowercase copy and a few contains() calls rule out most signs before any regex runs over the body
        String lower = text.toLowerCase(java.util.Locale.ROOT);
        for (BodySign b : BODY_FAST) {
            if (b.needles() != null && !containsAny(lower, b.needles())) {
                continue;
            }
            Sign s = b.sign();
            Matcher m = s.rx().matcher(text);
            if (m.find()) {
                add(found, s.name(), s.category(), "page", ver(m));
            }
        }
        Matcher g = GENERATOR.matcher(text);
        if (g.find()) {
            String gen = g.group(1).strip();
            if (gen.length() > 60) {
                gen = gen.substring(0, 60);
            }
            Matcher nm = GEN_NAME.matcher(gen);
            String name = gen;
            String v = "";
            if (nm.find()) {
                name = nm.group(1).strip();
                v = nm.group(2) == null ? "" : nm.group(2);
            }
            if (name.toLowerCase().startsWith("wordpress")) {
                name = "WordPress";
            }
            add(found, name, "CMS & platform", "meta generator", v);
        }
        if (RECAPTCHA.matcher(text).find()) {
            add(found, "reCAPTCHA", "Services", "page", "");
        }
        return toHits(found);
    }

    /** Technologies one response shows. Deterministic, deduplicated. */
    public static List<Hit> detect(Map<String, String> headers, List<String> cookieNames, String body, String path, boolean isMarkup) {
        return detect(headers, cookieNames, isMarkup ? bodyHits(body) : List.of(), path);
    }

    public static List<Hit> detect(Map<String, String> headers, List<String> cookieNames, List<Hit> bodyHits, String path) {
        Map<String, String[]> found = new LinkedHashMap<>();
        for (HeadSign h : HEAD) {
            String v = headers.get(h.header());
            if (v != null && !v.isEmpty()) {
                Matcher m = h.rx().matcher(v);
                if (m.find()) {
                    add(found, h.name(), h.category(), "header:" + h.header(), ver(m));
                }
            }
        }
        if (cookieNames != null) {
            for (String ck : cookieNames) {
                for (Sign s : COOK) {
                    if (s.rx().matcher(ck).find()) {
                        add(found, s.name(), s.category(), "cookie", "");
                    }
                }
            }
        }
        for (Sign s : PATH) {
            if (s.rx().matcher(path == null ? "" : path).find()) {
                add(found, s.name(), s.category(), "path", "");
            }
        }
        for (Hit h : bodyHits) {
            add(found, h.name(), h.category(), h.how(), h.version());
        }
        List<Hit> out = toHits(found);
        out.sort(Comparator.comparing(Hit::name).thenComparing(Hit::category).thenComparing(Hit::how).thenComparing(Hit::version));
        return out;
    }

    public record Vendor(String vendor, String kind, String host) {}

    public static List<Vendor> vendorsFor(List<String> hosts) {
        List<Vendor> out = new ArrayList<>();
        java.util.Set<String> seen = new java.util.HashSet<>();
        for (String host : hosts) {
            String h = host == null ? "" : host.toLowerCase();
            for (String[] v : StackData.VENDORS) {
                if (h.equals(v[0]) || h.endsWith("." + v[0])) {
                    if (seen.add(v[1] + "\0" + h)) {
                        out.add(new Vendor(v[1], v[2], h));
                    }
                    break;
                }
            }
        }
        return out;
    }
}
