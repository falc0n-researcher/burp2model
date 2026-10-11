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
            BODY.add(new Sign(Pattern.compile(r[0], Pattern.CASE_INSENSITIVE), r[1], r[2]));
        }
        for (String[] r : StackData.PATH_SIGNS) {
            PATH.add(new Sign(Pattern.compile(r[0], Pattern.CASE_INSENSITIVE), r[1], r[2]));
        }
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
        for (Sign s : BODY) {
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
