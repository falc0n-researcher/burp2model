package burp2model.engine;

import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.function.Function;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/**
 * Redaction: the trust core. Every value is masked before anything is stored; names and structure stay.
 * A credential is recorded as a keyed fingerprint (HMAC-SHA256, 12 hex chars), its length and entropy.
 * A port of redact.py.
 */
public final class Redact {
    private Redact() {}

    public static final String REDACTED = "[REDACTED]";

    public record Fingerprint(String kind, String hmac12, int length, double entropy) {
        public Map<String, Object> asMap() {
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("kind", kind);
            m.put("hmac_12", hmac12);
            m.put("length", (long) length);
            m.put("entropy", new java.math.BigDecimal(entropy).setScale(2, java.math.RoundingMode.HALF_EVEN).doubleValue());
            return m;
        }
    }

    public record Pair(String name, String value) {}

    public record Redacted<T>(T value, List<Fingerprint> prints) {}

    private static final Set<String> SENSITIVE_HEADERS = Set.of("authorization", "proxy-authorization", "cookie",
            "set-cookie", "x-api-key", "x-auth-token", "x-csrf-token", "x-xsrf-token", "api-key");
    private static final String[] SENSITIVE_HEADER_HINTS = {"token", "secret", "apikey", "api-key", "auth", "session"};
    private static final String[] SENSITIVE_PARAM_HINTS = {
        "password", "passwd", "pwd", "passcode", "secret", "token", "apikey", "api_key", "access_key", "refresh_token",
        "id_token", "client_secret", "private_key", "session", "sid", "csrf", "auth", "signature", "sig", "code", "otp",
        "pin", "ssn", "cvv", "cvc", "assertion", "answer", "passphrase", "totp", "mfa", "sessid", "nonce", "xsrf",
        "viewstate", "eventvalidation", "verification", "cookie", "credential", "bearer"};
    private static final Set<String> CREDENTIAL_GROUP = Set.of("current", "new", "repeat", "confirm", "old", "retype",
            "verify", "again", "newpass", "oldpass", "confirmation");

    private static final String[] VALUE_KINDS = {"jwt", "openai_key", "aws_key", "google_key", "slack_token",
        "github_token", "stripe_key", "private_key", "card", "email"};
    /** A cheap test that must hold for the pattern at the same index to have any chance of matching. */
    private static boolean mayMatch(int k, String text) {
        return switch (VALUE_KINDS[k]) {
            case "jwt" -> text.contains("eyJ");
            case "openai_key" -> text.contains("sk-");
            case "aws_key" -> text.contains("AKIA") || text.contains("ASIA");
            case "google_key" -> text.contains("AIza");
            case "slack_token" -> text.contains("xox");
            case "github_token" -> text.contains("gh");
            case "stripe_key" -> text.contains("k_live_") || text.contains("k_test_");
            case "private_key" -> text.contains("-----BEGIN ");
            case "card" -> hasDigitRun(text, 13);
            case "email" -> text.indexOf('@') >= 0;
            default -> true;
        };
    }

    /** Whether the text holds a run of at least n digits, allowing single spaces or dashes between them. */
    private static boolean hasDigitRun(String s, int n) {
        int run = 0;
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (c >= '0' && c <= '9') {
                if (++run >= n) {
                    return true;
                }
            } else if ((c == ' ' || c == '-') && run > 0 && i + 1 < s.length() && Character.isDigit(s.charAt(i + 1))) {
                continue;
            } else {
                run = 0;
            }
        }
        return false;
    }

    private static final Pattern[] VALUE_PATTERNS = {
        Pattern.compile("\\beyJ[A-Za-z0-9_-]{8,}\\.[A-Za-z0-9_-]{8,}\\.[A-Za-z0-9_-]{4,}\\b"),
        Pattern.compile("\\bsk-[A-Za-z0-9_-]{20,}\\b"),
        Pattern.compile("\\b(?:AKIA|ASIA)[0-9A-Z]{16}\\b"),
        Pattern.compile("\\bAIza[0-9A-Za-z_-]{35}\\b"),
        Pattern.compile("\\bxox[baprs]-[0-9A-Za-z-]{10,}\\b"),
        Pattern.compile("\\bgh[pousr]_[A-Za-z0-9]{36,}\\b"),
        Pattern.compile("\\b[rsp]k_(?:live|test)_[A-Za-z0-9]{16,}\\b"),
        Pattern.compile("-----BEGIN [A-Z ]*PRIVATE KEY-----"),
        Pattern.compile("\\b(?:\\d[ -]?){13,19}\\b"),
        Pattern.compile("\\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}\\b"),
    };

    // ------------------------------------------------------------ fingerprints

    private static byte[] key;

    public static synchronized void setKey(byte[] k) {
        key = k;
    }

    private static synchronized byte[] key() {
        if (key == null) {
            String env = System.getenv("BURP2MODEL_FP_KEY");
            if (env != null && !env.isEmpty()) {
                key = env.getBytes(StandardCharsets.UTF_8);
            } else {
                key = new byte[32];
                new SecureRandom().nextBytes(key);
            }
        }
        return key;
    }

    public static double entropy(String s) {
        if (s.isEmpty()) {
            return 0.0;
        }
        Map<Integer, Integer> counts = new HashMap<>();
        int n = 0;
        for (int i = 0; i < s.length(); ) {
            int cp = s.codePointAt(i);
            i += Character.charCount(cp);
            counts.merge(cp, 1, Integer::sum);
            n++;
        }
        double h = 0;
        for (int c : counts.values()) {
            double p = (double) c / n;
            h -= p * (Math.log(p) / Math.log(2));
        }
        return h;
    }

    public static Fingerprint fingerprint(String value, String kind) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(key(), "HmacSHA256"));
            byte[] d = mac.doFinal(value.getBytes(StandardCharsets.UTF_8));
            StringBuilder hex = new StringBuilder();
            for (int i = 0; i < 6; i++) {
                hex.append(String.format("%02x", d[i]));
            }
            return new Fingerprint(kind, hex.toString(), value.codePointCount(0, value.length()), entropy(value));
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    static boolean luhnOk(String digits) {
        int total = 0;
        for (int i = 0; i < digits.length(); i++) {
            int d = digits.charAt(digits.length() - 1 - i) - '0';
            if (i % 2 == 1) {
                d *= 2;
                if (d > 9) {
                    d -= 9;
                }
            }
            total += d;
        }
        return total % 10 == 0;
    }

    // ------------------------------------------------------------ names

    private static boolean isSensitiveHeader(String name) {
        String low = name.strip().toLowerCase();
        if (SENSITIVE_HEADERS.contains(low)) {
            return true;
        }
        for (String h : SENSITIVE_HEADER_HINTS) {
            if (low.contains(h)) {
                return true;
            }
        }
        return false;
    }

    private static final Pattern CAMEL = Pattern.compile("(?<=[a-z0-9])(?=[A-Z])");
    private static final Pattern NON_ALNUM = Pattern.compile("[^a-z0-9]+");

    static boolean isSensitiveParam(String name) {
        String low = CAMEL.matcher(name.strip()).replaceAll("_").toLowerCase();
        Set<String> tokens = new HashSet<>(Arrays.asList(NON_ALNUM.split(low, -1)));
        tokens.add(low);
        for (String h : SENSITIVE_PARAM_HINTS) {
            if (h.length() <= 4) {
                if (tokens.contains(h)) {
                    return true;
                }
            } else if (low.contains(h)) {
                return true;
            }
        }
        return false;
    }

    private static final Pattern ERROR_CONSTANT = Pattern.compile("^[A-Z][A-Z0-9]*(?:_[A-Z0-9]+)+$|^E[A-Z]{4,}$");

    static boolean isErrorConstant(String value) {
        String v = value.strip();
        if (v.startsWith("\"")) {
            v = v.substring(1);
        }
        if (v.endsWith("\"")) {
            v = v.substring(0, v.length() - 1);
        }
        return ERROR_CONSTANT.matcher(v).find();
    }

    private static final Pattern LEAF_SPLIT = Pattern.compile("[.\\[\\]$]+");

    static String leaf(String name) {
        String last = "";
        for (String p : LEAF_SPLIT.split(name.strip(), -1)) {
            if (!p.isEmpty()) {
                last = p;
            }
        }
        return CAMEL.matcher(last).replaceAll("_").toLowerCase().replace("_", "");
    }

    static boolean isCredentialGroup(Iterable<String> names) {
        Set<String> leaves = new HashSet<>();
        for (String n : names) {
            leaves.add(leaf(n));
        }
        leaves.retainAll(CREDENTIAL_GROUP);
        return leaves.size() >= 2;
    }

    // ------------------------------------------------------------ headers, params, bodies

    public static Redacted<List<Pair>> redactHeaders(List<Pair> headers) {
        List<Pair> out = new ArrayList<>();
        List<Fingerprint> prints = new ArrayList<>();
        for (Pair h : headers) {
            if (isSensitiveHeader(h.name()) && !h.value().isEmpty()) {
                prints.add(fingerprint(h.value(), h.name().strip().toLowerCase()));
                out.add(new Pair(h.name(), REDACTED));
            } else {
                Redacted<String> r = redactValuePatterns(h.value());
                prints.addAll(r.prints());
                out.add(new Pair(h.name(), r.value()));
            }
        }
        return new Redacted<>(out, prints);
    }

    static String sub(Pattern p, String text, Function<Matcher, String> f) {
        Matcher m = p.matcher(text);
        StringBuilder sb = new StringBuilder();
        int last = 0;
        while (m.find()) {
            sb.append(text, last, m.start()).append(f.apply(m));
            last = m.end();
        }
        return sb.append(text, last, text.length()).toString();
    }

    public static Redacted<String> redactValuePatterns(String text) {
        List<Fingerprint> prints = new ArrayList<>();
        if (text == null || text.isEmpty()) {
            return new Redacted<>(text, prints);
        }
        for (int k = 0; k < VALUE_PATTERNS.length; k++) {
            final String kind = VALUE_KINDS[k];
            if (!mayMatch(k, text)) {
                continue;
            }
            text = sub(VALUE_PATTERNS[k], text, m -> {
                String val = m.group();
                if (kind.equals("card")) {
                    String digits = val.replaceAll("\\D", "");
                    if (digits.length() < 13 || digits.length() > 19 || !luhnOk(digits)) {
                        return val;
                    }
                    if (digits.length() == 13 && digits.charAt(0) == '1') {
                        return val;                      // a millisecond timestamp, not a card
                    }
                }
                prints.add(fingerprint(val, kind));
                return "[REDACTED:" + kind + "]";
            });
        }
        return new Redacted<>(text, prints);
    }

    public static Redacted<List<Pair>> redactParams(List<Pair> params) {
        List<Pair> out = new ArrayList<>();
        List<Fingerprint> prints = new ArrayList<>();
        List<String> names = new ArrayList<>();
        for (Pair p : params) {
            names.add(p.name());
        }
        boolean group = isCredentialGroup(names);
        for (Pair p : params) {
            boolean sens = isSensitiveParam(p.name()) || (group && CREDENTIAL_GROUP.contains(leaf(p.name())));
            if (sens && !p.value().isEmpty() && !isErrorConstant(p.value())) {
                prints.add(fingerprint(p.value(), p.name().strip().toLowerCase()));
                out.add(new Pair(p.name(), REDACTED));
            } else {
                Redacted<String> r = redactValuePatterns(p.value());
                prints.addAll(r.prints());
                out.add(new Pair(p.name(), r.value()));
            }
        }
        return new Redacted<>(out, prints);
    }

    public static Redacted<String> redactBody(String body) {
        return redactValuePatterns(body);
    }

    private static final Pattern KV_ANY = Pattern.compile("(^|[?&;,#\\s])([A-Za-z0-9_.\\-\\[\\]]{1,64})(\\s*=\\s*)([^&;#\\s\"'<>]+)");
    private static final Pattern JSON_ANY = Pattern.compile(
            "\"((?:[^\"\\\\]|\\\\.){1,64})\"(\\s*:\\s*)(\"(?:[^\"\\\\]++|\\\\.)*+\"|-?\\d[\\d.eE+-]*|true|false|null)");
    private static final Pattern INPUT_TAG = Pattern.compile("<input\\b[^>]*>", Pattern.CASE_INSENSITIVE);
    private static final Pattern ATTR_NAME = Pattern.compile("\\bname\\s*=\\s*(?:\"([^\"]*)\"|'([^']*)'|([^\\s>]+))", Pattern.CASE_INSENSITIVE);
    private static final Pattern ATTR_VALUE = Pattern.compile("(\\bvalue\\s*=\\s*)(?:\"[^\"]*\"|'[^']*'|[^\\s>]+)", Pattern.CASE_INSENSITIVE);
    private static final Pattern MULTIPART = Pattern.compile(
            "(\\bname\\s*=\\s*\"([^\"\\r\\n]{1,64})\"[^\\r\\n]*(?:\\r?\\n[A-Za-z][A-Za-z\\-]*:[^\\r\\n]*)*\\r?\\n\\r?\\n)([^\\r\\n]+)");
    private static final Pattern XML_EL = Pattern.compile("<([A-Za-z_][\\w.\\-:]{0,63})(\\s[^<>]*)?>([^<>]{1,500})</\\1>");
    private static final Pattern ASSIGN = Pattern.compile("([\"']?)([A-Za-z_$][\\w$.\\-]{0,63})\\1(\\s*[:=]\\s*)([\"'])((?:(?!\\4)[^\\\\\\r\\n]|\\\\.){4,500})\\4");
    private static final Pattern YAML = Pattern.compile("(?m)^([ \\t]*)([A-Za-z_][\\w.\\-]{0,63})([ \\t]*:[ \\t]*)([^\\s\"'#<>{}\\[\\],][^\\r\\n#]{5,200})$");
    private static final Pattern JSON_LIST = Pattern.compile("\"((?:[^\"\\\\]|\\\\.){1,64})\"(\\s*:\\s*)\\[([^\\]]{0,2000})\\]");
    private static final Pattern ENC_JSON = Pattern.compile("(%22([A-Za-z0-9_.\\-]{1,64})%22%3[Aa]%22)((?:(?!%22).){1,500})(%22)");
    private static final Pattern STRING_LIT = Pattern.compile("\"(?:[^\"\\\\]|\\\\.)*\"");
    private static final Pattern TAG = Pattern.compile("<[A-Za-z][^<>]{0,2000}>");
    private static final Pattern ATTR_PAIR = Pattern.compile("([A-Za-z_:][\\w:.\\-]{0,63})(\\s*=\\s*)(\"[^\"]*\"|'[^']*')");
    private static final Pattern HEADER_LINE = Pattern.compile(
            "\\b(Cookie|Set-Cookie|Authorization|Proxy-Authorization|X-Auth-Token|X-API-Key|X-CSRF-Token|X-XSRF-Token)(\\s*:\\s*)[^\\r\\n<]+",
            Pattern.CASE_INSENSITIVE);

    /** Mask values that sit next to a sensitive name in form, query, JSON and HTML text. */
    public static String redactNamed(String text) {
        if (text == null || text.isEmpty()) {
            return text;
        }
        final boolean hasEq = text.indexOf('=') >= 0;
        final boolean hasJson = text.indexOf('"') >= 0 && text.indexOf(':') >= 0;
        if (!hasEq && !hasJson && text.indexOf('<') < 0 && text.indexOf(':') < 0) {
            return text;                                   // nothing in it that could carry a name and a value
        }
        List<String> names = new ArrayList<>();
        if (hasEq) {
            Matcher a = KV_ANY.matcher(text);
            while (a.find()) {
                names.add(a.group(2));
            }
        }
        if (hasJson) {
            Matcher b = JSON_ANY.matcher(text);
            while (b.find()) {
                names.add(b.group(1));
            }
        }
        final boolean group = names.size() >= 2 && isCredentialGroup(names);
        java.util.function.Predicate<String> sens = n -> isSensitiveParam(n) || (group && CREDENTIAL_GROUP.contains(leaf(n)));

        final String lower = text.toLowerCase();
        final boolean hasTag = text.indexOf('<') >= 0;
        text = !hasTag || !lower.contains("<input") ? text : sub(INPUT_TAG, text, m -> {
            String tag = m.group();
            Matcher n = ATTR_NAME.matcher(tag);
            String name = "";
            if (n.find()) {
                for (int g = 1; g <= 3; g++) {
                    if (n.group(g) != null && !n.group(g).isEmpty()) {
                        name = n.group(g);
                        break;
                    }
                }
            }
            if (!name.isEmpty() && sens.test(name)) {
                Matcher v = ATTR_VALUE.matcher(tag);
                if (v.find()) {
                    return tag.substring(0, v.start()) + v.group(1) + "\"" + REDACTED + "\"" + tag.substring(v.end());
                }
            }
            return tag;
        });
        text = !hasTag ? text : sub(TAG, text, m -> {
            String tag = m.group();
            if (tag.regionMatches(true, 0, "<input", 0, 6)) {
                return tag;
            }
            boolean metaSecret = false;
            if (tag.regionMatches(true, 0, "<meta", 0, 5)) {
                Matcher pm = ATTR_PAIR.matcher(tag);
                while (pm.find()) {
                    String v = pm.group(3);
                    if (pm.group(1).equalsIgnoreCase("name") && sens.test(v.substring(1, v.length() - 1))) {
                        metaSecret = true;
                    }
                }
            }
            final boolean ms = metaSecret;
            return sub(ATTR_PAIR, tag, am -> {
                String name = am.group(1);
                String val = am.group(3);
                String inner = val.substring(1, val.length() - 1);
                if (inner.isEmpty() || inner.equals(REDACTED) || isErrorConstant(inner)) {
                    return am.group();
                }
                if (sens.test(name) || (ms && name.equalsIgnoreCase("content"))) {
                    return name + am.group(2) + "\"" + REDACTED + "\"";
                }
                return am.group();
            });
        });
        if (lower.contains("cookie") || lower.contains("authorization") || lower.contains("-token") || lower.contains("api-key") || lower.contains("csrf")) {
            text = sub(HEADER_LINE, text, m -> m.group(1) + m.group(2) + REDACTED);
        }
        text = !hasEq ? text : sub(KV_ANY, text, m -> {
            if (sens.test(m.group(2)) && !m.group(4).equals(REDACTED) && !isErrorConstant(m.group(4))) {
                return m.group(1) + m.group(2) + m.group(3) + REDACTED;
            }
            return m.group();
        });
        text = !hasJson ? text : sub(JSON_ANY, text, m -> {
            if (sens.test(m.group(1)) && !isErrorConstant(m.group(3))) {
                return "\"" + m.group(1) + "\"" + m.group(2) + "\"" + REDACTED + "\"";
            }
            return m.group();
        });
        // other places a secret sits next to its name (see redact.py)
        java.util.function.Predicate<String> live = v -> !v.isEmpty() && !v.contains(REDACTED) && !isErrorConstant(v);
        if (text.contains("%22")) {
            text = sub(ENC_JSON, text, m -> sens.test(m.group(2)) && live.test(m.group(3)) ? m.group(1) + REDACTED + m.group(4) : m.group());
        }
        if (text.toLowerCase().contains("form-data")) {
            text = sub(MULTIPART, text, m -> sens.test(m.group(2)) && live.test(m.group(3)) ? m.group(1) + REDACTED : m.group());
        }
        if (text.contains("</")) {
            text = sub(XML_EL, text, m -> {
                if (sens.test(m.group(1)) && live.test(m.group(3).strip())) {
                    return "<" + m.group(1) + (m.group(2) == null ? "" : m.group(2)) + ">" + REDACTED + "</" + m.group(1) + ">";
                }
                return m.group();
            });
        }
        if (text.indexOf('"') >= 0 || text.indexOf('\'') >= 0) {
            text = sub(ASSIGN, text, m -> {
                if (sens.test(m.group(2)) && live.test(m.group(5))) {
                    return m.group(1) + m.group(2) + m.group(1) + m.group(3) + m.group(4) + REDACTED + m.group(4);
                }
                return m.group();
            });
            text = sub(JSON_LIST, text, m -> {
                if (sens.test(m.group(1)) && !m.group(3).contains("REDACTED")) {
                    return "\"" + m.group(1) + "\"" + m.group(2) + "[" + STRING_LIT.matcher(m.group(3)).replaceAll(Matcher.quoteReplacement("\"" + REDACTED + "\"")) + "]";
                }
                return m.group();
            });
        }
        if (text.indexOf(':') >= 0) {
            text = sub(YAML, text, m -> sens.test(m.group(2)) && live.test(m.group(4).strip()) ? m.group(1) + m.group(2) + m.group(3) + REDACTED : m.group());
        }
        return text;
    }

    // ------------------------------------------------------------ paths

    private static final Pattern UUID_RE = Pattern.compile("^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$");
    private static final Pattern HEX_RE = Pattern.compile("^[0-9a-fA-F]{24,}$");
    private static final Pattern HEXPAIR_RE = Pattern.compile("^[0-9a-fA-F]{3,8}-[0-9a-fA-F]{8,}$");
    private static final Pattern CODE_RE = Pattern.compile("^[A-Z0-9]{8,24}$");
    private static final Pattern TOKENISH_RE = Pattern.compile("^[A-Za-z0-9_\\-+=~.]{12,}$");
    private static final Pattern B64ISH_RE = Pattern.compile("^[A-Za-z0-9_\\-+/=]{32,}$");

    private static boolean allDigits(String s) {
        if (s.isEmpty()) {
            return false;
        }
        for (int i = 0; i < s.length(); i++) {
            if (!Character.isDigit(s.charAt(i))) {
                return false;
            }
        }
        return true;
    }

    private static boolean anyDigit(String s) {
        return s.chars().anyMatch(Character::isDigit);
    }

    private static boolean anyAlpha(String s) {
        return s.chars().anyMatch(Character::isLetter);
    }

    /** A placeholder for a path segment that is a value, or null to keep it. */
    public static String classifySegment(String seg) {
        if (seg == null || seg.isEmpty() || (seg.startsWith("{") && seg.endsWith("}"))) {
            return null;
        }
        String s = Url.unquote(seg);
        if (allDigits(s)) {
            return "{id}";
        }
        if (UUID_RE.matcher(s).find()) {
            return "{uuid}";
        }
        if (HEX_RE.matcher(s).find()) {
            return "{hash}";
        }
        if (HEXPAIR_RE.matcher(s).find() && anyDigit(s)) {
            return "{id}";
        }
        for (int k = 0; k < VALUE_PATTERNS.length; k++) {
            Matcher m = VALUE_PATTERNS[k].matcher(s);
            if (!m.find()) {
                continue;
            }
            if (VALUE_KINDS[k].equals("card")) {
                if (!luhnOk(m.group().replaceAll("\\D", ""))) {
                    continue;
                }
            }
            return "{" + VALUE_KINDS[k] + "}";
        }
        if (CODE_RE.matcher(s).find() && anyDigit(s) && anyAlpha(s)) {
            return "{code}";
        }
        if (B64ISH_RE.matcher(s).find() && entropy(s) >= 3.5) {
            return "{token}";
        }
        if (TOKENISH_RE.matcher(s).find() && !s.contains(".")) {
            int classes = 0;
            if (Pattern.compile("[a-z]").matcher(s).find()) {
                classes++;
            }
            if (Pattern.compile("[A-Z]").matcher(s).find()) {
                classes++;
            }
            if (Pattern.compile("[0-9]").matcher(s).find()) {
                classes++;
            }
            long digits = s.chars().filter(Character::isDigit).count();
            if (classes == 3 && digits >= 2 && entropy(s) >= 3.0) {
                return "{token}";
            }
        }
        return null;
    }

    private static String[] matrixBase(String seg) {
        return seg.contains(";") ? seg.split(";", -1) : null;
    }

    private static String templateMatrix(String seg) {
        String[] parts = matrixBase(seg);
        if (parts == null) {
            return null;
        }
        List<String> out = new ArrayList<>();
        String c = classifySegment(parts[0]);
        out.add(c != null ? c : parts[0]);
        for (int i = 1; i < parts.length; i++) {
            String p = parts[i];
            int eq = p.indexOf('=');
            String k = eq < 0 ? p : p.substring(0, eq);
            String v = eq < 0 ? "" : p.substring(eq + 1);
            if (eq >= 0 && !v.isEmpty() && (isSensitiveParam(k) || classifySegment(v) != null)) {
                out.add(k + "={value}");
            } else {
                out.add(p);
            }
        }
        return String.join(";", out);
    }

    private static final Pattern HASHED_ASSET = Pattern.compile(
            "^(.+?[-._])[0-9a-fA-F]{8,32}(\\.(?:js|mjs|css|map|woff2?|png|jpe?g|svg|webp))$");

    /** Collapse ids and value-like segments to placeholders; drop query and fragment. */
    public static String templatePath(String path) {
        String clean = path.split("\\?", 2)[0].split("#", 2)[0];
        List<String> out = new ArrayList<>();
        for (String s : clean.split("/", -1)) {
            String rep = templateMatrix(s);
            if (rep == null) {
                rep = classifySegment(s);
            }
            if (rep == null) {
                Matcher hm = HASHED_ASSET.matcher(s);
                if (hm.find() && !s.endsWith(".min.js") && !s.endsWith(".min.css")) {
                    String mid = s.substring(hm.group(1).length(), s.length() - hm.group(2).length());
                    if (Pattern.compile("\\d").matcher(mid).find()) {
                        rep = hm.group(1) + "{hash}" + hm.group(2);
                    }
                }
            }
            out.add(rep != null ? rep : s);
        }
        String t = String.join("/", out);
        return t.isEmpty() ? "/" : t;
    }

    /** Redact a raw request path (segments and query values), keeping its shape. */
    public static Redacted<String> redactPath(String path) {
        List<Fingerprint> prints = new ArrayList<>();
        int q = path.indexOf('?');
        String base = q < 0 ? path : path.substring(0, q);
        boolean hasQuery = q >= 0;
        String query = q < 0 ? "" : path.substring(q + 1).split("#", 2)[0];
        List<String> segs = new ArrayList<>();
        for (String s : base.split("#", 2)[0].split("/", -1)) {
            String[] mx = matrixBase(s);
            if (mx != null) {
                List<String> outParts = new ArrayList<>();
                outParts.add(mx[0]);
                for (int i = 1; i < mx.length; i++) {
                    String p = mx[i];
                    int eq = p.indexOf('=');
                    String k = eq < 0 ? p : p.substring(0, eq);
                    String v = eq < 0 ? "" : p.substring(eq + 1);
                    if (eq >= 0 && !v.isEmpty() && (isSensitiveParam(k) || classifySegment(v) != null)) {
                        prints.add(fingerprint(Url.unquote(v), "path:" + k.toLowerCase()));
                        outParts.add(k + "=" + REDACTED);
                    } else {
                        outParts.add(p);
                    }
                }
                segs.add(String.join(";", outParts));
                continue;
            }
            String rep = classifySegment(s);
            if (rep != null && !rep.equals("{id}") && !rep.equals("{uuid}") && !rep.equals("{hash}")) {
                prints.add(fingerprint(Url.unquote(s), "path:" + rep.replace("{", "").replace("}", "")));
                segs.add(rep);
            } else {
                segs.add(s);
            }
        }
        String out = String.join("/", segs);
        if (out.isEmpty()) {
            out = "/";
        }
        if (hasQuery) {
            Redacted<List<Pair>> red = redactParams(Url.parseQsl(query));
            prints.addAll(red.prints());
            out += "?" + Url.urlencode(red.value(), "[]:{}");
        }
        return new Redacted<>(out, prints);
    }

    static final List<String> ROUTE_PARAMS = List.of("page", "action", "view", "module", "route", "section", "tab",
            "controller", "do", "cmd", "mode", "screen", "op", "task", "act", "content", "p");
    private static final Pattern ROUTE_VALUE = Pattern.compile("^[A-Za-z0-9_.\\-/]{1,60}$");
    private static final Pattern STATIC_PATH = Pattern.compile(
            "\\.(?:png|jpe?g|gif|svg|ico|webp|css|js|mjs|map|woff2?|ttf|eot|json|txt|xml|pdf)$", Pattern.CASE_INSENSITIVE);

    /** `base` plus the page-selecting query parameters: /index.php?page=login.php. */
    public static String routeTemplate(String pathWithQuery, String base) {
        if (STATIC_PATH.matcher(base).find()) {
            return base;
        }
        int q = pathWithQuery.indexOf('?');
        String query = q < 0 ? "" : pathWithQuery.substring(q + 1).split("#", 2)[0];
        Map<String, String> keep = new TreeMap<>();
        for (Pair kv : Url.parseQsl(query)) {
            String k = kv.name().toLowerCase();
            String v = kv.value();
            if (ROUTE_PARAMS.contains(k) && !keep.containsKey(k) && ROUTE_VALUE.matcher(v).find() && !allDigits(v)
                    && classifySegment(v) == null && !isSensitiveParam(k)) {
                keep.put(k, v);
            }
        }
        if (keep.isEmpty()) {
            return base;
        }
        List<String> parts = new ArrayList<>();
        int n = 0;
        for (Map.Entry<String, String> e : keep.entrySet()) {
            if (n++ == 2) {
                break;
            }
            parts.add(e.getKey() + "=" + e.getValue());
        }
        return base + "?" + String.join("&", parts);
    }
}
