package burp2model.engine;

import java.io.BufferedReader;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.IDN;
import java.nio.charset.StandardCharsets;
import java.util.HashSet;
import java.util.Set;
import java.util.regex.Pattern;

/** Registrable domains from the bundled Public Suffix List (a port of domains.py). */
public final class Domains {
    private Domains() {}

    private static final Pattern IPV4 = Pattern.compile("^\\d{1,3}(\\.\\d{1,3}){3}$");
    private static Set<String> rules;
    private static Set<String> wildcards;
    private static Set<String> exceptions;

    private static String ascii(String label) {
        try {
            return IDN.toASCII(label, IDN.ALLOW_UNASSIGNED);
        } catch (Exception e) {
            return label;
        }
    }

    private static String asciiAll(String dotted) {
        StringBuilder sb = new StringBuilder();
        for (String p : dotted.split("\\.", -1)) {
            if (sb.length() > 0) {
                sb.append('.');
            }
            sb.append(ascii(p));
        }
        return sb.toString();
    }

    private static synchronized void load() {
        if (rules != null) {
            return;
        }
        Set<String> r = new HashSet<>();
        Set<String> w = new HashSet<>();
        Set<String> x = new HashSet<>();
        try (InputStream in = Domains.class.getResourceAsStream("/public_suffix_list.dat")) {
            if (in != null) {
                BufferedReader br = new BufferedReader(new InputStreamReader(in, StandardCharsets.UTF_8));
                String line;
                while ((line = br.readLine()) != null) {
                    line = line.strip();
                    if (line.isEmpty() || line.startsWith("//")) {
                        continue;
                    }
                    String rule = line.split("\\s+")[0].toLowerCase();
                    if (rule.startsWith("!")) {
                        x.add(asciiAll(rule.substring(1)));
                    } else if (rule.startsWith("*.")) {
                        w.add(asciiAll(rule.substring(2)));
                    } else {
                        r.add(asciiAll(rule));
                    }
                }
            }
        } catch (Exception e) {
            // an empty list degrades to "last label is the suffix"
        }
        rules = r;
        wildcards = w;
        exceptions = x;
    }

    private static String normalize(String host) {
        String h = host.strip().toLowerCase();
        while (h.endsWith(".")) {
            h = h.substring(0, h.length() - 1);
        }
        if (h.startsWith("[") || h.chars().filter(c -> c == ':').count() > 1) {
            return h;
        }
        h = h.split(":", 2)[0];
        StringBuilder sb = new StringBuilder();
        for (String p : h.split("\\.")) {
            if (p.isEmpty()) {
                continue;
            }
            if (sb.length() > 0) {
                sb.append('.');
            }
            sb.append(ascii(p));
        }
        return sb.toString();
    }

    static String publicSuffix(String host) {
        load();
        String[] labels = normalize(host).split("\\.", -1);
        for (int i = 0; i < labels.length; i++) {
            String cand = String.join(".", java.util.Arrays.copyOfRange(labels, i, labels.length));
            String parent = i + 1 < labels.length ? String.join(".", java.util.Arrays.copyOfRange(labels, i + 1, labels.length)) : "";
            if (exceptions.contains(cand)) {
                return parent;
            }
            if (rules.contains(cand)) {
                return cand;
            }
            if (!parent.isEmpty() && wildcards.contains(parent)) {
                return cand;
            }
        }
        return labels[labels.length - 1];
    }

    public static String registrableDomain(String host) {
        String h = normalize(host);
        if (h.isEmpty() || IPV4.matcher(h).find() || h.startsWith("[") || h.contains(":") || !h.contains(".")) {
            return h;
        }
        String suffix = publicSuffix(h);
        if (h.equals(suffix)) {
            return h;
        }
        String head = h.substring(0, h.length() - suffix.length() - 1);
        String[] parts = head.split("\\.");
        return parts[parts.length - 1] + "." + suffix;
    }
}
