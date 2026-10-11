package burp2model.engine;

import java.net.InetAddress;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Hashtable;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;

/**
 * Light, passive recon on one host you are authorised to test: DNS, the TLS certificate, the front page's headers,
 * robots.txt and security.txt, and mail policy. Observations only. It runs only when asked, from the Recon tab.
 */
public final class Recon {
    private Recon() {}

    private static final List<String> SEC_HEADERS = List.of("content-security-policy", "strict-transport-security", "x-content-type-options",
            "x-frame-options", "referrer-policy", "permissions-policy", "cross-origin-opener-policy", "cross-origin-resource-policy");

    private static Map<String, Object> map(Object... kv) {
        Map<String, Object> m = new LinkedHashMap<>();
        for (int i = 0; i + 1 < kv.length; i += 2) {
            m.put((String) kv[i], kv[i + 1]);
        }
        return m;
    }

    @SuppressWarnings("unchecked")
    private static List<String> dns(String name, String type) {
        List<String> out = new ArrayList<>();
        try {
            Hashtable<String, String> env = new Hashtable<>();
            env.put("java.naming.factory.initial", "com.sun.jndi.dns.DnsContextFactory");
            env.put("com.sun.jndi.dns.timeout.initial", "3000");
            env.put("com.sun.jndi.dns.timeout.retries", "1");
            javax.naming.directory.DirContext ctx = new javax.naming.directory.InitialDirContext(env);
            javax.naming.directory.Attributes a = ctx.getAttributes(name, new String[] {type});
            javax.naming.directory.Attribute at = a.get(type);
            if (at != null) {
                javax.naming.NamingEnumeration<?> en = at.getAll();
                while (en.hasMore()) {
                    out.add(String.valueOf(en.next()).replace("\"", "").strip());
                }
            }
            ctx.close();
        } catch (Throwable t) {
            // no DNS provider in this runtime, or the name has no such record
        }
        return out;
    }

    public static Map<String, Object> run(String host, java.util.function.Consumer<String> progress) {
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("host", host);
        out.put("generated_at", Instant.now().truncatedTo(ChronoUnit.SECONDS).toString());
        String domain = Domains.registrableDomain(host);
        progress.accept("DNS…");
        Map<String, Object> d = new LinkedHashMap<>();
        List<String> a = new ArrayList<>();
        try {
            for (InetAddress ia : InetAddress.getAllByName(host)) {
                a.add(ia.getHostAddress());
            }
        } catch (Exception e) {
            // unresolved
        }
        d.put("addresses", a);
        for (String t : new String[] {"MX", "NS", "TXT"}) {
            List<String> r = dns(domain, t);
            if (!r.isEmpty()) {
                d.put(t, r);
            }
        }
        out.put("dns", d);

        progress.accept("TLS…");
        try {
            SSLSocket s = (SSLSocket) SSLSocketFactory.getDefault().createSocket();
            s.connect(new java.net.InetSocketAddress(host, 443), 6000);
            s.setSoTimeout(6000);
            s.startHandshake();
            X509Certificate c = (X509Certificate) s.getSession().getPeerCertificates()[0];
            List<String> san = new ArrayList<>();
            Collection<List<?>> names = c.getSubjectAlternativeNames();
            if (names != null) {
                for (List<?> n : names) {
                    san.add(String.valueOf(n.get(1)));
                }
            }
            long days = Duration.between(Instant.now(), c.getNotAfter().toInstant()).toDays();
            out.put("tls", map("version", s.getSession().getProtocol(), "issuer", c.getIssuerX500Principal().getName(),
                    "expires", c.getNotAfter().toInstant().toString(), "days_left", days, "names", san));
            s.close();
        } catch (Exception e) {
            out.put("tls", map("error", String.valueOf(e.getMessage())));
        }

        progress.accept("HTTP…");
        HttpClient http = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(6)).followRedirects(HttpClient.Redirect.NORMAL).build();
        try {
            HttpResponse<String> r = http.send(HttpRequest.newBuilder(URI.create("https://" + host + "/")).timeout(Duration.ofSeconds(8))
                    .header("User-Agent", "burp2model-recon").GET().build(), HttpResponse.BodyHandlers.ofString());
            List<String> present = new ArrayList<>();
            List<String> missing = new ArrayList<>();
            for (String h : SEC_HEADERS) {
                (r.headers().firstValue(h).isPresent() ? present : missing).add(h);
            }
            out.put("http", map("status", (long) r.statusCode(), "server", r.headers().firstValue("server").orElse(""),
                    "security_headers_present", present, "security_headers_missing", missing));
        } catch (Exception e) {
            out.put("http", map("error", String.valueOf(e.getMessage())));
        }
        Map<String, Object> files = new LinkedHashMap<>();
        for (String path : new String[] {"/robots.txt", "/.well-known/security.txt", "/sitemap.xml"}) {
            progress.accept(path + "…");
            try {
                HttpResponse<String> r = http.send(HttpRequest.newBuilder(URI.create("https://" + host + path)).timeout(Duration.ofSeconds(6))
                        .header("User-Agent", "burp2model-recon").GET().build(), HttpResponse.BodyHandlers.ofString());
                String ct = r.headers().firstValue("content-type").orElse("");
                boolean real = r.statusCode() == 200 && !ct.contains("html");
                Map<String, Object> f = map("present", real);
                if (real && path.equals("/robots.txt")) {
                    f.put("disallow_rules", (long) r.body().lines().filter(l -> l.toLowerCase().startsWith("disallow:") && l.length() > 10).count());
                }
                files.put(path, f);
            } catch (Exception e) {
                files.put(path, map("present", false));
            }
        }
        out.put("well_known", files);

        progress.accept("mail policy…");
        Map<String, Object> mail = new LinkedHashMap<>();
        List<String> txt = (List<String>) d.getOrDefault("TXT", List.of());
        mail.put("spf", txt.stream().filter(t -> t.toLowerCase().startsWith("v=spf1")).findFirst().orElse("none"));
        List<String> dmarc = dns("_dmarc." + domain, "TXT");
        mail.put("dmarc", dmarc.stream().filter(t -> t.toLowerCase().startsWith("v=dmarc1")).findFirst().orElse("none"));
        out.put("mail", mail);
        return out;
    }

    @SuppressWarnings("unchecked")
    public static String format(Map<String, Object> r) {
        StringBuilder sb = new StringBuilder();
        sb.append("Recon · ").append(r.get("host")).append("   ").append(r.get("generated_at")).append("\n\n");
        Map<String, Object> d = (Map<String, Object>) r.get("dns");
        sb.append("DNS\n  addresses   ").append(String.join(", ", (List<String>) d.get("addresses"))).append('\n');
        for (String t : new String[] {"MX", "NS", "TXT"}) {
            if (d.containsKey(t)) {
                sb.append("  ").append(String.format("%-11s", t)).append(' ').append(String.join(" | ", (List<String>) d.get(t))).append('\n');
            }
        }
        Map<String, Object> tls = (Map<String, Object>) r.get("tls");
        sb.append("\nTLS\n");
        if (tls.containsKey("error")) {
            sb.append("  could not connect: ").append(tls.get("error")).append('\n');
        } else {
            sb.append("  version     ").append(tls.get("version")).append("\n  issuer      ").append(tls.get("issuer")).append("\n  expires     ")
                    .append(tls.get("expires")).append(" (").append(tls.get("days_left")).append(" days)\n  names       ")
                    .append(String.join(", ", (List<String>) tls.get("names"))).append('\n');
        }
        Map<String, Object> http = (Map<String, Object>) r.get("http");
        sb.append("\nHTTP front page\n");
        if (http.containsKey("error")) {
            sb.append("  could not fetch: ").append(http.get("error")).append('\n');
        } else {
            sb.append("  status      ").append(http.get("status")).append("\n  server      ").append(http.get("server")).append("\n  headers set   ")
                    .append(String.join(", ", (List<String>) http.get("security_headers_present"))).append("\n  headers missing   ")
                    .append(String.join(", ", (List<String>) http.get("security_headers_missing"))).append('\n');
        }
        sb.append("\nWell-known files\n");
        ((Map<String, Object>) r.get("well_known")).forEach((k, v) -> {
            Map<String, Object> f = (Map<String, Object>) v;
            sb.append("  ").append(String.format("%-26s", k)).append(Boolean.TRUE.equals(f.get("present")) ? "present" : "not found")
                    .append(f.containsKey("disallow_rules") ? " · " + f.get("disallow_rules") + " Disallow rules" : "").append('\n');
        });
        Map<String, Object> mail = (Map<String, Object>) r.get("mail");
        sb.append("\nMail policy\n  SPF    ").append(mail.get("spf")).append("\n  DMARC  ").append(mail.get("dmarc")).append('\n');
        sb.append("\nObservations only: nothing here is a vulnerability. Authorised targets only.");
        return sb.toString();
    }
}
