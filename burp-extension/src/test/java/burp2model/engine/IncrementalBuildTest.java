package burp2model.engine;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.File;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

/** A build that keeps pass 1 between builds (live capture) must give the same model as a build from scratch, every time. */
class IncrementalBuildTest {
    static final String[] EXPORTS = {"burp-history-sample.xml", "burp-history-admin-sample.xml", "juiceshop-user.xml", "juiceshop-admin.xml",
        "juiceshop-accountant.xml", "juiceshop-anon.xml"};

    @BeforeAll
    static void key() {
        Redact.setKey(new byte[32]);
    }

    /** Folding starts from the raw paths on every build, as Session.rebuild does. */
    private static void unfold(List<Exchange> exs) {
        for (int i = 0; i < exs.size(); i++) {
            Exchange e = exs.get(i);
            e.index = i + 1;
            e.pathTemplate = e.rawTemplate;
            e.refererPath = e.rawRefererPath;
        }
    }

    private static String build(List<Exchange> exs, Builder.Observed keep) {
        unfold(exs);
        Map<String, Object> stats = new LinkedHashMap<>();
        stats.put("items", (long) exs.size());
        return Json.write(Builder.build(new ArrayList<>(exs), "app", null, null, stats, keep).toMap());
    }

    /** Add the exchanges `step` at a time; after each step the kept build must equal a fresh one. Returns the restarts. */
    private static int grow(List<Exchange> all, int step) {
        Builder.Observed keep = new Builder.Observed();
        List<Exchange> sofar = new ArrayList<>();
        for (int i = 0; i < all.size(); i += step) {
            sofar.addAll(all.subList(i, Math.min(all.size(), i + step)));
            String kept = build(sofar, keep);
            assertEquals(build(sofar, null), kept, "after " + sofar.size() + " requests");
        }
        return keep.restarts();
    }

    private static Exchange ex(String method, String host, String path, int status, String mime, String body) {
        String req = method + " " + path + " HTTP/1.1\r\nHost: " + host + "\r\n\r\n";
        String ct = mime.equals("HTML") ? "text/html" : mime.equals("script") ? "application/javascript" : "application/json";
        String resp = "HTTP/1.1 " + status + " X\r\nContent-Type: " + ct + "\r\n\r\n" + body;
        return Parse.item(0, new Parse.Raw(method, host, 443, "https", path, status, mime, req.getBytes(StandardCharsets.UTF_8),
                resp.getBytes(StandardCharsets.UTF_8), false), null, "test", 0);
    }

    @Test
    void everyBundledExportGrowsToTheSameModel() throws Exception {
        String dir = System.getProperty("burp2model.samples", "../samples");
        List<Exchange> mixed = new ArrayList<>();
        for (String name : EXPORTS) {
            String role = name.contains("admin") ? "admin" : name.contains("user") ? "user" : null;
            List<Exchange> all = BurpXml.read(new File(dir, name), role);
            mixed.addAll(BurpXml.read(new File(dir, name), role));
            for (int step : new int[] {1, 7, 40}) {
                int restarts = grow(all, step);
                int builds = (all.size() + step - 1) / step;
                assertTrue(builds < 3 || restarts < builds, name + " step " + step + ": pass 1 restarted on every build (" + restarts + ")");
            }
        }
        // several roles in one model, as Roles builds it
        grow(mixed, 25);
    }

    @Test
    void foldingThatRewritesEarlierPathsStartsOver() {
        List<Exchange> all = new ArrayList<>();
        all.add(ex("GET", "shop.example.com", "/", 200, "HTML", "<a href=\"/blog/\">blog</a>"));
        for (int i = 0; i < 12; i++) {
            all.add(ex("GET", "shop.example.com", "/blog/winter-sale-" + (char) ('a' + i), 200, "HTML", "<p>post</p>"));
        }
        all.add(ex("POST", "shop.example.com", "/api/comments", 201, "json", "{}"));
        // the eighth sibling folds all of them to /blog/winter-sale-{slug}: the earlier paths change, so pass 1 starts over
        assertTrue(grow(all, 1) >= 2, "a fold that rewrites earlier paths must restart pass 1");
    }

    @Test
    void aNewBusiestHostStartsOver() {
        List<Exchange> all = new ArrayList<>();
        for (int i = 0; i < 3; i++) {
            all.add(ex("GET", "a.example.com", "/api/a" + i, 200, "json", "{}"));
        }
        for (int i = 0; i < 6; i++) {
            all.add(ex("GET", "b.other.test", "/api/b" + i, 200, "json", "{}"));
        }
        // b.other.test becomes the seed host, so the scope and every host's side change
        assertTrue(grow(all, 1) >= 2, "a new seed host must restart pass 1");
    }

    @Test
    void aPathThatAnswersAfterNotFoundComesBack() {
        List<Exchange> all = new ArrayList<>();
        all.add(ex("GET", "shop.example.com", "/", 200, "HTML", "<script src=\"/app.js\"></script>"));
        all.add(ex("GET", "shop.example.com", "/app.js", 200, "script", "fetch('/api/items');fetch('/api/cart')"));
        all.add(ex("GET", "shop.example.com", "/api/items", 404, "json", "{}"));
        all.add(ex("GET", "shop.example.com", "/api/cart", 200, "json", "{}"));
        all.add(ex("GET", "shop.example.com", "/api/items", 200, "json", "[]"));
        all.add(ex("POST", "shop.example.com", "/api/cart?x=1", 200, "json", "{}"));
        assertEquals(1, grow(all, 1), "only appended requests here: pass 1 never needs to start over");
    }
}
