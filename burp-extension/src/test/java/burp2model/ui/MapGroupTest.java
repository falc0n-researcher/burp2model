package burp2model.ui;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import burp2model.engine.Model;
import burp2model.engine.Parse;
import burp2model.engine.Redact;
import burp2model.engine.Session;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import javax.swing.SwingUtilities;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/** A large map shows path areas as groups that open in place. */
class MapGroupTest {
    @TempDir
    Path home;

    private static List<Parse.Raw> pages(int from, int to) {
        List<Parse.Raw> out = new ArrayList<>();
        for (int i = from; i < to; i++) {
            String p = "/area" + (i % 9) + "/page" + i + ".html";
            String body = "<html><a href='/api/v1/thing" + i + "'>x</a><script src='/js/app" + (i % 25) + ".js'></script></html>";
            String req = "GET " + p + " HTTP/1.1\r\nHost: shop.example.com\r\n\r\n";
            String resp = "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n" + body;
            out.add(new Parse.Raw("GET", "shop.example.com", 443, "https", p, 200, "", req.getBytes(StandardCharsets.ISO_8859_1),
                    resp.getBytes(StandardCharsets.ISO_8859_1), false));
        }
        return out;
    }

    private static GraphPanel panel(Model m) throws Exception {
        GraphPanel[] g = new GraphPanel[1];
        SwingUtilities.invokeAndWait(() -> {
            g[0] = new GraphPanel();
            g[0].setSize(1100, 750);
            g[0].doLayout();
            g[0].setModel(m);
        });
        g[0].awaitLayout(30_000);
        SwingUtilities.invokeAndWait(() -> { });
        return g[0];
    }

    private static GraphPanel.V group(GraphPanel g, String key) {
        for (GraphPanel.V v : g.vsForTest()) {
            if (v.members > 0 && v.node.id.equals("group:" + key)) {
                return v;
            }
        }
        return null;
    }

    private static long count(GraphPanel g, String prefix) {
        return g.vsForTest().stream().filter(v -> v.node.id.startsWith(prefix)).count();
    }

    @Test
    void aLargeMapIsShownAsGroupsThatOpenInPlace() throws Exception {
        Redact.setKey(new byte[32]);
        Session s = new Session(home, "big");
        List<Parse.Raw> raws = pages(0, 300);
        for (int i = 0; i < 25; i++) {
            // the scripts the pages load, requested too, so they are on the map
            String p = "/js/app" + i + ".js";
            String req = "GET " + p + " HTTP/1.1\r\nHost: shop.example.com\r\n\r\n";
            String resp = "HTTP/1.1 200 OK\r\nContent-Type: application/javascript\r\n\r\nfetch('/api/v2/item" + i + "');";
            raws.add(new Parse.Raw("GET", "shop.example.com", 443, "https", p, 200, "", req.getBytes(StandardCharsets.ISO_8859_1),
                    resp.getBytes(StandardCharsets.ISO_8859_1), false));
        }
        s.add(raws, null, "one", false);
        Model m = s.model();
        GraphPanel g = panel(m);

        int shown = g.vsForTest().size();
        assertTrue(shown < 40, "hundreds of pages and endpoints fold into a few dozen groups at most: " + shown);
        GraphPanel.V area0 = group(g, "shop.example.com /area0");
        assertNotNull(area0, "pages grouped by their first path segment");
        assertNotNull(group(g, "shop.example.com /api"), "endpoints too");
        assertNotNull(group(g, "shop.example.com scripts"), "scripts by host");
        assertTrue(area0.members > 20);

        // open one group: its members take its place, around where it was
        double gx = area0.x;
        double gy = area0.y;
        SwingUtilities.invokeAndWait(() -> g.expandGroup(area0));
        g.awaitLayout(30_000);
        SwingUtilities.invokeAndWait(() -> { });
        assertTrue(count(g, "route:") >= area0.members, "the group's pages are on the map now");
        double sum = 0;
        int n = 0;
        for (GraphPanel.V v : g.vsForTest()) {
            if (v.node.id.startsWith("route:") && v.node.label.contains("/area0/")) {
                sum += Math.hypot(v.x - gx, v.y - gy);
                n++;
            }
        }
        assertTrue(n > 0 && sum / n < 160, "they start around the group (mean distance " + (sum / Math.max(1, n)) + ")");
        assertEquals(null, group(g, "shop.example.com /area0"));
        // and the rest of the map made room for them: nothing else is inside the disc they fill
        double room = GraphPanel.openRadius(area0.members);
        for (GraphPanel.V v : g.vsForTest()) {
            if (!v.node.label.contains("/area0/") && !v.node.type.equals("parameter")) {
                assertTrue(Math.hypot(v.x - gx, v.y - gy) > room * 0.9, v.node.id + " is out of the way");
            }
        }

        // it stays open when more requests arrive
        s.add(pages(300, 320), null, "live", false, false);
        Model m2 = s.model();
        SwingUtilities.invokeAndWait(() -> g.setModel(m2));
        g.awaitLayout(30_000);
        SwingUtilities.invokeAndWait(() -> { });
        assertEquals(null, group(g, "shop.example.com /area0"), "still open after a refresh");

        // and closes again
        GraphPanel.V member = g.vsForTest().stream().filter(v -> v.node.id.startsWith("route:") && v.node.label.contains("/area0/")).findFirst().orElseThrow();
        SwingUtilities.invokeAndWait(() -> g.collapseGroupOf(member));
        g.awaitLayout(30_000);
        SwingUtilities.invokeAndWait(() -> { });
        assertNotNull(group(g, "shop.example.com /area0"), "closed again");

        // Group off: every node on its own
        SwingUtilities.invokeAndWait(() -> g.groupBox.doClick());
        g.awaitLayout(30_000);
        SwingUtilities.invokeAndWait(() -> { });
        assertFalse(g.vsForTest().stream().anyMatch(v -> v.members > 0));
        assertTrue(g.vsForTest().size() > 300);
    }

    @Test
    void aSmallMapIsNeverGrouped() throws Exception {
        Redact.setKey(new byte[32]);
        Session s = new Session(home, "small");
        s.add(pages(0, 20), null, "one", false);
        GraphPanel g = panel(s.model());
        assertFalse(g.vsForTest().stream().anyMatch(v -> v.members > 0));
    }
}
