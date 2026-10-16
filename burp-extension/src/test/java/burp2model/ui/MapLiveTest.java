package burp2model.ui;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import burp2model.engine.Model;
import burp2model.engine.Parse;
import burp2model.engine.Redact;
import burp2model.engine.Session;
import java.lang.reflect.Field;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import javax.swing.SwingUtilities;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/** A big map (laid out in the background) keeps still while live capture adds to it. */
class MapLiveTest {
    @TempDir
    Path home;

    /** n pages, each linking a script and an endpoint: a map well above the background-layout threshold. */
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

    private static Object get(Object o, String name) throws Exception {
        Field f = GraphPanel.class.getDeclaredField(name);
        f.setAccessible(true);
        return f.get(o);
    }

    @SuppressWarnings("unchecked")
    private static Map<String, double[]> positions(GraphPanel g) throws Exception {
        Map<String, double[]> out = new HashMap<>();
        SwingUtilities.invokeAndWait(() -> {
            try {
                for (Object v : (List<Object>) get(g, "vs")) {
                    Field node = v.getClass().getDeclaredField("node");
                    Field x = v.getClass().getDeclaredField("x");
                    Field y = v.getClass().getDeclaredField("y");
                    node.setAccessible(true);
                    x.setAccessible(true);
                    y.setAccessible(true);
                    out.put(((Model.Node) node.get(v)).id, new double[] {x.getDouble(v), y.getDouble(v)});
                }
            } catch (Exception e) {
                throw new IllegalStateException(e);
            }
        });
        return out;
    }

    private static void settle(GraphPanel g) throws Exception {
        g.awaitLayout(30_000);
        javax.swing.Timer sim = (javax.swing.Timer) get(g, "sim");
        var tick = GraphPanel.class.getDeclaredMethod("tick");
        tick.setAccessible(true);
        SwingUtilities.invokeAndWait(sim::stop);
        for (int i = 0; i < 400; i++) {
            SwingUtilities.invokeAndWait(() -> {
                try {
                    tick.invoke(g);
                } catch (ReflectiveOperationException e) {
                    throw new IllegalStateException(e);
                }
            });
        }
        // the first map's fit is animated: let it finish before reading the camera
        javax.swing.Timer anim = (javax.swing.Timer) get(g, "anim");
        for (int i = 0; i < 200 && anim.isRunning(); i++) {
            Thread.sleep(10);
        }
        SwingUtilities.invokeAndWait(() -> { });
    }

    @Test
    void liveRequestsDoNotMoveTheCameraOrBlankTheMap() throws Exception {
        Redact.setKey(new byte[32]);
        Session s = new Session(home, "map");
        s.add(pages(0, 150), null, "one", false);
        Model m1 = s.model();
        assertTrue(m1.nodes.size() > GraphPanel.ASYNC_LAYOUT, "big enough for the background layout: " + m1.nodes.size());
        GraphPanel[] g = new GraphPanel[1];
        SwingUtilities.invokeAndWait(() -> {
            g[0] = new GraphPanel();
            g[0].setSize(1100, 750);
            g[0].doLayout();
            g[0].setModel(m1);
        });
        settle(g[0]);
        double scale = (double) get(g[0], "scale");
        double ox = (double) get(g[0], "ox");
        Map<String, double[]> before = positions(g[0]);

        // live capture: a few more pages, then the refresh
        s.add(pages(150, 156), null, "live capture", false, false);
        Model m2 = s.model();
        boolean[] blank = {false};
        SwingUtilities.invokeAndWait(() -> {
            g[0].setModel(m2);
            try {
                blank[0] = ((List<?>) get(g[0], "vs")).isEmpty();
            } catch (Exception e) {
                throw new IllegalStateException(e);
            }
        });
        assertFalse(blank[0], "the current map stays on screen while the new one is laid out");
        settle(g[0]);
        assertEquals(scale, (double) get(g[0], "scale"), 1e-9, "the camera did not re-fit");
        assertEquals(ox, (double) get(g[0], "ox"), 1e-9);

        Map<String, double[]> after = positions(g[0]);
        double sum = 0;
        int kept = 0;
        for (var e : before.entrySet()) {
            double[] q = after.get(e.getKey());
            if (q != null) {
                sum += Math.hypot(e.getValue()[0] - q[0], e.getValue()[1] - q[1]);
                kept++;
            }
        }
        double mean = sum / Math.max(1, kept);
        assertTrue(kept > before.size() * 0.9, "the old nodes are still there");
        assertTrue(mean < 40, "nodes that were there stay close to where they were (mean move " + mean + ")");
    }
}
