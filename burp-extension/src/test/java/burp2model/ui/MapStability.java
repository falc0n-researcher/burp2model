package burp2model.ui;

import burp2model.engine.BurpXml;
import burp2model.engine.Model;
import burp2model.engine.Parse;
import burp2model.engine.Session;
import java.io.File;
import java.lang.reflect.Field;
import java.nio.file.Files;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import javax.swing.SwingUtilities;

/** java -Djava.awt.headless=true -cp ... burp2model.ui.MapStability export.xml: the map draws the same way every time and does not scramble as the model grows. */
public final class MapStability {
    private MapStability() {}

    private static void check(boolean ok, String what) {
        System.out.println((ok ? "ok   " : "FAIL ") + what);
        if (!ok) {
            System.exit(1);
        }
    }

    @SuppressWarnings("unchecked")
    private static Map<String, double[]> positions(GraphPanel g) throws Exception {
        Field vf = GraphPanel.class.getDeclaredField("vs");
        vf.setAccessible(true);
        List<Object> vs = (List<Object>) vf.get(g);
        Map<String, double[]> out = new HashMap<>();
        for (Object v : vs) {
            Class<?> c = v.getClass();
            Field nf = c.getDeclaredField("node");
            nf.setAccessible(true);
            Field xf = c.getDeclaredField("x");
            xf.setAccessible(true);
            Field yf = c.getDeclaredField("y");
            yf.setAccessible(true);
            out.put(((Model.Node) nf.get(v)).id, new double[] {xf.getDouble(v), yf.getDouble(v)});
        }
        return out;
    }

    private static void settle(GraphPanel g) throws Exception {
        g.awaitLayout(30_000);                                  // a larger map is first laid out in the background
        Field tf = GraphPanel.class.getDeclaredField("sim");
        tf.setAccessible(true);
        javax.swing.Timer timer = (javax.swing.Timer) tf.get(g);
        SwingUtilities.invokeAndWait(timer::stop);              // the test drives the steps itself
        var m = GraphPanel.class.getDeclaredMethod("tick");
        m.setAccessible(true);
        for (int i = 0; i < 400; i++) {
            SwingUtilities.invokeAndWait(() -> {
                try {
                    m.invoke(g);
                } catch (ReflectiveOperationException e) {
                    throw new IllegalStateException(e);
                }
            });
        }
    }

    public static void main(String[] a) throws Exception {
        List<Parse.Raw> raws = BurpXml.readRaw(new File(a[0]));
        int half = Math.max(2, raws.size() * 9 / 10);          // then the last tenth arrives
        Session s = new Session(Files.createTempDirectory("b2m-map"), "map");
        s.add(raws.subList(0, half), null, "first", false);
        Model m1 = s.model();

        GraphPanel[] g = new GraphPanel[2];
        SwingUtilities.invokeAndWait(() -> {
            g[0] = new GraphPanel();
            g[1] = new GraphPanel();
            g[0].setSize(1000, 700);
            g[1].setSize(1000, 700);
            g[0].setModel(m1);
            g[1].setModel(m1);
        });
        settle(g[0]);
        settle(g[1]);
        Map<String, double[]> p0 = positions(g[0]);
        Map<String, double[]> p1 = positions(g[1]);
        boolean same = p0.keySet().equals(p1.keySet());
        double worst = 0;
        for (var e : p0.entrySet()) {
            double[] q = p1.get(e.getKey());
            if (q != null) {
                worst = Math.max(worst, Math.hypot(e.getValue()[0] - q[0], e.getValue()[1] - q[1]));
            }
        }
        check(same && worst < 1e-6, "the same model lays out identically every time (worst difference " + worst + ")");

        // the model grows: nodes that were there stay close to where they were
        s.add(raws, null, "all", false);
        Model m2 = s.model();
        SwingUtilities.invokeAndWait(() -> g[0].setModel(m2));
        settle(g[0]);
        Map<String, double[]> p2 = positions(g[0]);
        int kept = 0;
        double sum = 0;
        double extent = 1;
        for (double[] v : p0.values()) {
            extent = Math.max(extent, Math.max(Math.abs(v[0]), Math.abs(v[1])));
        }
        for (var e : p0.entrySet()) {
            double[] q = p2.get(e.getKey());
            if (q != null) {
                kept++;
                sum += Math.hypot(e.getValue()[0] - q[0], e.getValue()[1] - q[1]);
            }
        }
        double mean = kept == 0 ? 0 : sum / kept;
        check(kept > 0 && mean < extent * 0.3, "adding requests keeps the map recognisable (mean move " + Math.round(mean) + " of an extent of " + Math.round(extent) + ")");
        System.exit(0);
    }
}
