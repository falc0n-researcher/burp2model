package burp2model;

import burp2model.engine.BurpXml;
import burp2model.engine.Parse;
import burp2model.engine.Query;
import burp2model.engine.Session;
import burp2model.ui.MainPanel;
import java.awt.image.BufferedImage;
import java.io.File;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import javax.imageio.ImageIO;
import javax.swing.SwingUtilities;

/** java -Djava.awt.headless=true -cp ... burp2model.Smoke export.xml [screenshot.png]: the engine and the tab, end to end. */
public final class Smoke {
    private Smoke() {}

    private static void layoutAll(java.awt.Container c) {
        c.doLayout();
        for (java.awt.Component k : c.getComponents()) {
            if (k instanceof java.awt.Container cc) {
                layoutAll(cc);
            }
        }
    }

    private static void check(boolean ok, String what) {
        System.out.println((ok ? "ok   " : "FAIL ") + what);
        if (!ok) {
            System.exit(1);
        }
    }

    public static void main(String[] a) throws Exception {
        Path home = Files.createTempDirectory("b2m-smoke");
        List<Parse.Raw> raws = BurpXml.readRaw(new File(a[0]));
        int half = Math.max(1, raws.size() / 2);

        Session s = new Session(home, "smoke");
        Session.AddResult r1 = s.add(raws.subList(0, half), null, "first half", false);
        check(r1.added() == half && s.builds().size() == 1, "first send builds one model (" + r1.added() + " requests)");
        Session.AddResult r1b = s.add(raws.subList(0, half), null, "again", false);
        check(r1b.added() == 0 && r1b.duplicates() == half, "the same requests are not added twice");
        Session.AddResult r2 = s.add(raws, null, "all", false);
        check(r2.added() == raws.size() - half && s.builds().size() == 3, "the rest adds to the same model");

        Query q = new Query(s.model());
        check(q.run("list-apis").total() > 0, "query: list-apis");
        check(q.run("req.method:GET limit 3").rows().size() <= 3, "query: BQL filter with limit");
        check(q.run("stats").total() > 0, "query: stats");
        Map<String, Object> d = s.diff(1, 3);
        check(d.containsKey("summary"), "diff between builds 1 and 3");

        Session again = new Session(home, "smoke");
        check(again.builds().size() == 3 && again.model() != null && again.requestCount() == raws.size(), "a saved session reloads");

        Map<String, String> prefs = new HashMap<>(Map.of("app", "smoke"));
        MainPanel[] panel = new MainPanel[1];
        SwingUtilities.invokeAndWait(() -> panel[0] = new MainPanel(new MainPanel.Host() {
            public String get(String k, String d2) {
                return prefs.getOrDefault(k, d2);
            }

            public void set(String k, String v) {
                prefs.put(k, v);
            }

            public void log(String l) {
                System.out.println("log: " + l);
            }

            public Session session(String name) throws java.io.IOException {
                return new Session(home, name);
            }
        }));
        panel[0].setSize(1200, 760);
        SwingUtilities.invokeAndWait(() -> {
            panel[0].refresh();
            panel[0].doLayout();
        });
        Thread.sleep(500);
        check(panel[0].session().model() != null, "the tab opens on the saved model");
        if (a.length > 1) {
            SwingUtilities.invokeAndWait(() -> panel[0].ask("node.type:endpoint AND node.state:STATIC_ONLY limit 8"));
            var f = MainPanel.class.getDeclaredField("tabs");
            f.setAccessible(true);
            javax.swing.JTabbedPane tabs = (javax.swing.JTabbedPane) f.get(panel[0]);
            for (int t = 0; t < tabs.getTabCount(); t++) {
                final int idx = t;
                SwingUtilities.invokeAndWait(() -> {
                    tabs.setSelectedIndex(idx);
                    panel[0].doLayout();
                    java.awt.Container c = panel[0];
                    layoutAll(c);
                });
                Thread.sleep(300);
                BufferedImage img = new BufferedImage(1200, 760, BufferedImage.TYPE_INT_RGB);
                SwingUtilities.invokeAndWait(() -> {
                    var g = img.createGraphics();
                    panel[0].printAll(g);
                    g.dispose();
                });
                File out = new File(a[1].replace(".png", "-" + tabs.getTitleAt(t).replace(' ', '_') + ".png"));
                ImageIO.write(img, "png", out);
            }
            System.out.println("wrote screenshots next to " + a[1]);
        }
        System.out.println("all good");
        System.exit(0);
    }
}
