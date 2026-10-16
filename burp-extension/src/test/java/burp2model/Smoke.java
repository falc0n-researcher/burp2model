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

    /** Roughly what Burp's dark theme sets, so the screenshots show how the tab looks there. */
    private static void darkTheme() {
        java.awt.Color bg = new java.awt.Color(0x2b, 0x2b, 0x2b);
        java.awt.Color fg = new java.awt.Color(0xdd, 0xdd, 0xdd);
        for (String k : new String[] {"Panel.background", "TabbedPane.background", "SplitPane.background", "ScrollPane.background", "Viewport.background",
            "Table.background", "Tree.background", "List.background", "TextArea.background", "TextField.background", "TextPane.background", "Button.background",
            "ComboBox.background", "CheckBox.background", "OptionPane.background", "MenuItem.background", "PopupMenu.background", "ToggleButton.background"}) {
            javax.swing.UIManager.put(k, bg);
        }
        for (String k : new String[] {"Label.foreground", "Table.foreground", "Tree.foreground", "List.foreground", "TextArea.foreground", "TextField.foreground",
            "TextPane.foreground", "Button.foreground", "ComboBox.foreground", "CheckBox.foreground", "TabbedPane.foreground", "ToggleButton.foreground"}) {
            javax.swing.UIManager.put(k, fg);
        }
        javax.swing.UIManager.put("Table.selectionBackground", new java.awt.Color(0x39, 0x6F, 0xD6));
        javax.swing.UIManager.put("Table.selectionForeground", java.awt.Color.WHITE);
        javax.swing.UIManager.put("Tree.textBackground", bg);
        javax.swing.UIManager.put("Tree.textForeground", fg);
    }

    private static void select(MainPanel p, String field, int row) {
        try {
            var f = MainPanel.class.getDeclaredField(field);
            f.setAccessible(true);
            javax.swing.JTable t = (javax.swing.JTable) f.get(p);
            if (t.getRowCount() > row) {
                t.setRowSelectionInterval(row, row);
            }
        } catch (ReflectiveOperationException e) {
            throw new IllegalStateException(e);
        }
    }

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
        if (System.getProperty("b2m.dark") != null) {
            darkTheme();
        }
        Path home = Files.createTempDirectory("b2m-smoke");
        List<Parse.Raw> raws = BurpXml.readRaw(new File(a[0]));
        int half = Math.max(1, raws.size() / 2);

        Session s = new Session(home, "smoke");
        Session.AddResult r1 = s.add(raws.subList(0, half), null, "first half", false);
        check(r1.added() > 0 && r1.added() + r1.duplicates() + r1.skipped() == half && s.builds().size() == 1, "first send builds one model (" + r1.added() + " requests)");
        Session.AddResult r1b = s.add(raws.subList(0, half), null, "again", false);
        check(r1b.added() == 0 && r1b.duplicates() + r1b.skipped() == half, "the same requests are not added twice");
        Session.AddResult r2 = s.add(raws, null, "all", false);
        check(s.builds().size() == 3, "the rest adds to the same model, as a new build");

        Query q = new Query(s.model());
        check(q.run("list-apis").total() > 0, "query: list-apis");
        check(q.run("req.method:GET limit 3").rows().size() <= 3, "query: BQL filter with limit");
        check(q.run("stats").total() > 0, "query: stats");
        Map<String, Object> d = s.diff(1, 3);
        check(d.containsKey("summary"), "diff between builds 1 and 3");

        // live capture: new requests join the working model without recording a build
        Session live = new Session(home, "live");
        Session.AddResult l1 = live.add(raws.subList(0, half), null, "live", false, false);
        check(l1.build() == null && live.builds().isEmpty() && live.model() != null && live.requestCount() == l1.added(), "live capture adds to the model without a build");
        Session.AddResult l2 = live.add(raws, null, "snap", false, true);
        check(l2.build() != null && live.builds().size() == 1, "a snapshot records one build");
        Session liveAgain = new Session(home, "live");
        check(liveAgain.model().nodes.size() == live.model().nodes.size(), "the working model is rebuilt from the saved inputs on load");
        Session fresh = new Session(Files.createTempDirectory("b2m-fresh"), "fresh");
        fresh.add(raws, null, "one go", false);
        check(fresh.requestCount() == s.requestCount(), "the same distinct requests either way");
        check(fresh.model().nodes.size() == live.model().nodes.size() && fresh.model().edges.size() == live.model().edges.size(),
                "adding in pieces gives the same model as adding at once");

        String md = burp2model.engine.Markdown.summary(s.model());
        check(md.contains("## To check") && md.contains("## Endpoints"), "markdown summary");
        String ai = burp2model.engine.ContextPack.forAi(s.model(), "whole");
        int fence = ai.indexOf("```json");
        Object parsed = burp2model.engine.Json.parse(ai.substring(fence + 8, ai.lastIndexOf("```")).strip());
        check(parsed instanceof Map<?, ?> mm && mm.containsKey("evidence") && mm.containsKey("rules"), "copy-for-AI package is valid JSON with rules and evidence");
        check(!burp2model.engine.Analysis.gaps(s.model()).isEmpty() || s.model().unknowns.isEmpty(), "open questions ranked");

        Session again = new Session(home, "smoke");
        check(again.builds().size() == 3 && again.model() != null && again.requestCount() == s.requestCount(), "a saved session reloads");

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
        panel[0].setSize(1300, 820);
        // the model opens in the background; wait for it, then for the refresh it queues
        check(panel[0].awaitSession(10_000) != null, "the model opens in the background");
        Thread.sleep(300);
        SwingUtilities.invokeAndWait(() -> {
            panel[0].refresh();
            panel[0].doLayout();
        });
        Thread.sleep(500);
        check(panel[0].session().model() != null, "the tab opens on the saved model");
        if (a.length > 1) {
            var tf = MainPanel.class.getDeclaredField("tabs");
            tf.setAccessible(true);
            javax.swing.JTabbedPane tp = (javax.swing.JTabbedPane) tf.get(panel[0]);
            SwingUtilities.invokeAndWait(() -> {
                for (int t = 0; t < tp.getTabCount(); t++) {
                    tp.setSelectedIndex(t);
                }
                tp.setSelectedIndex(0);
                panel[0].ask("req.method:POST");
                select(panel[0], "leadsTable", 1);
                select(panel[0], "reqTable", 5);
                select(panel[0], "surfaceTable", 3);
                select(panel[0], "queryTable", 0);
            });
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
                BufferedImage img = new BufferedImage(1300, 820, BufferedImage.TYPE_INT_RGB);
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
