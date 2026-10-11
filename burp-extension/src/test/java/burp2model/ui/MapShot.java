package burp2model.ui;

import burp2model.engine.BurpXml;
import burp2model.engine.Model;
import burp2model.engine.Session;
import java.awt.image.BufferedImage;
import java.io.File;
import java.lang.reflect.Field;
import java.nio.file.Files;
import java.util.List;
import javax.imageio.ImageIO;
import javax.swing.SwingUtilities;

/** java -Djava.awt.headless=true -cp ... burp2model.ui.MapShot export.xml out-prefix [dark]: draws the map in each layout. */
public final class MapShot {
    private MapShot() {}

    public static void main(String[] a) throws Exception {
        if (a.length > 2 && a[2].equals("dark")) {
            java.awt.Color bg = new java.awt.Color(0x2b, 0x2b, 0x2b);
            java.awt.Color fg = new java.awt.Color(0xdd, 0xdd, 0xdd);
            for (String k : new String[] {"Panel.background", "CheckBox.background", "ToggleButton.background", "Button.background", "TextField.background"}) {
                javax.swing.UIManager.put(k, bg);
            }
            for (String k : new String[] {"Label.foreground", "CheckBox.foreground", "ToggleButton.foreground", "Button.foreground", "TextField.foreground"}) {
                javax.swing.UIManager.put(k, fg);
            }
        }
        Session s = new Session(Files.createTempDirectory("b2m-shot"), "shot");
        s.add(BurpXml.readRaw(new File(a[0])), null, "all", false);
        Model m = s.model();
        GraphPanel[] g = new GraphPanel[1];
        SwingUtilities.invokeAndWait(() -> {
            g[0] = new GraphPanel();
            g[0].setSize(1250, 760);
            g[0].setModel(m);
        });
        for (String mode : new String[] {"network", "flow", "selected"}) {
            if (mode.equals("flow")) {
                SwingUtilities.invokeAndWait(() -> {
                    try {
                        var f = GraphPanel.class.getDeclaredMethod("setFlow", boolean.class);
                        f.setAccessible(true);
                        f.invoke(g[0], true);
                    } catch (ReflectiveOperationException e) {
                        throw new IllegalStateException(e);
                    }
                });
            }
            if (mode.equals("selected")) {
                SwingUtilities.invokeAndWait(() -> {
                    try {
                        var f = GraphPanel.class.getDeclaredMethod("setFlow", boolean.class);
                        f.setAccessible(true);
                        f.invoke(g[0], false);
                        Model.Node pick = null;
                        for (Model.Node n : m.nodes.values()) {
                            if (n.type.equals("script")) {
                                pick = n;
                                break;
                            }
                        }
                        if (pick != null) {
                            g[0].showNode(pick.id);
                        }
                    } catch (ReflectiveOperationException e) {
                        throw new IllegalStateException(e);
                    }
                });
            }
            for (int i = 0; i < 6; i++) {
                SwingUtilities.invokeAndWait(() -> {
                    layoutAll(g[0]);
                    g[0].fit();
                });
                Thread.sleep(150);
            }
            BufferedImage img = new BufferedImage(1250, 760, BufferedImage.TYPE_INT_RGB);
            SwingUtilities.invokeAndWait(() -> {
                var gr = img.createGraphics();
                g[0].printAll(gr);
                gr.dispose();
            });
            ImageIO.write(img, "png", new File(a[1] + "-" + mode + ".png"));
        }
        System.exit(0);
    }

    private static void layoutAll(java.awt.Container c) {
        c.doLayout();
        for (java.awt.Component k : c.getComponents()) {
            if (k instanceof java.awt.Container cc) {
                layoutAll(cc);
            }
        }
    }

    static Field unused() {
        return null;
    }

    static List<String> unusedToo() {
        return List.of();
    }
}
