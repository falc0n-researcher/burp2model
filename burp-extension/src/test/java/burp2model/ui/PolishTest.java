package burp2model.ui;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;

import burp2model.engine.Redact;
import burp2model.engine.Session;
import java.awt.Color;
import java.awt.event.InputEvent;
import java.awt.event.KeyEvent;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import javax.swing.JComboBox;
import javax.swing.JComponent;
import javax.swing.JTabbedPane;
import javax.swing.KeyStroke;
import javax.swing.SwingUtilities;
import javax.swing.UIManager;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class PolishTest {
    @TempDir
    Path home;

    @Test
    void everyAccentIsReadableAsTextInBothThemes() {
        Color[] accents = {Theme.ACCENT, Theme.GREEN, Theme.BLUE, Theme.PURPLE, Theme.AMBER, Theme.RED, Theme.GRAY};
        Color[] backgrounds = {Color.WHITE, new Color(0xf2, 0xf2, 0xf2), new Color(0x2b, 0x2b, 0x2b), new Color(0x1e, 0x1f, 0x22)};
        for (Color bg : backgrounds) {
            for (Color c : accents) {
                Color t = Theme.readable(c, bg);
                assertTrue(Theme.contrast(t, bg) >= 4.5, c + " on " + bg + " is " + Theme.contrast(t, bg));
            }
        }
    }

    @Test
    void liveColoursFollowATheme() {
        Object old = UIManager.get("Panel.background");
        try {
            UIManager.put("Panel.background", Color.WHITE);
            int light = Theme.LINE.getRGB();
            UIManager.put("Panel.background", new Color(0x2b, 0x2b, 0x2b));
            int dark = Theme.LINE.getRGB();
            assertNotEquals(light, dark, "the same LINE gives the dark theme's line colour once Burp switches");
            assertEquals(Theme.line().getRGB(), dark);
        } finally {
            UIManager.put("Panel.background", old);
        }
    }

    @Test
    void rolesAreRankedByWhatTheirNamesSay() {
        assertTrue(RolesTab.rank("guest") < RolesTab.rank("user"));
        assertTrue(RolesTab.rank("user") < RolesTab.rank("admin"));
        assertTrue(RolesTab.rank("customer") < RolesTab.rank("support-staff"));
        assertTrue(RolesTab.rank("anonymous") < RolesTab.rank("tenant-b"));
    }

    @Test
    void theOverviewReflowsWithTheWidth() throws Exception {
        var m = Dashboard.class.getDeclaredMethod("columnsFor", int.class);
        m.setAccessible(true);
        assertEquals(6, m.invoke(null, 1300));
        assertEquals(3, m.invoke(null, 700));
        assertEquals(2, m.invoke(null, 400));
    }

    private MainPanel open(Map<String, String> prefs) throws Exception {
        Redact.setKey(new byte[32]);
        MainPanel[] p = new MainPanel[1];
        SwingUtilities.invokeAndWait(() -> p[0] = new MainPanel(new MainPanel.Host() {
            public String get(String k, String d) {
                return prefs.getOrDefault(k, d);
            }

            public void set(String k, String v) {
                prefs.put(k, v);
            }

            public void log(String l) {
            }

            public Session session(String name) throws java.io.IOException {
                return new Session(home, name);
            }
        }));
        assertNotNull(p[0].awaitSession(10_000));
        for (int i = 0; i < 3; i++) {
            Thread.sleep(50);
            SwingUtilities.invokeAndWait(() -> { });
        }
        return p[0];
    }

    @SuppressWarnings("unchecked")
    private static <T> T field(Object o, String name) throws Exception {
        var f = o.getClass().getDeclaredField(name);
        f.setAccessible(true);
        return (T) f.get(o);
    }

    @Test
    void shortcutsAreBoundOnlyInsideTheTab() throws Exception {
        MainPanel p = open(new HashMap<>(Map.of("welcome.seen", "1")));
        int menu = MainPanel.menuMask();
        var im = p.getInputMap(JComponent.WHEN_ANCESTOR_OF_FOCUSED_COMPONENT);
        for (KeyStroke k : new KeyStroke[] {KeyStroke.getKeyStroke(KeyEvent.VK_1, menu), KeyStroke.getKeyStroke(KeyEvent.VK_0, menu),
            KeyStroke.getKeyStroke(KeyEvent.VK_F, menu), KeyStroke.getKeyStroke(KeyEvent.VK_L, menu),
            KeyStroke.getKeyStroke(KeyEvent.VK_C, menu | InputEvent.SHIFT_DOWN_MASK), KeyStroke.getKeyStroke(KeyEvent.VK_LEFT, InputEvent.ALT_DOWN_MASK)}) {
            assertNotNull(im.get(k), "bound: " + k);
        }
        assertTrue(p.getInputMap(JComponent.WHEN_IN_FOCUSED_WINDOW).size() == 0, "nothing is taken from the rest of Burp");
    }

    @Test
    void backReturnsToTheTabBeforeAJump() throws Exception {
        MainPanel p = open(new HashMap<>(Map.of("welcome.seen", "1")));
        JTabbedPane tabs = field(p, "tabs");
        List<java.awt.Component> seen = new ArrayList<>();
        SwingUtilities.invokeAndWait(() -> {
            tabs.setSelectedIndex(2);                           // Map
            seen.add(tabs.getSelectedComponent());
            tabs.setSelectedIndex(5);                           // Query
            p.getActionMap().get("back").actionPerformed(null);
            seen.add(tabs.getSelectedComponent());
        });
        assertSame(seen.get(0), seen.get(1), "Alt+Left goes back to the Map");
    }

    @Test
    void theSwitcherListsTheSavedModels() throws Exception {
        new Session(home, "alpha");
        new Session(home, "beta").add(burp2model.engine.BurpXml.readRaw(
                new java.io.File(System.getProperty("burp2model.samples", "../samples"), "burp-history-sample.xml")), null, "one", false);
        new Session(home, "empty");                             // nothing saved: not offered
        MainPanel p = open(new HashMap<>(Map.of("app", "alpha", "welcome.seen", "1")));
        JComboBox<String> models = p.header.models;
        List<String> items = new ArrayList<>();
        SwingUtilities.invokeAndWait(() -> {
            for (int i = 0; i < models.getItemCount(); i++) {
                items.add(models.getItemAt(i));
            }
        });
        assertTrue(items.contains("alpha") && items.contains("beta"), items.toString());
        assertTrue(!items.contains("empty"), "an empty model is not offered: " + items);
        assertEquals("New model…", items.get(items.size() - 1));
        assertEquals("alpha", models.getSelectedItem());
    }

    @Test
    void theLiveButtonTurnsCaptureOnAndOff() throws Exception {
        Map<String, String> prefs = new HashMap<>(Map.of("welcome.seen", "1"));
        MainPanel p = open(prefs);
        javax.swing.JButton live = p.header.live;
        SwingUtilities.invokeAndWait(live::doClick);
        assertEquals("1", prefs.get("auto"));
        assertTrue(live.getText().contains("Live") && !live.getText().contains("off"), live.getText());
        SwingUtilities.invokeAndWait(live::doClick);
        assertEquals("0", prefs.get("auto"));
    }
}
