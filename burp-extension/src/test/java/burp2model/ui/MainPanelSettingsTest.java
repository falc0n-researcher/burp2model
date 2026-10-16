package burp2model.ui;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import burp2model.engine.Session;
import java.nio.file.Path;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import javax.swing.JCheckBox;
import javax.swing.JTextField;
import javax.swing.SwingUtilities;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class MainPanelSettingsTest {
    @TempDir
    Path home;

    @Test
    void scopeAndRoleAreParsed() {
        MainPanel.Settings s = MainPanel.Settings.of("  admin ", "shop.example.com, api.example.com  cdn.example.com", true);
        assertEquals("admin", s.role());
        assertEquals(List.of("shop.example.com", "api.example.com", "cdn.example.com"), s.scope());
        assertTrue(s.replaceRole());
        MainPanel.Settings blank = MainPanel.Settings.of("  ", " ", false);
        assertNull(blank.role());
        assertTrue(blank.scope().isEmpty());
    }

    @Test
    void aRefreshKeepsWhatIsBeingTyped() throws Exception {
        Map<String, String> prefs = new HashMap<>(Map.of("app", "t", "role", "saved-role", "scope", "saved.example.com"));
        MainPanel[] panel = new MainPanel[1];
        SwingUtilities.invokeAndWait(() -> panel[0] = new MainPanel(new MainPanel.Host() {
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
        JTextField role = field(panel[0], "roleField");
        JTextField scope = field(panel[0], "scopeField");
        JCheckBox replace = field(panel[0], "replaceRole");
        assertEquals("saved-role", panel[0].settings().role(), "starts from the saved settings");

        SwingUtilities.invokeAndWait(() -> {
            role.setText("half-typ");
            scope.setText("new.example.com");
            replace.setSelected(true);
        });
        // live capture refreshes every few seconds; a refresh must not put the saved values back
        panel[0].refresh();
        SwingUtilities.invokeAndWait(() -> { });
        SwingUtilities.invokeAndWait(() -> { });

        assertEquals("half-typ", role.getText());
        assertEquals("new.example.com", scope.getText());
        MainPanel.Settings now = panel[0].settings();
        assertEquals("half-typ", now.role(), "the next send uses what is typed");
        assertEquals(List.of("new.example.com"), now.scope());
        assertTrue(now.replaceRole());
    }

    @Test
    void theTabIsBuiltBeforeTheModelFinishesOpening() throws Exception {
        java.util.concurrent.CountDownLatch release = new java.util.concurrent.CountDownLatch(1);
        MainPanel[] panel = new MainPanel[1];
        // the model cannot open until `release`; if building the tab waited for it, the build would never finish
        Thread builder = new Thread(() -> {
            try {
                SwingUtilities.invokeAndWait(() -> panel[0] = new MainPanel(new MainPanel.Host() {
                    public String get(String k, String d) {
                        return d;
                    }

                    public void set(String k, String v) {
                    }

                    public void log(String l) {
                    }

                    public Session session(String name) throws java.io.IOException {
                        try {
                            release.await();                            // a model that takes a while to open
                        } catch (InterruptedException e) {
                            Thread.currentThread().interrupt();
                        }
                        return new Session(home, name);
                    }
                }));
            } catch (Exception e) {
                throw new IllegalStateException(e);
            }
        });
        builder.start();
        builder.join(60_000);
        assertTrue(!builder.isAlive() && panel[0] != null, "the tab is built while the model is still opening");
        assertNull(panel[0].session(), "still opening");
        release.countDown();
        assertTrue(panel[0].awaitSession(10_000) != null, "then it opens");
    }

    @SuppressWarnings("unchecked")
    private static <T> T field(MainPanel p, String name) throws Exception {
        var f = MainPanel.class.getDeclaredField(name);
        f.setAccessible(true);
        return (T) f.get(p);
    }
}
