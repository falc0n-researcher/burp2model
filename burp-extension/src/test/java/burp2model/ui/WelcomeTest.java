package burp2model.ui;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import burp2model.engine.BurpXml;
import burp2model.engine.Redact;
import burp2model.engine.Session;
import java.io.File;
import java.nio.file.Path;
import java.util.HashMap;
import java.util.Map;
import javax.swing.SwingUtilities;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class WelcomeTest {
    @TempDir
    Path home;

    @BeforeAll
    static void key() {
        Redact.setKey(new byte[32]);
    }

    private MainPanel open(Map<String, String> prefs) throws Exception {
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
        settle();
        return p[0];
    }

    /** Let the refresh the model's opening queued run. */
    private static void settle() throws Exception {
        for (int i = 0; i < 3; i++) {
            Thread.sleep(50);
            SwingUtilities.invokeAndWait(() -> { });
        }
    }

    private static boolean showing(MainPanel p) throws Exception {
        var f = MainPanel.class.getDeclaredField("welcomeShowing");
        f.setAccessible(true);
        return (boolean) f.get(p);
    }

    private static Welcome.Actions actions(MainPanel p) throws Exception {
        var m = MainPanel.class.getDeclaredMethod("welcomeActions");
        m.setAccessible(true);
        return (Welcome.Actions) m.invoke(p);
    }

    @Test
    void aFirstRunShowsTheWelcomePage() throws Exception {
        assertTrue(showing(open(new HashMap<>())));
    }

    @Test
    void theSampleModelLoadsAndTheTabsTakeOver() throws Exception {
        Map<String, String> prefs = new HashMap<>(Map.of("app", "mine"));
        MainPanel p = open(prefs);
        SwingUtilities.invokeAndWait(() -> {
            try {
                actions(p).sample();
            } catch (Exception e) {
                throw new IllegalStateException(e);
            }
        });
        for (int i = 0; i < 200 && !"sample".equals(p.session().name); i++) {
            Thread.sleep(25);
        }
        settle();
        assertEquals("sample", p.session().name);
        assertTrue(p.session().requestCount() > 10, "the demo shop is in it");
        assertEquals(java.util.Set.of("admin", "user"), p.session().roles(), "two roles, so Roles has something to compare");
        assertFalse(showing(p));
        assertEquals("sample", prefs.get("app"));
        assertEquals("1", prefs.get("welcome.seen"));
        assertEquals(0, new Session(home, "mine").requestCount(), "the user's own model is untouched");
    }

    @Test
    void getStartedRemembersTheChoice() throws Exception {
        Map<String, String> prefs = new HashMap<>();
        MainPanel p = open(prefs);
        SwingUtilities.invokeAndWait(() -> {
            try {
                actions(p).getStarted(true);
            } catch (Exception e) {
                throw new IllegalStateException(e);
            }
        });
        assertFalse(showing(p));
        assertEquals("1", prefs.get("welcome.seen"));
        assertEquals("1", prefs.get("welcome.show"));
    }

    @Test
    void aReturningUserWithAModelGoesStraightToTheTabs() throws Exception {
        new Session(home, "app").add(BurpXml.readRaw(new File(System.getProperty("burp2model.samples", "../samples"), "burp-history-sample.xml")),
                null, "one", false);
        assertFalse(showing(open(new HashMap<>(Map.of("app", "app", "welcome.seen", "1")))));
    }

    @Test
    void anEmptyModelShowsItAndTheFirstRequestsTakeItAway() throws Exception {
        MainPanel p = open(new HashMap<>(Map.of("app", "empty", "welcome.seen", "1")));
        assertTrue(showing(p), "nothing to look at yet: the welcome page says how to start");
        p.session().add(BurpXml.readRaw(new File(System.getProperty("burp2model.samples", "../samples"), "burp-history-sample.xml")), null, "first send",
                false);
        p.refresh();
        settle();
        assertFalse(showing(p), "the first send shows the model");
    }

    @Test
    void liveCaptureCanBeTurnedOnFromThePage() throws Exception {
        Map<String, String> prefs = new HashMap<>();
        MainPanel p = open(prefs);
        SwingUtilities.invokeAndWait(() -> {
            try {
                actions(p).liveCapture();
            } catch (Exception e) {
                throw new IllegalStateException(e);
            }
        });
        assertEquals("1", prefs.get("auto"));
    }

    @Test
    void withoutAChoiceTheSampleOpensFull() throws Exception {
        Map<String, String> prefs = new HashMap<>();
        MainPanel p = open(prefs);
        assertEquals("sample", p.session().name, "no 'burp' model any more: the sample is the default");
        assertTrue(p.session().requestCount() > 10, "and it is filled before it is shown");
        assertTrue(showing(p), "a first run still starts on the welcome page");
    }

    @Test
    void anEmptyModelFromTheOldDefaultGivesWayToTheSample() throws Exception {
        new Session(home, "burp");
        Map<String, String> prefs = new HashMap<>(Map.of("app", "burp", "welcome.seen", "1"));
        MainPanel p = open(prefs);
        assertEquals("sample", p.session().name);
        assertEquals("sample", prefs.get("app"));
    }

    @Test
    void aMissingOldDefaultIsNotCreatedAgain() throws Exception {
        Map<String, String> prefs = new HashMap<>(Map.of("app", "burp", "welcome.seen", "1"));
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

            public boolean hasModel(String name) {
                return java.nio.file.Files.isDirectory(home.resolve(name));
            }
        }));
        assertNotNull(p[0].awaitSession(10_000));
        assertEquals("sample", p[0].session().name);
        assertFalse(java.nio.file.Files.exists(home.resolve("burp")), "no empty 'burp' folder appears");
    }

    @Test
    void aBurpModelWithRequestsIsKept() throws Exception {
        new Session(home, "burp").add(BurpXml.readRaw(new File(System.getProperty("burp2model.samples", "../samples"), "burp-history-sample.xml")),
                null, "one", false);
        MainPanel p = open(new HashMap<>(Map.of("app", "burp", "welcome.seen", "1")));
        assertEquals("burp", p.session().name, "the user's own requests are never set aside");
    }

    @Test
    void theDisplayFontIsInTheJar() {
        assertTrue(Theme.display(20f).getFamily().contains("IBM Plex Mono"), Theme.display(20f).getFamily());
        assertTrue(Theme.displayMedium(14f).getFontName().contains("SemiBold"), Theme.displayMedium(14f).getFontName());
        assertTrue(Theme.display(20f).getFontName().contains("Bold"), Theme.display(20f).getFontName());
        assertNotNull(WelcomeTest.class.getResource("/fonts/OFL-IBMPlexMono.txt"), "the licence ships with the font");
        assertTrue(Theme.display(20f).canDisplayUpTo("burp2model HOW IT WORKS Send Explore Ask Get started") < 0);
    }
}
