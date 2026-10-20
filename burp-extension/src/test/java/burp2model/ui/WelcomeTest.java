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

    private static boolean showing(MainPanel p) {
        return p.welcome.showing();
    }

    private static Welcome.Actions actions(MainPanel p) {
        return p.welcome.actions();
    }

    @Test
    void aFirstRunShowsTheWelcomePage() throws Exception {
        assertTrue(showing(open(new HashMap<>())));
    }

    @Test
    void theSampleModelLoadsOnlyWhenAskedAndIsNotRemembered() throws Exception {
        Map<String, String> prefs = new HashMap<>(Map.of("app", "mine"));
        MainPanel p = open(prefs);
        assertEquals("mine", p.session().name);
        SwingUtilities.invokeAndWait(() -> actions(p).sample());
        for (int i = 0; i < 200 && !"sample".equals(p.session().name); i++) {
            Thread.sleep(25);
        }
        settle();
        assertEquals("sample", p.session().name);
        assertTrue(p.session().requestCount() > 10, "the demo shop is in it");
        assertEquals(java.util.Set.of("admin", "user"), p.session().roles(), "two roles, so Roles has something to compare");
        assertFalse(showing(p));
        assertEquals("mine", prefs.get("app"), "the next start opens the user's own model, not the sample");
        assertEquals(0, new Session(home, "mine").requestCount(), "the user's own model is untouched");
    }

    @Test
    void getStartedGoesToTheTabs() throws Exception {
        MainPanel p = open(new HashMap<>());
        SwingUtilities.invokeAndWait(() -> actions(p).getStarted());
        assertFalse(showing(p));
    }

    @Test
    void everyStartShowsTheWelcomePageEvenWithAModel() throws Exception {
        new Session(home, "app").add(BurpXml.readRaw(new File(System.getProperty("burp2model.samples", "../samples"), "burp-history-sample.xml")),
                null, "one", false);
        MainPanel p = open(new HashMap<>(Map.of("app", "app")));
        assertTrue(showing(p), "the landing page first; the user opens the model from it");
        assertEquals("app", p.session().name, "the model is open behind it");
    }

    @Test
    void anEmptyModelShowsItAndTheFirstRequestsTakeItAway() throws Exception {
        MainPanel p = open(new HashMap<>(Map.of("app", "empty")));
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
        SwingUtilities.invokeAndWait(() -> actions(p).liveCapture());
        assertEquals("1", prefs.get("auto"));
    }

    @Test
    void withoutAChoiceAnEmptyDefaultModelOpens() throws Exception {
        MainPanel p = open(new HashMap<>());
        assertEquals("default", p.session().name, "the sample never opens by itself");
        assertEquals(0, p.session().requestCount());
        assertFalse(java.nio.file.Files.exists(home.resolve("sample")), "and is not even created");
        assertTrue(showing(p));
    }

    @Test
    void aSampleLeftOpenLastTimeDoesNotOpenAtStart() throws Exception {
        MainPanel p = open(new HashMap<>(Map.of("app", "sample")));
        assertEquals("default", p.session().name);
    }

    @Test
    void aBurpModelWithRequestsIsKept() throws Exception {
        new Session(home, "burp").add(BurpXml.readRaw(new File(System.getProperty("burp2model.samples", "../samples"), "burp-history-sample.xml")),
                null, "one", false);
        MainPanel p = open(new HashMap<>(Map.of("app", "burp")));
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
