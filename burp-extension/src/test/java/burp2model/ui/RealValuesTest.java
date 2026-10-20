package burp2model.ui;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import burp2model.engine.BurpXml;
import burp2model.engine.Parse;
import burp2model.engine.Redact;
import burp2model.engine.Session;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.zip.GZIPOutputStream;
import javax.swing.SwingUtilities;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/** The viewer shows requests as captured (real cookies), while everything stored stays masked. */
class RealValuesTest {
    static final String SECRET = "s3cr3tSESSIONv4lue123456";
    static List<Parse.Raw> raws;

    @TempDir
    Path home;

    @BeforeAll
    static void read() throws Exception {
        Redact.setKey(new byte[32]);
        raws = BurpXml.readRaw(new File(System.getProperty("burp2model.samples", "../samples"), "burp-history-sample.xml"));
    }

    /** The evidence id of the first request whose raw bytes hold the planted session cookie. */
    private static int withSecret(Session s) {
        for (int id = 1; id <= s.requestCount(); id++) {
            byte[][] r = s.raw(id);
            if (r != null && new String(r[0], StandardCharsets.ISO_8859_1).contains(SECRET)) {
                return id;
            }
        }
        throw new AssertionError("the sample has a request with the planted cookie");
    }

    @Test
    void addedRequestsKeepTheirRawBytesInMemoryOnly() throws Exception {
        Session s = new Session(home, "app");
        s.add(raws, "user", "one", false);
        int id = withSecret(s);
        assertNotNull(s.raw(id));
        assertNull(s.raw(0));
        assertNull(s.raw(s.requestCount() + 1));
        // nothing on disk holds the real value
        try (var walk = Files.walk(s.dir())) {
            for (Path p : (Iterable<Path>) walk.filter(Files::isRegularFile)::iterator) {
                byte[] b = Files.readAllBytes(p);
                if (p.toString().endsWith(".gz")) {
                    b = new java.util.zip.GZIPInputStream(new java.io.ByteArrayInputStream(b)).readAllBytes();
                }
                assertFalse(new String(b, StandardCharsets.ISO_8859_1).contains(SECRET), "the real cookie reached " + p);
            }
        }
        List<Parse.Raw> without = new ArrayList<>();
        for (Parse.Raw r : raws) {
            if (!new String(r.request(), StandardCharsets.ISO_8859_1).contains(SECRET)) {
                without.add(r);
            }
        }
        s.add(without, "user", "again", true);
        for (int i = 1; i <= s.requestCount(); i++) {
            byte[][] r = s.raw(i);
            assertTrue(r == null || !new String(r[0], StandardCharsets.ISO_8859_1).contains(SECRET), "replacing the role forgets its raw bytes");
        }
        s.clear();
        assertNull(s.raw(1));
        s.close();
        Session reopened = new Session(home, "app");
        assertNull(reopened.raw(1), "after a restart the raw bytes are gone; the extension looks in Burp instead");
    }

    @Test
    void plainShowsTheMessageUnmaskedAndDecoded() throws Exception {
        ByteArrayOutputStream gz = new ByteArrayOutputStream();
        try (GZIPOutputStream z = new GZIPOutputStream(gz)) {
            z.write("{\"token\":\"abc123\"}".getBytes(StandardCharsets.UTF_8));
        }
        ByteArrayOutputStream msg = new ByteArrayOutputStream();
        msg.write(("HTTP/1.1 200 OK\r\nSet-Cookie: sid=" + SECRET + "\r\nContent-Encoding: gzip\r\n\r\n").getBytes(StandardCharsets.ISO_8859_1));
        msg.write(gz.toByteArray());
        Map<String, Object> m = Parse.plain(msg.toByteArray());
        assertEquals("HTTP/1.1 200 OK", m.get("line"));
        assertTrue(String.valueOf(m.get("headers")).contains("sid=" + SECRET), "the cookie is shown as captured");
        assertEquals("{\"token\":\"abc123\"}", m.get("body"));
        assertEquals(false, m.get("truncated"));
    }

    private MainPanel panel(Map<String, String> prefs, BurpEditorTest.Fake editors) throws Exception {
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

            @Override
            public MessageEditors editors() {
                return editors;
            }
        }));
        assertNotNull(p[0].awaitSession(10_000));
        return p[0];
    }

    private static EvidenceViewer viewer(MainPanel p) {
        List<EvidenceViewer> out = new ArrayList<>();
        collect(p, out);
        return out.get(0);
    }

    private static void collect(java.awt.Container c, List<EvidenceViewer> out) {
        for (java.awt.Component k : c.getComponents()) {
            if (k instanceof EvidenceViewer v) {
                out.add(v);
            } else if (k instanceof java.awt.Container kc) {
                collect(kc, out);
            }
        }
    }

    /** Show evidence `id` in a viewer and return the request text the editor ends up with. */
    private static String shown(MainPanel p, BurpEditorTest.Fake fake, int id) throws Exception {
        EvidenceViewer v = viewer(p);
        SwingUtilities.invokeAndWait(() -> {
            v.setModel(p.session().model());
            v.show(List.of(id), "ev_" + id);
        });
        for (int i = 0; i < 40; i++) {
            Thread.sleep(25);
            SwingUtilities.invokeAndWait(() -> { });
        }
        return fake.given.get(fake.given.size() - 2);           // the request; the response came last
    }

    @Test
    void theViewerShowsTheRealCookieUnlessTurnedOff() throws Exception {
        Map<String, String> prefs = new HashMap<>(Map.of("app", "app"));
        BurpEditorTest.Fake fake = new BurpEditorTest.Fake();
        MainPanel p = panel(prefs, fake);
        p.session().add(raws, null, "one", false);
        int id = withSecret(p.session());
        assertTrue(shown(p, fake, id).contains(SECRET), "as captured: the real session cookie");

        SwingUtilities.invokeAndWait(() -> p.settingsTab.realValues.doClick());
        assertEquals("0", prefs.get("viewer.real"));
        String masked = shown(p, fake, id);
        assertFalse(masked.contains(SECRET), "turned off: the masked copy");
        assertTrue(masked.contains("[REDACTED"));
    }
}
