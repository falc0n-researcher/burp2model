package burp2model.ui;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import burp2model.engine.BurpXml;
import burp2model.engine.Builder;
import burp2model.engine.Exchange;
import burp2model.engine.Model;
import burp2model.engine.Redact;
import burp2model.engine.Session;
import java.awt.Component;
import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import javax.swing.JLabel;
import javax.swing.SwingUtilities;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/** Burp's message editor shows only the masked text burp2model stores, and the setting switches every viewer. */
class BurpEditorTest {
    @TempDir
    Path home;

    /** Stands in for Burp's editors: keeps every text it is given. */
    static final class Fake implements MessageEditors {
        final List<String> given = new ArrayList<>();
        int made;

        private Editor editor() {
            made++;
            JLabel c = new JLabel();
            return new Editor() {
                @Override
                public Component component() {
                    return c;
                }

                @Override
                public void show(String text) {
                    given.add(text);
                    c.setText(text);
                }
            };
        }

        @Override
        public Editor request() {
            return editor();
        }

        @Override
        public Editor response() {
            return editor();
        }
    }

    @Test
    @SuppressWarnings("unchecked")
    void theEditorIsGivenOnlyMaskedText() throws Exception {
        Redact.setKey(new byte[32]);
        File xml = new File(System.getProperty("burp2model.samples", "../samples"), "burp-history-sample.xml");
        StringBuilder raw = new StringBuilder();
        for (burp2model.engine.Parse.Raw r : BurpXml.readRaw(xml)) {
            raw.append(new String(r.request(), StandardCharsets.ISO_8859_1)).append(new String(r.response(), StandardCharsets.ISO_8859_1));
        }
        // the CI leak check plants these in the bundled sample; the captured requests really hold them
        List<String> planted = new ArrayList<>();
        for (String s : new String[] {"s3cr3tSESSIONv4lue123456", "AKIAIOSFODNN7EXAMPLE", "user@shop.example.com", "eyJhbGciOiJIUzI1NiJ9"}) {
            if (raw.indexOf(s) >= 0) {
                planted.add(s);
            }
        }
        assertFalse(planted.isEmpty(), "the sample carries planted secrets");
        List<Exchange> ex = BurpXml.read(xml, null);
        Model m = Builder.build(ex, "app", null, null, null);
        Fake fake = new Fake();
        BurpMessagePane req = new BurpMessagePane("Request", fake.request());
        BurpMessagePane resp = new BurpMessagePane("Response", fake.response());
        int shown = 0;
        for (int i = 0; i < m.evidenceLog.size(); i++) {
            Map<String, Object> ev = m.evidenceLog.get(i);
            req.show((Map<String, Object>) ev.get("request"));
            resp.show((Map<String, Object>) ev.get("response"));
            assertEquals(BurpMessagePane.text((Map<String, Object>) ev.get("request")), req.shownText());
            shown++;
        }
        assertTrue(shown > 4);
        boolean masked = false;
        for (String text : fake.given) {
            for (String s : planted) {
                assertFalse(text.contains(s), "a planted secret reached the editor: " + s);
            }
            masked |= text.contains("[REDACTED");
        }
        assertTrue(masked, "masked values show as masks in the editor");
    }

    @Test
    void aMessageThatWasCutOffSaysSo() {
        Fake fake = new Fake();
        BurpMessagePane p = new BurpMessagePane("Response", fake.response());
        Map<String, Object> msg = new HashMap<>();
        msg.put("line", "HTTP/1.1 200 OK");
        msg.put("headers", List.of(List.of("Content-Type", "text/html")));
        msg.put("body", "<html>");
        msg.put("truncated", true);
        p.show(msg);
        assertEquals("HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<html>", p.shownText());
        p.clear("nothing here");
        assertEquals("", fake.given.get(fake.given.size() - 1), "a cleared pane leaves the editor empty");
    }

    private MainPanel panel(Map<String, String> prefs, MessageEditors editors) throws Exception {
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

            @Override
            public MessageEditors editors() {
                return editors;
            }
        }));
        return panel[0];
    }

    private static List<EvidenceViewer> viewers(java.awt.Container c, List<EvidenceViewer> out) {
        for (Component k : c.getComponents()) {
            if (k instanceof EvidenceViewer v) {
                out.add(v);
            } else if (k instanceof java.awt.Container kc) {
                viewers(kc, out);
            }
        }
        return out;
    }

    @Test
    void insideBurpEveryViewerUsesTheEditorUntilItIsTurnedOff() throws Exception {
        Map<String, String> prefs = new HashMap<>(Map.of("app", "t", "welcome.seen", "1"));
        Fake fake = new Fake();
        MainPanel p = panel(prefs, fake);
        List<EvidenceViewer> all = viewers(p, new ArrayList<>());
        assertEquals(6, all.size(), "To check, Map, Surface, Requests, Query and Roles each have a viewer");
        assertTrue(all.stream().allMatch(EvidenceViewer::usesEditors));
        assertEquals(12, fake.made, "a request and a response editor for each");
        assertTrue(p.settingsTab.burpEditor.isEnabled() && p.settingsTab.burpEditor.isSelected());

        SwingUtilities.invokeAndWait(() -> p.settingsTab.burpEditor.doClick());
        assertEquals("0", prefs.get("editor.burp"));
        assertTrue(all.stream().noneMatch(EvidenceViewer::usesEditors), "turned off: burp2model's own view");

        MainPanel again = panel(prefs, fake);
        assertTrue(viewers(again, new ArrayList<>()).stream().noneMatch(EvidenceViewer::usesEditors), "the choice is remembered");
        SwingUtilities.invokeAndWait(() -> again.settingsTab.burpEditor.doClick());
        assertTrue(viewers(again, new ArrayList<>()).stream().allMatch(EvidenceViewer::usesEditors));
    }

    @Test
    void outsideBurpTheOwnViewIsUsedAndTheSettingIsOff() throws Exception {
        MainPanel p = panel(new HashMap<>(Map.of("app", "t", "welcome.seen", "1")), null);
        assertTrue(viewers(p, new ArrayList<>()).stream().noneMatch(EvidenceViewer::usesEditors));
        assertFalse(p.settingsTab.burpEditor.isEnabled());
    }
}
