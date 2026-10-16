package burp2model.engine;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class BurpXmlTest {
    @TempDir
    Path dir;

    private static File sample(String name) {
        return new File(System.getProperty("burp2model.samples", "../samples"), name);
    }

    @Test
    void readsTheBundledExports() throws Exception {
        Redact.setKey(new byte[32]);
        assertEquals(17, BurpXml.readRaw(sample("burp-history-sample.xml")).size());
        List<Exchange> ex = BurpXml.read(sample("burp-history-sample.xml"), "user");
        assertFalse(ex.isEmpty());
        for (int i = 0; i < ex.size(); i++) {
            assertEquals("user", ex.get(i).role);
        }
    }

    @Test
    void entityExpansionIsCapped() throws Exception {
        StringBuilder dtd = new StringBuilder("<?xml version=\"1.0\"?>\n<!DOCTYPE items [\n<!ENTITY l0 \"lol\">\n");
        for (int i = 1; i <= 10; i++) {
            dtd.append("<!ENTITY l").append(i).append(" \"").append(("&l" + (i - 1) + ";").repeat(10)).append("\">\n");
        }
        dtd.append("]>\n<items><item><host>&l10;</host><path>/</path><method>GET</method></item></items>\n");
        Path f = dir.resolve("laughs.xml");
        Files.writeString(f, dtd, StandardCharsets.UTF_8);
        assertThrows(Exception.class, () -> BurpXml.readRaw(f.toFile()), "ten billion 'lol's must not be expanded");
    }

    @Test
    void externalEntitiesAreNeverRead() throws Exception {
        Path secret = dir.resolve("secret.txt");
        Files.writeString(secret, "TOPSECRET-VALUE", StandardCharsets.UTF_8);
        String xml = "<?xml version=\"1.0\"?>\n<!DOCTYPE items [<!ENTITY x SYSTEM \"" + secret.toUri() + "\">]>\n"
                + "<items><item><host>h&x;</host><path>/</path><method>GET</method><port>80</port><protocol>http</protocol></item></items>\n";
        Path f = dir.resolve("xxe.xml");
        Files.writeString(f, xml, StandardCharsets.UTF_8);
        try {
            for (Parse.Raw r : BurpXml.readRaw(f.toFile())) {
                assertFalse(String.valueOf(r.host()).contains("TOPSECRET"), "the external file must not be read into the model");
            }
        } catch (Exception refused) {
            // refusing the document outright is also fine
        }
    }
}
