package burp2model.engine;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.File;
import java.lang.reflect.Method;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/** The streaming HAR reader gives exactly what parsing the whole document gave. */
class HarStreamTest {
    @TempDir
    Path dir;

    private static String entry(String path, String body) {
        return "{\"request\":{\"method\":\"POST\",\"url\":\"https://shop.example.com" + path + "\",\"headers\":[{\"name\":\"Host\",\"value\":\"shop.example.com\"}],"
                + "\"postData\":{\"mimeType\":\"application/json\",\"text\":" + Json.write(body) + "}},"
                + "\"response\":{\"status\":200,\"headers\":[{\"name\":\"Content-Type\",\"value\":\"application/json\"}],"
                + "\"content\":{\"mimeType\":\"application/json\",\"text\":" + Json.write("{\"ok\":[1,2,{\"x\":\"]}\"}]}") + "}}}";
    }

    /** What the old reader did: the whole document parsed at once. */
    @SuppressWarnings("unchecked")
    private static List<Parse.Raw> whole(File f) throws Exception {
        Method m = Har.class.getDeclaredMethod("entry", Map.class);
        m.setAccessible(true);
        String text = Files.readString(f.toPath(), StandardCharsets.UTF_8);
        if (text.startsWith("﻿")) {
            text = text.substring(1);
        }
        Map<String, Object> doc = (Map<String, Object>) Json.parse(text);
        List<Parse.Raw> out = new ArrayList<>();
        for (Object o : (List<Object>) ((Map<String, Object>) doc.get("log")).get("entries")) {
            out.add(o instanceof Map<?, ?> e ? (Parse.Raw) m.invoke(null, e) : null);
        }
        return out;
    }

    private File write(String name, String text) throws Exception {
        Path p = dir.resolve(name);
        Files.writeString(p, text, StandardCharsets.UTF_8);
        return p.toFile();
    }

    private static void same(List<Parse.Raw> a, List<Parse.Raw> b) {
        assertEquals(a.size(), b.size());
        for (int i = 0; i < a.size(); i++) {
            if (a.get(i) == null) {
                assertNull(b.get(i));
                continue;
            }
            assertEquals(a.get(i).method(), b.get(i).method());
            assertEquals(a.get(i).path(), b.get(i).path());
            assertEquals(a.get(i).status(), b.get(i).status());
            assertArrayEquals(a.get(i).request(), b.get(i).request());
            assertArrayEquals(a.get(i).response(), b.get(i).response());
        }
    }

    @Test
    void trickyContentReadsTheSameAsTheWholeDocument() throws Exception {
        String doc = "﻿{ \"version\" : \"1.2\", \"extra\": {\"log\": {\"entries\": [\"decoy\"]}, \"s\": \"} ] {\\\"\"},\n"
                + " \"log\" : { \"creator\": {\"name\": \"x\", \"list\": [1, true, null, -2.5e3]},\n"
                + "  \"entries\" : [\n   " + entry("/a?q=1", "{\"p\":\"}]\\\"]\"}") + ",\n   null, 7,\n   "
                + entry("/b/é/🙂", "line\nbreak \\ backslash \u0001") + " ], \"after\": [\"]\"] } ,\n \"tail\": 1 }";
        File f = write("tricky.har", doc);
        List<Parse.Raw> streamed = Har.readRaw(f);
        assertEquals(4, streamed.size(), "two entries and two non-objects, in order");
        same(whole(f), streamed);
    }

    @Test
    void anEmptyEntriesListIsFine() throws Exception {
        assertTrue(Har.readRaw(write("empty.har", "{\"log\":{\"entries\":[]}}")).isEmpty());
    }

    @Test
    void aFileWithoutEntriesOrCutOffIsRefused() throws Exception {
        assertThrows(IllegalArgumentException.class, () -> Har.readRaw(write("nolog.har", "{\"version\":1}")));
        String good = "{\"log\":{\"entries\":[" + entry("/a", "x") + "," + entry("/b", "y") + "]}}";
        assertThrows(Exception.class, () -> Har.readRaw(write("cut.har", good.substring(0, good.length() / 2))));
    }

    @Test
    void theBundledHarStillReads() throws Exception {
        File samples = new File(System.getProperty("burp2model.samples", "../samples"));
        File[] hars = samples.listFiles((d, n) -> n.endsWith(".har"));
        if (hars == null) {
            return;
        }
        for (File h : hars) {
            same(whole(h), Har.readRaw(h));
        }
    }
}
