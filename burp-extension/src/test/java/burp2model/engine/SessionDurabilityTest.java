package burp2model.engine;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.File;
import java.io.IOException;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Stream;
import java.util.zip.GZIPOutputStream;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

/** A saved model survives crashes and damaged files: nothing is wiped, damaged files are kept aside. */
class SessionDurabilityTest {
    static List<Parse.Raw> raws;

    @TempDir
    Path home;

    @BeforeAll
    static void readSample() throws Exception {
        Redact.setKey(new byte[32]);
        raws = BurpXml.readRaw(new File(System.getProperty("burp2model.samples", "../samples"), "burp-history-sample.xml"));
    }

    private static List<Parse.Raw> first() {
        return raws.subList(0, raws.size() / 2);
    }

    private static List<Parse.Raw> rest() {
        return raws.subList(raws.size() / 2, raws.size());
    }

    private static long corruptCopies(Path dir) throws IOException {
        try (Stream<Path> s = Files.list(dir)) {
            return s.filter(p -> p.getFileName().toString().contains(".corrupt-")).count();
        }
    }

    private static void appendGz(Path p, String text) throws IOException {
        try (OutputStream out = new GZIPOutputStream(Files.newOutputStream(p, java.nio.file.StandardOpenOption.APPEND))) {
            out.write(text.getBytes(StandardCharsets.UTF_8));
        }
    }

    /** Crash while appending the second batch: cut the inputs file anywhere inside the last gzip member. */
    @ParameterizedTest
    @ValueSource(ints = {1, 3, 9, 15, 40, -1})
    void aTornAppendKeepsTheCompleteRequestsAndHealsOnTheNextSave(int cutFromEnd) throws Exception {
        Session s = new Session(home, "live");
        int a = s.add(first(), null, "live", false, false).added();
        Path inputs = s.dir().resolve("inputs.jsonl.gz");
        long afterFirst = Files.size(inputs);
        int b = s.add(rest(), null, "live", false, false).added();
        byte[] all = Files.readAllBytes(inputs);
        assertTrue(all.length > afterFirst, "the second batch is a second gzip member");
        int keep = cutFromEnd < 0 ? (int) afterFirst + 5 : all.length - cutFromEnd;
        Files.write(inputs, Arrays.copyOf(all, keep));

        Session reopened = new Session(home, "live");
        assertEquals(a, reopened.requestCount(), "the complete first batch is read");
        assertNotNull(reopened.model());
        assertFalse(reopened.problems().isEmpty(), "the damage is reported");
        assertEquals(1, corruptCopies(reopened.dir()), "the damaged file is kept");

        // the next save rewrites a clean file, so later appends are not hidden behind the torn end
        reopened.add(raws, null, "live", false, false);
        reopened.add(raws.subList(0, 1), "other-role", "live", false, false);
        Session healed = new Session(home, "live");
        assertTrue(healed.problems().isEmpty(), healed.problems().toString());
        assertEquals(a + b + 1, healed.requestCount(), "everything is there after the heal");
    }

    @Test
    void anUnreadableLineSkipsOnlyThatLine() throws Exception {
        Session s = new Session(home, "app");
        int n = s.add(raws, null, "one", false).added();
        appendGz(s.dir().resolve("inputs.jsonl.gz"), "{\"method\": \"GET\", broken\n");

        Session reopened = new Session(home, "app");
        assertEquals(n, reopened.requestCount());
        assertEquals(1, reopened.builds().size(), "the build history is untouched");
        assertEquals(1, reopened.problems().size());
        assertTrue(reopened.problems().get(0).contains("1 unreadable"), reopened.problems().get(0));
    }

    @Test
    void aCorruptSessionFileNeverWipesTheRequests() throws Exception {
        Session s = new Session(home, "app");
        int n = s.add(raws, null, "one", false).added();
        s.add(raws, "admin", "two", false);
        int total = s.requestCount();
        assertTrue(total > n);
        Files.writeString(s.dir().resolve("session.json"), "{\"name\": \"app\", \"builds\": [", StandardCharsets.UTF_8);

        Session reopened = new Session(home, "app");
        assertEquals(total, reopened.requestCount(), "every saved request is still there");
        assertNotNull(reopened.model());
        assertTrue(reopened.builds().isEmpty(), "the unreadable history starts again");
        assertFalse(reopened.problems().isEmpty());
        assertEquals(2, corruptCopies(reopened.dir()), "session.json and the old builds are kept aside");

        Session.BuildInfo next = reopened.snapshot("after repair");
        assertNotNull(next);
        assertEquals(1, next.id());
        Session again = new Session(home, "app");
        assertEquals(1, again.builds().size());
        assertTrue(again.problems().isEmpty());
        assertEquals(total, again.requestCount());
    }

    @Test
    void savesLeaveNoTemporaryFiles() throws Exception {
        Session s = new Session(home, "app");
        s.add(first(), null, "one", false);
        s.add(raws, "admin", "two", true);
        s.add(rest(), null, "live", false, false);
        try (Stream<Path> all = Files.walk(s.dir())) {
            assertTrue(all.noneMatch(p -> p.toString().endsWith(".tmp")));
        }
    }

    @Test
    void anEmptyOrGarbageInputsFileIsTornNotFatal() throws Exception {
        Path p = home.resolve("x.gz");
        Files.write(p, new byte[0]);
        Session.GzText empty = Session.readGzTolerant(p);
        assertFalse(empty.torn());
        assertEquals("", empty.text());
        Files.write(p, "not gzip at all".getBytes(StandardCharsets.UTF_8));
        Session.GzText junk = Session.readGzTolerant(p);
        assertTrue(junk.torn());
        assertEquals("", junk.text());
    }

    @Test
    void aLockedModelCannotBeOpenedTwice() throws Exception {
        Session s = new Session(home, "app");
        s.lock();
        s.lock();
        Session other = new Session(home, "app");
        IOException e = assertThrows(IOException.class, other::lock);
        assertTrue(e.getMessage().contains("another Burp"));
        s.close();
        other.lock();
        other.close();
    }
}
