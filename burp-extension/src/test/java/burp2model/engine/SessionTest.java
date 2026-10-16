package burp2model.engine;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.File;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Iterator;
import java.util.List;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class SessionTest {
    static List<Parse.Raw> raws;

    @TempDir
    Path home;

    @BeforeAll
    static void readSample() throws Exception {
        Redact.setKey(new byte[32]);
        raws = BurpXml.readRaw(new File(System.getProperty("burp2model.samples", "../samples"), "burp-history-sample.xml"));
        assertTrue(raws.size() > 4, "the bundled sample has requests");
    }

    private static List<Parse.Raw> half() {
        return raws.subList(0, raws.size() / 2);
    }

    @Test
    void aClearedModelOpensAgain() throws Exception {
        Session s = new Session(home, "app");
        s.add(raws, null, "first", false);
        s.add(half(), "user", "second", false);
        assertFalse(s.builds().isEmpty());
        s.clear();

        Session reopened = assertDoesNotThrow(() -> new Session(home, "app"), "a cleared model must reopen");
        assertNull(reopened.model());
        assertTrue(reopened.builds().isEmpty());
        assertEquals(0, reopened.requestCount());

        Session.AddResult r = reopened.add(half(), null, "after clear", false);
        assertEquals(1, r.build().id(), "build ids start again from 1");
        assertEquals(1, new Session(home, "app").builds().size());
    }

    @Test
    void aMissingBuildFileKeepsTheBuildsBeforeIt() throws Exception {
        Session s = new Session(home, "app");
        s.add(half(), null, "one", false);
        s.add(raws, null, "two", false);
        s.add(raws, "admin", "three", false);
        Files.delete(s.dir().resolve("builds").resolve("2.json.gz"));

        Session reopened = new Session(home, "app");
        assertEquals(1, reopened.builds().size(), "only the builds before the missing one are kept");
        assertNotNull(reopened.model(), "the working model is rebuilt from the saved requests");
        assertEquals(s.requestCount(), reopened.requestCount());
        assertEquals(2, reopened.add(raws, "other", "next", false).build().id(), "the next build follows the kept ones");
    }

    @Test
    void liveRequestsSurviveAReloadBeforeTheFirstBuild() throws Exception {
        Session s = new Session(home, "live");
        Session.AddResult r = s.add(half(), null, "live capture", false, false);
        assertNull(r.build());
        assertFalse(Files.exists(s.dir().resolve("session.json")), "no build recorded yet");

        Session reopened = new Session(home, "live");
        assertEquals(r.added(), reopened.requestCount(), "requests captured before any build are not lost");
        assertNotNull(reopened.model());
        assertEquals(0, reopened.add(half(), null, "live capture", false, false).added(), "and they still count as seen");
    }

    @Test
    void snapshotRecordsOnlyWhenSomethingIsNew() throws Exception {
        Session s = new Session(home, "live");
        assertNull(s.snapshot("live capture"), "nothing to record in an empty model");
        s.add(half(), null, "live capture", false, false);
        Session.BuildInfo b = s.snapshot("live capture");
        assertNotNull(b);
        assertEquals(1, b.id());
        assertNull(s.snapshot("live capture"), "the same model twice is not a new build");

        Session.AddResult dup = s.add(half(), null, "live capture", false, false);
        assertEquals(0, dup.added());
        assertNull(s.snapshot("live capture"), "duplicates alone are not a new build");
        assertEquals(1, s.builds().size());

        s.add(raws, null, "live capture", false, false);
        assertEquals(2, s.snapshot("live capture").id());
    }

    @Test
    void anUnrecordedLiveTailIsSnapshottedAfterReload() throws Exception {
        Session s = new Session(home, "live");
        s.add(half(), null, "sent", false);
        s.add(raws, null, "live capture", false, false);
        Session reopened = new Session(home, "live");
        assertNotNull(reopened.snapshot("live capture"), "requests newer than the last build still get recorded");
        assertNull(new Session(home, "live").snapshot("live capture"), "and once recorded, a reload has nothing new");
    }

    @Test
    void aDuplicateSendIsStillABuildWithTheSameModel() throws Exception {
        Session s = new Session(home, "app");
        Session.AddResult first = s.add(raws, null, "one", false);
        Session.AddResult again = s.add(raws, null, "again", false);
        assertEquals(0, again.added());
        assertEquals(raws.size() - first.skipped(), again.duplicates());
        assertEquals(2, again.build().id(), "each send is a build");
        assertEquals(first.build().nodes(), again.build().nodes());
        assertEquals(first.build().edges(), again.build().edges());
        assertEquals(0, s.diff(1, 2).get("summary") instanceof java.util.Map<?, ?> m ? count(m) : 0, "and the two builds do not differ");
    }

    private static long count(java.util.Map<?, ?> summary) {
        long n = 0;
        for (Object v : summary.values()) {
            if (v instanceof Number x) {
                n += x.longValue();
            }
        }
        return n;
    }

    @Test
    void buildsCanBeIteratedWhileRequestsAreAdded() throws Exception {
        Session s = new Session(home, "app");
        s.add(half(), null, "one", false);
        Iterator<Session.BuildInfo> it = s.builds().iterator();
        s.add(raws, null, "two", false);
        assertDoesNotThrow(() -> {
            while (it.hasNext()) {
                it.next();
            }
        });
        assertThrows(UnsupportedOperationException.class, () -> s.builds().clear(), "callers cannot change the history");
        assertEquals(2, s.builds().size());
    }

    @Test
    void rolesComeFromTheRequests() throws Exception {
        Session s = new Session(home, "app");
        s.add(half(), "user", "u", false);
        s.add(raws, "admin", "a", false);
        assertEquals(java.util.Set.of("admin", "user"), s.roles());
        s.clear();
        assertTrue(s.roles().isEmpty());
    }
}
