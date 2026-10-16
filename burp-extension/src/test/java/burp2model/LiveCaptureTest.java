package burp2model;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import burp2model.engine.BurpXml;
import burp2model.engine.Extract;
import burp2model.engine.Parse;
import burp2model.engine.Redact;
import burp2model.engine.Session;
import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.Test;

class LiveCaptureTest {
    @org.junit.jupiter.api.io.TempDir
    java.nio.file.Path home;

    /** A flush loop with a fake clock, recording what it reports. */
    private final class Rig implements LiveCapture.Out {
        final LiveQueue q = new LiveQueue(5000, Long.MAX_VALUE);
        final long[] now = {1_000_000};
        final List<String> said = new ArrayList<>();
        final List<String> errors = new ArrayList<>();
        int refreshes;
        Session session;
        final LiveCapture cap;

        Rig() throws Exception {
            Redact.setKey(new byte[32]);
            session = new Session(home, "live");
            cap = new LiveCapture(q, () -> session, () -> null, List::of, () -> now[0], this);
        }

        @Override
        public void refresh() {
            refreshes++;
        }

        @Override
        public void say(String text) {
            said.add(text);
        }

        @Override
        public void error(String text) {
            errors.add(text);
        }
    }

    private static List<Parse.Raw> sample() throws Exception {
        return BurpXml.readRaw(new java.io.File(System.getProperty("burp2model.samples", "../samples"), "burp-history-sample.xml"));
    }

    @Test
    void aFlushAddsTheQueueAndSaysSo() throws Exception {
        Rig r = new Rig();
        sample().forEach(r.q::offer);
        r.cap.flush();
        assertTrue(r.session.requestCount() > 0);
        assertEquals(1, r.refreshes);
        assertTrue(r.said.get(0).startsWith("burp2model live: +"), r.said.get(0));
        assertTrue(r.session.builds().isEmpty(), "fewer than 40 new requests and no time passed: no build yet");
        r.cap.flush();
        assertEquals(1, r.refreshes, "an empty queue does nothing");
    }

    @Test
    void aBuildIsRecordedAfterThreeMinutesOnlyIfSomethingNewArrived() throws Exception {
        Rig r = new Rig();
        List<Parse.Raw> raws = sample();
        raws.forEach(r.q::offer);
        r.cap.flush();
        assertTrue(r.session.builds().isEmpty(), "a few new requests: not yet");
        r.now[0] += 181_000;
        raws.forEach(r.q::offer);
        r.cap.flush();
        assertEquals(1, r.session.builds().size(), "three minutes on, the requests not yet in a build get one");
        r.now[0] += 181_000;
        raws.forEach(r.q::offer);                               // duplicates only, three more minutes
        r.cap.flush();
        assertEquals(1, r.session.builds().size(), "duplicates never make a build");
    }

    @Test
    void aFailureIsReportedNotThrown() throws Exception {
        Rig r = new Rig();
        r.session = null;
        r.q.offer(raw(1, 10));
        r.cap.flush();                                          // no model open: nothing happens, nothing thrown
        assertTrue(r.errors.isEmpty());
        LiveCapture broken = new LiveCapture(r.q, () -> {
            throw new IllegalStateException("boom");
        }, () -> null, List::of, () -> 0L, r);
        broken.flush();
        assertTrue(r.errors.get(0).contains("boom"));
    }
    private static Parse.Raw raw(int i, int responseBytes) {
        return new Parse.Raw("GET", "h", 443, "https", "/p" + i, 200, "", ("GET /p" + i + " HTTP/1.1\r\n\r\n").getBytes(), new byte[responseBytes], false);
    }

    @Test
    void drainingAFullBatchLosesNothing() {
        LiveQueue q = new LiveQueue(5000, Long.MAX_VALUE);
        for (int i = 0; i < 1201; i++) {
            assertTrue(q.offer(raw(i, 10)));
        }
        List<String> got = new ArrayList<>();
        while (!q.isEmpty()) {
            List<Parse.Raw> batch = q.drain(500);
            assertTrue(batch.size() <= 500);
            batch.forEach(r -> got.add(r.path()));
        }
        assertEquals(1201, got.size(), "every queued request comes out exactly once");
        for (int i = 0; i < got.size(); i++) {
            assertEquals("/p" + i, got.get(i), "in order");
        }
        assertEquals(0, q.size());
        assertEquals(0, q.bytes());
    }

    @Test
    void theQueueIsBoundedByCountAndBytesAndCountsWhatItDrops() {
        LiveQueue byCount = new LiveQueue(3, Long.MAX_VALUE);
        for (int i = 0; i < 5; i++) {
            byCount.offer(raw(i, 1));
        }
        assertEquals(3, byCount.size());
        assertEquals(2, byCount.takeDropped());
        assertEquals(0, byCount.takeDropped(), "the count resets once read");

        LiveQueue byBytes = new LiveQueue(1000, 10_000);
        int kept = 0;
        for (int i = 0; i < 10; i++) {
            kept += byBytes.offer(raw(i, 3000)) ? 1 : 0;
        }
        assertEquals(3, kept, "three 3 KB responses fit in 10 KB");
        assertTrue(byBytes.bytes() <= 10_000);
        byBytes.drain(1);
        assertTrue(byBytes.offer(raw(99, 3000)), "draining frees room");
    }

    @Test
    void aHugeResponseIsCutToWhatIsScanned() {
        Parse.Raw big = raw(1, Extract.MAX_SCAN_BYTES + 5);
        Parse.Raw cut = LiveQueue.capped(big);
        assertEquals(Extract.MAX_SCAN_BYTES, cut.response().length);
        assertTrue(cut.truncated());
        Parse.Raw small = raw(2, 100);
        assertTrue(LiveQueue.capped(small) == small);
    }

    @Test
    void snapshotsCountNewRequestsNotBatchSize() {
        assertTrue(LiveCapture.snapshotDue(40, 0));
        assertFalse(LiveCapture.snapshotDue(39, 0));
        assertTrue(LiveCapture.snapshotDue(1, 180_001), "something new and three minutes passed");
        assertFalse(LiveCapture.snapshotDue(0, 3_600_000), "only duplicates arrived: no build however long it has been");
    }
}
