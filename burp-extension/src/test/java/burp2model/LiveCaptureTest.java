package burp2model;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import burp2model.engine.Extract;
import burp2model.engine.Parse;
import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.Test;

class LiveCaptureTest {
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
        assertTrue(Burp2ModelExtension.snapshotDue(40, 0));
        assertFalse(Burp2ModelExtension.snapshotDue(39, 0));
        assertTrue(Burp2ModelExtension.snapshotDue(1, 180_001), "something new and three minutes passed");
        assertFalse(Burp2ModelExtension.snapshotDue(0, 3_600_000), "only duplicates arrived: no build however long it has been");
    }
}
