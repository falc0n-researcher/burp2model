package burp2model;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ConcurrentLinkedQueue;
import org.junit.jupiter.api.Test;

class LiveCaptureTest {
    @Test
    void drainingAFullBatchLosesNothing() {
        ConcurrentLinkedQueue<Integer> q = new ConcurrentLinkedQueue<>();
        for (int i = 0; i < 1201; i++) {
            q.add(i);
        }
        List<Integer> got = new ArrayList<>();
        while (!q.isEmpty()) {
            List<Integer> batch = Burp2ModelExtension.drain(q, 500);
            assertTrue(batch.size() <= 500);
            got.addAll(batch);
        }
        assertEquals(1201, got.size(), "every queued request comes out exactly once");
        for (int i = 0; i < got.size(); i++) {
            assertEquals(i, got.get(i), "in order");
        }
    }

    @Test
    void drainingFewerThanABatch() {
        ConcurrentLinkedQueue<Integer> q = new ConcurrentLinkedQueue<>(List.of(1, 2, 3));
        assertEquals(List.of(1, 2, 3), Burp2ModelExtension.drain(q, 500));
        assertTrue(q.isEmpty());
        assertTrue(Burp2ModelExtension.drain(q, 500).isEmpty());
    }

    @Test
    void snapshotsCountNewRequestsNotBatchSize() {
        assertTrue(Burp2ModelExtension.snapshotDue(40, 0));
        assertFalse(Burp2ModelExtension.snapshotDue(39, 0));
        assertTrue(Burp2ModelExtension.snapshotDue(1, 180_001), "something new and three minutes passed");
        assertFalse(Burp2ModelExtension.snapshotDue(0, 3_600_000), "only duplicates arrived: no build however long it has been");
    }
}
