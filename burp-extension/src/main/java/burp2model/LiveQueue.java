package burp2model;

import burp2model.engine.Extract;
import burp2model.engine.Parse;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Proxied requests waiting to join the model. Bounded by count and by bytes, so a burst of large responses
 * cannot use up Burp's memory; what does not fit is counted, never silently lost from view.
 */
final class LiveQueue {
    private final ConcurrentLinkedQueue<Parse.Raw> q = new ConcurrentLinkedQueue<>();
    private final AtomicInteger count = new AtomicInteger();
    private final AtomicLong bytes = new AtomicLong();
    private final AtomicInteger dropped = new AtomicInteger();
    private final int maxCount;
    private final long maxBytes;

    LiveQueue(int maxCount, long maxBytes) {
        this.maxCount = maxCount;
        this.maxBytes = maxBytes;
    }

    private static long size(Parse.Raw r) {
        return (r.request() == null ? 0 : r.request().length) + (r.response() == null ? 0 : r.response().length);
    }

    /** A response beyond what the parser scans is cut there (and marked truncated) before it is queued. */
    static Parse.Raw capped(Parse.Raw r) {
        if (r.response() == null || r.response().length <= Extract.MAX_SCAN_BYTES) {
            return r;
        }
        byte[] cut = java.util.Arrays.copyOf(r.response(), Extract.MAX_SCAN_BYTES);
        return new Parse.Raw(r.method(), r.host(), r.port(), r.protocol(), r.path(), r.status(), r.mime(), r.request(), cut, true);
    }

    /** Queue a request, or count it as dropped when the queue is full. */
    boolean offer(Parse.Raw raw) {
        Parse.Raw r = capped(raw);
        long n = size(r);
        if (count.get() >= maxCount || bytes.get() + n > maxBytes) {
            dropped.incrementAndGet();
            return false;
        }
        count.incrementAndGet();
        bytes.addAndGet(n);
        q.add(r);
        return true;
    }

    /** Take up to max requests; the size is checked before polling, so nothing is taken and then dropped. */
    List<Parse.Raw> drain(int max) {
        List<Parse.Raw> out = new ArrayList<>();
        Parse.Raw r;
        while (out.size() < max && (r = q.poll()) != null) {
            out.add(r);
            count.decrementAndGet();
            bytes.addAndGet(-size(r));
        }
        return out;
    }

    boolean isEmpty() {
        return q.isEmpty();
    }

    int size() {
        return count.get();
    }

    long bytes() {
        return bytes.get();
    }

    /** How many were dropped since the last call. */
    int takeDropped() {
        return dropped.getAndSet(0);
    }

    void clear() {
        drain(Integer.MAX_VALUE);
    }
}
