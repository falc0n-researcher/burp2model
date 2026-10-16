package burp2model;

import burp2model.engine.Parse;
import burp2model.engine.Session;
import java.util.List;
import java.util.function.LongSupplier;
import java.util.function.Supplier;

/**
 * What live capture does every few seconds: add what the queue holds to the open model, keep a few samples of each
 * shape, record a build now and then, and say what happened. Burp-free (the queue, model, settings, clock and the
 * ways to report are passed in), so it is tested on its own.
 */
final class LiveCapture {
    /** Live capture keeps this many requests of any one shape (method, host, path template, query names, status). */
    static final int SAMPLES_PER_SHAPE = 10;
    /** At most this many requests are added per flush; the rest wait for the next one. */
    static final int BATCH = 500;

    /** Where a flush reports: the tab's refresh and status line, and Burp's error log. */
    interface Out {
        void refresh();

        void say(String text);

        void error(String text);
    }

    private final LiveQueue queue;
    private final Supplier<Session> session;
    private final Supplier<String> role;
    private final Supplier<List<String>> scope;
    private final LongSupplier clock;
    private final Out out;
    private int sinceSnapshot;
    private long lastSnapshot;
    private int cappedSinceSay;

    LiveCapture(LiveQueue queue, Supplier<Session> session, Supplier<String> role, Supplier<List<String>> scope, LongSupplier clock, Out out) {
        this.queue = queue;
        this.session = session;
        this.role = role;
        this.scope = scope;
        this.clock = clock;
        this.out = out;
        this.lastSnapshot = clock.getAsLong();
    }

    /** Live capture records a build every 40 new requests, or after three minutes once anything new arrived; duplicates never count. */
    static boolean snapshotDue(int newSinceLast, long msSinceLast) {
        return newSinceLast >= 40 || (newSinceLast > 0 && msSinceLast > 180_000);
    }

    /** One flush. Never throws: a failure is reported and the next flush tries again. */
    void flush() {
        try {
            Session s = session.get();
            if (s == null || queue.isEmpty()) {
                return;
            }
            List<Parse.Raw> raws = queue.drain(BATCH);
            s.scope = scope.get();
            Session.AddResult res = s.add(raws, role.get(), "live capture", false, false, SAMPLES_PER_SHAPE);
            cappedSinceSay += res.capped();
            int dropped = queue.takeDropped();
            if (dropped > 0) {
                out.error("burp2model live capture: the queue was full, " + dropped + " requests were not captured");
            }
            sinceSnapshot += res.added();
            if (snapshotDue(sinceSnapshot, clock.getAsLong() - lastSnapshot)) {
                s.snapshot("live capture");
                sinceSnapshot = 0;
                lastSnapshot = clock.getAsLong();
            }
            if (res.added() > 0 || dropped > 0) {
                out.refresh();
                out.say("burp2model live: +" + res.added() + " requests · " + s.requestCount() + " in the model"
                        + (cappedSinceSay > 0 ? " · " + cappedSinceSay + " repeats of known shapes skipped" : "")
                        + (dropped > 0 ? " · " + dropped + " not captured (queue full)" : ""));
                cappedSinceSay = 0;
            }
        } catch (Throwable t) {
            out.error("burp2model live capture: " + t);
        }
    }
}
