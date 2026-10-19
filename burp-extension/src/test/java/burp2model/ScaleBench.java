package burp2model;

import burp2model.engine.BurpXml;
import burp2model.engine.Parse;
import burp2model.engine.Redact;
import burp2model.engine.Session;
import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Stream;

/**
 * java -cp ... burp2model.ScaleBench export.xml N [snapshots]: an export replicated to N distinct requests, then
 * live-capture ticks of 5 new requests each, with a snapshot every 8 ticks (40 requests, like live capture).
 * Prints the initial add, a tick, a snapshot, reload, heap and disk use.
 */
public final class ScaleBench {
    private ScaleBench() {}

    public static List<Parse.Raw> replicate(List<Parse.Raw> base, int n, String prefix) {
        List<Parse.Raw> all = new ArrayList<>(n);
        int k = 0;
        while (all.size() < n) {
            for (Parse.Raw r : base) {
                if (all.size() >= n) {
                    break;
                }
                String path = "/" + prefix + k + (r.path().startsWith("/") ? "" : "/") + r.path();
                String req = new String(r.request(), StandardCharsets.ISO_8859_1);
                int sp = req.indexOf(' ');
                int sp2 = sp < 0 ? -1 : req.indexOf(' ', sp + 1);
                if (sp2 > sp) {
                    req = req.substring(0, sp + 1) + path + req.substring(sp2);
                }
                all.add(new Parse.Raw(r.method(), r.host(), r.port(), r.protocol(), path, r.status(), "", req.getBytes(StandardCharsets.ISO_8859_1),
                        r.response(), false));
            }
            k++;
        }
        return all;
    }

    private static long dirBytes(Path d) throws Exception {
        try (Stream<Path> s = Files.walk(d)) {
            return s.filter(Files::isRegularFile).mapToLong(p -> p.toFile().length()).sum();
        }
    }

    private static long heapMb() throws InterruptedException {
        System.gc();
        Thread.sleep(100);
        System.gc();
        Runtime rt = Runtime.getRuntime();
        return (rt.totalMemory() - rt.freeMemory()) / (1024 * 1024);
    }

    public static void main(String[] a) throws Exception {
        Redact.setKey(new byte[32]);
        List<Parse.Raw> base = BurpXml.readRaw(new File(a[0]));
        int n = Integer.parseInt(a[1]);
        int snapshots = a.length > 2 ? Integer.parseInt(a[2]) : 10;
        boolean check = java.util.Arrays.asList(a).contains("--check");
        List<Parse.Raw> all = replicate(base, n, "x");
        Path home = Files.createTempDirectory("b2m-scale");
        Session s = new Session(home, "scale");

        long t = System.nanoTime();
        s.add(all, null, "initial", false);
        System.out.printf("N=%d  initial add+build+save: %d ms, %d nodes%n", n, (System.nanoTime() - t) / 1_000_000, s.model().nodes.size());

        long tickMs = 0;
        long snapMs = 0;
        int ticks = 0;
        for (int i = 0; i < snapshots; i++) {
            for (int j = 0; j < 8; j++) {
                List<Parse.Raw> five = replicate(base.subList(0, Math.min(5, base.size())), 5, "t" + i + "_" + j + "_");
                t = System.nanoTime();
                s.add(five, null, "live capture", false, false);
                tickMs += System.nanoTime() - t;
                ticks++;
            }
            t = System.nanoTime();
            s.snapshot("live capture");
            snapMs += System.nanoTime() - t;
        }
        long tickAvg = tickMs / ticks / 1_000_000;
        long snapAvg = snapMs / snapshots / 1_000_000;
        System.out.printf("  live tick (+5): %d ms avg over %d%n", tickAvg, ticks);
        System.out.printf("  snapshot: %d ms avg over %d%n", snapAvg, snapshots);
        System.out.printf("  heap after gc: %d MB%n", heapMb());
        Path builds = s.dir().resolve("builds");
        System.out.printf("  disk: %d MB total, builds %d MB (%d builds), inputs %d MB%n", dirBytes(s.dir()) >> 20, dirBytes(builds) >> 20,
                s.builds().size(), Files.size(s.dir().resolve("inputs.jsonl.gz")) >> 20);

        t = System.nanoTime();
        Session again = new Session(home, "scale");
        System.out.printf("  reload: %d ms (%d requests)%n", (System.nanoTime() - t) / 1_000_000, again.requestCount());
        t = System.nanoTime();
        again.diff(1, again.builds().size());
        long diffMs = (System.nanoTime() - t) / 1_000_000;
        System.out.printf("  diff first..last after reload: %d ms%n", diffMs);
        if (check) {
            // CI guard: limits several times today's numbers at 5,000 requests, so a slow runner passes and a regression does not
            long buildsKb = dirBytes(builds) >> 10;
            List<String> over = new ArrayList<>();
            if (tickAvg > 300) {
                over.add("live tick " + tickAvg + " ms > 300");
            }
            if (snapAvg > 600) {
                over.add("snapshot " + snapAvg + " ms > 600");
            }
            if (diffMs > 2000) {
                over.add("diff " + diffMs + " ms > 2000");
            }
            if (buildsKb > 6 * 1024) {
                over.add("builds on disk " + buildsKb + " KB > 6 MB (are panes being saved in builds again?)");
            }
            if (!over.isEmpty()) {
                System.out.println("SLOWER THAN ALLOWED: " + String.join("; ", over));
                System.exit(1);
            }
            System.out.println("within limits");
        }
    }
}
