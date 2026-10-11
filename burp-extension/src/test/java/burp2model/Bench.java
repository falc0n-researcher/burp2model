package burp2model;

import burp2model.engine.BurpXml;
import burp2model.engine.Parse;
import burp2model.engine.Query;
import burp2model.engine.Session;
import java.io.File;
import java.nio.file.Files;
import java.util.List;

/** java -Xmx512m -cp ... burp2model.Bench big.xml: how long the engine takes on a large capture. */
public final class Bench {
    private Bench() {}

    public static void main(String[] a) throws Exception {
        long t0 = System.nanoTime();
        List<Parse.Raw> raws = BurpXml.readRaw(new File(a[0]));
        long t1 = System.nanoTime();
        System.out.printf("read %d items: %d ms%n", raws.size(), (t1 - t0) / 1_000_000);
        Session s = new Session(Files.createTempDirectory("b2m-bench"), "bench");
        long t2 = System.nanoTime();
        Session.AddResult r = s.add(raws, null, "all", false);
        long t3 = System.nanoTime();
        System.out.printf("parse+build+save %d requests: %d ms (nodes %d, edges %d)%n", r.added(), (t3 - t2) / 1_000_000, s.model().nodes.size(), s.model().edges.size());
        long t4 = System.nanoTime();
        s.add(raws.subList(0, 50), null, "again", false);
        System.out.printf("a small add on top: %d ms%n", (System.nanoTime() - t4) / 1_000_000);
        long t5 = System.nanoTime();
        Query q = new Query(s.model());
        q.run("req.method:POST AND resp.code.gte:400");
        System.out.printf("first query (builds the request table): %d ms%n", (System.nanoTime() - t5) / 1_000_000);
        long t6 = System.nanoTime();
        new Session(s.dir().getParent(), "bench");
        System.out.printf("reload from disk: %d ms%n", (System.nanoTime() - t6) / 1_000_000);
        Runtime rt = Runtime.getRuntime();
        System.out.printf("heap in use: %d MB%n", (rt.totalMemory() - rt.freeMemory()) / (1024 * 1024));
    }
}
