package burp2model;

import burp2model.engine.Builder;
import burp2model.engine.BurpXml;
import burp2model.engine.Exchange;
import burp2model.engine.Json;
import burp2model.engine.Model;
import burp2model.engine.Parse;
import java.io.File;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

public final class Bench2 {
    private Bench2() {}

    public static void main(String[] a) throws Exception {
        List<Parse.Raw> raws = BurpXml.readRaw(new File(a[0]));
        Thread main = Thread.currentThread();
        Map<String, Integer> hot = new java.util.concurrent.ConcurrentHashMap<>();
        Thread sampler = new Thread(() -> {
            while (!Thread.interrupted()) {
                for (StackTraceElement f : main.getStackTrace()) {
                    if (f.getClassName().startsWith("burp2model.engine")) {
                        hot.merge(f.getClassName().substring(17) + "." + f.getMethodName() + ":" + f.getLineNumber(), 1, Integer::sum);
                        break;
                    }
                }
                try {
                    Thread.sleep(4);
                } catch (InterruptedException e) {
                    return;
                }
            }
        });
        sampler.setDaemon(true);
        sampler.start();
        long t0 = System.nanoTime();
        List<Exchange> ex = new ArrayList<>();
        int i = 1;
        for (Parse.Raw r : raws) {
            Exchange e = Parse.item(i, r, null, "b", i);
            if (e != null) {
                ex.add(e);
                i++;
            }
        }
        long t1 = System.nanoTime();
        sampler.interrupt();
        hot.entrySet().stream().sorted((x, y) -> y.getValue() - x.getValue()).limit(14).forEach(e -> System.out.println("   " + e.getValue() + "  " + e.getKey()));
        System.out.printf("Parse.item x%d: %d ms%n", ex.size(), (t1 - t0) / 1_000_000);
        Map<String, Object> st = new LinkedHashMap<>();
        hot.clear();
        Thread sampler2 = new Thread(() -> {
            while (!Thread.interrupted()) {
                for (StackTraceElement f : main.getStackTrace()) {
                    if (f.getClassName().startsWith("burp2model.engine")) {
                        hot.merge(f.getClassName().substring(17) + "." + f.getMethodName() + ":" + f.getLineNumber(), 1, Integer::sum);
                        break;
                    }
                }
                try {
                    Thread.sleep(3);
                } catch (InterruptedException e) {
                    return;
                }
            }
        });
        sampler2.setDaemon(true);
        sampler2.start();
        Model m = Builder.build(new ArrayList<>(ex), "x", null, null, st);
        sampler2.interrupt();
        hot.entrySet().stream().sorted((x, y) -> y.getValue() - x.getValue()).limit(10).forEach(e -> System.out.println("   build: " + e.getValue() + "  " + e.getKey()));
        long t2 = System.nanoTime();
        System.out.printf("Builder.build: %d ms%n", (t2 - t1) / 1_000_000);
        StringBuilder sb = new StringBuilder();
        for (Exchange e : ex) {
            sb.append(Json.write(e.toMap())).append('\n');
        }
        long t3 = System.nanoTime();
        System.out.printf("Json.write inputs: %d ms (%d MB)%n", (t3 - t2) / 1_000_000, sb.length() / 1048576);
        String model = Json.write(m.toMap());
        long t4 = System.nanoTime();
        System.out.printf("Json.write model: %d ms (%d MB)%n", (t4 - t3) / 1_000_000, model.length() / 1048576);
        java.io.ByteArrayOutputStream bo = new java.io.ByteArrayOutputStream();
        try (java.util.zip.GZIPOutputStream g = new java.util.zip.GZIPOutputStream(bo)) {
            g.write(sb.toString().getBytes(java.nio.charset.StandardCharsets.UTF_8));
        }
        long t5 = System.nanoTime();
        System.out.printf("gzip inputs: %d ms (%d MB)%n", (t5 - t4) / 1_000_000, bo.size() / 1048576);
    }
}
