package burp2model.ui;

import burp2model.ScaleBench;
import burp2model.engine.BurpXml;
import burp2model.engine.Parse;
import burp2model.engine.Redact;
import burp2model.engine.Session;
import java.io.File;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.concurrent.atomic.AtomicLong;
import javax.swing.JTabbedPane;
import javax.swing.SwingUtilities;

/**
 * java -Djava.awt.headless=true -cp ... burp2model.ui.EdtBench export.xml N: the tab on a model of N requests,
 * with a watchdog measuring the longest time the Swing thread could not answer while it opens the model,
 * shows every tab, runs a body regex query and compares builds.
 */
public final class EdtBench {
    private EdtBench() {}

    /** Posts a probe to the Swing thread every 5 ms and keeps the longest wait. */
    static final class Watchdog extends Thread {
        final AtomicLong worst = new AtomicLong();
        volatile boolean on = true;

        Watchdog() {
            setDaemon(true);
        }

        @Override
        public void run() {
            while (on) {
                long sent = System.nanoTime();
                try {
                    SwingUtilities.invokeAndWait(() -> { });
                } catch (Exception e) {
                    return;
                }
                worst.accumulateAndGet((System.nanoTime() - sent) / 1_000_000, Math::max);
                try {
                    Thread.sleep(5);
                } catch (InterruptedException e) {
                    return;
                }
            }
        }

        long take() {
            return worst.getAndSet(0);
        }
    }

    public static void main(String[] a) throws Exception {
        Redact.setKey(new byte[32]);
        List<Parse.Raw> base = BurpXml.readRaw(new File(a[0]));
        int n = Integer.parseInt(a[1]);
        boolean check = java.util.Arrays.asList(a).contains("--check");
        java.util.List<String> over = new java.util.ArrayList<>();
        Path home = Files.createTempDirectory("b2m-edt");
        Session seed = new Session(home, "edt");
        seed.add(ScaleBench.replicate(base, n, "x"), null, "one", false);
        seed.add(base, "admin", "two", false);

        Watchdog w = new Watchdog();
        w.start();
        MainPanel[] panel = new MainPanel[1];
        SwingUtilities.invokeAndWait(() -> panel[0] = new MainPanel(new MainPanel.Host() {
            public String get(String k, String d) {
                return k.equals("app") ? "edt" : d;
            }

            public void set(String k, String v) {
            }

            public void log(String l) {
            }

            public Session session(String name) throws java.io.IOException {
                return new Session(home, name);
            }
        }));
        panel[0].setSize(1300, 820);
        panel[0].awaitSession(60_000);
        Thread.sleep(500);
        System.out.printf("open the model: worst Swing stall %d ms%n", w.take());

        var tf = MainPanel.class.getDeclaredField("tabs");
        tf.setAccessible(true);
        JTabbedPane tabs = (JTabbedPane) tf.get(panel[0]);
        for (int t = 0; t < tabs.getTabCount(); t++) {
            int i = t;
            SwingUtilities.invokeAndWait(() -> tabs.setSelectedIndex(i));
            Thread.sleep(400);
            long stall = w.take();
            System.out.printf("show %-10s worst Swing stall %d ms%n", tabs.getTitleAt(i), stall);
            if (stall > 500) {
                over.add(tabs.getTitleAt(i) + " " + stall + " ms");
            }
        }
        SwingUtilities.invokeAndWait(() -> panel[0].ask("resp.body.regex:\"pass(word)?\""));
        Thread.sleep(1500);
        long q1 = w.take();
        System.out.printf("body regex query: worst Swing stall %d ms%n", q1);
        if (q1 > 500) {
            over.add("body regex query " + q1 + " ms");
        }
        SwingUtilities.invokeAndWait(() -> panel[0].ask("changed-since 1"));
        Thread.sleep(1500);
        System.out.printf("changed-since query: worst Swing stall %d ms%n", w.take());
        w.on = false;
        if (check) {
            // CI guard: nothing the user does may hold Burp's Swing thread for half a second (building the tab once is exempt)
            if (!over.isEmpty()) {
                System.out.println("SWING THREAD BLOCKED: " + String.join("; ", over));
                System.exit(1);
            }
            System.out.println("within limits");
        }
        System.exit(0);
    }
}
