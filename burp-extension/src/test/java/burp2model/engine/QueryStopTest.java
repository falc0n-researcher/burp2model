package burp2model.engine;

import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTimeoutPreemptively;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.time.Duration;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class QueryStopTest {
    @TempDir
    Path home;

    /** A response whose body makes (.*a){8}b backtrack for minutes: a long run of 'a' with no 'b' (Java memoizes the simpler (a+)+b). */
    private Model model() throws Exception {
        Redact.setKey(new byte[32]);
        String body = "<html>" + "a".repeat(60) + "!</html>";
        String resp = "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n" + body;
        String req = "GET / HTTP/1.1\r\nHost: shop.example.com\r\n\r\n";
        Parse.Raw r = new Parse.Raw("GET", "shop.example.com", 443, "https", "/", 200, "", req.getBytes(StandardCharsets.ISO_8859_1),
                resp.getBytes(StandardCharsets.ISO_8859_1), false);
        Session s = new Session(home, "q");
        s.add(List.of(r), null, "one", false);
        return s.model();
    }

    @Test
    void aRunawayRegexStopsWhenAsked() throws Exception {
        Query q = new Query(model());
        long deadline = System.currentTimeMillis() + 300;
        q.stop = () -> System.currentTimeMillis() > deadline;
        assertTimeoutPreemptively(Duration.ofSeconds(10), () -> {
            assertThrows(Query.Stopped.class, () -> q.run("resp.body.regex:\"(.*a){8}b\""));
        }, "the query must give up soon after stop says so, not run for minutes");
    }

    @Test
    void anOrdinaryQueryIsUnaffected() throws Exception {
        Query q = new Query(model());
        q.stop = () -> false;
        assertTrue(q.run("resp.body.regex:\"a{10}\"").total() >= 1);
        assertTrue(q.run("resp.body.regex:\"(.*a){2}!\"").total() >= 1);
    }
}
