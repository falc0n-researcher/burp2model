package burp2model;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.proxy.Proxy;
import burp.api.montoya.proxy.ProxyHttpRequestResponse;
import burp.api.montoya.sitemap.SiteMap;
import burp2model.engine.BurpXml;
import burp2model.engine.Parse;
import burp2model.engine.Redact;
import burp2model.engine.Session;
import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/** After a restart the raw bytes are gone; the request is found again in Burp's history, and only the very same one. */
class BurpHistoryTest {
    static final String SECRET = "s3cr3tSESSIONv4lue123456";

    @TempDir
    Path home;

    @SuppressWarnings("unchecked")
    private static <T> T proxy(Class<T> type, java.util.function.BiFunction<String, Object[], Object> answer) {
        return (T) java.lang.reflect.Proxy.newProxyInstance(type.getClassLoader(), new Class<?>[] {type}, (p, m, a) -> {
            if (m.getDeclaringClass() == Object.class) {
                return m.getName().equals("hashCode") ? System.identityHashCode(p) : m.getName().equals("equals") ? p == a[0] : type.getSimpleName();
            }
            return answer.apply(m.getName(), a);
        });
    }

    private static ByteArray bytes(byte[] b) {
        return proxy(ByteArray.class, (n, a) -> n.equals("getBytes") ? b : null);
    }

    /** Burp's view of one captured request and response. */
    private static ProxyHttpRequestResponse item(Parse.Raw r) {
        HttpService svc = proxy(HttpService.class, (n, a) -> switch (n) {
            case "host" -> r.host();
            case "port" -> r.port();
            case "secure" -> "https".equals(r.protocol());
            default -> null;
        });
        HttpRequest rq = proxy(HttpRequest.class, (n, a) -> switch (n) {
            case "method" -> r.method();
            case "path" -> r.path();
            case "httpService" -> svc;
            case "toByteArray" -> bytes(r.request());
            default -> null;
        });
        HttpResponse rs = proxy(HttpResponse.class, (n, a) -> switch (n) {
            case "statusCode" -> (short) (r.status() == null ? 0 : r.status());
            case "toByteArray" -> bytes(r.response());
            default -> null;
        });
        return proxy(ProxyHttpRequestResponse.class, (n, a) -> switch (n) {
            case "method" -> r.method();
            case "host" -> r.host();
            case "path" -> r.path();
            case "finalRequest", "request" -> rq;
            case "originalResponse", "response" -> rs;
            default -> null;
        });
    }

    private static MontoyaApi burp(List<ProxyHttpRequestResponse> history) {
        Proxy px = proxy(Proxy.class, (n, a) -> n.equals("history") ? history : null);
        SiteMap sm = proxy(SiteMap.class, (n, a) -> n.equals("requestResponses") ? List.of() : null);
        return proxy(MontoyaApi.class, (n, a) -> n.equals("proxy") ? px : n.equals("siteMap") ? sm : null);
    }

    @Test
    void theSavedRequestIsFoundAndALookAlikeIsNot() throws Exception {
        Redact.setKey(new byte[32]);
        List<Parse.Raw> raws = BurpXml.readRaw(new File(System.getProperty("burp2model.samples", "../samples"), "burp-history-sample.xml"));
        Parse.Raw real = null;
        for (Parse.Raw r : raws) {
            if (new String(r.request(), StandardCharsets.ISO_8859_1).contains(SECRET)) {
                real = r;
                break;
            }
        }
        assertNotNull(real);
        Session first = new Session(home, "app");
        first.add(raws, null, "one", false);
        first.close();
        Session s = new Session(home, "app");                    // a restart: nothing raw in memory
        int id = -1;
        for (int i = 1; i <= s.requestCount() && id < 0; i++) {
            if (s.isSaved(i, real)) {
                id = i;
            }
        }
        assertNull(s.raw(id));

        // the same request with another session cookie masks to the same stored copy, but it is not the saved one
        String other = new String(real.request(), StandardCharsets.ISO_8859_1).replace(SECRET, "0therSESSIONv4lue999999");
        Parse.Raw lookAlike = new Parse.Raw(real.method(), real.host(), real.port(), real.protocol(), real.path(), real.status(), real.mime(),
                other.getBytes(StandardCharsets.ISO_8859_1), real.response(), false);
        List<ProxyHttpRequestResponse> history = new ArrayList<>();
        history.add(item(lookAlike));
        assertNull(new BurpHistory(burp(history)).find(s, id), "a look-alike is never shown in its place");

        history.add(item(real));
        byte[][] got = new BurpHistory(burp(history)).find(s, id);
        assertNotNull(got);
        assertArrayEquals(real.request(), got[0]);
        assertArrayEquals(real.response(), got[1]);
    }
}
