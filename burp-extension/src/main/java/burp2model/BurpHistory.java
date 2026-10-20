package burp2model;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.proxy.ProxyHttpRequestResponse;
import burp2model.engine.Exchange;
import burp2model.engine.Model;
import burp2model.engine.Parse;
import burp2model.engine.Redact;
import burp2model.engine.Session;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Finds a model's request in Burp's own Proxy history and site map, so the viewer can show it as Burp captured it
 * (real cookies and tokens). A candidate counts only if masking it gives exactly the copy the model stores, so the
 * viewer never shows a different request. What it finds is shown, never saved.
 */
final class BurpHistory {
    private final MontoyaApi api;
    /** Recent answers, by the stored copy's bytes: the same request is not searched for twice. */
    private final Map<String, byte[][]> found = new LinkedHashMap<>(64, 0.75f, true) {
        private static final long serialVersionUID = 1L;

        @Override
        protected boolean removeEldestEntry(Map.Entry<String, byte[][]> e) {
            return size() > 200;
        }
    };

    BurpHistory(MontoyaApi api) {
        this.api = api;
    }

    byte[][] find(Session s, int id) {
        if (s == null) {
            return null;
        }
        byte[][] kept = s.raw(id);
        if (kept != null) {
            return kept;
        }
        Model m = s.model();
        int i = m == null ? -1 : m.evidenceLog.indexOfId(id);
        if (i < 0) {
            return null;
        }
        String key = java.util.Base64.getEncoder().encodeToString(m.evidenceLog.packed(i));
        synchronized (found) {
            if (found.containsKey(key)) {
                return found.get(key);
            }
        }
        Map<String, Object> want = m.evidenceLog.get(i);
        Map<String, Object> meta = m.evidenceLog.meta(i);
        String method = String.valueOf(meta.get("method"));
        String host = String.valueOf(meta.get("host"));
        String path = m.evidenceLog.path(i);
        String role = (String) meta.get("role");
        byte[][] hit = null;
        for (ProxyHttpRequestResponse p : api.proxy().history()) {
            HttpRequest fr = p.finalRequest();
            if (fr != null && method.equals(fr.method()) && host.equalsIgnoreCase(fr.httpService().host()) && path.equals(Redact.redactPath(fr.path()).value())) {
                hit = same(s, id, p.finalRequest(), p.originalResponse(), role, want);
                if (hit == null) {
                    hit = same(s, id, p.request(), p.response(), role, want);
                }
                if (hit != null) {
                    break;
                }
            }
        }
        if (hit == null) {
            for (HttpRequestResponse rr : api.siteMap().requestResponses()) {
                HttpRequest rq = rr.request();
                if (rq != null && method.equals(rq.method()) && host.equalsIgnoreCase(rq.httpService().host())
                        && path.equals(Redact.redactPath(rq.path()).value())) {
                    hit = same(s, id, rq, rr.hasResponse() ? rr.response() : null, role, want);
                    if (hit != null) {
                        break;
                    }
                }
            }
        }
        synchronized (found) {
            found.put(key, hit);
        }
        return hit;
    }

    /**
     * The raw pair when it is the saved request itself: the same raw bytes (by the model's key) and, masked, exactly
     * the stored copy `want`. Two requests that differ only in a cookie mask alike; the key tells them apart.
     */
    private static byte[][] same(Session s, int id, HttpRequest rq, HttpResponse rs, String role, Map<String, Object> want) {
        if (rq == null) {
            return null;
        }
        byte[] req = rq.toByteArray().getBytes();
        byte[] resp = rs == null ? new byte[0] : rs.toByteArray().getBytes();
        Parse.Raw raw = new Parse.Raw(rq.method(), rq.httpService().host(), rq.httpService().port(),
                rq.httpService().secure() ? "https" : "http", rq.path(), rs == null ? null : (int) rs.statusCode(), "", req, resp, false);
        if (!s.isSaved(id, raw)) {
            return null;
        }
        Exchange ex = Parse.item(0, raw, role, "", 0);
        if (ex == null) {
            return null;
        }
        Map<String, Object> got = ex.ev();
        return java.util.Objects.equals(got.get("request"), want.get("request")) && java.util.Objects.equals(got.get("response"), want.get("response"))
                ? new byte[][] {req, resp} : null;
    }
}
