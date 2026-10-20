package burp2model;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertSame;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.internal.MontoyaObjectFactory;
import burp.api.montoya.internal.ObjectFactoryLocator;
import burp.api.montoya.ui.UserInterface;
import burp.api.montoya.ui.editor.EditorOptions;
import burp2model.ui.MessageEditors;
import java.awt.Component;
import java.lang.reflect.Proxy;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import javax.swing.JPanel;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

/** The adapter asks Burp for read-only editors and hands them the masked text, as UTF-8 bytes. */
class BurpEditorsTest {
    private final List<Object[]> calls = new ArrayList<>();
    private final Component ui = new JPanel();

    @SuppressWarnings("unchecked")
    private <T> T proxy(Class<T> type, java.util.function.BiFunction<String, Object[], Object> answer) {
        return (T) Proxy.newProxyInstance(type.getClassLoader(), new Class<?>[] {type}, (p, m, a) -> {
            if (m.getDeclaringClass() == Object.class) {
                return m.getName().equals("hashCode") ? System.identityHashCode(p) : m.getName().equals("equals") ? p == a[0] : type.getSimpleName();
            }
            calls.add(new Object[] {type.getSimpleName() + "." + m.getName(), a});
            return answer.apply(m.getName(), a);
        });
    }

    private MontoyaApi api() {
        // Burp's static factories (ByteArray.byteArray, HttpRequest.httpRequest ...) go through this locator
        ObjectFactoryLocator.FACTORY = proxy(MontoyaObjectFactory.class, (name, a) -> switch (name) {
            case "byteArray" -> proxy(ByteArray.class, (n, x) -> n.equals("getBytes") ? a[0] : null);
            case "httpRequest" -> proxy(burp.api.montoya.http.message.requests.HttpRequest.class, (n, x) -> null);
            case "httpResponse" -> proxy(burp.api.montoya.http.message.responses.HttpResponse.class, (n, x) -> null);
            default -> null;
        });
        UserInterface ux = proxy(UserInterface.class, (name, a) -> switch (name) {
            case "createHttpRequestEditor" -> proxy(burp.api.montoya.ui.editor.HttpRequestEditor.class, (n, x) -> n.equals("uiComponent") ? ui : null);
            case "createHttpResponseEditor" -> proxy(burp.api.montoya.ui.editor.HttpResponseEditor.class, (n, x) -> n.equals("uiComponent") ? ui : null);
            default -> null;
        });
        return proxy(MontoyaApi.class, (name, a) -> name.equals("userInterface") ? ux : null);
    }

    @AfterEach
    void forget() {
        ObjectFactoryLocator.FACTORY = null;
    }

    private Object[] last(String call) {
        for (int i = calls.size() - 1; i >= 0; i--) {
            if (calls.get(i)[0].equals(call)) {
                return (Object[]) calls.get(i)[1];
            }
        }
        throw new AssertionError("no call to " + call);
    }

    @Test
    void editorsAreReadOnlyAndShowTheMaskedText() {
        BurpEditors editors = new BurpEditors(api());
        MessageEditors.Editor req = editors.request();
        assertArrayEquals(new Object[] {EditorOptions.READ_ONLY}, (Object[]) last("UserInterface.createHttpRequestEditor")[0]);
        assertSame(ui, req.component());
        String text = "GET /api/users/{id}?token=[REDACTED:token] HTTP/1.1\r\nCookie: sid=[REDACTED:cookie]\r\n\r\nnaïve";
        req.show(text);
        assertArrayEquals(text.getBytes(StandardCharsets.UTF_8), (byte[]) last("MontoyaObjectFactory.byteArray")[0]);
        assertEquals(1, last("HttpRequestEditor.setRequest").length);
        assertEquals(1, last("MontoyaObjectFactory.httpRequest").length, "a request with no target service");

        MessageEditors.Editor resp = editors.response();
        assertArrayEquals(new Object[] {EditorOptions.READ_ONLY}, (Object[]) last("UserInterface.createHttpResponseEditor")[0]);
        resp.show("HTTP/1.1 200 OK\r\n\r\n{}");
        assertArrayEquals("HTTP/1.1 200 OK\r\n\r\n{}".getBytes(StandardCharsets.UTF_8), (byte[]) last("MontoyaObjectFactory.byteArray")[0]);
        assertEquals(1, last("HttpResponseEditor.setResponse").length);

        int before = calls.size();
        req.show("");
        assertEquals(null, last("MontoyaObjectFactory.httpRequest"), "an empty pane is Burp's empty request, not a parse of nothing");
        assertEquals(before + 2, calls.size());
    }
}
