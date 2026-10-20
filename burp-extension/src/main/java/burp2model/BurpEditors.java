package burp2model;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.ui.editor.EditorOptions;
import burp.api.montoya.ui.editor.HttpRequestEditor;
import burp.api.montoya.ui.editor.HttpResponseEditor;
import burp2model.ui.MessageEditors;
import java.awt.Component;
import java.nio.charset.StandardCharsets;

/**
 * Burp's read-only HTTP message editors for the burp2model tab. They are given only the masked text the model
 * stores (a request with no target service), never a captured request, so nothing unmasked can show in them.
 */
final class BurpEditors implements MessageEditors {
    private final MontoyaApi api;

    BurpEditors(MontoyaApi api) {
        this.api = api;
    }

    private static ByteArray bytes(String text) {
        return ByteArray.byteArray(text.getBytes(StandardCharsets.UTF_8));
    }

    @Override
    public Editor request() {
        HttpRequestEditor e = api.userInterface().createHttpRequestEditor(EditorOptions.READ_ONLY);
        return new Editor() {
            @Override
            public Component component() {
                return e.uiComponent();
            }

            @Override
            public void show(String text) {
                e.setRequest(text.isEmpty() ? HttpRequest.httpRequest() : HttpRequest.httpRequest(bytes(text)));
            }
        };
    }

    @Override
    public Editor response() {
        HttpResponseEditor e = api.userInterface().createHttpResponseEditor(EditorOptions.READ_ONLY);
        return new Editor() {
            @Override
            public Component component() {
                return e.uiComponent();
            }

            @Override
            public void show(String text) {
                e.setResponse(text.isEmpty() ? HttpResponse.httpResponse() : HttpResponse.httpResponse(bytes(text)));
            }
        };
    }
}
