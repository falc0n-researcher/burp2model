package burp2model;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.persistence.Preferences;
import burp.api.montoya.ui.contextmenu.ContextMenuEvent;
import burp.api.montoya.ui.contextmenu.ContextMenuItemsProvider;

import javax.swing.JButton;
import javax.swing.JLabel;
import javax.swing.JMenuItem;
import javax.swing.JPanel;
import javax.swing.JPasswordField;
import javax.swing.JTextField;
import java.awt.Component;
import java.awt.Desktop;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest.BodyPublishers;
import java.net.http.HttpResponse.BodyHandlers;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * A thin bridge: right-click requests in Burp, "Send to burp2model", and the selection goes to a local
 * `burp2model serve` process, which builds the model. No modeling happens here.
 */
public class Burp2ModelExtension implements BurpExtension, ContextMenuItemsProvider {
    private MontoyaApi api;
    private Preferences prefs;
    private final HttpClient http = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(5)).build();

    @Override
    public void initialize(MontoyaApi api) {
        this.api = api;
        this.prefs = api.persistence().preferences();
        api.extension().setName("burp2model");
        api.userInterface().registerContextMenuItemsProvider(this);
        api.userInterface().registerSuiteTab("burp2model", settingsPanel());
        api.logging().logToOutput("burp2model ready. Start `burp2model serve -w NAME`, then set the token in the burp2model tab.");
    }

    // ------------------------------------------------------------------ menu

    @Override
    public List<Component> provideMenuItems(ContextMenuEvent event) {
        List<HttpRequestResponse> picked = new ArrayList<>(event.selectedRequestResponses());
        if (picked.isEmpty()) {
            event.messageEditorRequestResponse().ifPresent(m -> picked.add(m.requestResponse()));
        }
        if (picked.isEmpty()) {
            return List.of();
        }
        JMenuItem item = new JMenuItem("Send " + picked.size() + " to burp2model");
        item.addActionListener(e -> new Thread(() -> send(picked), "burp2model-send").start());
        return List.of(item);
    }

    private void send(List<HttpRequestResponse> picked) {
        String token = prefs.getString("token");
        if (token == null || token.isBlank()) {
            api.logging().raiseErrorEvent("burp2model: set the token in the burp2model tab first.");
            return;
        }
        String port = orDefault(prefs.getString("port"), "8765");
        String role = orDefault(prefs.getString("role"), "");
        StringBuilder query = new StringBuilder("?label=").append(enc("burp-" + System.currentTimeMillis() / 1000));
        if (!role.isBlank()) {
            query.append("&role=").append(enc(role));
        }
        try {
            java.net.http.HttpRequest req = java.net.http.HttpRequest
                    .newBuilder(URI.create("http://127.0.0.1:" + port + "/ingest" + query))
                    .timeout(Duration.ofMinutes(10))
                    .header("X-B2M-Token", token)
                    .POST(BodyPublishers.ofString(toItemsXml(picked), StandardCharsets.UTF_8))
                    .build();
            java.net.http.HttpResponse<String> res = http.send(req, BodyHandlers.ofString());
            if (res.statusCode() == 200) {
                String url = field(res.body(), "report_url");
                api.logging().logToOutput("burp2model: built a model from " + picked.size() + " request(s). " + url);
                open(url);
            } else {
                api.logging().raiseErrorEvent("burp2model: " + res.statusCode() + " " + res.body());
            }
        } catch (Exception ex) {
            api.logging().raiseErrorEvent("burp2model: could not reach 127.0.0.1:" + port
                    + ". Is `burp2model serve` running? (" + ex.getMessage() + ")");
        }
    }

    // ------------------------------------------------------- Burp "Save items" XML

    static String toItemsXml(List<HttpRequestResponse> picked) {
        StringBuilder x = new StringBuilder("<?xml version=\"1.0\"?>\n<items>\n");
        for (HttpRequestResponse rr : picked) {
            HttpRequest rq = rr.request();
            HttpResponse rs = rr.hasResponse() ? rr.response() : null;
            x.append("<item>")
                    .append("<url>").append(esc(rq.url())).append("</url>")
                    .append("<host>").append(esc(rq.httpService().host())).append("</host>")
                    .append("<port>").append(rq.httpService().port()).append("</port>")
                    .append("<protocol>").append(rq.httpService().secure() ? "https" : "http").append("</protocol>")
                    .append("<method>").append(esc(rq.method())).append("</method>")
                    .append("<path>").append(esc(rq.path())).append("</path>");
            if (rs != null) {
                x.append("<status>").append(rs.statusCode()).append("</status>");
            }
            x.append("<request base64=\"true\">").append(b64(rq.toByteArray().getBytes())).append("</request>");
            if (rs != null) {
                x.append("<response base64=\"true\">").append(b64(rs.toByteArray().getBytes())).append("</response>");
            }
            x.append("</item>\n");
        }
        return x.append("</items>\n").toString();
    }

    private static String b64(byte[] b) {
        return Base64.getEncoder().encodeToString(b);
    }

    private static String esc(String s) {
        return s == null ? "" : s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;");
    }

    private static String enc(String s) {
        return URLEncoder.encode(s, StandardCharsets.UTF_8);
    }

    private static String orDefault(String s, String d) {
        return s == null || s.isBlank() ? d : s;
    }

    private static String field(String json, String key) {
        Matcher m = Pattern.compile("\"" + key + "\"\\s*:\\s*\"([^\"]*)\"").matcher(json);
        return m.find() ? m.group(1) : "";
    }

    private void open(String url) {
        try {
            if (!url.isBlank() && Desktop.isDesktopSupported()) {
                Desktop.getDesktop().browse(URI.create(url));
            }
        } catch (Exception ignored) {
            // the path is in the Output tab either way
        }
    }

    // -------------------------------------------------------------- settings tab

    private Component settingsPanel() {
        JPanel p = new JPanel(new GridBagLayout());
        JTextField port = new JTextField(orDefault(prefs.getString("port"), "8765"), 8);
        JPasswordField token = new JPasswordField(orDefault(prefs.getString("token"), ""), 30);
        JTextField role = new JTextField(orDefault(prefs.getString("role"), ""), 14);
        JButton save = new JButton("Save");
        save.addActionListener(e -> {
            prefs.setString("port", port.getText().trim());
            prefs.setString("token", new String(token.getPassword()).trim());
            prefs.setString("role", role.getText().trim());
            api.logging().logToOutput("burp2model: settings saved.");
        });
        GridBagConstraints c = new GridBagConstraints();
        c.insets = new Insets(6, 8, 6, 8);
        c.anchor = GridBagConstraints.WEST;
        String[] names = {"Port", "Token (printed by `burp2model serve`)", "Role (optional, e.g. admin)"};
        Component[] fields = {port, token, role};
        for (int i = 0; i < names.length; i++) {
            c.gridx = 0;
            c.gridy = i;
            p.add(new JLabel(names[i]), c);
            c.gridx = 1;
            p.add(fields[i], c);
        }
        c.gridx = 1;
        c.gridy = names.length;
        p.add(save, c);
        JPanel outer = new JPanel(new java.awt.BorderLayout());
        outer.add(p, java.awt.BorderLayout.NORTH);
        return outer;
    }
}
