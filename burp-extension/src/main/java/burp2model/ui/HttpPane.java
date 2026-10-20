package burp2model.ui;

import burp2model.engine.Json;
import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.FlowLayout;
import java.awt.Font;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import javax.swing.BorderFactory;
import javax.swing.JButton;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTextPane;
import javax.swing.text.BadLocationException;
import javax.swing.text.SimpleAttributeSet;
import javax.swing.text.StyleConstants;
import javax.swing.text.StyledDocument;

/** One HTTP message (request or response), syntax-coloured, with Pretty and Raw views and a copy button. */
final class HttpPane extends JPanel implements MessageView {
    private final JTextPane pane = new JTextPane();
    private final JLabel title = new JLabel();
    private final JLabel meta = new JLabel(" ");
    private final JButton pretty = new JButton("Pretty");
    private final JButton raw = new JButton("Raw");
    private Map<String, Object> message;
    private boolean prettyOn = true;

    HttpPane(String name) {
        super(new BorderLayout());
        title.setText(name);
        title.setFont(Theme.font(12f, Font.BOLD));
        meta.setFont(Theme.font(11f, Font.PLAIN));
        meta.setForeground(Theme.MUTED);
        pane.setEditable(false);
        pane.setFont(Theme.mono(12f));
        pane.setMargin(new java.awt.Insets(8, 10, 8, 10));
        pane.setBackground(Theme.SURFACE);
        JPanel bar = new JPanel(new BorderLayout());
        bar.setBorder(BorderFactory.createEmptyBorder(4, 8, 4, 6));
        JPanel left = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 0));
        left.setOpaque(false);
        left.add(title);
        left.add(meta);
        JPanel right = new JPanel(new FlowLayout(FlowLayout.RIGHT, 4, 0));
        right.setOpaque(false);
        for (JButton b : new JButton[] {pretty, raw}) {
            b.setMargin(new java.awt.Insets(1, 8, 1, 8));
            right.add(b);
        }
        JButton copy = new JButton("Copy");
        copy.setMargin(new java.awt.Insets(1, 8, 1, 8));
        right.add(copy);
        pretty.addActionListener(e -> {
            prettyOn = true;
            render();
        });
        raw.addActionListener(e -> {
            prettyOn = false;
            render();
        });
        copy.addActionListener(e -> Tables.copy(pane.getText()));
        bar.add(left, BorderLayout.WEST);
        bar.add(right, BorderLayout.EAST);
        JScrollPane sp = new JScrollPane(pane);
        sp.setBorder(BorderFactory.createMatteBorder(1, 0, 0, 0, Theme.LINE));
        add(bar, BorderLayout.NORTH);
        add(sp, BorderLayout.CENTER);
        syncButtons();
    }

    @Override
    public javax.swing.JComponent view() {
        return this;
    }

    @Override
    public void clear(String hint) {
        message = null;
        pane.setText(hint == null ? "" : hint);
        meta.setText(" ");
    }

    @Override
    public void show(Map<String, Object> m) {
        message = m;
        render();
    }

    private void syncButtons() {
        pretty.setFont(Theme.font(11f, prettyOn ? Font.BOLD : Font.PLAIN));
        raw.setFont(Theme.font(11f, prettyOn ? Font.PLAIN : Font.BOLD));
    }

    @SuppressWarnings("unchecked")
    private void render() {
        syncButtons();
        if (message == null) {
            return;
        }
        StyledDocument doc = pane.getStyledDocument();
        try {
            doc.remove(0, doc.getLength());
        } catch (BadLocationException ignored) {
            // the document was already empty
        }
        String line = String.valueOf(message.getOrDefault("line", ""));
        List<Object> headers = (List<Object>) message.getOrDefault("headers", List.of());
        String body = String.valueOf(message.getOrDefault("body", ""));
        String contentType = "";
        for (Object h : headers) {
            List<Object> kv = (List<Object>) h;
            if (String.valueOf(kv.get(0)).equalsIgnoreCase("content-type")) {
                contentType = String.valueOf(kv.get(1)).toLowerCase();
            }
        }
        int size = body.length();
        meta.setText(size == 0 ? "no body" : size + " chars" + (Boolean.TRUE.equals(message.get("truncated")) ? " (cut off)" : ""));

        add(doc, line + "\n", firstLineColor(line), true);
        for (Object h : headers) {
            List<Object> kv = (List<Object>) h;
            add(doc, kv.get(0) + ": ", Theme.ACCENT, true);
            addValue(doc, String.valueOf(kv.get(1)) + "\n");
        }
        if (!body.isEmpty()) {
            add(doc, "\n", Theme.fg(), false);
            String shown = body;
            Kind kind = kind(contentType, body);
            if (prettyOn && kind == Kind.JSON) {
                try {
                    shown = Json.pretty(Json.parse(body.strip()));
                } catch (RuntimeException ignored) {
                    shown = body;
                }
            }
            int start = doc.getLength();
            add(doc, shown, Theme.fg(), false);
            colour(doc, start, shown, kind);
            if (Boolean.TRUE.equals(message.get("truncated"))) {
                add(doc, "\n… cut off", Theme.muted(), false);
            }
        }
        pane.setCaretPosition(0);
    }

    private enum Kind { JSON, HTML, JS, TEXT }

    private static Kind kind(String ct, String body) {
        String b = body.stripLeading();
        if (ct.contains("json") || (b.startsWith("{") || b.startsWith("[")) && b.length() > 1 && !ct.contains("html") && !ct.contains("javascript")) {
            return Kind.JSON;
        }
        if (ct.contains("html") || b.startsWith("<")) {
            return Kind.HTML;
        }
        if (ct.contains("javascript") || ct.contains("ecmascript")) {
            return Kind.JS;
        }
        return Kind.TEXT;
    }

    private static Color firstLineColor(String line) {
        Matcher m = Pattern.compile("^HTTP/\\S+\\s+(\\d{3})").matcher(line);
        if (m.find()) {
            return Theme.status(Integer.parseInt(m.group(1)));
        }
        String first = line.split(" ", 2)[0];
        return Theme.method(first);
    }

    private static final Pattern JSON_TOKEN = Pattern.compile("(\"(?:[^\"\\\\\\n]|\\\\.)*\")(\\s*:)?|\\b(true|false|null)\\b|-?\\b\\d+(?:\\.\\d+)?\\b");
    private static final Pattern HTML_TAG = Pattern.compile("</?[A-Za-z][^<>]{0,300}>|<!--.*?-->|<!doctype[^>]*>", Pattern.DOTALL | Pattern.CASE_INSENSITIVE);
    private static final Pattern JS_TOKEN = Pattern.compile("(\"(?:[^\"\\\\\\n]|\\\\.){0,300}\"|'(?:[^'\\\\\\n]|\\\\.){0,300}')|\\b(function|return|var|let|const|if|else|for|while|new|this|typeof|null|true|false|async|await|import|export)\\b|//[^\\n]*");
    private static final Pattern MASK = Pattern.compile("\\[REDACTED[^\\]]*\\]|\\{(?:id|uuid|hash|token|jwt|email|code|param|slug|value)\\}");

    private static void colour(StyledDocument doc, int offset, String text, Kind kind) {
        if (text.length() > 120_000) {
            return;
        }
        Color key = Theme.dark() ? new Color(0x82, 0xAA, 0xFF) : new Color(0x1F, 0x5F, 0xBF);
        Color str = Theme.dark() ? new Color(0xA5, 0xD6, 0x8B) : new Color(0x2E, 0x7D, 0x32);
        Color num = Theme.dark() ? new Color(0xF2, 0xA6, 0x5A) : new Color(0xB4, 0x5F, 0x06);
        Color kw = Theme.dark() ? new Color(0xC7, 0x92, 0xEA) : new Color(0x7B, 0x3F, 0xC4);
        if (kind == Kind.JSON) {
            Matcher m = JSON_TOKEN.matcher(text);
            while (m.find()) {
                Color c = m.group(1) != null ? (m.group(2) != null ? key : str) : m.group(3) != null ? kw : num;
                int end = m.group(1) != null && m.group(2) != null ? m.start(1) + m.group(1).length() : m.end();
                style(doc, offset + m.start(), end - m.start(), c, false);
            }
        } else if (kind == Kind.HTML) {
            Matcher m = HTML_TAG.matcher(text);
            while (m.find()) {
                style(doc, offset + m.start(), m.end() - m.start(), m.group().startsWith("<!--") ? Theme.muted() : key, false);
            }
        } else if (kind == Kind.JS) {
            Matcher m = JS_TOKEN.matcher(text);
            while (m.find()) {
                Color c = m.group(1) != null ? str : m.group(2) != null ? kw : Theme.muted();
                style(doc, offset + m.start(), m.end() - m.start(), c, false);
            }
        }
        Matcher mk = MASK.matcher(text);
        while (mk.find()) {
            style(doc, offset + mk.start(), mk.end() - mk.start(), Theme.ACCENT, true);
        }
    }

    private static void style(StyledDocument doc, int from, int len, Color c, boolean bold) {
        SimpleAttributeSet a = new SimpleAttributeSet();
        StyleConstants.setForeground(a, c);
        StyleConstants.setBold(a, bold);
        doc.setCharacterAttributes(from, len, a, false);
    }

    private static void add(StyledDocument doc, String text, Color c, boolean bold) {
        SimpleAttributeSet a = new SimpleAttributeSet();
        StyleConstants.setForeground(a, c);
        StyleConstants.setBold(a, bold);
        try {
            doc.insertString(doc.getLength(), text, a);
        } catch (BadLocationException ignored) {
            // appending at the end cannot fail
        }
    }

    private static void addValue(StyledDocument doc, String text) {
        int start = doc.getLength();
        add(doc, text, Theme.fg(), false);
        Matcher mk = MASK.matcher(text);
        while (mk.find()) {
            style(doc, start + mk.start(), mk.end() - mk.start(), Theme.ACCENT, true);
        }
    }
}
