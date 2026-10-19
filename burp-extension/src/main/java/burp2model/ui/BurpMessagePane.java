package burp2model.ui;

import java.awt.BorderLayout;
import java.awt.CardLayout;
import java.awt.FlowLayout;
import java.awt.Font;
import java.util.List;
import java.util.Map;
import javax.swing.BorderFactory;
import javax.swing.JComponent;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.SwingConstants;

/**
 * One request or response in Burp's own message editor (Pretty, Raw, Hex, Inspector, search). The editor is only
 * ever given text rebuilt from the masked panes, so what it shows is exactly what burp2model stores: masked values
 * stay masked, and nothing of the original request reaches it.
 */
final class BurpMessagePane extends JPanel implements MessageView {
    private static final long serialVersionUID = 1L;
    private final transient MessageEditors.Editor editor;
    private final JLabel meta = new JLabel(" ");
    private final JLabel hint = new JLabel(" ", SwingConstants.CENTER);
    private final CardLayout cards = new CardLayout();
    private final JPanel body = new JPanel(cards);
    private String shown;

    BurpMessagePane(String name, MessageEditors.Editor editor) {
        super(new BorderLayout());
        this.editor = editor;
        JLabel title = new JLabel(name);
        title.setFont(Theme.font(12f, Font.BOLD));
        meta.setFont(Theme.font(11f, Font.PLAIN));
        meta.setForeground(Theme.MUTED);
        JPanel bar = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 0));
        bar.setBorder(BorderFactory.createEmptyBorder(4, 8, 4, 6));
        bar.add(title);
        bar.add(meta);
        hint.setForeground(Theme.MUTED);
        hint.setFont(Theme.font(12f, Font.PLAIN));
        body.add(hint, "hint");
        body.add(editor.component(), "editor");
        add(bar, BorderLayout.NORTH);
        add(body, BorderLayout.CENTER);
    }

    @Override
    public JComponent view() {
        return this;
    }

    @Override
    public void clear(String text) {
        shown = null;
        editor.show("");
        meta.setText(" ");
        hint.setText(text == null || text.isEmpty() ? " " : text);
        cards.show(body, "hint");
    }

    @Override
    public void show(Map<String, Object> message) {
        if (message == null) {
            clear("");
            return;
        }
        String body0 = String.valueOf(message.getOrDefault("body", ""));
        boolean cut = Boolean.TRUE.equals(message.get("truncated"));
        meta.setText(body0.isEmpty() ? "no body" : body0.length() + " chars" + (cut ? " (cut off: the stored body ends early)" : ""));
        shown = text(message);
        editor.show(shown);
        cards.show(body, "editor");
    }

    /** The text last given to the editor (for tests). */
    String shownText() {
        return shown;
    }

    /** The masked message as HTTP text: its first line, its headers, a blank line and its body. */
    @SuppressWarnings("unchecked")
    static String text(Map<String, Object> message) {
        StringBuilder sb = new StringBuilder();
        sb.append(message.getOrDefault("line", "")).append("\r\n");
        for (Object h : (List<Object>) message.getOrDefault("headers", List.of())) {
            List<Object> kv = (List<Object>) h;
            sb.append(kv.get(0)).append(": ").append(kv.get(1)).append("\r\n");
        }
        sb.append("\r\n").append(message.getOrDefault("body", ""));
        return sb.toString();
    }
}
