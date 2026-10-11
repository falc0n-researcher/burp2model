package burp2model.ui;

import java.awt.BorderLayout;
import java.awt.Color;
import javax.swing.BorderFactory;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTextPane;
import javax.swing.text.BadLocationException;
import javax.swing.text.SimpleAttributeSet;
import javax.swing.text.StyleConstants;
import javax.swing.text.StyledDocument;

/** The change report, coloured: new things green, gone things red, changed amber, headings bold. */
final class DiffView extends JPanel {
    private final JTextPane pane = new JTextPane();

    DiffView() {
        super(new BorderLayout());
        pane.setEditable(false);
        pane.setFont(Theme.mono(12f));
        pane.setMargin(new java.awt.Insets(10, 14, 10, 14));
        JScrollPane sp = new JScrollPane(pane);
        sp.setBorder(BorderFactory.createMatteBorder(1, 0, 0, 0, Theme.line()));
        add(sp, BorderLayout.CENTER);
    }

    void show(String text) {
        StyledDocument doc = pane.getStyledDocument();
        try {
            doc.remove(0, doc.getLength());
            for (String line : text.split("\n", -1)) {
                Color c = Theme.fg();
                boolean bold = false;
                String t = line.stripLeading();
                if (line.equals("NEW WORKFLOWS (connected additions, one line each)") || line.equals("CHANGED") || line.equals("NEW")
                        || line.startsWith("GONE")) {
                    c = Theme.ACCENT;
                    bold = true;
                } else if (t.startsWith("+ ") || t.startsWith("▸")) {
                    c = Theme.GREEN;
                } else if (t.startsWith("- ")) {
                    c = Theme.RED;
                } else if (t.startsWith("~ ")) {
                    c = Theme.AMBER;
                    bold = true;
                } else if (line.startsWith("      ") && (t.matches("ev_\\d+.*"))) {
                    c = Theme.muted();
                } else if (line.startsWith("  ") && line.contains("workflow(s)")) {
                    c = Theme.muted();
                }
                SimpleAttributeSet a = new SimpleAttributeSet();
                StyleConstants.setForeground(a, c);
                StyleConstants.setBold(a, bold);
                doc.insertString(doc.getLength(), line + "\n", a);
            }
        } catch (BadLocationException ignored) {
            // appending cannot fail
        }
        pane.setCaretPosition(0);
    }
}
