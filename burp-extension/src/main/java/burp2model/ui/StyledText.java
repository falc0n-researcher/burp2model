package burp2model.ui;

import java.awt.Color;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import javax.swing.JTextPane;
import javax.swing.text.BadLocationException;
import javax.swing.text.SimpleAttributeSet;
import javax.swing.text.StyleConstants;
import javax.swing.text.StyledDocument;

/**
 * A text answer made easy to scan, with fonts and colours only (no HTML, which Burp's theme may not render):
 * headings in the accent colour, "Label:" prefixes in bold, evidence ids muted, and added, removed and changed
 * lines of a comparison in green, red and amber.
 */
final class StyledText {
    private StyledText() {}

    private static final Pattern HEADING = Pattern.compile("^[A-Z][A-Z0-9 &/(),.'-]{2,}$|^[A-Z][A-Za-z ]{1,30}:$");
    private static final Pattern LABEL = Pattern.compile("^(\\s*)([A-Za-z][A-Za-z0-9 _/()-]{0,24}:)(\\s)");
    private static final Pattern EVIDENCE = Pattern.compile("\\bev_\\d+\\b|\\bModel call: none\\b");

    static JTextPane pane() {
        JTextPane p = new JTextPane();
        p.setEditable(false);
        p.setFont(Theme.mono(12f));
        p.setMargin(new java.awt.Insets(10, 14, 10, 14));
        p.setBackground(Theme.SURFACE);
        return p;
    }

    static void set(JTextPane pane, String text) {
        StyledDocument doc = pane.getStyledDocument();
        try {
            doc.remove(0, doc.getLength());
            for (String line : (text == null ? "" : text).split("\n", -1)) {
                int start = doc.getLength();
                doc.insertString(start, line + "\n", attrs(Theme.fg(), false));
                String t = line.strip();
                if (HEADING.matcher(t).matches()) {
                    doc.setCharacterAttributes(start, line.length(), attrs(Theme.readable(Theme.ACCENT, Theme.SURFACE), true), false);
                    continue;
                }
                if (t.startsWith("+ ") || t.startsWith("- ") || t.startsWith("~ ")) {
                    Color c = t.startsWith("+") ? Theme.GREEN : t.startsWith("-") ? Theme.RED : Theme.AMBER;
                    doc.setCharacterAttributes(start, line.length(), attrs(Theme.readable(c, Theme.SURFACE), false), false);
                }
                Matcher l = LABEL.matcher(line);
                if (l.find()) {
                    doc.setCharacterAttributes(start + l.start(2), l.group(2).length(), attrs(Theme.fg(), true), false);
                }
                Matcher ev = EVIDENCE.matcher(line);
                while (ev.find()) {
                    doc.setCharacterAttributes(start + ev.start(), ev.end() - ev.start(), attrs(Theme.muted(), false), false);
                }
            }
        } catch (BadLocationException ignored) {
            // offsets come from the document itself
        }
        pane.setCaretPosition(0);
    }

    private static SimpleAttributeSet attrs(Color c, boolean bold) {
        SimpleAttributeSet a = new SimpleAttributeSet();
        StyleConstants.setForeground(a, c);
        StyleConstants.setBold(a, bold);
        return a;
    }
}
