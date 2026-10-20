package burp2model.ui;

import java.awt.Color;
import java.awt.Component;
import java.awt.Font;
import java.awt.Graphics;
import java.awt.Graphics2D;
import java.awt.geom.RoundRectangle2D;
import javax.swing.JTable;
import javax.swing.SwingConstants;
import javax.swing.table.DefaultTableCellRenderer;
import javax.swing.table.TableCellRenderer;

/** Cell renderers: coloured methods, status codes, states and severities; muted evidence ids. */
final class Renderers {
    private Renderers() {}

    interface Tint {
        Color of(String value);
    }

    /** A rounded, tinted label inside the cell (a badge). */
    static final class Badge extends DefaultTableCellRenderer {
        private final Tint tint;
        private Color color;
        private boolean selected;

        Badge(Tint tint) {
            this.tint = tint;
            setHorizontalAlignment(SwingConstants.LEFT);
        }

        @Override
        public Component getTableCellRendererComponent(JTable t, Object v, boolean sel, boolean focus, int r, int c) {
            super.getTableCellRendererComponent(t, v, sel, focus, r, c);
            String s = v == null ? "" : String.valueOf(v);
            color = s.isEmpty() ? null : tint.of(s);
            selected = sel;
            setFont(Theme.font(11f, Font.BOLD));
            setText(s.replace('_', ' '));
            setBorder(javax.swing.BorderFactory.createEmptyBorder(0, 10, 0, 4));
            return this;
        }

        @Override
        protected void paintComponent(Graphics g0) {
            Graphics2D g = (Graphics2D) g0.create();
            Theme.quality(g);
            g.setColor(getBackground());
            g.fillRect(0, 0, getWidth(), getHeight());
            if (color != null) {
                g.setFont(getFont());
                int h = g.getFontMetrics().getHeight() + 3;
                int w = g.getFontMetrics().stringWidth(getText()) + 14;
                int y = (getHeight() - h) / 2;
                g.setColor(Theme.alpha(color, selected ? 90 : 48));
                g.fill(new RoundRectangle2D.Float(4, y, w, h, h, h));
                // the badge's own colour as text, shaded until it reads at 4.5:1 on the tinted pill
                g.setColor(selected ? getForeground() : Theme.readable(color, getBackground()));
                g.drawString(getText(), 11, y + (h + g.getFontMetrics().getAscent() - g.getFontMetrics().getDescent()) / 2);
            }
            g.dispose();
        }
    }

    static TableCellRenderer method() {
        return new Badge(Theme::method);
    }

    static TableCellRenderer state() {
        return new Badge(Theme::state);
    }

    static TableCellRenderer severity() {
        return new Badge(Theme::severity);
    }

    static TableCellRenderer status() {
        return new Badge(v -> v.matches("\\d+") ? Theme.status(Integer.parseInt(v)) : Theme.GRAY);
    }

    private static final java.util.regex.Pattern CODE = java.util.regex.Pattern.compile("\\b[1-5]\\d\\d\\b");

    /** Status codes, one or several ("200, 403" or "user 403 · admin 200"): each code in its colour, the rest muted. */
    static TableCellRenderer codes() {
        return new DefaultTableCellRenderer() {
            private String text = "";
            private boolean selected;

            @Override
            public Component getTableCellRendererComponent(JTable t, Object v, boolean sel, boolean focus, int r, int c) {
                super.getTableCellRendererComponent(t, v, sel, focus, r, c);
                text = v == null ? "" : String.valueOf(v);
                selected = sel;
                setText("");
                setToolTipText(text.isEmpty() ? null : text);
                return this;
            }

            @Override
            protected void paintComponent(Graphics g0) {
                super.paintComponent(g0);
                Graphics2D g = (Graphics2D) g0.create();
                Theme.textHints(g);
                g.setFont(Theme.mono(12f));
                java.awt.FontMetrics fm = g.getFontMetrics();
                int x = 8;
                int y = (getHeight() + fm.getAscent() - fm.getDescent()) / 2;
                java.util.regex.Matcher m = CODE.matcher(text);
                int at = 0;
                while (m.find()) {
                    g.setColor(selected ? getForeground() : Theme.MUTED);
                    g.drawString(text.substring(at, m.start()), x, y);
                    x += fm.stringWidth(text.substring(at, m.start()));
                    g.setFont(Theme.mono(12f).deriveFont(Font.BOLD));
                    g.setColor(selected ? getForeground() : Theme.readable(Theme.status(Integer.parseInt(m.group())), getBackground()));
                    g.drawString(m.group(), x, y);
                    x += g.getFontMetrics().stringWidth(m.group());
                    g.setFont(Theme.mono(12f));
                    at = m.end();
                }
                g.setColor(selected ? getForeground() : Theme.MUTED);
                g.drawString(text.substring(at), x, y);
                g.dispose();
            }
        };
    }

    static TableCellRenderer type() {
        return new Badge(Theme::type);
    }

    /** Monospaced, muted: evidence ids and other identifiers. */
    static TableCellRenderer ids() {
        return new DefaultTableCellRenderer() {
            @Override
            public Component getTableCellRendererComponent(JTable t, Object v, boolean sel, boolean focus, int r, int c) {
                super.getTableCellRendererComponent(t, v, sel, focus, r, c);
                setFont(Theme.mono(11f));
                if (!sel) {
                    setForeground(Theme.MUTED);
                }
                setBorder(javax.swing.BorderFactory.createEmptyBorder(0, 8, 0, 4));
                return this;
            }
        };
    }

    /** Plain text with a little padding. */
    static TableCellRenderer text() {
        return new DefaultTableCellRenderer() {
            @Override
            public Component getTableCellRendererComponent(JTable t, Object v, boolean sel, boolean focus, int r, int c) {
                super.getTableCellRendererComponent(t, v, sel, focus, r, c);
                setBorder(javax.swing.BorderFactory.createEmptyBorder(0, 8, 0, 4));
                return this;
            }
        };
    }

    /** A path or label: monospaced, so templated segments line up. */
    static TableCellRenderer path() {
        return new DefaultTableCellRenderer() {
            @Override
            public Component getTableCellRendererComponent(JTable t, Object v, boolean sel, boolean focus, int r, int c) {
                super.getTableCellRendererComponent(t, v, sel, focus, r, c);
                setFont(Theme.mono(12f));
                setBorder(javax.swing.BorderFactory.createEmptyBorder(0, 8, 0, 4));
                setToolTipText(v == null ? null : String.valueOf(v));
                return this;
            }
        };
    }
}
