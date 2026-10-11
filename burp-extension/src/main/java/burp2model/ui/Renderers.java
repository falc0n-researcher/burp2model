package burp2model.ui;

import java.awt.Color;
import java.awt.Component;
import java.awt.Font;
import java.awt.Graphics;
import java.awt.Graphics2D;
import java.awt.geom.RoundRectangle2D;
import javax.swing.JLabel;
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
                int h = 17;
                int w = g.getFontMetrics().stringWidth(getText()) + 14;
                int y = (getHeight() - h) / 2;
                g.setColor(Theme.alpha(color, selected ? 90 : 48));
                g.fill(new RoundRectangle2D.Float(4, y, w, h, h, h));
                g.setColor(selected ? getForeground() : color);
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
                    setForeground(Theme.muted());
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

    static void unused(JLabel l, Graphics g) {
        // keeps the imports honest if a renderer is removed
    }
}
