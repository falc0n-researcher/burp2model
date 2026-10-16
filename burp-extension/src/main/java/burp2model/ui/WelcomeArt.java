package burp2model.ui;

import java.awt.Color;
import java.awt.Dimension;
import java.awt.Font;
import java.awt.FontMetrics;
import java.awt.Graphics;
import java.awt.Graphics2D;
import java.util.function.Supplier;
import javax.swing.JButton;
import javax.swing.JComponent;

/**
 * The welcome page's look, drawn in code: the logo mark, cards with a thin border, an arrow, a faint dot texture,
 * and text and buttons set in the bundled IBM Plex Mono.
 */
final class WelcomeArt {
    private WelcomeArt() {}

    /** The mark: three nodes of the model (a page, a script, an endpoint) and the links between them. */
    private static final String[] LOGO = {
        "AAAA............",
        "AAAA............",
        "AAAA............",
        "AAAA............",
        "....##..........",
        "......##........",
        "........##......",
        "..........BBBB..",
        "..........BBBB..",
        "..........BBBB..",
        ".........#BBBB..",
        "........#.......",
        ".......#........",
        "...CCCC.........",
        "...CCCC.........",
        "...CCCC.........",
        "...CCCC.........",
    };

    static int logoSize(int px) {
        return LOGO.length * px;
    }

    static void logo(Graphics2D g, int x, int y, int px) {
        for (int r = 0; r < LOGO.length; r++) {
            for (int c = 0; c < LOGO[r].length(); c++) {
                Color col = switch (LOGO[r].charAt(c)) {
                    case 'A' -> Theme.ACCENT;
                    case 'B' -> Theme.BLUE;
                    case 'C' -> Theme.GREEN;
                    case '#' -> Theme.muted();
                    default -> null;
                };
                if (col != null) {
                    g.setColor(col);
                    g.fillRect(x + c * px, y + r * px, px, px);
                }
            }
        }
    }

    /** A card: rounded corners, a one-pixel border. */
    static void frame(Graphics2D g, int x, int y, int w, int h, int radius, Color fill, Color line) {
        Graphics2D c = (Graphics2D) g.create();
        Theme.quality(c);
        if (fill != null) {
            c.setColor(fill);
            c.fillRoundRect(x, y, w - 1, h - 1, radius * 2, radius * 2);
        }
        if (line != null) {
            c.setColor(line);
            c.drawRoundRect(x, y, w - 1, h - 1, radius * 2, radius * 2);
        }
        c.dispose();
    }

    /** A small right-pointing arrow head, `size` pixels tall. */
    static void arrow(Graphics2D g, int x, int y, int size, Color c) {
        Graphics2D a = (Graphics2D) g.create();
        Theme.quality(a);
        a.setColor(c);
        a.setStroke(new java.awt.BasicStroke(Math.max(1.6f, size / 6f), java.awt.BasicStroke.CAP_ROUND, java.awt.BasicStroke.JOIN_ROUND));
        a.drawLine(x, y, x + size / 2, y + size / 2);
        a.drawLine(x + size / 2, y + size / 2, x, y + size);
        a.dispose();
    }

    /** A faint grid of dots, the texture behind the page in dark mode. */
    static void dither(Graphics2D g, int w, int h, int step, Color c) {
        g.setColor(c);
        for (int y = 0; y < h; y += step) {
            for (int x = (y / step) % 2 == 0 ? 0 : step / 2; x < w; x += step) {
                g.fillRect(x, y, 1, 1);
            }
        }
    }

    /** One line of display type; its colour is looked up at paint time, so it follows a theme switch. */
    static final class Text extends JComponent {
        private static final long serialVersionUID = 1L;
        private final String text;
        private final transient Supplier<Font> font;
        private final transient Supplier<Color> color;

        Text(String text, Supplier<Font> font, Supplier<Color> color) {
            this.text = text;
            this.font = font;
            this.color = color;
            setOpaque(false);
        }

        /** Read out like a label by screen readers. */
        @Override
        public javax.accessibility.AccessibleContext getAccessibleContext() {
            if (accessibleContext == null) {
                accessibleContext = new AccessibleJComponent() {
                    private static final long serialVersionUID = 1L;

                    @Override
                    public javax.accessibility.AccessibleRole getAccessibleRole() {
                        return javax.accessibility.AccessibleRole.LABEL;
                    }

                    @Override
                    public String getAccessibleName() {
                        return text;
                    }
                };
            }
            return accessibleContext;
        }

        private Font f() {
            return Theme.displayOr(font.get(), text);
        }

        @Override
        public Dimension getPreferredSize() {
            FontMetrics fm = getFontMetrics(f());
            return new Dimension(fm.stringWidth(text) + 2, fm.getAscent() + fm.getDescent());
        }

        @Override
        public Dimension getMaximumSize() {
            return getPreferredSize();
        }

        /** Never squeezed: a layout short of room must not shrink the title to nothing. */
        @Override
        public Dimension getMinimumSize() {
            return getPreferredSize();
        }

        @Override
        protected void paintComponent(Graphics g0) {
            Graphics2D g = (Graphics2D) g0.create();
            Theme.textHints(g);
            g.setFont(f());
            g.setColor(color.get());
            g.drawString(text, 0, g.getFontMetrics().getAscent());
            g.dispose();
        }
    }

    /**
     * A button drawn as a card. The primary one is filled with a darker orange that keeps white text above 4.5:1;
     * the others are outlined. Keyboard focus shows as an accent ring.
     */
    static final class Button extends JButton {
        private static final long serialVersionUID = 1L;
        static final Color PRIMARY = new Color(0xB3, 0x3D, 0x00);
        private final boolean primary;
        private final boolean arrow;

        Button(String text, boolean primary, boolean arrow) {
            super(text);
            this.primary = primary;
            this.arrow = arrow;
            setContentAreaFilled(false);
            setBorderPainted(false);
            setFocusPainted(false);
            setOpaque(false);
            setCursor(java.awt.Cursor.getPredefinedCursor(java.awt.Cursor.HAND_CURSOR));
            setRolloverEnabled(true);
        }

        private Font f() {
            return Theme.displayOr(Theme.displayMedium(14f), getText());
        }

        private int arrowSize(FontMetrics fm) {
            return Math.max(8, fm.getAscent() / 2);
        }

        @Override
        public Dimension getPreferredSize() {
            FontMetrics fm = getFontMetrics(f());
            int extra = arrow ? arrowSize(fm) + 12 : 0;
            return new Dimension(fm.stringWidth(getText()) + 40 + extra, fm.getHeight() + 20);
        }

        @Override
        protected void paintComponent(Graphics g0) {
            Graphics2D g = (Graphics2D) g0.create();
            Theme.textHints(g);
            int w = getWidth();
            int h = getHeight();
            boolean down = getModel().isPressed();
            boolean over = getModel().isRollover();
            int r = 7;
            Color fill = !isEnabled() ? Theme.surface2() : primary ? (over || down ? Theme.ACCENT : PRIMARY) : over ? Theme.surface2() : Theme.surface();
            Color line = primary ? PRIMARY.darker() : over ? Theme.alpha(Theme.ACCENT, 160) : Theme.line();
            WelcomeArt.frame(g, 0, down ? 1 : 0, w, h - 1, r, fill, line);
            if (isFocusOwner()) {
                g.setColor(primary ? Theme.alpha(Color.WHITE, 200) : Theme.ACCENT);
                g.setStroke(new java.awt.BasicStroke(1.5f));
                g.drawRoundRect(3, (down ? 1 : 0) + 3, w - 7, h - 8, r * 2 - 4, r * 2 - 4);
            }
            Color text = !isEnabled() ? Theme.muted() : primary ? Color.WHITE : Theme.fg();
            g.setFont(f());
            g.setColor(text);
            FontMetrics fm = g.getFontMetrics();
            int as = arrowSize(fm);
            int tw = fm.stringWidth(getText()) + (arrow ? as + 12 : 0);
            int tx = (w - tw) / 2;
            int ty = (h - 1 - fm.getHeight()) / 2 + fm.getAscent() + (down ? 1 : 0);
            g.drawString(getText(), tx, ty);
            if (arrow) {
                WelcomeArt.arrow(g, tx + fm.stringWidth(getText()) + 12, ty - fm.getAscent() / 2 - as / 2 + 2, as, text);
            }
            g.dispose();
        }
    }
}
