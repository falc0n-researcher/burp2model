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
 * The welcome page's pixel look, drawn in code: a logo mark, frames with stepped corners, an arrow, a dither, and
 * text and buttons set in the bundled pixel fonts. Every shape is whole pixels at a whole-number scale.
 */
final class PixelArt {
    private PixelArt() {}

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

    /** A rectangle whose corners are cut by one pixel step: the classic pixel-art card. */
    static void frame(Graphics2D g, int x, int y, int w, int h, int px, Color fill, Color line) {
        if (fill != null) {
            g.setColor(fill);
            g.fillRect(x + px, y + px, w - 2 * px, h - 2 * px);
        }
        if (line != null) {
            g.setColor(line);
            g.fillRect(x + px, y, w - 2 * px, px);                // top
            g.fillRect(x + px, y + h - px, w - 2 * px, px);       // bottom
            g.fillRect(x, y + px, px, h - 2 * px);                // left
            g.fillRect(x + w - px, y + px, px, h - 2 * px);       // right
        }
    }

    /** A right-pointing arrow, 4 pixels wide and 7 high. */
    static void arrow(Graphics2D g, int x, int y, int px, Color c) {
        g.setColor(c);
        for (int i = 0; i < 4; i++) {
            g.fillRect(x + i * px, y + i * px, px, (7 - 2 * i) * px);
        }
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

    /** One line of pixel type; its colour is looked up at paint time, so it follows a theme switch. */
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
            return Theme.pixelOr(font.get(), text);
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

        /** Never squeezed: a layout short of room must not shrink pixel type to nothing. */
        @Override
        public Dimension getMinimumSize() {
            return getPreferredSize();
        }

        @Override
        protected void paintComponent(Graphics g0) {
            Graphics2D g = (Graphics2D) g0.create();
            Theme.pixelHints(g);
            g.setFont(f());
            g.setColor(color.get());
            g.drawString(text, 0, g.getFontMetrics().getAscent());
            g.dispose();
        }
    }

    /**
     * A button drawn as a pixel card. The primary one is filled with a darker orange that keeps white text above
     * 4.5:1; the others are outlined. Keyboard focus shows as a second frame.
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

        private int px() {
            return Math.max(2, Math.round(2 * Theme.uiScale()));
        }

        private Font f() {
            return Theme.pixelOr(Theme.pixelSans(false), getText());
        }

        @Override
        public Dimension getPreferredSize() {
            FontMetrics fm = getFontMetrics(f());
            int px = px();
            return new Dimension(fm.stringWidth(getText()) + 18 * px + (arrow ? 7 * px : 0), fm.getHeight() + 8 * px);
        }

        @Override
        protected void paintComponent(Graphics g0) {
            Graphics2D g = (Graphics2D) g0.create();
            Theme.pixelHints(g);
            int px = px();
            int w = getWidth();
            int h = getHeight();
            boolean down = getModel().isPressed();
            boolean over = getModel().isRollover();
            int sink = down ? px : 0;
            Color fill = !isEnabled() ? Theme.surface2() : primary ? (over ? Theme.ACCENT : PRIMARY) : over ? Theme.surface2() : Theme.surface();
            Color line = primary ? PRIMARY.darker() : Theme.line();
            if (!down && isEnabled()) {
                PixelArt.frame(g, px, px, w - px, h - px, px, null, Theme.alpha(Theme.fg(), 40));   // the drop shadow
            }
            PixelArt.frame(g, sink, sink, w - px, h - px, px, fill, line);
            if (isFocusOwner()) {
                PixelArt.frame(g, sink + 2 * px, sink + 2 * px, w - 5 * px, h - 5 * px, px, null, primary ? Color.WHITE : Theme.ACCENT);
            }
            Color text = !isEnabled() ? Theme.muted() : primary ? Color.WHITE : Theme.fg();
            g.setFont(f());
            g.setColor(text);
            FontMetrics fm = g.getFontMetrics();
            int tw = fm.stringWidth(getText()) + (arrow ? 7 * px : 0);
            int tx = (w - px - tw) / 2 + sink;
            int ty = (h - px - fm.getHeight()) / 2 + fm.getAscent() + sink;
            g.drawString(getText(), tx, ty);
            if (arrow) {
                PixelArt.arrow(g, tx + fm.stringWidth(getText()) + 3 * px, ty - fm.getAscent() / 2 - 3 * px, px, text);
            }
            g.dispose();
        }
    }
}
