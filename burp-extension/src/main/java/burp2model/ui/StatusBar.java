package burp2model.ui;

import java.awt.BorderLayout;
import java.awt.Component;
import java.awt.Font;
import javax.swing.BorderFactory;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.SwingUtilities;

/**
 * The line under the tab: a busy indicator while background work runs, and a message with a coloured dot that goes
 * back to the model summary after a while.
 */
final class StatusBar extends JPanel {
    private static final long serialVersionUID = 1L;
    private final JLabel status = new JLabel(" ");
    private final javax.swing.JProgressBar busyBar = new javax.swing.JProgressBar();
    private final java.util.concurrent.atomic.AtomicInteger busy = new java.util.concurrent.atomic.AtomicInteger();
    /** The last "…ing" message shown while busy; when the work ends and it is still showing, the summary comes back. */
    private volatile String workingText;
    /** What the line shows when no message is: the model summary. */
    private String summary = " ";
    private final javax.swing.Timer revert = new javax.swing.Timer(10_000, e -> set(summary, null));

    StatusBar() {
        super(new BorderLayout());
        status.setBorder(BorderFactory.createEmptyBorder(4, 8, 4, 12));
        status.setFont(Theme.font(11f, Font.PLAIN));
        status.setForeground(Theme.MUTED);
        status.setIconTextGap(6);
        busyBar.setIndeterminate(true);
        busyBar.setPreferredSize(new java.awt.Dimension(70, 8));
        busyBar.setVisible(false);
        JPanel busyBox = new JPanel(new java.awt.GridBagLayout());
        busyBox.setBorder(BorderFactory.createEmptyBorder(0, 12, 0, 0));
        busyBox.add(busyBar);
        add(busyBox, BorderLayout.WEST);
        add(status, BorderLayout.CENTER);
        revert.setRepeats(false);
    }

    /** Show the busy indicator (from any thread); pair each call with idle(). */
    void working(String what) {
        busy.incrementAndGet();
        if (what != null) {
            workingText = what;
        }
        SwingUtilities.invokeLater(() -> {
            busyBar.setVisible(busy.get() > 0);
            if (what != null) {
                set(what, MainPanel.Level.INFO);
            }
        });
    }

    void idle() {
        busy.updateAndGet(n -> Math.max(0, n - 1));
        SwingUtilities.invokeLater(() -> {
            busyBar.setVisible(busy.get() > 0);
            if (busy.get() == 0 && workingText != null && workingText.equals(status.getText())) {
                set(summary, null);                       // "Comparing builds…" must not outlive the comparison
            }
        });
    }

    /** A message with a coloured dot (errors red), or with no level the summary itself, which stays. */
    void set(String text, MainPanel.Level level) {
        status.setText(text);
        status.setIcon(level == null ? null : new Dot(level == MainPanel.Level.ERROR ? Theme.RED : level == MainPanel.Level.OK ? Theme.GREEN : Theme.BLUE));
        status.setForeground(level == MainPanel.Level.ERROR ? Theme.readable(Theme.RED, Theme.bg()) : Theme.MUTED);
        if (level == null) {
            revert.stop();
        } else {
            revert.setInitialDelay(level == MainPanel.Level.ERROR ? 20_000 : 10_000);
            revert.restart();
        }
    }

    /** The model summary (with its folder as the tooltip); shown now unless a message is still up. */
    void summary(String text, String tooltip) {
        summary = text;
        status.setToolTipText(tooltip);
        if (!revert.isRunning()) {
            set(summary, null);
        }
    }

    /** Let the next summary show at once, over whatever message is up ("Opening the model…" gives way to its summary). */
    void dropMessage() {
        revert.stop();
    }

    private static final class Dot implements javax.swing.Icon {
        private final java.awt.Color c;

        Dot(java.awt.Color c) {
            this.c = c;
        }

        @Override
        public void paintIcon(Component comp, java.awt.Graphics g0, int x, int y) {
            java.awt.Graphics2D g = (java.awt.Graphics2D) g0.create();
            Theme.quality(g);
            g.setColor(c);
            g.fillOval(x, y + 1, 7, 7);
            g.dispose();
        }

        @Override
        public int getIconWidth() {
            return 7;
        }

        @Override
        public int getIconHeight() {
            return 9;
        }
    }
}
