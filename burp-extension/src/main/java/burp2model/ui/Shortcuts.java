package burp2model.ui;

import java.awt.Component;
import java.awt.event.KeyEvent;

/**
 * Keys, active while focus is anywhere in the tab (never elsewhere in Burp): Cmd/Ctrl+1..9 and 0 for the tabs,
 * Cmd/Ctrl+F to search, Cmd/Ctrl+L for the query box, Cmd/Ctrl+Shift+C for Copy for AI, and Alt+Left to go back to
 * the tab shown before a jump.
 */
final class Shortcuts {
    private final MainPanel app;
    private final java.util.ArrayDeque<Component> history = new java.util.ArrayDeque<>();
    private Component lastTab;
    private boolean goingBack;

    Shortcuts(MainPanel app) {
        this.app = app;
    }

    /** A tab came to the front: remember the one before it, unless this is going back. */
    void shown(Component now) {
        if (lastTab != null && lastTab != now && !goingBack) {
            history.push(lastTab);
            while (history.size() > 30) {
                history.removeLast();
            }
        }
        lastTab = now;
    }

    /** Alt+Left: the tab shown before (after a jump from a lead, a search or a connection). */
    private void back() {
        Component prev = history.poll();
        if (prev != null) {
            goingBack = true;
            try {
                app.showWelcome(false);
                app.tabs.setSelectedComponent(prev);
                lastTab = prev;
            } finally {
                goingBack = false;
            }
        }
    }

    void install() {
        int menu = menuMask();
        javax.swing.InputMap im = app.getInputMap(javax.swing.JComponent.WHEN_ANCESTOR_OF_FOCUSED_COMPONENT);
        javax.swing.ActionMap am = app.getActionMap();
        for (int i = 0; i <= 9; i++) {
            int index = i == 0 ? app.tabs.getTabCount() - 1 : i - 1;
            bind(im, am, javax.swing.KeyStroke.getKeyStroke(KeyEvent.VK_0 + i, menu), "tab" + i, () -> {
                if (index < app.tabs.getTabCount()) {
                    app.showWelcome(false);
                    app.tabs.setSelectedIndex(index);
                }
            });
        }
        bind(im, am, javax.swing.KeyStroke.getKeyStroke(KeyEvent.VK_F, menu), "search", () -> {
            app.header.globalSearch.requestFocusInWindow();
            app.header.globalSearch.selectAll();
        });
        bind(im, am, javax.swing.KeyStroke.getKeyStroke(KeyEvent.VK_L, menu), "query", () -> {
            app.select(app.queryTab);
            app.queryTab.focusField();
        });
        bind(im, am, javax.swing.KeyStroke.getKeyStroke(KeyEvent.VK_C, menu | java.awt.event.InputEvent.SHIFT_DOWN_MASK), "copyForAi",
                () -> app.header.copyForAi("whole"));
        bind(im, am, javax.swing.KeyStroke.getKeyStroke(KeyEvent.VK_LEFT, java.awt.event.InputEvent.ALT_DOWN_MASK), "back", this::back);
    }

    /** Cmd on a Mac, Ctrl elsewhere (asked of the toolkit, which a headless JVM cannot answer). */
    static int menuMask() {
        try {
            return java.awt.Toolkit.getDefaultToolkit().getMenuShortcutKeyMaskEx();
        } catch (java.awt.HeadlessException e) {
            return System.getProperty("os.name", "").toLowerCase().contains("mac") ? java.awt.event.InputEvent.META_DOWN_MASK
                    : java.awt.event.InputEvent.CTRL_DOWN_MASK;
        }
    }

    private static void bind(javax.swing.InputMap im, javax.swing.ActionMap am, javax.swing.KeyStroke k, String name, Runnable r) {
        im.put(k, name);
        am.put(name, new javax.swing.AbstractAction() {
            private static final long serialVersionUID = 1L;

            @Override
            public void actionPerformed(java.awt.event.ActionEvent e) {
                r.run();
            }
        });
    }
}
