package burp2model.ui;

import java.awt.Component;

/** Burp's own read-only HTTP message editors, which the extension supplies inside Burp. */
public interface MessageEditors {
    /** One editor: its component, and a way to show a message's text in it. */
    interface Editor {
        Component component();

        void show(String text);
    }

    Editor request();

    Editor response();
}
