package burp2model.ui;

import java.util.Map;
import javax.swing.JComponent;

/** Where one request or response is shown: burp2model's own pane (HttpPane) or Burp's message editor (BurpMessagePane). */
interface MessageView {
    JComponent view();

    /** Show no message, only a hint. */
    void clear(String hint);

    /** Show a masked message: {line, headers: [[name, value]...], body, truncated}. */
    void show(Map<String, Object> message);
}
