package burp2model.ui;

import static burp2model.ui.Layouts.*;

import burp2model.engine.Json;
import burp2model.engine.Model;
import burp2model.engine.Recon;
import java.awt.BorderLayout;
import java.awt.Component;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.Map;
import javax.swing.JButton;
import javax.swing.JComboBox;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JTextArea;
import javax.swing.SwingUtilities;

/** Recon: light, passive recon on one host, only when asked. */
final class ReconTab implements Tab {
    private final MainPanel app;
    private final JComboBox<String> reconHost = new JComboBox<>();
    private final JTextArea reconText = textArea();
    private final JLabel reconStatus = new JLabel(" ");
    private final Component view;

    ReconTab(MainPanel app) {
        this.app = app;
        this.view = build();
    }

    @Override
    public Component view() {
        return view;
    }

    @Override
    public void fill(Model m) {
        fillRecon(m);
    }

    private Component build() {
        JPanel top = toolbar();
        top.add(new JLabel("Host"));
        reconHost.setEditable(true);
        reconHost.setPreferredSize(new java.awt.Dimension(280, 26));
        top.add(reconHost);
        JButton run = new JButton("Run light recon…");
        top.add(run);
        top.add(reconStatus);
        run.addActionListener(e -> runRecon());
        reconText.setText("Light, passive recon on one host: DNS, the TLS certificate, the front page's headers, robots.txt and security.txt, and mail policy.\n\n"
                + "It sends a handful of ordinary requests to the host, so run it only on targets you are authorised to test. "
                + "Nothing is run until you press the button.");
        JPanel p = new JPanel(new BorderLayout());
        p.add(top, BorderLayout.NORTH);
        p.add(scroll(reconText), BorderLayout.CENTER);
        return p;
    }

    private void fillRecon(Model m) {
        Object cur = reconHost.getEditor().getItem();
        reconHost.removeAllItems();
        if (m != null) {
            for (Model.Node n : m.nodes.values()) {
                if (n.type.equals("host")) {
                    reconHost.addItem(n.label);
                }
            }
        }
        if (cur != null && !String.valueOf(cur).isBlank()) {
            reconHost.setSelectedItem(cur);
        }
    }

    private void runRecon() {
        String h = String.valueOf(reconHost.getEditor().getItem()).strip().toLowerCase();
        if (h.isEmpty() || !h.matches("[a-z0-9.\\-]+")) {
            reconStatus.setText("enter a host name");
            return;
        }
        int ok = JOptionPane.showConfirmDialog(app, "Run light recon against " + h + "?\n\nThis sends a few ordinary requests (DNS, a TLS handshake, GETs for /, robots.txt,\n"
                + "security.txt and sitemap.xml). Only do this for targets you are authorised to test.", "burp2model recon", JOptionPane.OK_CANCEL_OPTION);
        if (ok != JOptionPane.OK_OPTION) {
            return;
        }
        reconStatus.setText("running…");
        app.host().background("burp2model-recon", () -> {
            try {
                Map<String, Object> r = Recon.run(h, s -> SwingUtilities.invokeLater(() -> reconStatus.setText("running: " + s)));
                String text = Recon.format(r);
                if (app.session() != null) {
                    Files.writeString(app.session().dir().resolve("recon-" + h + ".json"), Json.pretty(r), StandardCharsets.UTF_8);
                }
                SwingUtilities.invokeLater(() -> {
                    reconText.setText(text);
                    reconText.setCaretPosition(0);
                    reconStatus.setText("done");
                });
            } catch (Throwable t) {
                SwingUtilities.invokeLater(() -> reconStatus.setText("failed: " + t.getMessage()));
            }
        });
    }
}
