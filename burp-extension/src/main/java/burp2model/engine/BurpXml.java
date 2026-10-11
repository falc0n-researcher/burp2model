package burp2model.engine;

import java.io.File;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import javax.xml.parsers.DocumentBuilderFactory;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;

/** Reads Burp's "Save items" XML. Used by the command-line tools and tests, never inside Burp itself. */
public final class BurpXml {
    private BurpXml() {}

    private static String text(Element item, String tag) {
        NodeList l = item.getElementsByTagName(tag);
        return l.getLength() == 0 ? null : l.item(0).getTextContent();
    }

    private static byte[] blob(Element item, String tag) {
        NodeList l = item.getElementsByTagName(tag);
        if (l.getLength() == 0) {
            return new byte[0];
        }
        Element e = (Element) l.item(0);
        String t = e.getTextContent();
        if ("true".equals(e.getAttribute("base64"))) {
            String s = t.replaceAll("\\s+", "");
            if (s.length() % 4 == 1) {
                s = s.substring(0, s.length() - 1);
            }
            while (s.length() % 4 != 0) {
                s += "=";
            }
            try {
                return Base64.getDecoder().decode(s);
            } catch (IllegalArgumentException ex) {
                return t.getBytes(java.nio.charset.StandardCharsets.UTF_8);
            }
        }
        return t.getBytes(java.nio.charset.StandardCharsets.UTF_8);
    }

    /** The raw items of an export, as they would arrive from Burp's API. */
    public static List<Parse.Raw> readRaw(File f) throws Exception {
        List<Parse.Raw> out = new ArrayList<>();
        forEach(f, (raw, i) -> out.add(raw));
        return out;
    }

    private interface ItemSink {
        void accept(Parse.Raw raw, int index);
    }

    private static void forEach(File f, ItemSink sink) throws Exception {
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", false);
        dbf.setFeature("http://xml.org/sax/features/external-general-entities", false);
        dbf.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
        dbf.setFeature("http://apache.org/xml/features/nonvalidating/load-external-dtd", false);
        Document doc = dbf.newDocumentBuilder().parse(f);
        NodeList items = doc.getElementsByTagName("item");
        for (int i = 0; i < items.getLength(); i++) {
            Element it = (Element) items.item(i);
            String path = text(it, "path");
            if (path == null || path.isBlank()) {
                String url = text(it, "url");
                String[] hp = url == null ? null : Extract.splitAbsolute(url);
                String q = url != null && url.contains("?") ? url.substring(url.indexOf('?')) : "";
                path = hp == null ? "/" : (hp[1].isEmpty() ? "/" : hp[1]) + q.split("#", 2)[0];
            }
            String st = text(it, "status");
            Integer status = st != null && st.strip().matches("\\d+") ? Integer.parseInt(st.strip()) : null;
            String port = text(it, "port");
            sink.accept(new Parse.Raw(text(it, "method"), text(it, "host"),
                    port != null && port.strip().matches("\\d+") ? Integer.parseInt(port.strip()) : 0, text(it, "protocol"),
                    path, status, text(it, "mimetype"), blob(it, "request"), blob(it, "response"),
                    it.getElementsByTagName("truncated").getLength() > 0), i);
        }
    }

    public static List<Exchange> read(File f, String role) throws Exception {
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", false);
        dbf.setFeature("http://xml.org/sax/features/external-general-entities", false);
        dbf.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
        dbf.setFeature("http://apache.org/xml/features/nonvalidating/load-external-dtd", false);
        Document doc = dbf.newDocumentBuilder().parse(f);
        NodeList items = doc.getElementsByTagName("item");
        List<Exchange> out = new ArrayList<>();
        int idx = 1;
        for (int i = 0; i < items.getLength(); i++) {
            Element it = (Element) items.item(i);
            String path = text(it, "path");
            if (path == null || path.isBlank()) {
                String url = text(it, "url");
                String[] hp = url == null ? null : Extract.splitAbsolute(url);
                String q = url != null && url.contains("?") ? url.substring(url.indexOf('?')) : "";
                path = hp == null ? "/" : (hp[1].isEmpty() ? "/" : hp[1]) + q.split("#", 2)[0];
            }
            String st = text(it, "status");
            Integer status = st != null && st.strip().matches("\\d+") ? Integer.parseInt(st.strip()) : null;
            String port = text(it, "port");
            Parse.Raw raw = new Parse.Raw(text(it, "method"), text(it, "host"),
                    port != null && port.strip().matches("\\d+") ? Integer.parseInt(port.strip()) : 0, text(it, "protocol"),
                    path, status, text(it, "mimetype"), blob(it, "request"), blob(it, "response"),
                    it.getElementsByTagName("truncated").getLength() > 0);
            Exchange ex;
            try {
                ex = Parse.item(idx, raw, role, f.getName(), i);
            } catch (RuntimeException e) {
                ex = null;
            }
            if (ex != null) {
                out.add(ex);
                idx++;
            }
        }
        return out;
    }
}
