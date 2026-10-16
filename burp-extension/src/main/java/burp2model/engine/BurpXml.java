package burp2model.engine;

import java.io.File;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;

/** Reads Burp's "Save items" XML: the extension's Import, the command-line tools and the tests. */
public final class BurpXml {
    private BurpXml() {}

    private static String text(java.util.Map<String, String> item, String tag) {
        return item.get(tag);
    }

    private static byte[] blob(java.util.Map<String, String> item, java.util.Set<String> base64, String tag) {
        String t = item.get(tag);
        if (t == null) {
            return new byte[0];
        }
        if (base64.contains(tag)) {
            String s = t.replaceAll("\\s+", "");
            if (s.length() % 4 == 1) {
                s = s.substring(0, s.length() - 1);
            }
            StringBuilder pad = new StringBuilder(s);
            while (pad.length() % 4 != 0) {
                pad.append('=');
            }
            try {
                return Base64.getDecoder().decode(pad.toString());
            } catch (IllegalArgumentException ex) {
                return t.getBytes(java.nio.charset.StandardCharsets.UTF_8);
            }
        }
        return t.getBytes(java.nio.charset.StandardCharsets.UTF_8);
    }

    /** The raw items of an export, as they would arrive from Burp's API. */
    public static List<Parse.Raw> readRaw(File f) throws Exception {
        try (java.io.InputStream in = new java.io.FileInputStream(f)) {
            return readRaw(in);
        }
    }

    /** The same, from a stream (the extension's bundled sample is a resource, not a file). */
    public static List<Parse.Raw> readRaw(java.io.InputStream in) throws Exception {
        List<Parse.Raw> out = new ArrayList<>();
        forEach(in, (raw, i) -> out.add(raw));
        return out;
    }

    private interface ItemSink {
        void accept(Parse.Raw raw, int index);
    }

    /**
     * Read the export one item at a time (StAX), so a large export never sits in memory as a document tree.
     * Burp's inline DOCTYPE is skipped, not processed: no entity is ever expanded or fetched, so neither
     * billion laughs nor external entities can do anything.
     */
    private static void forEach(File f, ItemSink sink) throws Exception {
        try (java.io.InputStream in = new java.io.FileInputStream(f)) {
            forEach(in, sink);
        }
    }

    private static void forEach(java.io.InputStream raw, ItemSink sink) throws Exception {
        javax.xml.stream.XMLInputFactory xf = javax.xml.stream.XMLInputFactory.newFactory();
        xf.setProperty(javax.xml.stream.XMLInputFactory.SUPPORT_DTD, false);
        xf.setProperty(javax.xml.stream.XMLInputFactory.IS_SUPPORTING_EXTERNAL_ENTITIES, false);
        xf.setProperty(javax.xml.stream.XMLInputFactory.IS_COALESCING, true);
        javax.xml.stream.XMLStreamReader r = xf.createXMLStreamReader(new java.io.BufferedInputStream(raw, 1 << 16));
        try {
            int index = 0;
            while (r.hasNext()) {
                if (r.next() == javax.xml.stream.XMLStreamConstants.START_ELEMENT && r.getLocalName().equals("item")) {
                    java.util.Map<String, String> it = new java.util.HashMap<>();
                    java.util.Set<String> base64 = new java.util.HashSet<>();
                    readItem(r, it, base64);
                    sink.accept(toRaw(it, base64), index++);
                }
            }
        } finally {
            r.close();
        }
    }

    /** The first value of each element inside one item (what the DOM reader's getElementsByTagName(tag).item(0) gave). */
    private static void readItem(javax.xml.stream.XMLStreamReader r, java.util.Map<String, String> it, java.util.Set<String> base64) throws Exception {
        int depth = 1;
        while (depth > 0 && r.hasNext()) {
            int ev = r.next();
            if (ev == javax.xml.stream.XMLStreamConstants.START_ELEMENT) {
                String tag = r.getLocalName();
                boolean b64 = "true".equals(r.getAttributeValue(null, "base64"));
                String text;
                try {
                    text = r.getElementText();                 // consumes up to and including the end tag
                } catch (javax.xml.stream.XMLStreamException nested) {
                    depth++;                                   // an element with children: walk into it instead
                    continue;
                }
                if (!it.containsKey(tag)) {
                    it.put(tag, text);
                    if (b64) {
                        base64.add(tag);
                    }
                }
            } else if (ev == javax.xml.stream.XMLStreamConstants.END_ELEMENT) {
                depth--;
            }
        }
    }

    private static Parse.Raw toRaw(java.util.Map<String, String> it, java.util.Set<String> base64) {
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
        return new Parse.Raw(text(it, "method"), text(it, "host"),
                port != null && port.strip().matches("\\d+") ? Integer.parseInt(port.strip()) : 0, text(it, "protocol"),
                path, status, text(it, "mimetype"), blob(it, base64, "request"), blob(it, base64, "response"), it.containsKey("truncated"));
    }

    public static List<Exchange> read(File f, String role) throws Exception {
        List<Exchange> out = new ArrayList<>();
        forEach(f, (raw, i) -> {
            Exchange ex;
            try {
                ex = Parse.item(out.size() + 1, raw, role, f.getName(), i);
            } catch (RuntimeException e) {
                ex = null;
            }
            if (ex != null) {
                out.add(ex);
            }
        });
        return out;
    }
}
