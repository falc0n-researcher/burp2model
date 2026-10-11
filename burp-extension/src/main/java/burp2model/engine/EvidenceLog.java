package burp2model.engine;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.util.AbstractList;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.zip.Deflater;
import java.util.zip.DeflaterOutputStream;
import java.util.zip.InflaterInputStream;

/**
 * The request log behind every citation. Each entry keeps its small fields as a map and its masked request and
 * response panes as compressed JSON (about a sixth of the memory); reading an entry gives the same full map as before.
 */
public final class EvidenceLog extends AbstractList<Map<String, Object>> implements Json.Writable {
    private record Row(Map<String, Object> meta, byte[] z, String reqPath) {}

    private final List<Row> rows = new ArrayList<>();

    // ---- panes <-> bytes

    /** Compress the {request, response} object's JSON. */
    public static byte[] pack(Map<String, Object> panes) {
        if (panes == null || panes.isEmpty()) {
            return new byte[0];
        }
        Map<String, Object> only = new LinkedHashMap<>();
        only.put("request", panes.get("request"));
        only.put("response", panes.get("response"));
        return deflate(Json.write(only).getBytes(StandardCharsets.UTF_8));
    }

    private static byte[] deflate(byte[] raw) {
        ByteArrayOutputStream out = new ByteArrayOutputStream(raw.length / 4 + 32);
        Deflater d = new Deflater(2);
        try (DeflaterOutputStream z = new DeflaterOutputStream(out, d)) {
            z.write(raw);
        } catch (java.io.IOException e) {
            throw new IllegalStateException(e);
        } finally {
            d.end();
        }
        return out.toByteArray();
    }

    static String inflate(byte[] z) {
        try (InflaterInputStream in = new InflaterInputStream(new java.io.ByteArrayInputStream(z))) {
            return new String(in.readAllBytes(), StandardCharsets.UTF_8);
        } catch (java.io.IOException e) {
            throw new IllegalStateException(e);
        }
    }

    @SuppressWarnings("unchecked")
    public static Map<String, Object> unpack(byte[] z) {
        return z == null || z.length == 0 ? new LinkedHashMap<>() : (Map<String, Object>) Json.parse(inflate(z));
    }

    // ---- the list

    /** Add an entry whose panes are already compressed (what a parsed exchange carries). */
    public void add(Map<String, Object> meta, byte[] z, String reqPath) {
        rows.add(new Row(meta, z, reqPath));
    }

    /** Add a full entry (as read from a saved model). */
    @Override
    public boolean add(Map<String, Object> entry) {
        Map<String, Object> meta = new LinkedHashMap<>(entry);
        Object rq = meta.remove("request");
        Object rs = meta.remove("response");
        Map<String, Object> panes = new LinkedHashMap<>();
        if (rq != null || rs != null) {
            panes.put("request", rq);
            panes.put("response", rs);
        }
        rows.add(new Row(meta, pack(panes), pathOf(rq)));
        return true;
    }

    @SuppressWarnings("unchecked")
    private static String pathOf(Object request) {
        if (request instanceof Map<?, ?> m) {
            String[] parts = String.valueOf(((Map<String, Object>) m).getOrDefault("line", "")).split(" ");
            return parts.length >= 2 ? parts[1] : "";
        }
        return "";
    }

    @Override
    public Map<String, Object> get(int i) {
        Row r = rows.get(i);
        Map<String, Object> full = new LinkedHashMap<>(r.meta());
        if (r.z().length > 0) {
            Map<String, Object> panes = unpack(r.z());
            full.put("request", panes.get("request"));
            full.put("response", panes.get("response"));
        }
        return full;
    }

    @Override
    public int size() {
        return rows.size();
    }

    /** The small fields of entry i (no unpacking). */
    public Map<String, Object> meta(int i) {
        return rows.get(i).meta();
    }

    /** The redacted request path of entry i, as the request line shows it. */
    public String path(int i) {
        return rows.get(i).reqPath();
    }

    /** Every entry's small fields, without unpacking any pane. */
    public List<Map<String, Object>> metas() {
        List<Map<String, Object>> out = new ArrayList<>(rows.size());
        for (Row r : rows) {
            out.add(r.meta());
        }
        return out;
    }

    /** The entry whose id is `id`, or null. Ids are 1-based and usually equal to position + 1. */
    public Map<String, Object> byId(int id) {
        int i = indexOfId(id);
        return i < 0 ? null : get(i);
    }

    public int indexOfId(int id) {
        int guess = id - 1;
        if (guess >= 0 && guess < rows.size() && ((Number) rows.get(guess).meta().get("id")).intValue() == id) {
            return guess;
        }
        for (int i = 0; i < rows.size(); i++) {
            if (((Number) rows.get(i).meta().get("id")).intValue() == id) {
                return i;
            }
        }
        return -1;
    }

    /** Pane i's compressed bytes (to persist or copy without a round trip). */
    public byte[] packed(int i) {
        return rows.get(i).z();
    }

    // ---- writing

    @Override
    public void writeTo(StringBuilder sb, int indent, int depth) {
        if (indent >= 0) {
            Json.writeIterable(sb, this, indent, depth);       // pretty output goes the ordinary way
            return;
        }
        sb.append('[');
        boolean first = true;
        for (Row r : rows) {
            if (!first) {
                sb.append(',');
            }
            first = false;
            String meta = Json.write(r.meta());
            if (r.z().length == 0) {
                sb.append(meta);
            } else {
                String panes = inflate(r.z());                      // {"request":..,"response":..}
                sb.append(meta, 0, meta.length() - 1).append(',').append(panes, 1, panes.length());
            }
        }
        sb.append(']');
    }
}
