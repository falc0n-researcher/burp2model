package burp2model.engine;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;
import java.util.zip.GZIPInputStream;
import java.util.zip.GZIPOutputStream;

/**
 * One app's working state inside Burp: every exchange sent so far, the current model, and the history of builds.
 * Each add is a build; builds are kept so what changed between them can be diffed. Everything lives on disk
 * under one folder, redacted: names and shapes only.
 */
public final class Session {
    public record BuildInfo(int id, String builtAt, String label, int nodes, int edges, int requests) {}

    private final Path dir;
    public String name;
    public List<String> scope = new ArrayList<>();
    private final List<Exchange> exchanges = new ArrayList<>();
    private final Set<String> seen = new LinkedHashSet<>();
    private final List<BuildInfo> builds = new ArrayList<>();
    private final Map<Integer, Model> cache = new LinkedHashMap<>();
    /** node id -> {first build, last build}. */
    private final Map<String, int[]> nodeHistory = new LinkedHashMap<>();
    private Model model;

    public Session(Path home, String name) throws IOException {
        this.name = name;
        this.dir = home.resolve(name);
        Files.createDirectories(dir.resolve("builds"));
        load();
    }

    public Model model() {
        return model;
    }

    public List<BuildInfo> builds() {
        return builds;
    }

    public int requestCount() {
        return exchanges.size();
    }

    public Path dir() {
        return dir;
    }

    public int[] historyOf(String nodeId) {
        return nodeHistory.get(nodeId);
    }

    // ----------------------------------------------------------------- adding

    private static String digest(Parse.Raw r, String role) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            md.update((r.method() + "|" + r.host() + "|" + r.port() + "|" + r.path() + "|" + role + "|").getBytes(StandardCharsets.UTF_8));
            if (r.request() != null) {
                md.update(r.request());
            }
            md.update((byte) 0);
            if (r.response() != null) {
                md.update(r.response());
            }
            StringBuilder sb = new StringBuilder();
            for (byte b : md.digest()) {
                sb.append(String.format("%02x", b));
            }
            return sb.toString();
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    public record AddResult(int added, int duplicates, int skipped, BuildInfo build) {}

    /** Parse and add requests (the same request seen again is not added twice), then rebuild and keep the build. */
    public synchronized AddResult add(List<Parse.Raw> raws, String role, String label, boolean replaceRole) throws IOException {
        return add(raws, role, label, replaceRole, true);
    }

    /** `snapshot` false keeps the new requests in the working model without recording a build (live capture). */
    public synchronized AddResult add(List<Parse.Raw> raws, String role, String label, boolean replaceRole, boolean snapshot) throws IOException {
        if (replaceRole && role != null) {
            exchanges.removeIf(e -> role.equals(e.role));
            seen.removeIf(s -> s.endsWith("@" + role));
        }
        int added = 0;
        int dup = 0;
        int skipped = 0;
        for (Parse.Raw r : raws) {
            String key = digest(r, role == null ? "" : role) + "@" + (role == null ? "" : role);
            if (!seen.add(key)) {
                dup++;
                continue;
            }
            Exchange ex;
            try {
                ex = Parse.item(exchanges.size() + 1, r, role, "burp", exchanges.size());
            } catch (RuntimeException e) {
                ex = null;
            }
            if (ex == null) {
                skipped++;
                seen.remove(key);
                continue;
            }
            exchanges.add(ex);
            added++;
        }
        if (added == 0 && replaceRole == false && !snapshot) {
            return new AddResult(0, dup, skipped, null);
        }
        BuildInfo b = rebuild(label, skipped, snapshot);
        return new AddResult(added, dup, skipped, b);
    }

    public synchronized void clear() throws IOException {
        exchanges.clear();
        seen.clear();
        builds.clear();
        cache.clear();
        nodeHistory.clear();
        model = null;
        try (var s = Files.list(dir.resolve("builds"))) {
            for (Path p : (Iterable<Path>) s::iterator) {
                Files.deleteIfExists(p);
            }
        }
        Files.deleteIfExists(dir.resolve("inputs.jsonl.gz"));
        Files.deleteIfExists(dir.resolve("seen.txt"));
    }

    private BuildInfo rebuild(String label, int skipped, boolean snapshot) throws IOException {
        // evidence ids are 1-based and stable across the exchanges kept so far; folding starts from the raw paths each time
        for (int i = 0; i < exchanges.size(); i++) {
            Exchange e = exchanges.get(i);
            e.index = i + 1;
            if (e.rawTemplate != null) {
                e.pathTemplate = e.rawTemplate;
                e.refererPath = e.rawRefererPath;
            }
        }
        Map<String, Object> stats = new LinkedHashMap<>();
        stats.put("items", (long) exchanges.size() + skipped);
        stats.put("parsed", (long) exchanges.size());
        stats.put("skipped", (long) skipped);
        List<Exchange> copy = new ArrayList<>(exchanges);
        model = Builder.build(copy, name, null, scope.isEmpty() ? null : scope, stats);
        if (!snapshot) {
            saveInputs();
            return null;
        }
        int id = builds.size() + 1;
        BuildInfo info = new BuildInfo(id, Instant.now().toString().substring(0, 19) + "Z",
                label == null || label.isBlank() ? "build " + id : label, model.nodes.size(), model.edges.size(), model.evidenceLog.size());
        builds.add(info);
        cache.put(id, model);
        for (String nid : model.nodes.keySet()) {
            int[] h = nodeHistory.get(nid);
            if (h == null) {
                nodeHistory.put(nid, new int[] {id, id});
            } else {
                h[1] = id;
            }
        }
        save(info);
        return info;
    }

    // ----------------------------------------------------------------- diff

    public Model buildModel(int id) throws IOException {
        Model m = cache.get(id);
        if (m == null) {
            Path p = dir.resolve("builds").resolve(id + ".json.gz");
            m = Model.fromMap(readMap(p));
            cache.put(id, m);
        }
        return m;
    }

    public Map<String, Object> diff(int older, int newer) throws IOException {
        Model a = buildModel(older);
        Model b = buildModel(newer);
        Map<String, Object> ma = new LinkedHashMap<>();
        Map<String, Object> mb = new LinkedHashMap<>();
        BuildInfo ia = builds.get(older - 1);
        BuildInfo ib = builds.get(newer - 1);
        ma.put("id", (long) ia.id());
        ma.put("built_at", ia.builtAt());
        mb.put("id", (long) ib.id());
        mb.put("built_at", ib.builtAt());
        return Diff.diff(a, b, ma, mb, null);
    }

    // ----------------------------------------------------------------- disk

    private void saveInputs() throws IOException {
        StringBuilder in = new StringBuilder();
        for (Exchange e : exchanges) {
            in.append(Json.write(e.toMap())).append('\n');
        }
        writeGz(dir.resolve("inputs.jsonl.gz"), in.toString());
        Files.writeString(dir.resolve("seen.txt"), String.join("\n", seen), StandardCharsets.UTF_8);
    }

    private void save(BuildInfo info) throws IOException {
        writeGz(dir.resolve("builds").resolve(info.id() + ".json.gz"), Json.write(model.toMap()));
        saveInputs();
        List<Object> list = new ArrayList<>();
        for (BuildInfo b : builds) {
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("id", (long) b.id());
            m.put("built_at", b.builtAt());
            m.put("label", b.label());
            m.put("nodes", (long) b.nodes());
            m.put("edges", (long) b.edges());
            m.put("requests", (long) b.requests());
            list.add(m);
        }
        Map<String, Object> meta = new LinkedHashMap<>();
        meta.put("name", name);
        meta.put("scope", scope);
        meta.put("builds", list);
        Map<String, Object> hist = new LinkedHashMap<>();
        nodeHistory.forEach((k, v) -> hist.put(k, List.of((long) v[0], (long) v[1])));
        meta.put("history", hist);
        Files.writeString(dir.resolve("session.json"), Json.write(meta), StandardCharsets.UTF_8);
    }

    @SuppressWarnings("unchecked")
    private void load() throws IOException {
        Path meta = dir.resolve("session.json");
        if (!Files.exists(meta)) {
            return;
        }
        try {
            Map<String, Object> m = (Map<String, Object>) Json.parse(Files.readString(meta, StandardCharsets.UTF_8));
            scope = new ArrayList<>((List<String>) m.getOrDefault("scope", List.of()));
            for (Object o : (List<Object>) m.get("builds")) {
                Map<String, Object> b = (Map<String, Object>) o;
                builds.add(new BuildInfo(((Number) b.get("id")).intValue(), (String) b.get("built_at"), (String) b.get("label"),
                        ((Number) b.get("nodes")).intValue(), ((Number) b.get("edges")).intValue(), ((Number) b.get("requests")).intValue()));
            }
            ((Map<String, Object>) m.getOrDefault("history", Map.of())).forEach((k, v) -> {
                List<Object> l = (List<Object>) v;
                nodeHistory.put(k, new int[] {((Number) l.get(0)).intValue(), ((Number) l.get(1)).intValue()});
            });
            Path inputs = dir.resolve("inputs.jsonl.gz");
            if (Files.exists(inputs)) {
                for (String line : readGz(inputs).split("\n")) {
                    if (!line.isBlank()) {
                        exchanges.add(Exchange.fromMap((Map<String, Object>) Json.parse(line)));
                    }
                }
            }
            Path seenFile = dir.resolve("seen.txt");
            if (Files.exists(seenFile)) {
                for (String s : Files.readString(seenFile, StandardCharsets.UTF_8).split("\n")) {
                    if (!s.isBlank()) {
                        seen.add(s);
                    }
                }
            }
            if (!exchanges.isEmpty()) {
                // the working model may hold live-captured requests newer than the last build: rebuild it from the inputs
                rebuild(null, 0, false);
            } else if (!builds.isEmpty()) {
                model = buildModel(builds.get(builds.size() - 1).id());
            }
        } catch (RuntimeException e) {
            // an unreadable saved session starts over rather than blocking the tab
            exchanges.clear();
            seen.clear();
            builds.clear();
            nodeHistory.clear();
            model = null;
        }
    }

    private static void writeGz(Path p, String text) throws IOException {
        try (GZIPOutputStream out = new GZIPOutputStream(Files.newOutputStream(p))) {
            out.write(text.getBytes(StandardCharsets.UTF_8));
        }
    }

    private static String readGz(Path p) throws IOException {
        try (GZIPInputStream in = new GZIPInputStream(Files.newInputStream(p))) {
            return new String(in.readAllBytes(), StandardCharsets.UTF_8);
        }
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> readMap(Path p) throws IOException {
        return (Map<String, Object>) Json.parse(readGz(p));
    }

    public Set<String> roles() {
        Set<String> r = new TreeSet<>();
        exchanges.forEach(e -> {
            if (e.role != null) {
                r.add(e.role);
            }
        });
        return r;
    }
}
