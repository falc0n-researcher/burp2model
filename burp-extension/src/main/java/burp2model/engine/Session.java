package burp2model.engine;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;
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
    // read by the Swing thread while a background add writes them: copy-on-write, concurrent, or synchronized
    private final List<BuildInfo> builds = new CopyOnWriteArrayList<>();
    private final Map<Integer, Model> cache = new ConcurrentHashMap<>();
    /** node id -> {first build, last build}. */
    private final Map<String, int[]> nodeHistory = Collections.synchronizedMap(new LinkedHashMap<>());
    private volatile Model model;
    private volatile Set<String> roles = Set.of();
    /** The working model holds requests no recorded build has. */
    private boolean dirty;
    /** Exchanges and keys not yet appended to disk; a role replacement rewrites the whole file instead. */
    private final List<Exchange> pendingNew = new ArrayList<>();
    private final List<String> pendingKeys = new ArrayList<>();
    private boolean fullRewrite;

    private java.nio.channels.FileChannel lockChannel;
    private java.nio.channels.FileLock lock;

    /**
     * Hold the model's folder for this Burp: a second Burp (another process) opening the same model would
     * interleave writes. Released by close().
     */
    public synchronized void lock() throws IOException {
        if (lock != null) {
            return;
        }
        var ch = java.nio.channels.FileChannel.open(dir.resolve(".lock"), java.nio.file.StandardOpenOption.CREATE, java.nio.file.StandardOpenOption.WRITE);
        java.nio.channels.FileLock l;
        try {
            l = ch.tryLock();
        } catch (java.nio.channels.OverlappingFileLockException e) {
            l = null;
        }
        if (l == null) {
            ch.close();
            throw new IOException("the model '" + name + "' is open in another Burp; close it there or choose another model name");
        }
        lockChannel = ch;
        lock = l;
    }

    public synchronized void close() {
        try {
            if (lock != null) {
                lock.release();
            }
            if (lockChannel != null) {
                lockChannel.close();
            }
        } catch (IOException ignored) {
            // the process is going away or the file is gone; either way the lock is released
        }
        lock = null;
        lockChannel = null;
    }

    /** Stop the parsing threads (the extension is unloading); the next large add starts them again. */
    public static void shutdownPool() {
        synchronized (Session.class) {
            if (pool != null) {
                pool.shutdown();
                pool = null;
            }
        }
    }

    public Session(Path home, String name) throws IOException {
        this.name = name;
        this.dir = home.resolve(name);
        Files.createDirectories(dir.resolve("builds"));
        load();
    }

    public Model model() {
        return model;
    }

    /** The builds so far; safe to iterate while requests are being added. */
    public List<BuildInfo> builds() {
        return Collections.unmodifiableList(builds);
    }

    private BuildInfo lastBuild() {
        return builds.isEmpty() ? null : builds.get(builds.size() - 1);
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
            fullRewrite = true;
        }
        final String roleKey = role == null ? "" : role;
        int n = raws.size();
        String[] keys = new String[n];
        parallel(n, 32, i -> keys[i] = digest(raws.get(i), roleKey) + "@" + roleKey);
        List<Integer> todo = new ArrayList<>();
        int dup = 0;
        for (int i = 0; i < n; i++) {
            if (seen.add(keys[i])) {
                todo.add(i);
            } else {
                dup++;
            }
        }
        Exchange[] parsed = new Exchange[todo.size()];
        final int base = exchanges.size();
        parallel(todo.size(), 16, k -> {
            try {
                parsed[k] = Parse.item(0, raws.get(todo.get(k)), role, "burp", base + k);
            } catch (RuntimeException e) {
                parsed[k] = null;
            }
        });
        int added = 0;
        int skipped = 0;
        List<Exchange> fresh = new ArrayList<>();
        List<String> freshKeys = new ArrayList<>();
        for (int k = 0; k < parsed.length; k++) {
            if (parsed[k] == null) {
                skipped++;
                seen.remove(keys[todo.get(k)]);
            } else {
                parsed[k].item = base + added;
                exchanges.add(parsed[k]);
                fresh.add(parsed[k]);
                freshKeys.add(keys[todo.get(k)]);
                added++;
            }
        }
        if (added == 0 && !fullRewrite && model != null) {
            // nothing new, so the model is unchanged: no rebuild. A send is still a build; live capture uses snapshot().
            return new AddResult(0, dup, skipped, snapshot ? record(label) : null);
        }
        pendingNew.addAll(fresh);
        pendingKeys.addAll(freshKeys);
        BuildInfo b = rebuild(label, skipped, snapshot);
        return new AddResult(added, dup, skipped, b);
    }

    private static volatile java.util.concurrent.ForkJoinPool pool;

    /** Run body(i) for 0..n-1, on several threads when there is enough work to be worth it. */
    private static void parallel(int n, int threshold, java.util.function.IntConsumer body) {
        if (n < threshold) {
            for (int i = 0; i < n; i++) {
                body.accept(i);
            }
            return;
        }
        java.util.concurrent.ForkJoinPool fj = pool;
        if (fj == null) {
            synchronized (Session.class) {
                if (pool == null) {
                    pool = new java.util.concurrent.ForkJoinPool(Math.max(2, Runtime.getRuntime().availableProcessors() - 1),
                            p -> {
                                var t = java.util.concurrent.ForkJoinPool.defaultForkJoinWorkerThreadFactory.newThread(p);
                                t.setDaemon(true);
                                return t;
                            }, null, false);
                }
                fj = pool;
            }
        }
        try {
            fj.submit(() -> java.util.stream.IntStream.range(0, n).parallel().forEach(body)).get();
        } catch (InterruptedException | java.util.concurrent.ExecutionException e) {
            throw new IllegalStateException(e);
        }
    }

    /** Record the working model as a build, if it holds requests no build has yet; null when there is nothing new. */
    public synchronized BuildInfo snapshot(String label) throws IOException {
        return dirty && model != null ? record(label) : null;
    }

    public synchronized void clear() throws IOException {
        exchanges.clear();
        roles = Set.of();
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
        // session.json lists the builds just deleted; left behind, the model could not be opened again
        Files.deleteIfExists(dir.resolve("session.json"));
        pendingNew.clear();
        pendingKeys.clear();
        fullRewrite = false;
        dirty = false;
        Parse.clearCache();
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
        Set<String> r = new TreeSet<>();
        for (Exchange e : exchanges) {
            if (e.role != null) {
                r.add(e.role);
            }
        }
        roles = Collections.unmodifiableSet(r);
        dirty = true;
        if (!snapshot) {
            saveInputs();
            return null;
        }
        return record(label);
    }

    /** Keep the current model as the next build. */
    private BuildInfo record(String label) throws IOException {
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
        dirty = false;
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

    /** Write what is new since the last save: appended as one more gzip member, so a save costs the new requests, not all of them. */
    private void saveInputs() throws IOException {
        Path inputs = dir.resolve("inputs.jsonl.gz");
        Path seenFile = dir.resolve("seen.txt");
        if (fullRewrite || !Files.exists(inputs)) {
            StringBuilder in = new StringBuilder();
            for (Exchange e : exchanges) {
                in.append(Json.write(e.toMap())).append('\n');
            }
            writeGz(inputs, in.toString());
            // end with a newline: later batches are appended, and without it the next key would join this last one
            writeText(seenFile, seen.isEmpty() ? "" : String.join("\n", seen) + "\n");
            fullRewrite = false;
        } else if (!pendingNew.isEmpty()) {
            StringBuilder in = new StringBuilder();
            for (Exchange e : pendingNew) {
                in.append(Json.write(e.toMap())).append('\n');
            }
            try (GZIPOutputStream out = new GZIPOutputStream(Files.newOutputStream(inputs, java.nio.file.StandardOpenOption.APPEND))) {
                out.write(in.toString().getBytes(StandardCharsets.UTF_8));
            }
            Files.writeString(seenFile, String.join("\n", pendingKeys) + "\n", StandardCharsets.UTF_8,
                    java.nio.file.StandardOpenOption.CREATE, java.nio.file.StandardOpenOption.APPEND);
        }
        pendingNew.clear();
        pendingKeys.clear();
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
        writeText(dir.resolve("session.json"), Json.write(meta));
    }

    /** What went wrong reading the saved model, if anything; the damaged files were kept next to it as *.corrupt-<time>. */
    public List<String> problems() {
        return List.copyOf(problems);
    }

    private final List<String> problems = new ArrayList<>();

    /**
     * Read what can be read. Nothing is ever cleared because a file is damaged: a bad session.json or a torn
     * inputs file is copied aside first, then the model carries on with everything that parsed.
     */
    @SuppressWarnings("unchecked")
    private void load() throws IOException {
        Path meta = dir.resolve("session.json");
        if (Files.exists(meta)) {
            try {
                Map<String, Object> m = (Map<String, Object>) Json.parse(Files.readString(meta, StandardCharsets.UTF_8));
                List<String> sc = new ArrayList<>((List<String>) m.getOrDefault("scope", List.of()));
                List<BuildInfo> bs = new ArrayList<>();
                for (Object o : (List<Object>) m.get("builds")) {
                    Map<String, Object> b = (Map<String, Object>) o;
                    bs.add(new BuildInfo(((Number) b.get("id")).intValue(), (String) b.get("built_at"), (String) b.get("label"),
                            ((Number) b.get("nodes")).intValue(), ((Number) b.get("edges")).intValue(), ((Number) b.get("requests")).intValue()));
                }
                Map<String, int[]> hist = new LinkedHashMap<>();
                ((Map<String, Object>) m.getOrDefault("history", Map.of())).forEach((k, v) -> {
                    List<Object> l = (List<Object>) v;
                    hist.put(k, new int[] {((Number) l.get(0)).intValue(), ((Number) l.get(1)).intValue()});
                });
                // keep the builds up to the first one whose file is missing, so build ids stay 1..n
                int kept = 0;
                while (kept < bs.size() && kept + 1 == bs.get(kept).id()
                        && Files.exists(dir.resolve("builds").resolve(bs.get(kept).id() + ".json.gz"))) {
                    kept++;
                }
                scope = sc;
                builds.addAll(bs.subList(0, kept));
                final int last = kept;
                hist.forEach((k, v) -> {
                    if (v[0] <= last) {
                        nodeHistory.put(k, new int[] {v[0], Math.min(last, v[1])});
                    }
                });
            } catch (RuntimeException e) {
                // the build list is unreadable: keep it and the builds aside, and start the history again from the requests
                String at = stamp();
                Files.move(meta, dir.resolve("session.json.corrupt-" + at));
                Path old = dir.resolve("builds");
                if (Files.exists(old)) {
                    Files.move(old, dir.resolve("builds.corrupt-" + at));
                }
                Files.createDirectories(dir.resolve("builds"));
                builds.clear();
                nodeHistory.clear();
                problems.add("session.json could not be read (" + e.getMessage() + "); the build history starts again. The old files are kept as *.corrupt-" + at + ".");
            }
        }
        readInputs();
        try {
            if (!exchanges.isEmpty()) {
                // the working model may hold live-captured requests newer than the last build: rebuild it from the inputs
                rebuild(null, 0, false);
                BuildInfo b = lastBuild();
                dirty = b == null || b.requests() != exchanges.size();
            } else if (!builds.isEmpty()) {
                model = buildModel(lastBuild().id());
            }
        } catch (IOException | RuntimeException e) {
            model = null;
            problems.add("the saved model could not be rebuilt (" + e + "); the saved requests are untouched.");
        }
    }

    @SuppressWarnings("unchecked")
    private void readInputs() throws IOException {
        Path inputs = dir.resolve("inputs.jsonl.gz");
        Path seenFile = dir.resolve("seen.txt");
        List<String> keys = new ArrayList<>();
        if (Files.exists(seenFile)) {
            for (String line : Files.readString(seenFile, StandardCharsets.UTF_8).split("\n")) {
                // models saved before 1.1.1 can have two keys on one line (the first save had no final newline)
                for (String k : GLUED_KEY.split(line)) {
                    if (!k.isBlank()) {
                        keys.add(k);
                    }
                }
            }
        }
        if (Files.exists(inputs)) {
            GzText in = readGzTolerant(inputs);
            int bad = 0;
            // seen.txt is written in the same order as the requests: line i is the key of request i
            List<Integer> readLines = new ArrayList<>();
            int lineNo = 0;
            for (String line : in.text().split("\n")) {
                if (line.isBlank()) {
                    continue;
                }
                try {
                    exchanges.add(Exchange.fromMap((Map<String, Object>) Json.parse(line)));
                    readLines.add(lineNo);
                } catch (RuntimeException e) {
                    bad++;
                }
                lineNo++;
            }
            if (in.torn() || bad > 0) {
                // forget the keys of requests that were lost, so sending them again adds them back
                List<String> kept = new ArrayList<>();
                for (int i : readLines) {
                    if (i < keys.size()) {
                        kept.add(keys.get(i));
                    }
                }
                keys = kept;
                // keep the damaged file, and write a clean one on the next save: appending after a torn end would hide what follows
                String at = stamp();
                Files.copy(inputs, dir.resolve("inputs.jsonl.gz.corrupt-" + at));
                fullRewrite = true;
                problems.add("the saved requests were damaged (" + (in.torn() ? "cut off at the end" : "") + (in.torn() && bad > 0 ? ", " : "")
                        + (bad > 0 ? bad + " unreadable" : "") + "); " + exchanges.size() + " were read. The old file is kept as inputs.jsonl.gz.corrupt-" + at + ".");
            }
        }
        seen.addAll(keys);
    }

    /** A key is 64 hex digits, '@' and the role; a second key starting mid-line is split off. */
    private static final java.util.regex.Pattern GLUED_KEY = java.util.regex.Pattern.compile("(?<=.)(?=[0-9a-f]{64}@)");

    private static String stamp() {
        return Instant.now().toString().replaceAll("[^0-9]", "").substring(0, 14);
    }

    /** Write to a temporary file beside the target, then move it into place: a crash leaves the old file or the new one, never half of either. */
    private static void writeAtomic(Path p, byte[] data) throws IOException {
        Path tmp = p.resolveSibling(p.getFileName() + ".tmp");
        Files.write(tmp, data);
        try {
            Files.move(tmp, p, java.nio.file.StandardCopyOption.ATOMIC_MOVE, java.nio.file.StandardCopyOption.REPLACE_EXISTING);
        } catch (java.nio.file.AtomicMoveNotSupportedException e) {
            Files.move(tmp, p, java.nio.file.StandardCopyOption.REPLACE_EXISTING);
        }
    }

    private static void writeText(Path p, String text) throws IOException {
        writeAtomic(p, text.getBytes(StandardCharsets.UTF_8));
    }

    private static void writeGz(Path p, String text) throws IOException {
        java.io.ByteArrayOutputStream buf = new java.io.ByteArrayOutputStream();
        try (GZIPOutputStream out = new GZIPOutputStream(buf)) {
            out.write(text.getBytes(StandardCharsets.UTF_8));
        }
        writeAtomic(p, buf.toByteArray());
    }

    private static String readGz(Path p) throws IOException {
        try (GZIPInputStream in = new GZIPInputStream(Files.newInputStream(p))) {
            return new String(in.readAllBytes(), StandardCharsets.UTF_8);
        }
    }

    record GzText(String text, boolean torn) {}

    /**
     * Read every gzip member of an appended file, member by member with exact byte accounting. Anything after the
     * last complete member (a crash mid-append, however short) marks the file torn; the complete members are kept.
     */
    static GzText readGzTolerant(Path p) throws IOException {
        byte[] f = Files.readAllBytes(p);
        java.io.ByteArrayOutputStream out = new java.io.ByteArrayOutputStream();
        int pos = 0;
        boolean torn = false;
        byte[] buf = new byte[64 * 1024];
        while (pos < f.length) {
            int body = gzipHeaderEnd(f, pos);
            if (body < 0) {
                torn = true;
                break;
            }
            java.util.zip.Inflater inf = new java.util.zip.Inflater(true);
            java.util.zip.CRC32 crc = new java.util.zip.CRC32();
            java.io.ByteArrayOutputStream member = new java.io.ByteArrayOutputStream();
            try {
                inf.setInput(f, body, f.length - body);
                while (!inf.finished()) {
                    int n = inf.inflate(buf);
                    if (n == 0 && (inf.needsInput() || inf.needsDictionary())) {
                        break;
                    }
                    member.write(buf, 0, n);
                    crc.update(buf, 0, n);
                }
                if (!inf.finished()) {
                    torn = true;
                    break;
                }
                int trailer = f.length - inf.getRemaining();
                if (trailer + 8 > f.length || le32(f, trailer) != (int) crc.getValue() || le32(f, trailer + 4) != (int) inf.getBytesWritten()) {
                    torn = true;
                    break;
                }
                member.writeTo(out);
                pos = trailer + 8;
            } catch (java.util.zip.DataFormatException e) {
                torn = true;
                break;
            } finally {
                inf.end();
            }
        }
        return new GzText(out.toString(StandardCharsets.UTF_8), torn);
    }

    private static int le32(byte[] b, int i) {
        return (b[i] & 0xff) | (b[i + 1] & 0xff) << 8 | (b[i + 2] & 0xff) << 16 | (b[i + 3] & 0xff) << 24;
    }

    /** Where a gzip member's deflate data starts, or -1 if no complete header is there. */
    private static int gzipHeaderEnd(byte[] b, int pos) {
        if (pos + 10 > b.length || (b[pos] & 0xff) != 0x1f || (b[pos + 1] & 0xff) != 0x8b || b[pos + 2] != 8) {
            return -1;
        }
        int flags = b[pos + 3] & 0xff;
        int i = pos + 10;
        if ((flags & 4) != 0) {
            if (i + 2 > b.length) {
                return -1;
            }
            i += 2 + ((b[i] & 0xff) | (b[i + 1] & 0xff) << 8);
        }
        for (int bit : new int[] {8, 16}) {
            if ((flags & bit) != 0) {
                while (i < b.length && b[i] != 0) {
                    i++;
                }
                i++;
            }
        }
        if ((flags & 2) != 0) {
            i += 2;
        }
        return i <= b.length ? i : -1;
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> readMap(Path p) throws IOException {
        return (Map<String, Object>) Json.parse(readGz(p));
    }

    public Set<String> roles() {
        return roles;
    }
}
