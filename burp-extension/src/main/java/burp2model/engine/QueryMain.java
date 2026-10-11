package burp2model.engine;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/** java ... QueryMain model.json queries.json: runs each query and prints the results as JSON (for parity tests). */
public final class QueryMain {
    private QueryMain() {}

    @SuppressWarnings("unchecked")
    public static void main(String[] a) throws Exception {
        Model m = Model.fromMap((Map<String, Object>) Json.parse(Files.readString(Path.of(a[0]), StandardCharsets.UTF_8)));
        List<Object> queries = (List<Object>) Json.parse(Files.readString(Path.of(a[1]), StandardCharsets.UTF_8));
        Query q = new Query(m);
        List<Object> out = new ArrayList<>();
        for (Object s : queries) {
            Map<String, Object> r = new LinkedHashMap<>();
            try {
                Query.Result res = q.run((String) s);
                r.put("ok", true);
                r.put("kind", res.kind());
                r.put("columns", res.columns());
                r.put("rows", res.rows());
                r.put("total", (long) res.total());
                r.put("note", res.note());
            } catch (Query.QueryError e) {
                r.put("ok", false);
                r.put("error", e.getMessage());
            }
            out.add(r);
        }
        System.out.println(Json.write(out));
    }
}
