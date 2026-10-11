package burp2model.engine;

import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/** java -cp ... burp2model.engine.Dump export.xml out.json [scope]: builds the model and writes model.json. */
public final class Dump {
    private Dump() {}

    public static void main(String[] a) throws Exception {
        List<Exchange> ex = BurpXml.read(new File(a[0]), null);
        Map<String, Object> stats = new LinkedHashMap<>();
        stats.put("items", (long) ex.size());
        Model m = Builder.build(ex, a.length > 2 ? a[2] : "app", null, null, stats);
        Files.writeString(Path.of(a[1]), Json.pretty(m.toMap()), StandardCharsets.UTF_8);
        System.out.println(m.counts());
    }
}
