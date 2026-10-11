package burp2model.engine;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Map;

/** java ... DiffMain old.json new.json: prints the diff as JSON (for parity tests). */
public final class DiffMain {
    private DiffMain() {}

    @SuppressWarnings("unchecked")
    public static void main(String[] a) throws Exception {
        Model o = Model.fromMap((Map<String, Object>) Json.parse(Files.readString(Path.of(a[0]), StandardCharsets.UTF_8)));
        Model n = Model.fromMap((Map<String, Object>) Json.parse(Files.readString(Path.of(a[1]), StandardCharsets.UTF_8)));
        Map<String, Object> d = Diff.diff(o, n, Map.of("id", 1L), Map.of("id", 2L), null);
        if (a.length > 2) {
            System.out.println(Diff.formatText(d));
        } else {
            System.out.println(Json.write(d));
        }
    }
}
