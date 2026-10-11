package burp2model.engine;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

/** java ... RedactMain texts.json: prints what the redaction that runs on stored text makes of each text (for parity tests). */
public final class RedactMain {
    private RedactMain() {}

    public static void main(String[] a) throws Exception {
        List<?> texts = (List<?>) Json.parse(Files.readString(Path.of(a[0]), StandardCharsets.UTF_8));
        List<Object> out = new ArrayList<>();
        for (Object t : texts) {
            out.add(Redact.redactNamed(Redact.redactValuePatterns((String) t).value()));
        }
        System.out.println(Json.write(out));
    }
}
