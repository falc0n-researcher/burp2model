package burp2model.engine;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.junit.jupiter.api.Test;

class JsonTest {
    /** What a saved file goes through: written, encoded as UTF-8, decoded, parsed. */
    private static Object throughDisk(Object v) {
        byte[] bytes = Json.write(v).getBytes(StandardCharsets.UTF_8);
        return Json.parse(new String(bytes, StandardCharsets.UTF_8));
    }

    @Test
    void roundTrip() {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("s", "quote \" slash \\ tab \t nl \n ctrl \u0001 é 中");
        m.put("n", 42L);
        m.put("neg", -7L);
        m.put("d", 1.5);
        m.put("t", true);
        m.put("f", false);
        m.put("z", null);
        m.put("l", List.of(1L, "two", List.of(), Map.of()));
        assertEquals(m, throughDisk(m));
    }

    @Test
    void surrogatePairsAndLoneSurrogatesSurviveUtf8() {
        String emoji = "a\uD83D\uDE00b";
        assertEquals(emoji, throughDisk(emoji), "a pair is written as is");
        String lone = "x\uD800y\uDFFFz";
        assertEquals(lone, throughDisk(lone), "a lone surrogate is escaped, not turned into '?'");
        assertTrue(Json.write(lone).contains("\\ud800"));
    }

    @ParameterizedTest
    @ValueSource(strings = {
        "{\"a\" 1}",          // missing colon
        "{\"a\":1 \"b\":2}",  // missing comma
        "[1 2]",
        "{1:2}",
        "{\"a\":\"b",         // cut off inside a string
        "{\"a\":",
        "[",
        "{",
        "\"\\u12",
        "\"\\uzzzz\"",
        "-",
        "1.2.3",
        "{\"a\":1}x",
    })
    void malformedInputIsATypedErrorWithAnOffset(String bad) {
        Json.JsonError e = assertThrows(Json.JsonError.class, () -> Json.parse(bad));
        assertTrue(e.offset >= 0 && e.offset <= bad.length(), e.getMessage());
    }

    @Test
    void aTruncatedSavedLineIsRejected() {
        String line = Json.write(Map.of("method", "GET", "path", "/api/x", "headers", List.of("a", "b")));
        for (int cut = 1; cut < line.length(); cut++) {
            String part = line.substring(0, cut);
            assertThrows(Json.JsonError.class, () -> Json.parse(part), "cut at " + cut);
        }
        assertFalse(Arrays.asList(line).isEmpty());
    }
}
