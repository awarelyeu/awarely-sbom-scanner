package io.jenkins.plugins.awarely;

import com.fasterxml.jackson.core.JsonFactory;
import com.fasterxml.jackson.core.StreamReadConstraints;
import com.fasterxml.jackson.core.StreamReadFeature;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.IOException;

final class BoundedJson {
    static final int LIMIT = 5 * 1024 * 1024;
    private static final ObjectMapper MAPPER = new ObjectMapper(JsonFactory.builder()
                    .streamReadConstraints(StreamReadConstraints.builder()
                            .maxNestingDepth(32)
                            .maxStringLength(65536)
                            .maxNumberLength(64)
                            .build())
                    .enable(StreamReadFeature.STRICT_DUPLICATE_DETECTION)
                    .build())
            .enable(DeserializationFeature.FAIL_ON_TRAILING_TOKENS);

    private BoundedJson() {}

    static JsonNode read(byte[] bytes) throws IOException {
        if (bytes.length == 0 || bytes.length > LIMIT) throw new IOException("Result size is invalid");
        try {
            JsonNode n = MAPPER.readTree(bytes);
            if (n == null || !n.isObject()) throw new IOException("Expected a result object");
            return n;
        } catch (IOException e) {
            throw new IOException("Result is not valid bounded JSON");
        }
    }

    static String text(JsonNode n, String key, int limit) throws IOException {
        JsonNode value = n.get(key);
        if (value == null
                || !value.isTextual()
                || value.textValue().length() > limit
                || value.textValue()
                        .codePoints()
                        .anyMatch(c -> Character.isISOControl(c) || Character.getType(c) == Character.FORMAT)) {
            throw new IOException("Result contains an invalid text field");
        }
        return value.textValue();
    }

    static int count(JsonNode n, String key, int max) throws IOException {
        JsonNode v = n.get(key);
        if (v == null || !v.isIntegralNumber() || !v.canConvertToInt() || v.intValue() < 0 || v.intValue() > max)
            throw new IOException("Result contains an invalid count");
        return v.intValue();
    }
}
