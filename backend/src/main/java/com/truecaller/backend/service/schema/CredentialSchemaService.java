package com.truecaller.backend.service.schema;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.json.JsonMapper;
import com.networknt.schema.JsonSchema;
import com.networknt.schema.JsonSchemaFactory;
import com.networknt.schema.SchemaValidatorsConfig;
import com.networknt.schema.SpecVersion;
import com.networknt.schema.ValidationMessage;
import org.springframework.core.io.ClassPathResource;
import org.springframework.stereotype.Service;

import java.io.InputStream;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Loads JSON Schema 2020-12 documents and validates {@code credentialSubject}
 * against them, per AGENT.md §6 step 7. Schemas live under
 * {@code resources/schemas/<name>.json} and are also exposed via
 * {@code /api/schemas/{name}.json} so the verifier can fetch them by URL.
 *
 * <p>For the demo, {@code credentialSchema.id}s pointing at
 * {@code https://truecaller.demo/schemas/<name>.json} are short-circuited to
 * the local resource so the test suite is offline-safe; this is documented
 * as out-of-scope behavior in AGENT.md §11.
 */
@Service
public class CredentialSchemaService {

    private static final String DEMO_HOST_PREFIX = "https://truecaller.demo/schemas/";
    private static final SchemaValidatorsConfig CFG = new SchemaValidatorsConfig();

    private final ObjectMapper mapper = JsonMapper.builder().build();
    private final JsonSchemaFactory factory =
            JsonSchemaFactory.getInstance(SpecVersion.VersionFlag.V202012);
    private final Map<String, JsonSchema> cache = new ConcurrentHashMap<>();

    /** Returns the raw schema JSON tree for serving over /api/schemas/{name}.json. */
    public JsonNode loadSchemaJson(String name) {
        try (InputStream in = new ClassPathResource("schemas/" + name + ".json").getInputStream()) {
            return mapper.readTree(in);
        } catch (Exception e) {
            throw new IllegalArgumentException("Unknown schema: " + name);
        }
    }

    /**
     * Validates {@code credentialSubject} against the schema referenced by
     * the credential's {@code credentialSchema.id}. Returns the set of
     * validation messages (empty = valid).
     */
    @SuppressWarnings("unchecked")
    public Set<String> validate(Map<String, Object> credential) {
        Object cs = credential.get("credentialSchema");
        if (!(cs instanceof Map<?, ?> csm))
            return Set.of("missing credentialSchema");
        String id = (String) ((Map<String, Object>) csm).get("id");
        if (id == null) return Set.of("credentialSchema.id missing");

        JsonSchema schema = resolve(id);
        if (schema == null) return Set.of("could not resolve credentialSchema: " + id);

        Object subject = credential.get("credentialSubject");
        if (subject == null) return Set.of("missing credentialSubject");
        JsonNode subjectNode = mapper.valueToTree(subject);

        Set<ValidationMessage> messages = schema.validate(subjectNode);
        java.util.LinkedHashSet<String> out = new java.util.LinkedHashSet<>();
        for (ValidationMessage m : messages) out.add(m.getMessage());
        return out;
    }

    /**
     * Same as {@link #validate} but tolerates absent claims — the caller is
     * verifying a BBS+ derived proof where {@code credentialSubject} legitimately
     * carries only the disclosed subset (AGENT.md §6 step 7 + §2.1). We ignore
     * any "required: …" violation while still failing on type / pattern errors
     * for whatever IS disclosed.
     */
    @SuppressWarnings("unchecked")
    public Set<String> validateDisclosed(Map<String, Object> credential) {
        Set<String> all = validate(credential);
        java.util.LinkedHashSet<String> filtered = new java.util.LinkedHashSet<>();
        for (String msg : all) {
            // networknt's JSON Schema validator phrases missing-required as
            // "required property '<name>' not found" — drop those, keep everything else.
            if (msg == null) continue;
            String lower = msg.toLowerCase();
            if (lower.contains("required") && lower.contains("not found")) continue;
            filtered.add(msg);
        }
        return filtered;
    }

    private JsonSchema resolve(String id) {
        return cache.computeIfAbsent(id, key -> {
            try {
                if (key.startsWith(DEMO_HOST_PREFIX)) {
                    String name = key.substring(DEMO_HOST_PREFIX.length()).replaceFirst("\\.json$", "");
                    JsonNode tree = loadSchemaJson(name);
                    return factory.getSchema(tree, CFG);
                }
                // Out of scope: fetching arbitrary schema URLs over the network.
                return null;
            } catch (Exception e) {
                return null;
            }
        });
    }
}

