package com.truecaller.backend.service.canon;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.json.JsonMapper;
import org.erdtman.jcs.JsonCanonicalizer;
import org.springframework.stereotype.Service;

/**
 * RFC 8785 JSON Canonicalization Scheme (JCS).
 *
 * <p>Used by the {@code eddsa-jcs-2022} cryptosuite (W3C-DI-EDDSA §3.2)
 * and by every place we need a deterministic byte representation of a
 * JSON object (e.g. status list verification, schema fingerprinting).
 */
@Service
public class JcsCanonicalizer {

    private final ObjectMapper mapper = JsonMapper.builder().build();

    public byte[] canonicalize(JsonNode node) {
        try {
            return new JsonCanonicalizer(mapper.writeValueAsString(node)).getEncodedUTF8();
        } catch (Exception e) {
            throw new RuntimeException("JCS canonicalisation failed", e);
        }
    }

    public byte[] canonicalize(Object pojo) {
        try {
            return new JsonCanonicalizer(mapper.writeValueAsString(pojo)).getEncodedUTF8();
        } catch (Exception e) {
            throw new RuntimeException("JCS canonicalisation failed", e);
        }
    }
}

