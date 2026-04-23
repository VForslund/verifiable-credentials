package com.truecaller.backend.dto;

import java.util.List;
import java.util.Map;

public record VerifyRequest(
        Map<String, Object> presentation,
        List<Assertion> assertions,
        /* Audience the verifier expects to find in the KB-JWT (its own DID). */
        String expectedAud,
        /* Nonce the verifier issued earlier; must match KB-JWT nonce. */
        String expectedNonce
) {
    public record Assertion(
            String field,       // e.g. "dateOfBirth", "bloodType", "degree"
            String operator,    // "gte", "lte", "eq", "neq", "exists", "age_gte", "age_lte"
            String value        // e.g. "21", "B+", "Bachelor of Science"
    ) {}
}
