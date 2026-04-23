package com.truecaller.backend.dto;

import java.util.List;
import java.util.Map;

public record PresentRequest(
        String holderDid,
        List<Map<String, Object>> verifiableCredentials,
        List<ProofRequestItem> proofRequest,
        /* Verifier DID — bound into the KB-JWT 'aud' for replay protection. */
        String verifierDid,
        /* Verifier-supplied nonce — bound into the KB-JWT 'nonce'. */
        String nonce
) {
    public record ProofRequestItem(
            String field,       // credential field name, e.g. "dateOfBirth"
            String operator,    // "age_gte", "neq", "eq", "exists", "gte", "lt", etc.
            String value,       // comparison value, e.g. "21", "B+"
            boolean disclose    // if true, include raw value; if false, only include derived boolean
    ) {}
}
