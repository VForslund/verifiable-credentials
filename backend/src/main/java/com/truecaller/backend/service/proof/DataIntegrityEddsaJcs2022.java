package com.truecaller.backend.service.proof;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.json.JsonMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.truecaller.backend.service.canon.JcsCanonicalizer;
import com.truecaller.backend.service.crypto.Ed25519KeyService;
import org.springframework.stereotype.Service;

import java.security.MessageDigest;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * W3C Data Integrity {@code eddsa-jcs-2022} cryptosuite (W3C-DI-EDDSA §3).
 *
 * <p>Signing input = {@code SHA-256(JCS(proofOptions)) || SHA-256(JCS(unsecuredDocument))}.
 * Signed with Ed25519. {@code proofValue} is multibase base58btc.
 *
 * <p>Supports the {@code proofPurpose}s required by VCDM 2.0:
 * {@code assertionMethod} (issuer-signed credentials) and {@code authentication}
 * (holder-signed presentations, with {@code domain} + {@code challenge} per §6.2.1).
 */
@Service
public class DataIntegrityEddsaJcs2022 {

    public static final String CRYPTOSUITE = "eddsa-jcs-2022";

    private final Ed25519KeyService keys;
    private final JcsCanonicalizer jcs;
    private final ObjectMapper mapper = JsonMapper.builder().build();

    public DataIntegrityEddsaJcs2022(Ed25519KeyService keys, JcsCanonicalizer jcs) {
        this.keys = keys;
        this.jcs = jcs;
    }

    /** Attaches a DataIntegrityProof to {@code document}. */
    public void attachProof(ObjectNode document, String did, String proofPurpose,
                            String domain, String challenge) {
        try {
            ObjectNode proofOptions = mapper.createObjectNode();
            proofOptions.put("type", "DataIntegrityProof");
            proofOptions.put("cryptosuite", CRYPTOSUITE);
            proofOptions.put("created", Instant.now().truncatedTo(ChronoUnit.SECONDS).toString());
            proofOptions.put("verificationMethod", keys.verificationMethodFor(did));
            proofOptions.put("proofPurpose", proofPurpose);
            if (domain != null && !domain.isEmpty()) proofOptions.put("domain", domain);
            if (challenge != null && !challenge.isEmpty()) proofOptions.put("challenge", challenge);

            ObjectNode unsecured = document.deepCopy();
            unsecured.remove("proof");

            byte[] hashInput = signingInput(proofOptions, unsecured);
            String proofValue = keys.signRaw(did, hashInput);

            ObjectNode proof = proofOptions.deepCopy();
            proof.put("proofValue", proofValue);
            document.set("proof", proof);
        } catch (Exception e) {
            throw new RuntimeException("Failed to attach " + CRYPTOSUITE + " proof", e);
        }
    }

    /**
     * Verifies the proof on {@code document}. If {@code expectedDomain} or
     * {@code expectedChallenge} are non-null they MUST match the proof object
     * (W3C-VC-DI §2.2; AGENT.md §6 step 3). Returns a structured result.
     */
    public VerifyResult verify(Map<String, Object> document, String expectedDomain, String expectedChallenge) {
        try {
            Object proofObj = document.get("proof");
            if (!(proofObj instanceof Map<?, ?> proofMap))
                return VerifyResult.fail("missing proof");

            String type = (String) proofMap.get("type");
            String suite = (String) proofMap.get("cryptosuite");
            String proofValue = (String) proofMap.get("proofValue");
            String verificationMethod = (String) proofMap.get("verificationMethod");
            if (!"DataIntegrityProof".equals(type) || !CRYPTOSUITE.equals(suite)
                    || proofValue == null || verificationMethod == null) {
                return VerifyResult.fail("malformed proof object");
            }
            if (expectedDomain != null && !expectedDomain.equals(proofMap.get("domain")))
                return VerifyResult.fail("proof.domain mismatch (expected " + expectedDomain + ")");
            if (expectedChallenge != null && !expectedChallenge.equals(proofMap.get("challenge")))
                return VerifyResult.fail("proof.challenge mismatch (replay protection)");

            // Reconstruct proof options (everything except proofValue).
            Map<String, Object> proofOptionsMap = new LinkedHashMap<>();
            for (var e : proofMap.entrySet()) {
                String k = String.valueOf(e.getKey());
                if (!"proofValue".equals(k)) proofOptionsMap.put(k, e.getValue());
            }
            Map<String, Object> unsecured = new LinkedHashMap<>(document);
            unsecured.remove("proof");

            JsonNode proofOptionsNode = mapper.valueToTree(proofOptionsMap);
            JsonNode unsecuredNode = mapper.valueToTree(unsecured);

            byte[] hashInput = signingInput(proofOptionsNode, unsecuredNode);
            boolean ok = keys.verifyRaw(verificationMethod, hashInput, proofValue);
            return ok
                    ? new VerifyResult(true, verificationMethod, null)
                    : VerifyResult.fail("signature does not verify");
        } catch (Exception e) {
            return VerifyResult.fail("verify error: " + e.getMessage());
        }
    }

    private byte[] signingInput(JsonNode proofOptions, JsonNode unsecuredDocument) {
        byte[] proofOptionsHash = sha256(jcs.canonicalize(proofOptions));
        byte[] documentHash = sha256(jcs.canonicalize(unsecuredDocument));
        byte[] out = new byte[proofOptionsHash.length + documentHash.length];
        System.arraycopy(proofOptionsHash, 0, out, 0, proofOptionsHash.length);
        System.arraycopy(documentHash, 0, out, proofOptionsHash.length, documentHash.length);
        return out;
    }

    private static byte[] sha256(byte[] input) {
        try { return MessageDigest.getInstance("SHA-256").digest(input); }
        catch (Exception e) { throw new RuntimeException(e); }
    }

    public record VerifyResult(boolean valid, String verificationMethod, String error) {
        static VerifyResult fail(String why) { return new VerifyResult(false, null, why); }
    }
}

