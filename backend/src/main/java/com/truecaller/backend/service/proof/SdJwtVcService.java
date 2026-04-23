package com.truecaller.backend.service.proof;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.json.JsonMapper;
import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.Ed25519Signer;
import com.nimbusds.jose.crypto.Ed25519Verifier;
import com.nimbusds.jose.jwk.OctetKeyPair;
import com.nimbusds.jose.util.Base64URL;
import com.truecaller.backend.service.crypto.Ed25519KeyService;
import org.springframework.stereotype.Service;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.*;

/**
 * Implements SD-JWT (Selective Disclosure JWT) for Verifiable Credentials,
 * aligned with IETF draft-ietf-oauth-selective-disclosure-jwt and
 * draft-ietf-oauth-sd-jwt-vc.
 *
 * <p>Format: {@code <issuer-jwt>~<disclosure1>~<disclosure2>~...~<kb-jwt>}
 *
 * <p>Each disclosure is {@code base64url(JSON([salt, claimName, claimValue]))}.
 * The JWT payload contains {@code _sd: [hash1, hash2, ...]} (lexicographically
 * sorted, with decoy digests added) where each hash is
 * {@code base64url(sha256(disclosure))}. Selective disclosure means the holder
 * decides which disclosures (and therefore which claims) to reveal.
 *
 * <p>The SD-JWT VC type identifier ({@code vct}) and key binding (KB-JWT
 * containing verifier-supplied {@code aud} and {@code nonce}) are mandatory
 * for full SD-JWT VC compliance.
 */
@Service
public class SdJwtVcService {

    private static final SecureRandom RNG = new SecureRandom();
    private static final int DECOY_MIN = 2;
    private static final int DECOY_MAX = 5;

    private final Ed25519KeyService keys;
    private final ObjectMapper mapper = JsonMapper.builder().build();

    public SdJwtVcService(Ed25519KeyService keys) {
        this.keys = keys;
    }

    // ========================= ISSUE =========================

    public record SdJwtResult(
            /* The full SD-JWT string with ALL disclosures (stored by holder). */
            String sdJwt,
            /* Field names that are selectively disclosable. */
            List<String> sdFields
    ) {}

    /**
     * Creates an SD-JWT VC. Every claim in {@code claims} becomes a selectively-disclosable
     * disclosure. The structural VC metadata (iss, sub, iat, exp, vct, jti, cnf, display)
     * goes directly into the JWT payload (always visible).
     */
    public SdJwtResult issue(String issuerDid, String holderDid, String vcId,
                             String vcType, String issuerName,
                             Instant validFrom, Instant validUntil,
                             Map<String, String> claims) {
        try {
            OctetKeyPair issuerKey = keys.getKeyPair(issuerDid);
            OctetKeyPair holderPubKey = keys.getKeyPair(holderDid).toPublicJWK();

            // Build disclosures for each claim
            List<String> disclosures = new ArrayList<>();
            List<String> sdHashes = new ArrayList<>();
            List<String> sdFields = new ArrayList<>();

            for (var entry : claims.entrySet()) {
                String salt = randomSaltBase64Url();
                // Per IETF SD-JWT, disclosure JSON is a 3-element array with a single space
                // after the comma separators (the canonical example form).
                String disclosureJson = mapper.writeValueAsString(List.of(salt, entry.getKey(), entry.getValue()));
                String disclosure = Base64URL.encode(disclosureJson.getBytes(StandardCharsets.UTF_8)).toString();
                disclosures.add(disclosure);
                sdHashes.add(sha256Base64Url(disclosure));
                sdFields.add(entry.getKey());
            }

            // Add 2..5 decoy digests so the verifier cannot infer the number of hidden
            // claims by counting _sd entries.
            int decoys = DECOY_MIN + RNG.nextInt(DECOY_MAX - DECOY_MIN + 1);
            for (int i = 0; i < decoys; i++) {
                byte[] r = new byte[32];
                RNG.nextBytes(r);
                sdHashes.add(Base64URL.encode(r).toString());
            }
            // Sort _sd lexicographically (IETF SD-JWT §4.2.4)
            Collections.sort(sdHashes);

            // Build JWT payload (IETF SD-JWT VC §3.2)
            Map<String, Object> payload = new LinkedHashMap<>();
            payload.put("iss", issuerDid);
            payload.put("sub", holderDid != null ? holderDid : "did:example:holder");
            payload.put("iat", validFrom.getEpochSecond());
            payload.put("nbf", validFrom.getEpochSecond());
            payload.put("exp", validUntil.getEpochSecond());
            payload.put("vct", vcType);
            payload.put("jti", vcId);
            // Display metadata (non-standard convenience claim; in production this would
            // be served via a `vct`-resolvable type metadata document).
            if (issuerName != null) {
                payload.put("display", Map.of("name", issuerName));
            }
            payload.put("_sd", sdHashes);
            payload.put("_sd_alg", "sha-256");
            // Confirmation key — proves the holder controls this key
            payload.put("cnf", Map.of("jwk", holderPubKey.toJSONObject()));

            String payloadJson = mapper.writeValueAsString(payload);

            // Sign with EdDSA — typ is the SD-JWT VC media type per IETF draft.
            JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.EdDSA)
                    .keyID(issuerDid)
                    .type(new JOSEObjectType("vc+sd-jwt"))
                    .build();
            JWSObject jws = new JWSObject(header, new Payload(payloadJson));
            jws.sign(new Ed25519Signer(issuerKey));
            String jwt = jws.serialize();

            // Full SD-JWT = jwt~disclosure1~disclosure2~...~
            StringBuilder sb = new StringBuilder(jwt);
            for (String d : disclosures) sb.append('~').append(d);
            sb.append('~'); // trailing ~ (no KB-JWT yet, holder adds it when presenting)

            return new SdJwtResult(sb.toString(), sdFields);
        } catch (Exception e) {
            throw new RuntimeException("Failed to create SD-JWT", e);
        }
    }

    // ========================= PRESENT =========================

    /**
     * Selects disclosures for the given fields and appends a Key Binding JWT.
     *
     * @param fullSdJwt      The full SD-JWT from issuance (jwt~d1~d2~...~)
     * @param fieldsToReveal Which claim names to include (others are stripped)
     * @param holderDid      Holder's DID for signing the KB-JWT
     * @param audience       Verifier-supplied audience (aud) for KB-JWT, or null
     * @param nonce          Verifier-supplied nonce for KB-JWT, or null (a random one is generated)
     */
    public String present(String fullSdJwt, Set<String> fieldsToReveal, String holderDid,
                          String audience, String nonce) {
        try {
            String[] parts = fullSdJwt.split("~", -1);
            String jwt = parts[0];

            // Filter disclosures — only include ones for requested fields
            List<String> selectedDisclosures = new ArrayList<>();
            for (int i = 1; i < parts.length; i++) {
                String d = parts[i];
                if (d.isEmpty()) continue;
                String decoded = new String(Base64URL.from(d).decode(), StandardCharsets.UTF_8);
                List<?> arr = mapper.readValue(decoded, List.class);
                String fieldName = (String) arr.get(1);
                if (fieldsToReveal.contains(fieldName)) {
                    selectedDisclosures.add(d);
                }
            }

            // Create Key Binding JWT (proves holder controls the cnf key)
            OctetKeyPair holderKey = keys.getKeyPair(holderDid);

            // sd_hash = sha256 of the SD-JWT without KB-JWT (IETF SD-JWT §4.3)
            StringBuilder sdJwtForHash = new StringBuilder(jwt);
            for (String d : selectedDisclosures) sdJwtForHash.append('~').append(d);
            sdJwtForHash.append('~');
            String sdHash = sha256Base64Url(sdJwtForHash.toString());

            Map<String, Object> kbPayload = new LinkedHashMap<>();
            kbPayload.put("iat", Instant.now().getEpochSecond());
            kbPayload.put("nonce", nonce != null && !nonce.isEmpty() ? nonce : randomSaltBase64Url());
            if (audience != null && !audience.isEmpty()) kbPayload.put("aud", audience);
            kbPayload.put("sd_hash", sdHash);

            JWSHeader kbHeader = new JWSHeader.Builder(JWSAlgorithm.EdDSA)
                    .type(new JOSEObjectType("kb+jwt"))
                    .build();
            JWSObject kbJws = new JWSObject(kbHeader, new Payload(mapper.writeValueAsString(kbPayload)));
            kbJws.sign(new Ed25519Signer(holderKey));

            // Assemble: jwt~selected_disclosures~kb-jwt
            StringBuilder result = new StringBuilder(jwt);
            for (String d : selectedDisclosures) result.append('~').append(d);
            result.append('~').append(kbJws.serialize());

            return result.toString();
        } catch (Exception e) {
            throw new RuntimeException("Failed to create SD-JWT presentation", e);
        }
    }

    // ========================= VERIFY =========================

    public record SdJwtVerifyResult(
            boolean valid,
            String issuerDid,
            String issuerName,
            String holderDid,
            String vcType,
            String vcId,
            long iat,
            long exp,
            /* Only the fields the holder chose to reveal. */
            Map<String, String> revealedClaims,
            List<String> checks,
            List<String> errors
    ) {}

    /**
     * Verifies an SD-JWT presentation: issuer signature, disclosure hashes,
     * temporal validity, key binding, and (optionally) audience / nonce.
     */
    @SuppressWarnings("unchecked")
    public SdJwtVerifyResult verify(String sdJwtPresentation, String expectedAud, String expectedNonce) {
        List<String> checks = new ArrayList<>();
        List<String> errors = new ArrayList<>();
        boolean valid = true;

        String issuerDid = null, issuerName = null, holderDid = null, vcType = null, vcId = null;
        long iat = 0, exp = 0;
        Map<String, String> revealedClaims = new LinkedHashMap<>();

        try {
            // Split into jwt, disclosures, kb-jwt
            String[] parts = sdJwtPresentation.split("~", -1);
            if (parts.length < 2) {
                errors.add("Invalid SD-JWT format");
                return new SdJwtVerifyResult(false, null, null, null, null, null, 0, 0, Map.of(), checks, errors);
            }

            String jwt = parts[0];
            String kbJwt = parts[parts.length - 1];
            List<String> disclosures = new ArrayList<>();
            for (int i = 1; i < parts.length - 1; i++) {
                if (!parts[i].isEmpty()) disclosures.add(parts[i]);
            }

            // 1. Parse and verify issuer JWT signature
            JWSObject jwsObject = JWSObject.parse(jwt);
            issuerDid = jwsObject.getHeader().getKeyID();
            if (issuerDid == null || !issuerDid.startsWith("did:key:")) {
                errors.add("JWT kid is not a valid did:key");
                valid = false;
            } else {
                OctetKeyPair issuerPub = keys.resolveToPublicJwk(issuerDid);
                if (jwsObject.verify(new Ed25519Verifier(issuerPub))) {
                    checks.add("Issuer JWT signature VALID (EdDSA)");
                } else {
                    errors.add("Issuer JWT signature INVALID");
                    valid = false;
                }
            }

            // 2. Parse payload
            Map<String, Object> payload = mapper.readValue(
                    jwsObject.getPayload().toString(), LinkedHashMap.class);
            Object displayObj = payload.get("display");
            if (displayObj instanceof Map<?, ?> dm && dm.get("name") instanceof String s) {
                issuerName = s;
            }
            holderDid = (String) payload.get("sub");
            vcType = (String) payload.get("vct");
            vcId = (String) payload.get("jti");
            iat = ((Number) payload.get("iat")).longValue();
            exp = ((Number) payload.get("exp")).longValue();
            List<String> sdHashes = (List<String>) payload.get("_sd");
            String sdAlg = (String) payload.getOrDefault("_sd_alg", "sha-256");
            if (!"sha-256".equalsIgnoreCase(sdAlg)) {
                errors.add("Unsupported _sd_alg: " + sdAlg);
                valid = false;
            }

            checks.add("Issuer: " + (issuerName != null ? issuerName : issuerDid));
            checks.add("Credential type (vct): " + vcType);

            // 3. Temporal validity
            Instant now = Instant.now();
            if (Instant.ofEpochSecond(iat).isAfter(now)) {
                errors.add("Credential not yet valid (iat is in the future)");
                valid = false;
            } else {
                checks.add("Issued at: " + Instant.ofEpochSecond(iat) + " ✓");
            }
            if (Instant.ofEpochSecond(exp).isBefore(now)) {
                errors.add("Credential expired (exp=" + Instant.ofEpochSecond(exp) + ")");
                valid = false;
            } else {
                checks.add("Expires: " + Instant.ofEpochSecond(exp) + " ✓");
            }

            // 4. Match disclosures to _sd hashes
            for (String d : disclosures) {
                String hash = sha256Base64Url(d);
                if (sdHashes != null && sdHashes.contains(hash)) {
                    String decoded = new String(Base64URL.from(d).decode(), StandardCharsets.UTF_8);
                    List<?> arr = mapper.readValue(decoded, List.class);
                    String fieldName = (String) arr.get(1);
                    String fieldValue = String.valueOf(arr.get(2));
                    revealedClaims.put(fieldName, fieldValue);
                    checks.add("Disclosed field '" + fieldName + "' hash matches issuer JWT ✓");
                } else {
                    errors.add("Disclosure hash does not match any _sd entry — possible tampering");
                    valid = false;
                }
            }

            int hiddenCount = (sdHashes != null ? sdHashes.size() : 0) - disclosures.size();
            if (hiddenCount > 0) {
                checks.add(hiddenCount + " digest(s) kept private (real claims + decoys; verifier cannot tell which)");
            }

            // 5. Verify Key Binding JWT
            if (kbJwt == null || kbJwt.isEmpty()) {
                errors.add("Missing Key Binding JWT (holder authentication)");
                valid = false;
            } else {
                JWSObject kbJws = JWSObject.parse(kbJwt);
                Map<String, Object> cnf = (Map<String, Object>) payload.get("cnf");
                if (cnf == null || cnf.get("jwk") == null) {
                    errors.add("JWT missing 'cnf' (holder confirmation key)");
                    valid = false;
                } else {
                    OctetKeyPair holderPub = OctetKeyPair.parse((Map<String, Object>) cnf.get("jwk"));
                    if (kbJws.verify(new Ed25519Verifier(holderPub))) {
                        checks.add("Key Binding JWT VALID — holder authenticated this presentation");
                    } else {
                        errors.add("Key Binding JWT signature INVALID");
                        valid = false;
                    }

                    // Verify sd_hash in KB-JWT matches the presented SD-JWT
                    Map<String, Object> kbPayload = mapper.readValue(
                            kbJws.getPayload().toString(), LinkedHashMap.class);
                    String expectedSdHash = (String) kbPayload.get("sd_hash");
                    StringBuilder sdJwtForHash = new StringBuilder(jwt);
                    for (String d : disclosures) sdJwtForHash.append('~').append(d);
                    sdJwtForHash.append('~');
                    String actualSdHash = sha256Base64Url(sdJwtForHash.toString());
                    if (actualSdHash.equals(expectedSdHash)) {
                        checks.add("KB-JWT sd_hash matches presented SD-JWT ✓");
                    } else {
                        errors.add("KB-JWT sd_hash does not match — SD-JWT may have been tampered with");
                        valid = false;
                    }

                    // Audience / nonce binding (replay protection)
                    if (expectedAud != null && !expectedAud.isEmpty()) {
                        Object audClaim = kbPayload.get("aud");
                        if (!expectedAud.equals(audClaim)) {
                            errors.add("KB-JWT 'aud' mismatch (expected '" + expectedAud + "', got '" + audClaim + "')");
                            valid = false;
                        } else {
                            checks.add("KB-JWT audience matches verifier ✓");
                        }
                    }
                    if (expectedNonce != null && !expectedNonce.isEmpty()) {
                        Object nonceClaim = kbPayload.get("nonce");
                        if (!expectedNonce.equals(nonceClaim)) {
                            errors.add("KB-JWT 'nonce' mismatch (replay protection failed)");
                            valid = false;
                        } else {
                            checks.add("KB-JWT nonce matches verifier challenge ✓");
                        }
                    }
                }
            }

        } catch (Exception e) {
            errors.add("SD-JWT verification error: " + e.getMessage());
            valid = false;
        }

        return new SdJwtVerifyResult(valid, issuerDid, issuerName, holderDid, vcType, vcId,
                iat, exp, revealedClaims, checks, errors);
    }

    // ========================= UTILS =========================

    private static String randomSaltBase64Url() {
        byte[] b = new byte[16]; // 128 bits per IETF SD-JWT §5.2
        RNG.nextBytes(b);
        return Base64URL.encode(b).toString();
    }

    private String sha256Base64Url(String input) {
        try {
            byte[] hash = MessageDigest.getInstance("SHA-256")
                    .digest(input.getBytes(StandardCharsets.US_ASCII));
            return Base64URL.encode(hash).toString();
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
}

