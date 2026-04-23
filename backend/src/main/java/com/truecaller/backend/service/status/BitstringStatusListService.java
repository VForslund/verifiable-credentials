package com.truecaller.backend.service.status;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.json.JsonMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.truecaller.backend.service.crypto.Ed25519KeyService;
import com.truecaller.backend.service.proof.DataIntegrityEddsaJcs2022;
import org.springframework.stereotype.Service;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.zip.GZIPOutputStream;

/**
 * Bitstring Status List v1.0 (W3C-STATUS-LIST).
 *
 * <p>For the demo we host a single revocation list per "list id" in memory
 * and serve it as a signed Verifiable Credential of type
 * {@code BitstringStatusListCredential} (eddsa-jcs-2022). Per AGENT.md §11
 * the list lives in the same backend — production deployments would split
 * issuer and status-list hosts.
 */
@Service
public class BitstringStatusListService {

    /** 16K bits per list — enough for the demo, comfortably under the 131 072 minimum
     *  recommended by W3C-STATUS-LIST §6 for high-privacy buckets. */
    private static final int LIST_BITS = 131_072;

    private final Ed25519KeyService keys;
    private final DataIntegrityEddsaJcs2022 eddsa;
    private final ObjectMapper mapper = JsonMapper.builder().build();

    /** listId -> bitset (we store as boolean[] for clarity). */
    private final Map<String, boolean[]> lists = new ConcurrentHashMap<>();
    /** Monotonically increasing counter for new entries per list. */
    private final Map<String, Integer> nextIndex = new ConcurrentHashMap<>();

    /** A dedicated Ed25519 DID for signing all status-list VCs, regardless of the
     *  credential issuer's key type (which may be BLS12-381 for bbs-2023). */
    private volatile String statusListSignerDid;

    public BitstringStatusListService(Ed25519KeyService keys, DataIntegrityEddsaJcs2022 eddsa) {
        this.keys = keys;
        this.eddsa = eddsa;
    }

    private synchronized String getStatusListSignerDid() {
        if (statusListSignerDid == null) {
            statusListSignerDid = keys.generateKeyPair().did();
        }
        return statusListSignerDid;
    }

    /** Allocates a fresh entry on the named list and returns its index. */
    public synchronized int allocateEntry(String listId, String issuerDid) {
        lists.computeIfAbsent(listId, _ -> new boolean[LIST_BITS]);
        int idx = nextIndex.getOrDefault(listId, 0);
        nextIndex.put(listId, idx + 1);
        return idx;
    }

    /** Flips the revocation bit at {@code index} in {@code listId}. */
    public synchronized void revoke(String listId, int index) {
        boolean[] bits = lists.get(listId);
        if (bits == null || index < 0 || index >= bits.length)
            throw new IllegalArgumentException("Unknown list/index: " + listId + "/" + index);
        bits[index] = true;
    }

    /** Returns whether the entry at {@code index} on {@code listId} is revoked. */
    public boolean isRevoked(String listId, int index) {
        boolean[] bits = lists.get(listId);
        if (bits == null) return false;
        if (index < 0 || index >= bits.length) return true; // out-of-range → treat as revoked
        return bits[index];
    }

    /**
     * Builds (and signs) the {@code BitstringStatusListCredential} for a list,
     * per W3C-STATUS-LIST §3.1. Multibase {@code encodedList} = base64url of
     * gzip(bitstring), where bit i corresponds to entry i (LSB-first within byte).
     */
    public Map<String, Object> buildStatusListCredential(String listId, String selfBaseUrl) {
        boolean[] bits = lists.get(listId);
        if (bits == null) throw new IllegalArgumentException("Unknown status list: " + listId);
        String signerDid = getStatusListSignerDid();

        String credId = selfBaseUrl + "/api/status/" + listId;
        String now = Instant.now().truncatedTo(ChronoUnit.SECONDS).toString();

        ObjectNode vc = mapper.createObjectNode();
        ArrayNode ctx = vc.putArray("@context");
        ctx.add("https://www.w3.org/ns/credentials/v2");

        vc.put("id", credId);

        ArrayNode type = vc.putArray("type");
        type.add("VerifiableCredential");
        type.add("BitstringStatusListCredential");

        vc.put("issuer", signerDid);
        vc.put("validFrom", now);

        ObjectNode subject = mapper.createObjectNode();
        subject.put("id", credId + "#list");
        subject.put("type", "BitstringStatusList");
        subject.put("statusPurpose", "revocation");
        subject.put("encodedList", encodeBitstring(bits));
        vc.set("credentialSubject", subject);

        eddsa.attachProof(vc, signerDid, "assertionMethod", null, null);
        return mapper.convertValue(vc, Map.class);
    }

    /** Encodes the bitstring per W3C-STATUS-LIST §3.2: gzip then base64url, multibase 'u' prefix. */
    private static String encodeBitstring(boolean[] bits) {
        try {
            byte[] packed = new byte[(bits.length + 7) / 8];
            for (int i = 0; i < bits.length; i++) {
                if (bits[i]) packed[i >>> 3] |= (byte) (1 << (7 - (i & 7)));
            }
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            try (GZIPOutputStream gz = new GZIPOutputStream(baos)) {
                gz.write(packed);
            }
            // multibase base64url no-pad: leading 'u' (multibase code).
            return "u" + Base64.getUrlEncoder().withoutPadding().encodeToString(baos.toByteArray());
        } catch (Exception e) {
            throw new RuntimeException("Failed to encode status list", e);
        }
    }

    /**
     * Verifies a status list VC and looks up the bit at {@code index}. Returns
     * {@code true} iff the credential is revoked. Performs the signature check
     * and rejects out-of-range indices per W3C-STATUS-LIST §7.
     */
    public boolean verifyAndCheck(Map<String, Object> statusListVc, int index) {
        DataIntegrityEddsaJcs2022.VerifyResult vr = eddsa.verify(statusListVc, null, null);
        if (!vr.valid()) throw new IllegalStateException("Status list signature invalid: " + vr.error());
        @SuppressWarnings("unchecked")
        Map<String, Object> subject = (Map<String, Object>) statusListVc.get("credentialSubject");
        if (subject == null) throw new IllegalStateException("Status list missing credentialSubject");
        String encoded = (String) subject.get("encodedList");
        if (encoded == null || encoded.isEmpty() || encoded.charAt(0) != 'u')
            throw new IllegalStateException("encodedList must be multibase base64url ('u' prefix)");
        boolean[] bits = decodeBitstring(encoded.substring(1));
        if (index < 0 || index >= bits.length) return true;
        return bits[index];
    }

    private static boolean[] decodeBitstring(String b64url) {
        try {
            byte[] gz = Base64.getUrlDecoder().decode(b64url);
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            try (java.util.zip.GZIPInputStream in = new java.util.zip.GZIPInputStream(
                    new java.io.ByteArrayInputStream(gz))) {
                in.transferTo(out);
            }
            byte[] packed = out.toByteArray();
            boolean[] bits = new boolean[packed.length * 8];
            for (int i = 0; i < bits.length; i++) {
                bits[i] = (packed[i >>> 3] & (1 << (7 - (i & 7)))) != 0;
            }
            return bits;
        } catch (Exception e) {
            throw new RuntimeException("Failed to decode status list bitstring", e);
        }
    }

    /** Convenience for tests / logging. */
    @SuppressWarnings("unused")
    private static String utf8(byte[] b) { return new String(b, StandardCharsets.UTF_8); }
}

