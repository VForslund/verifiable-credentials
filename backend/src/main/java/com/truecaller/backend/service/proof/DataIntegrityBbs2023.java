package com.truecaller.backend.service.proof;

import ch.bfh.p2bbs.Types.OctetString;
import ch.bfh.p2bbs.proof.ProofGen;
import ch.bfh.p2bbs.proof.ProofVerify;
import ch.bfh.p2bbs.signature.Sign;
import ch.bfh.p2bbs.signature.SignVerify;
import ch.openchvote.util.sequence.Vector;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.json.JsonMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.truecaller.backend.service.canon.JcsCanonicalizer;
import com.truecaller.backend.service.crypto.BlsKeyService;
import org.springframework.stereotype.Service;

import java.security.MessageDigest;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.*;

/**
 * W3C Data Integrity {@code bbs-2023} cryptosuite (W3C-DI-BBS, IRTF-BBS),
 * implemented on top of the BFH BLS12-381 / IRTF-BBS-draft-v5 reference
 * library copied from https://github.com/roblesjoel/P2_BBS_Signature.
 *
 * <p><b>Conformance scope.</b> This is real BBS+ over BLS12-381 G1 with
 * 96-byte G2 public keys, exercising {@code Sign}/{@code Verify}/{@code
 * ProofGen}/{@code ProofVerify} per IRTF-BBS-05. We diverge from
 * W3C-DI-BBS §3.4.6 only in the canonicalisation: instead of URDNA2015
 * N-Quads we hash each {@code credentialSubject} claim independently with
 * RFC 8785 JCS — one BBS message per claim, alphabetically ordered. The
 * cryptographic guarantees (selective disclosure, unlinkability of
 * derived proofs, tamper-evidence) are identical to the spec; only the
 * canonical-form and pointer-encoding differ. URDNA2015 wire-conformance
 * is a follow-up (titanium-rdfc would slot in cleanly at
 * {@link JcsCanonicalizer}'s layer).
 *
 * <p>True derived <b>predicate</b> proofs (e.g. "age &ge; N for any N the
 * issuer never enumerated") are NOT possible with the IRTF-BBS draft
 * primitive — they need an extra ZK range-proof layer. As with SD-JWT VC
 * the issuer pre-signs {@code age_equal_or_over_NN} booleans; the wallet
 * selectively discloses the right one. The DOB stays hidden and the
 * disclosure is unlinkable across presentations thanks to BBS+
 * re-randomisation.
 */
@Service
public class DataIntegrityBbs2023 {

    public static final String CRYPTOSUITE = "bbs-2023";

    private final BlsKeyService bls;
    private final JcsCanonicalizer jcs;
    private final ObjectMapper mapper = JsonMapper.builder().build();

    public DataIntegrityBbs2023(BlsKeyService bls, JcsCanonicalizer jcs) {
        this.bls = bls;
        this.jcs = jcs;
    }

    // =====================================================================
    // ISSUER — base proof
    // =====================================================================

    /**
     * Attaches a BBS+ <em>base proof</em> to {@code document}. The signed
     * messages are the JCS-canonical bytes of each {@code credentialSubject}
     * claim (excluding {@code id}), in alphabetical order. The proof's
     * {@code messageOrder} field carries that ordering so the verifier can
     * reproduce it from a derived presentation.
     */
    public void attachBaseProof(ObjectNode document, String issuerDid) {
        try {
            BlsKeyService.BlsKeyPair kp = bls.getKeyPair(issuerDid);
            String created = Instant.now().truncatedTo(ChronoUnit.SECONDS).toString();

            ObjectNode proofOptions = mapper.createObjectNode();
            proofOptions.put("type", "DataIntegrityProof");
            proofOptions.put("cryptosuite", CRYPTOSUITE);
            proofOptions.put("created", created);
            proofOptions.put("verificationMethod", bls.verificationMethodFor(issuerDid));
            proofOptions.put("proofPurpose", "assertionMethod");

            // Build the message list = sorted (k, v) pairs from credentialSubject.
            ObjectNode subject = (ObjectNode) document.get("credentialSubject");
            List<String> messageOrder = sortedClaimNames(subject);
            ArrayNode order = proofOptions.putArray("messageOrder");
            for (String n : messageOrder) order.add(n);

            ObjectString[] msgs = canonicalMessages(subject, messageOrder);

            // header binds the proof options + the unsecured document body
            // (so that no field outside credentialSubject can be tampered with
            // without breaking signature verification).
            byte[] header = headerBytes(proofOptions, document);

            OctetString sig = Sign.Sign(
                    kp.secret(), kp.publicKey(),
                    new OctetString(header),
                    Vector.of(unwrap(msgs))
            );
            String proofValue = "u" + Base64Url.encode(sig.toBytes());

            ObjectNode proof = proofOptions.deepCopy();
            proof.put("proofValue", proofValue);
            document.set("proof", proof);
        } catch (Exception e) {
            throw new RuntimeException("Failed to attach bbs-2023 base proof", e);
        }
    }

    // =====================================================================
    // HOLDER — derive selective-disclosure proof
    // =====================================================================

    /**
     * Replaces a base BBS+ proof with a derived proof revealing only the
     * named claims. {@code credentialSubject} is rewritten in place to
     * carry only those claims (plus {@code id}). The proof binds
     * {@code domain} + {@code challenge} into the IRTF-BBS presentation
     * header (PH) so the proof cannot be replayed to a different verifier.
     */
    public void deriveProof(ObjectNode document, Set<String> revealClaimNames,
                            String domain, String challenge) {
        try {
            ObjectNode proof = (ObjectNode) document.get("proof");
            if (proof == null || !CRYPTOSUITE.equals(proof.path("cryptosuite").asText()))
                throw new IllegalStateException("VC has no bbs-2023 base proof");

            String vmUrl = proof.path("verificationMethod").asText();
            // Verification method = "<did>#<fragment>" — extract the DID for pubkey resolution.
            String issuerDid = vmUrl.substring(0, vmUrl.indexOf('#'));
            OctetString pk = bls.resolveToPublicOctetString(issuerDid);

            // Original signature
            OctetString baseSig = new OctetString(Base64Url.decode(stripMultibaseU(proof.path("proofValue").asText())));

            // Original message order from the proof
            ArrayNode order = (ArrayNode) proof.get("messageOrder");
            List<String> fullOrder = new ArrayList<>();
            for (JsonNode n : order) fullOrder.add(n.asText());

            // Original messages (recompute from current subject — the wallet still
            // holds the full subject set, even if the verifier won't see all of it).
            ObjectNode fullSubject = (ObjectNode) document.get("credentialSubject");
            ObjectString[] allMsgs = canonicalMessages(fullSubject, fullOrder);

            // Compute disclosed indexes (1-based per IRTF-BBS) and disclosed messages.
            // Note: ProofGen below expects indexes that match the revealed slice
            // (1..fullOrder.size, the index in the ORIGINAL signed list).
            List<Integer> disclosedIndexes = new ArrayList<>();
            List<OctetString> disclosedMessages = new ArrayList<>();
            for (int i = 0; i < fullOrder.size(); i++) {
                String name = fullOrder.get(i);
                if (revealClaimNames.contains(name)) {
                    disclosedIndexes.add(i + 1); // 1-based
                    disclosedMessages.add(allMsgs[i].octet);
                }
            }

            // Build derived proof options (drops messageOrder — the verifier needs it
            // back for index alignment, so we keep it in the derived proof too).
            ObjectNode derivedOpts = mapper.createObjectNode();
            derivedOpts.put("type", "DataIntegrityProof");
            derivedOpts.put("cryptosuite", CRYPTOSUITE);
            derivedOpts.put("created", proof.path("created").asText());
            derivedOpts.put("verificationMethod", vmUrl);
            derivedOpts.put("proofPurpose", "assertionMethod");
            ArrayNode mo = derivedOpts.putArray("messageOrder");
            for (String n : fullOrder) mo.add(n);
            ArrayNode di = derivedOpts.putArray("disclosedIndexes");
            for (Integer i : disclosedIndexes) di.add(i);
            if (domain != null) derivedOpts.put("domain", domain);
            if (challenge != null) derivedOpts.put("challenge", challenge);

            // Header & PH must be computed BEFORE rewriting credentialSubject.
            byte[] header = headerBytes(stripValue(proof), document);
            byte[] ph = presentationHeaderBytes(domain, challenge);

            // Rewrite the credentialSubject to expose only the disclosed claims.
            ObjectNode newSubject = mapper.createObjectNode();
            if (fullSubject.has("id")) newSubject.set("id", fullSubject.get("id"));
            for (String name : fullOrder) {
                if (revealClaimNames.contains(name)) newSubject.set(name, fullSubject.get(name));
            }
            document.set("credentialSubject", newSubject);

            // ProofGen expects ALL messages (not just disclosed), plus the indexes
            // of which ones to disclose. It splits them internally.
            OctetString proofBytes = ProofGen.ProofGen(
                    pk, baseSig,
                    new OctetString(header),
                    new OctetString(ph),
                    Vector.of(unwrap(allMsgs)),
                    Vector.of(disclosedIndexes.toArray(Integer[]::new))
            );

            if (proofBytes == null || proofBytes == OctetString.INVALID || proofBytes.toBytes() == null) {
                throw new RuntimeException("BBS+ ProofGen returned INVALID — check message/index alignment");
            }

            derivedOpts.put("proofValue", "u" + Base64Url.encode(proofBytes.toBytes()));
            document.set("proof", derivedOpts);
        } catch (Exception e) {
            throw new RuntimeException("Failed to derive bbs-2023 proof", e);
        }
    }

    // =====================================================================
    // VERIFIER
    // =====================================================================

    /**
     * Verifies a BBS+ derived proof. Requires that
     * {@code proof.domain == expectedDomain} and {@code proof.challenge ==
     * expectedChallenge} (W3C-VC-DI §2.2 / VCDM 2.0 §6.2.1).
     */
    public VerifyResult verify(Map<String, Object> document,
                               String expectedDomain, String expectedChallenge) {
        try {
            Object proofObj = document.get("proof");
            if (!(proofObj instanceof Map<?, ?> proofMap))
                return VerifyResult.fail("missing proof");

            String type = (String) proofMap.get("type");
            String suite = (String) proofMap.get("cryptosuite");
            String proofValue = (String) proofMap.get("proofValue");
            String vm = (String) proofMap.get("verificationMethod");
            if (!"DataIntegrityProof".equals(type) || !CRYPTOSUITE.equals(suite)
                    || proofValue == null || vm == null)
                return VerifyResult.fail("malformed proof object");

            if (expectedDomain != null && !expectedDomain.equals(proofMap.get("domain")))
                return VerifyResult.fail("proof.domain mismatch (expected " + expectedDomain + ")");
            if (expectedChallenge != null && !expectedChallenge.equals(proofMap.get("challenge")))
                return VerifyResult.fail("proof.challenge mismatch (replay protection)");

            String issuerDid = vm.substring(0, vm.indexOf('#'));
            OctetString pk = bls.resolveToPublicOctetString(issuerDid);

            @SuppressWarnings("unchecked")
            List<String> fullOrder = (List<String>) proofMap.get("messageOrder");
            @SuppressWarnings("unchecked")
            List<Number> disclosedIndexesRaw = (List<Number>) proofMap.get("disclosedIndexes");
            if (fullOrder == null || disclosedIndexesRaw == null)
                return VerifyResult.fail("derived proof missing messageOrder/disclosedIndexes");
            List<Integer> disclosedIndexes = new ArrayList<>();
            for (Number n : disclosedIndexesRaw) disclosedIndexes.add(n.intValue());

            @SuppressWarnings("unchecked")
            Map<String, Object> subject = (Map<String, Object>) document.get("credentialSubject");
            if (subject == null) return VerifyResult.fail("missing credentialSubject");

            // Reconstruct disclosed messages from the disclosed indexes.
            OctetString[] disclosedMessages = new OctetString[disclosedIndexes.size()];
            for (int i = 0; i < disclosedIndexes.size(); i++) {
                int idx = disclosedIndexes.get(i) - 1; // back to 0-based
                if (idx < 0 || idx >= fullOrder.size())
                    return VerifyResult.fail("disclosedIndex out of range");
                String name = fullOrder.get(idx);
                Object value = subject.get(name);
                if (value == null)
                    return VerifyResult.fail("disclosed claim '" + name + "' not present in credentialSubject");
                disclosedMessages[i] = new OctetString(jcs.canonicalize(List.of(name, String.valueOf(value))));
            }

            // Re-derive the *base* proof options to recompute the header.
            // The base options are the derived options minus
            // {disclosedIndexes, domain, challenge, proofValue}.
            ObjectNode derivedOptionsTree = (ObjectNode) mapper.valueToTree(proofMap);
            ObjectNode baseOptions = derivedOptionsTree.deepCopy();
            baseOptions.remove("disclosedIndexes");
            baseOptions.remove("domain");
            baseOptions.remove("challenge");
            baseOptions.remove("proofValue");

            // Document body for the header is "the unsecured document with the
            // FULL subject's claim *names* — values can vary per derivation, but
            // the issuer signed over the names+values they originally provided.
            // We bind only the proofOptions plus the credential's structural
            // identity (issuer/id/types/validity) into the header. The actual
            // claim values are bound through the BBS message list, not the header.
            ObjectNode docCopy = mapper.valueToTree(document);
            docCopy.remove("proof");
            // The verifier's subject only has disclosed claims. But the header
            // must contain ALL claim names (from messageOrder) to match the issuer's
            // original header. Build a synthetic subject using fullOrder.
            {
                ObjectNode synth = mapper.createObjectNode();
                if (subject.containsKey("id"))
                    synth.put("id", (String) subject.get("id"));
                ArrayNode namesArr = synth.putArray("_signedClaimNames");
                for (String n : fullOrder) namesArr.add(n);
                docCopy.set("credentialSubject", synth);
            }

            byte[] header = headerBytesRaw(baseOptions, docCopy);
            byte[] ph = presentationHeaderBytes(
                    (String) proofMap.get("domain"),
                    (String) proofMap.get("challenge"));

            OctetString proofOctet = new OctetString(Base64Url.decode(stripMultibaseU(proofValue)));

            boolean ok = ProofVerify.ProofVerify(
                    pk, proofOctet,
                    new OctetString(header),
                    new OctetString(ph),
                    Vector.of(unwrap(disclosedMessages)),
                    Vector.of(disclosedIndexes.toArray(Integer[]::new))
            );

            return ok ? new VerifyResult(true, vm, null)
                      : VerifyResult.fail("BBS+ proof failed verification");
        } catch (Exception e) {
            return VerifyResult.fail("verify error: " + e.getMessage());
        }
    }

    // =====================================================================
    // helpers
    // =====================================================================

    public record VerifyResult(boolean valid, String verificationMethod, String error) {
        public static VerifyResult fail(String why) { return new VerifyResult(false, null, why); }
    }

    /** Tiny tuple so we can carry both name and bytes around. */
    private record ObjectString(String name, OctetString octet) {}

    /** Returns the credentialSubject claim names sorted alphabetically (excluding "id"). */
    private List<String> sortedClaimNames(ObjectNode subject) {
        List<String> names = new ArrayList<>();
        subject.fieldNames().forEachRemaining(n -> { if (!"id".equals(n)) names.add(n); });
        Collections.sort(names);
        return names;
    }

    /** Builds the BBS message list = JCS([name, value]) for each claim, in order. */
    private ObjectString[] canonicalMessages(ObjectNode subject, List<String> order) {
        ObjectString[] out = new ObjectString[order.size()];
        for (int i = 0; i < order.size(); i++) {
            String name = order.get(i);
            JsonNode v = subject.get(name);
            String value = v != null && v.isValueNode() ? v.asText() : (v == null ? "" : v.toString());
            byte[] bytes = jcs.canonicalize(List.of(name, value));
            out[i] = new ObjectString(name, new OctetString(bytes));
        }
        return out;
    }

    private static OctetString[] unwrap(ObjectString[] msgs) {
        OctetString[] out = new OctetString[msgs.length];
        for (int i = 0; i < msgs.length; i++) out[i] = msgs[i].octet;
        return out;
    }
    private static OctetString[] unwrap(OctetString[] msgs) { return msgs; }

    /** Header = SHA-256(JCS(proofOptions) || JCS(unsecured-document-no-subject-values)). */
    private byte[] headerBytes(JsonNode proofOptions, JsonNode unsecuredDocument) {
        // For initial signing we get the full document; for verification the values
        // may have been stripped by the caller already. Strip here defensively.
        ObjectNode doc = (ObjectNode) unsecuredDocument.deepCopy();
        doc.remove("proof");
        stripSubjectValuesInPlace(doc);
        return headerBytesRaw(proofOptions, doc);
    }

    private byte[] headerBytesRaw(JsonNode proofOptions, JsonNode strippedDoc) {
        byte[] po = sha256(jcs.canonicalize(proofOptions));
        byte[] dh = sha256(jcs.canonicalize(strippedDoc));
        byte[] out = new byte[po.length + dh.length];
        System.arraycopy(po, 0, out, 0, po.length);
        System.arraycopy(dh, 0, out, po.length, dh.length);
        return out;
    }

    /** PH binds the verifier-supplied (domain, challenge) into the derived proof. */
    private byte[] presentationHeaderBytes(String domain, String challenge) {
        ObjectNode ph = mapper.createObjectNode();
        if (domain != null) ph.put("domain", domain);
        if (challenge != null) ph.put("challenge", challenge);
        return jcs.canonicalize(ph);
    }

    /** Removes claim VALUES from credentialSubject; keeps the claim NAMES (as empty). */
    private static void stripSubjectValuesInPlace(ObjectNode doc) {
        JsonNode s = doc.get("credentialSubject");
        if (!(s instanceof ObjectNode subj)) return;
        ObjectNode replacement = ((ObjectNode) doc).objectNode();
        if (subj.has("id")) replacement.set("id", subj.get("id"));
        // name list only, sorted, so it's identical across base/derived presentations.
        List<String> names = new ArrayList<>();
        subj.fieldNames().forEachRemaining(n -> { if (!"id".equals(n)) names.add(n); });
        Collections.sort(names);
        ArrayNode arr = replacement.putArray("_signedClaimNames");
        for (String n : names) arr.add(n);
        doc.set("credentialSubject", replacement);
    }

    private static ObjectNode stripValue(ObjectNode proof) {
        ObjectNode c = proof.deepCopy();
        c.remove("proofValue");
        return c;
    }

    private static String stripMultibaseU(String s) {
        if (s == null || s.isEmpty()) throw new IllegalArgumentException("empty proofValue");
        if (s.charAt(0) != 'u')
            throw new IllegalArgumentException("expected multibase 'u' prefix on proofValue");
        return s.substring(1);
    }

    private static byte[] sha256(byte[] in) {
        try { return MessageDigest.getInstance("SHA-256").digest(in); }
        catch (Exception e) { throw new RuntimeException(e); }
    }

    /** Tiny base64url helper without the multibase prefix. */
    private static final class Base64Url {
        private static final Base64.Encoder ENC = Base64.getUrlEncoder().withoutPadding();
        private static final Base64.Decoder DEC = Base64.getUrlDecoder();
        static String encode(byte[] b) { return ENC.encodeToString(b); }
        static byte[] decode(String s) { return DEC.decode(s); }
    }
}

