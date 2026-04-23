package com.truecaller.backend.conformance;

import com.truecaller.backend.dto.PresentRequest;
import com.truecaller.backend.dto.VerifyRequest;
import com.truecaller.backend.service.HolderService;
import com.truecaller.backend.service.IssuerService;
import com.truecaller.backend.service.VerifierService;
import com.truecaller.backend.service.crypto.Ed25519KeyService;
import com.truecaller.backend.service.status.BitstringStatusListService;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

import java.util.*;

import static org.junit.jupiter.api.Assertions.*;

/**
 * AGENT.md §10 conformance suite.
 *
 * <p>Each test runs a full issue → present → verify cycle through the real
 * Spring services (no mocks) and asserts the outcome the spec mandates.
 * BBS-related tests are {@link Disabled} with a link to AGENT.md §2.1 so
 * the failure mode is explicit.
 */
@SpringBootTest
class VcConformanceTest {

    @Autowired Ed25519KeyService ed25519;
    @Autowired IssuerService issuerService;
    @Autowired HolderService holderService;
    @Autowired VerifierService verifierService;
    @Autowired BitstringStatusListService statusLists;

    // ---------------------------------------------------------------------
    // eddsa-jcs-2022
    // ---------------------------------------------------------------------

    @Test
    @DisplayName("Eddsa_Issue_Verify_HappyPath")
    @SuppressWarnings("unchecked")
    void eddsaIssueVerifyHappyPath() {
        Ctx c = newCtx();
        Map<String, Object> issued = issuerService.issueCredential(
                "government", c.holderDid, govClaims(), "eddsa-jcs-2022");

        Map<String, Object> vc = (Map<String, Object>) issued.get("verifiableCredential");
        assertNotNull(vc.get("proof"), "issuer must attach DataIntegrityProof");
        assertEquals(List.of("https://www.w3.org/ns/credentials/v2",
                "https://truecaller.demo/contexts/identity/v1"),
                vc.get("@context"), "VC must include both contexts (AGENT.md §5.1)");

        Map<String, Object> vp = present(c, List.of(vc), List.of());
        Map<String, Object> report = verifierService.verify(vp,
                List.of(new VerifyRequest.Assertion("fullName", "exists", "")),
                c.verifierDid, c.nonce);

        assertTrue((Boolean) report.get("valid"), () -> "report should be valid: " + report);
    }

    @Test
    @DisplayName("Eddsa_TamperedClaim_Rejected")
    @SuppressWarnings("unchecked")
    void eddsaTamperedClaimRejected() {
        Ctx c = newCtx();
        Map<String, Object> issued = issuerService.issueCredential(
                "government", c.holderDid, govClaims(), "eddsa-jcs-2022");
        Map<String, Object> vc = new LinkedHashMap<>((Map<String, Object>) issued.get("verifiableCredential"));
        Map<String, Object> subject = new LinkedHashMap<>((Map<String, Object>) vc.get("credentialSubject"));
        subject.put("fullName", "Mallory");          // single-claim tamper
        vc.put("credentialSubject", subject);

        Map<String, Object> vp = present(c, List.of(vc), List.of());
        Map<String, Object> report = verifierService.verify(vp, List.of(), c.verifierDid, c.nonce);
        assertFalse((Boolean) report.get("valid"), "tampered claim must invalidate proof");
    }

    @Test
    @DisplayName("Status_RevokedCredential_Rejected")
    @SuppressWarnings("unchecked")
    void statusRevokedCredentialRejected() {
        Ctx c = newCtx();
        Map<String, Object> issued = issuerService.issueCredential(
                "government", c.holderDid, govClaims(), "eddsa-jcs-2022");
        Map<String, Object> hints = (Map<String, Object>) issued.get("_walletHints");
        String listId = (String) hints.get("statusListId");
        int idx = (Integer) hints.get("statusListIndex");

        statusLists.revoke(listId, idx);

        Map<String, Object> vc = (Map<String, Object>) issued.get("verifiableCredential");
        Map<String, Object> vp = present(c, List.of(vc), List.of());
        Map<String, Object> report = verifierService.verify(vp, List.of(), c.verifierDid, c.nonce);
        assertFalse((Boolean) report.get("valid"), "revoked credential must fail verify");
    }

    @Test
    @DisplayName("Schema_InvalidSubject_Rejected")
    @SuppressWarnings("unchecked")
    void schemaInvalidSubjectRejected() {
        Ctx c = newCtx();
        Map<String, String> bad = new LinkedHashMap<>(govClaims());
        bad.put("dateOfBirth", "not-a-date");
        Map<String, Object> issued = issuerService.issueCredential(
                "government", c.holderDid, bad, "eddsa-jcs-2022");
        Map<String, Object> vc = (Map<String, Object>) issued.get("verifiableCredential");
        Map<String, Object> vp = present(c, List.of(vc), List.of());
        Map<String, Object> report = verifierService.verify(vp, List.of(), c.verifierDid, c.nonce);
        assertFalse((Boolean) report.get("valid"), "invalid dateOfBirth must fail JSON Schema validation");
    }

    @Test
    @DisplayName("Vp_MissingChallenge_Rejected")
    @SuppressWarnings("unchecked")
    void vpMissingChallengeRejected() {
        Ctx c = newCtx();
        Map<String, Object> issued = issuerService.issueCredential(
                "government", c.holderDid, govClaims(), "eddsa-jcs-2022");
        Map<String, Object> vc = (Map<String, Object>) issued.get("verifiableCredential");
        Map<String, Object> vp = present(c, List.of(vc), List.of());

        // Strip challenge from the VP proof — must fail.
        Map<String, Object> proof = new LinkedHashMap<>((Map<String, Object>) vp.get("proof"));
        proof.remove("challenge");
        vp.put("proof", proof);

        Map<String, Object> report = verifierService.verify(vp, List.of(), c.verifierDid, c.nonce);
        assertFalse((Boolean) report.get("valid"), "VP without challenge must be rejected");
    }

    @Test
    @DisplayName("Vp_WrongHolderKey_Rejected")
    @SuppressWarnings("unchecked")
    void vpWrongHolderKeyRejected() {
        Ctx c = newCtx();
        Map<String, Object> issued = issuerService.issueCredential(
                "government", c.holderDid, govClaims(), "eddsa-jcs-2022");
        Map<String, Object> vc = (Map<String, Object>) issued.get("verifiableCredential");
        Map<String, Object> vp = present(c, List.of(vc), List.of());

        // Swap verificationMethod to a freshly minted DID — its kid won't verify.
        Map<String, Object> proof = new LinkedHashMap<>((Map<String, Object>) vp.get("proof"));
        String otherDid = ed25519.generateKeyPair().did();
        proof.put("verificationMethod", otherDid + "#" + otherDid.substring("did:key:".length()));
        vp.put("proof", proof);

        Map<String, Object> report = verifierService.verify(vp, List.of(), c.verifierDid, c.nonce);
        assertFalse((Boolean) report.get("valid"), "VP signed with wrong key must be rejected");
    }

    // ---------------------------------------------------------------------
    // SD-JWT VC
    // ---------------------------------------------------------------------

    @Test
    @DisplayName("SdJwt_SelectiveDisclosure_HidesNonRevealed")
    @SuppressWarnings("unchecked")
    void sdJwtSelectiveDisclosureHidesNonRevealed() {
        Ctx c = newCtx();
        Map<String, Object> issued = issuerService.issueCredential(
                "government", c.holderDid, govClaims(), "sd-jwt-vc");
        Map<String, Object> vc = (Map<String, Object>) issued.get("verifiableCredential");

        Map<String, Object> vp = present(c, List.of(vc),
                List.of(new PresentRequest.ProofRequestItem("nationality", "exists", "", true)));
        Map<String, Object> report = verifierService.verify(vp,
                List.of(new VerifyRequest.Assertion("nationality", "exists", "")),
                c.verifierDid, c.nonce);

        assertTrue((Boolean) report.get("valid"), () -> "verify must pass: " + report);
        // dateOfBirth must NOT have been disclosed. Walk all checks for any leakage marker.
        String checks = String.valueOf(report.get("checks"));
        assertFalse(checks.contains("'dateOfBirth'"),
                "dateOfBirth must remain hidden when only nationality was requested: " + checks);
    }

    @Test
    @DisplayName("SdJwt_AgeOver21_PredicateBoolean")
    @SuppressWarnings("unchecked")
    void sdJwtAgeOver21PredicateBoolean() {
        Ctx c = newCtx();
        Map<String, Object> issued = issuerService.issueCredential(
                "government", c.holderDid, govClaims(), "sd-jwt-vc");
        Map<String, Object> vc = (Map<String, Object>) issued.get("verifiableCredential");

        Map<String, Object> vp = present(c, List.of(vc),
                List.of(new PresentRequest.ProofRequestItem("dateOfBirth", "age_gte", "21", false)));
        Map<String, Object> report = verifierService.verify(vp,
                List.of(new VerifyRequest.Assertion("dateOfBirth", "age_gte", "21")),
                c.verifierDid, c.nonce);

        assertTrue((Boolean) report.get("valid"), () -> "report should be valid: " + report);
        String checks = String.valueOf(report.get("checks"));
        assertTrue(checks.contains("age_equal_or_over_21"),
                "verifier must see the age_equal_or_over_21 predicate: " + checks);
    }

    @Test
    @DisplayName("SdJwt_KbJwt_Aud_Mismatch_Rejected")
    @SuppressWarnings("unchecked")
    void sdJwtKbJwtAudMismatchRejected() {
        Ctx c = newCtx();
        Map<String, Object> issued = issuerService.issueCredential(
                "government", c.holderDid, govClaims(), "sd-jwt-vc");
        Map<String, Object> vc = (Map<String, Object>) issued.get("verifiableCredential");

        Map<String, Object> vp = present(c, List.of(vc),
                List.of(new PresentRequest.ProofRequestItem("nationality", "exists", "", true)));
        Map<String, Object> report = verifierService.verify(vp, List.of(),
                "did:key:zSomeOtherVerifier", c.nonce);
        assertFalse((Boolean) report.get("valid"), "wrong aud must be rejected (KB-JWT replay)");
    }

    @Test
    @DisplayName("SdJwt_KbJwt_Nonce_Mismatch_Rejected")
    @SuppressWarnings("unchecked")
    void sdJwtKbJwtNonceMismatchRejected() {
        Ctx c = newCtx();
        Map<String, Object> issued = issuerService.issueCredential(
                "government", c.holderDid, govClaims(), "sd-jwt-vc");
        Map<String, Object> vc = (Map<String, Object>) issued.get("verifiableCredential");

        Map<String, Object> vp = present(c, List.of(vc),
                List.of(new PresentRequest.ProofRequestItem("nationality", "exists", "", true)));
        Map<String, Object> report = verifierService.verify(vp, List.of(),
                c.verifierDid, "definitely-not-the-real-nonce");
        assertFalse((Boolean) report.get("valid"), "wrong nonce must be rejected (replay)");
    }

    @Test
    @DisplayName("SdJwt_TamperedDisclosure_Rejected")
    @SuppressWarnings("unchecked")
    void sdJwtTamperedDisclosureRejected() {
        Ctx c = newCtx();
        Map<String, Object> issued = issuerService.issueCredential(
                "government", c.holderDid, govClaims(), "sd-jwt-vc");
        Map<String, Object> vc = (Map<String, Object>) issued.get("verifiableCredential");

        Map<String, Object> vp = present(c, List.of(vc),
                List.of(new PresentRequest.ProofRequestItem("nationality", "exists", "", true)));
        // Mutate the envelope id (the SD-JWT) by flipping one disclosure character.
        List<Map<String, Object>> arr = (List<Map<String, Object>>) vp.get("verifiableCredential");
        Map<String, Object> envelope = arr.get(0);
        String id = (String) envelope.get("id");
        // Flip one character somewhere in the middle of the second disclosure segment.
        int firstTilde = id.indexOf('~');
        int secondTilde = id.indexOf('~', firstTilde + 1);
        int target = (firstTilde + secondTilde) / 2;
        char ch = id.charAt(target);
        char repl = (ch == 'A') ? 'B' : 'A';
        String tampered = id.substring(0, target) + repl + id.substring(target + 1);
        envelope.put("id", tampered);

        Map<String, Object> report = verifierService.verify(vp, List.of(), c.verifierDid, c.nonce);
        assertFalse((Boolean) report.get("valid"), "tampered disclosure must be rejected");
    }

    // ---------------------------------------------------------------------
    // bbs-2023 — real BBS+ over BLS12-381 (BFH P2_BBS_Signature library).
    // ---------------------------------------------------------------------

    @Test
    @DisplayName("Bbs_Issue_Verify_HappyPath")
    @SuppressWarnings("unchecked")
    void bbsIssueVerifyHappyPath() {
        Ctx c = newCtx();
        Map<String, Object> issued = issuerService.issueCredential(
                "government", c.holderDid, govClaims(), "bbs-2023");
        Map<String, Object> vc = (Map<String, Object>) issued.get("verifiableCredential");
        assertEquals("bbs-2023", ((Map<String, Object>) vc.get("proof")).get("cryptosuite"),
                "issued VC must carry a bbs-2023 DataIntegrityProof");

        Map<String, Object> vp = present(c, List.of(vc),
                List.of(new PresentRequest.ProofRequestItem("nationality", "exists", "", true)));
        Map<String, Object> report = verifierService.verify(vp,
                List.of(new VerifyRequest.Assertion("nationality", "exists", "")),
                c.verifierDid, c.nonce);
        assertTrue((Boolean) report.get("valid"), () -> "BBS+ derived proof must verify: " + report);
    }

    @Test
    @DisplayName("Bbs_DerivedProof_AgeOver21_NoDobLeak")
    @SuppressWarnings("unchecked")
    void bbsDerivedProofAgeOver21() {
        // Note: the IRTF-BBS draft primitive does NOT support arbitrary range
        // proofs, so "age >= N for any N" requires the issuer to have signed
        // pre-computed `age_equal_or_over_NN` booleans (mDL convention,
        // AGENT.md §2.1). The test name uses 21 because that is one of the
        // thresholds AGE_THRESHOLDS in IssuerService enumerates; "27" would
        // require either a different threshold list or a true range proof.
        Ctx c = newCtx();
        Map<String, Object> issued = issuerService.issueCredential(
                "government", c.holderDid, govClaims(), "bbs-2023");
        Map<String, Object> vc = (Map<String, Object>) issued.get("verifiableCredential");

        Map<String, Object> vp = present(c, List.of(vc),
                List.of(new PresentRequest.ProofRequestItem("dateOfBirth", "age_gte", "21", false)));

        // Inspect the disclosed credentialSubject — DOB must be absent.
        Map<String, Object> vpDoc = vp;
        List<Map<String, Object>> arr = (List<Map<String, Object>>) vpDoc.get("verifiableCredential");
        Map<String, Object> derived = arr.get(0);
        Map<String, Object> subject = (Map<String, Object>) derived.get("credentialSubject");
        assertFalse(subject.containsKey("dateOfBirth"),
                "BBS+ derived proof must NOT leak dateOfBirth: " + subject);
        assertEquals("true", String.valueOf(subject.get("age_equal_or_over_21")),
                "the age_equal_or_over_21 predicate must be the only age-related disclosure");

        Map<String, Object> report = verifierService.verify(vp,
                List.of(new VerifyRequest.Assertion("dateOfBirth", "age_gte", "21")),
                c.verifierDid, c.nonce);
        assertTrue((Boolean) report.get("valid"), () -> "report should be valid: " + report);
    }

    @Test
    @DisplayName("Bbs_DerivedProof_Unlinkable")
    @SuppressWarnings("unchecked")
    void bbsDerivedProofUnlinkable() {
        // Two derived proofs from the SAME stored VC must produce DIFFERENT
        // proofValue bytes — that's the BBS+ unlinkability guarantee.
        Ctx c1 = newCtx();
        Map<String, Object> issued = issuerService.issueCredential(
                "government", c1.holderDid, govClaims(), "bbs-2023");
        Map<String, Object> vc = (Map<String, Object>) issued.get("verifiableCredential");

        Ctx c2 = new Ctx(c1.holderDid, c1.verifierDid, "nonce-" + UUID.randomUUID());
        Map<String, Object> vp1 = present(c1, List.of(vc),
                List.of(new PresentRequest.ProofRequestItem("nationality", "exists", "", true)));
        Map<String, Object> vp2 = present(c2, List.of(vc),
                List.of(new PresentRequest.ProofRequestItem("nationality", "exists", "", true)));

        String pv1 = derivedProofValue(vp1);
        String pv2 = derivedProofValue(vp2);
        assertNotEquals(pv1, pv2,
                "two BBS+ derived proofs from the same base must be unlinkable (different proofValues)");
    }

    @Test
    @DisplayName("Bbs_TamperedRevealedClaim_Rejected")
    @SuppressWarnings("unchecked")
    void bbsTamperedRevealedClaimRejected() {
        Ctx c = newCtx();
        Map<String, Object> issued = issuerService.issueCredential(
                "government", c.holderDid, govClaims(), "bbs-2023");
        Map<String, Object> vc = (Map<String, Object>) issued.get("verifiableCredential");

        Map<String, Object> vp = present(c, List.of(vc),
                List.of(new PresentRequest.ProofRequestItem("nationality", "exists", "", true)));
        // Mutate the disclosed claim VALUE in the derived VC — must invalidate the proof.
        List<Map<String, Object>> arr = (List<Map<String, Object>>) vp.get("verifiableCredential");
        Map<String, Object> derived = arr.get(0);
        Map<String, Object> subject = new LinkedHashMap<>((Map<String, Object>) derived.get("credentialSubject"));
        subject.put("nationality", "ZZ");
        derived.put("credentialSubject", subject);

        Map<String, Object> report = verifierService.verify(vp, List.of(), c.verifierDid, c.nonce);
        assertFalse((Boolean) report.get("valid"), "tampered revealed claim must fail BBS+ verification");
    }

    @SuppressWarnings("unchecked")
    private static String derivedProofValue(Map<String, Object> vp) {
        List<Map<String, Object>> arr = (List<Map<String, Object>>) vp.get("verifiableCredential");
        Map<String, Object> proof = (Map<String, Object>) arr.get(0).get("proof");
        return (String) proof.get("proofValue");
    }

    // ---------------------------------------------------------------------
    // helpers
    // ---------------------------------------------------------------------

    private record Ctx(String holderDid, String verifierDid, String nonce) {}

    private Ctx newCtx() {
        return new Ctx(
                ed25519.generateKeyPair().did(),
                ed25519.generateKeyPair().did(),
                "nonce-" + UUID.randomUUID());
    }

    private static Map<String, String> govClaims() {
        Map<String, String> m = new LinkedHashMap<>();
        m.put("fullName", "Anna Andersson");
        m.put("dateOfBirth", "1990-05-15");
        m.put("personalNumber", "199005150123");
        m.put("nationality", "SE");
        return m;
    }

    @SuppressWarnings("unchecked")
    private Map<String, Object> present(Ctx c, List<Map<String, Object>> vcs,
                                        List<PresentRequest.ProofRequestItem> items) {
        Map<String, Object> wrapped = holderService.createPresentation(
                c.holderDid, vcs, items, c.verifierDid, c.nonce);
        return (Map<String, Object>) wrapped.get("verifiableCredential");
    }
}


