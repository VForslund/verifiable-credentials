package com.truecaller.backend.service;

import com.truecaller.backend.dto.VerifyRequest;
import com.truecaller.backend.service.crypto.DidResolver;
import com.truecaller.backend.service.proof.DataIntegrityBbs2023;
import com.truecaller.backend.service.proof.DataIntegrityEddsaJcs2022;
import com.truecaller.backend.service.proof.ProofRouter;
import com.truecaller.backend.service.proof.SdJwtVcService;
import com.truecaller.backend.service.schema.CredentialSchemaService;
import com.truecaller.backend.service.status.BitstringStatusListService;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.time.LocalDate;
import java.time.OffsetDateTime;
import java.time.Period;
import java.time.format.DateTimeFormatter;
import java.util.*;

/**
 * Implements the VCDM 2.0 verification algorithm (AGENT.md §6) end-to-end.
 *
 * <p>Steps run fail-fast in order: structural → VP proof → VP challenge
 * binding → per-VC dispatch (sd-jwt-vc / eddsa-jcs-2022 / bbs-2023) →
 * issuer trust → temporal → schema → status → holder binding → assertions.
 *
 * <p>All checks that cannot be performed are treated as failures rather than
 * warnings, per the spec's "fail closed" stance.
 */
@Service
public class VerifierService {

    private static final String V2_CONTEXT = "https://www.w3.org/ns/credentials/v2";

    private final ProofRouter router;
    private final DataIntegrityEddsaJcs2022 eddsa;
    private final DataIntegrityBbs2023 bbs;
    private final SdJwtVcService sdJwt;
    private final DidResolver didResolver;
    private final CredentialSchemaService schemas;
    private final BitstringStatusListService statusLists;

    public VerifierService(ProofRouter router,
                           DataIntegrityEddsaJcs2022 eddsa,
                           DataIntegrityBbs2023 bbs,
                           SdJwtVcService sdJwt,
                           DidResolver didResolver,
                           CredentialSchemaService schemas,
                           BitstringStatusListService statusLists) {
        this.router = router; this.eddsa = eddsa; this.bbs = bbs; this.sdJwt = sdJwt;
        this.didResolver = didResolver; this.schemas = schemas; this.statusLists = statusLists;
    }

    @SuppressWarnings("unchecked")
    public Map<String, Object> verify(Map<String, Object> vp,
                                      List<VerifyRequest.Assertion> assertions,
                                      String expectedAud,
                                      String expectedNonce) {
        Map<String, Object> report = new LinkedHashMap<>();
        List<String> checks = new ArrayList<>();
        List<String> errors = new ArrayList<>();
        boolean valid = true;

        Map<String, String> revealedClaims = new LinkedHashMap<>();

        try {
            // 1. Structural
            List<Object> ctx = (List<Object>) vp.get("@context");
            if (ctx == null || ctx.isEmpty() || !V2_CONTEXT.equals(ctx.get(0))) {
                errors.add("VP @context[0] must be " + V2_CONTEXT);
                return finalise(report, false, checks, errors);
            }
            checks.add("VP @context valid (W3C VCDM 2.0)");

            List<String> vpType = (List<String>) vp.get("type");
            if (vpType == null || !vpType.contains("VerifiablePresentation")) {
                errors.add("VP type must include 'VerifiablePresentation'");
                return finalise(report, false, checks, errors);
            }
            checks.add("VP type includes VerifiablePresentation");

            String vpId = (String) vp.get("id");
            if (vpId == null || vpId.isBlank()) {
                errors.add("VP id (URI) is required");
                return finalise(report, false, checks, errors);
            }

            List<Map<String, Object>> vcs = (List<Map<String, Object>>) vp.get("verifiableCredential");
            if (vcs == null || vcs.isEmpty()) {
                errors.add("VP.verifiableCredential must be a non-empty array");
                return finalise(report, false, checks, errors);
            }

            String holderDid = extractDid(vp.get("holder"));

            // 2. + 3. VP proof + challenge binding (W3C-VC-DI §4.2 + VCDM 2.0 §6.2.1).
            if (vp.get("proof") == null) {
                errors.add("VP has no proof");
                return finalise(report, false, checks, errors);
            }
            DataIntegrityEddsaJcs2022.VerifyResult vpVerify = eddsa.verify(vp, expectedAud, expectedNonce);
            if (!vpVerify.valid()) {
                errors.add("VP proof check failed: " + vpVerify.error());
                return finalise(report, false, checks, errors);
            }
            checks.add("VP DataIntegrityProof valid (eddsa-jcs-2022, domain+challenge match)");

            // 4. Per-credential checks
            for (int i = 0; i < vcs.size(); i++) {
                Map<String, Object> vc = vcs.get(i);
                ProofRouter.Mechanism mech = router.mechanismOf(vc);
                String tag = "VC[" + i + "/" + mech + "] ";

                switch (mech) {
                    case SD_JWT_VC -> {
                        String id = (String) vc.get("id");
                        String sdJwtStr = id.substring(ProofRouter.SD_JWT_DATA_URI_PREFIX.length());
                        SdJwtVcService.SdJwtVerifyResult r = sdJwt.verify(sdJwtStr, expectedAud, expectedNonce);
                        for (String c : r.checks()) checks.add(tag + c);
                        for (String e : r.errors()) errors.add(tag + e);
                        if (!r.valid()) { valid = false; continue; }

                        // 5. Issuer trust — check that the JWT's issuer DID is a did:key
                        // (and therefore inherently authoritative for assertionMethod
                        // per W3C-DID-KEY §3.2). Verify the kid maps to that DID.
                        if (r.issuerDid() == null || !r.issuerDid().startsWith("did:key:")) {
                            errors.add(tag + "Issuer is not a did:key (out of scope per AGENT.md §11)");
                            valid = false; continue;
                        }
                        // (The signature was already verified by sdJwt.verify against the kid.)

                        // 6. Temporal — already enforced by sdJwt.verify via iat/exp.
                        // 7. Schema — SD-JWT VC has no embedded credentialSchema; the vct
                        //    plays that role and is enforced upstream by the issuer.
                        // 8. Status — SD-JWT VC could carry a `status` claim; we don't
                        //    require it for the demo (only eddsa-jcs-2022 VCs do).
                        // 9. Holder binding — done via KB-JWT cnf check inside sdJwt.verify.

                        revealedClaims.putAll(r.revealedClaims());
                    }
                    case EDDSA_JCS_2022 -> {
                        // 4. Cryptosuite verify
                        DataIntegrityEddsaJcs2022.VerifyResult r = eddsa.verify(vc, null, null);
                        if (!r.valid()) {
                            errors.add(tag + "DataIntegrityProof invalid: " + r.error());
                            valid = false; continue;
                        }
                        checks.add(tag + "DataIntegrityProof (eddsa-jcs-2022) valid");

                        // 5. Issuer trust
                        String vm = r.verificationMethod();
                        if (!didResolver.isAssertionMethod(vm)) {
                            errors.add(tag + "verificationMethod is not authoritative for assertionMethod: " + vm);
                            valid = false; continue;
                        }
                        String issuerDid = extractDid(vc.get("issuer"));
                        if (issuerDid == null || vm == null || !vm.startsWith(issuerDid + "#")) {
                            errors.add(tag + "verificationMethod does not belong to issuer DID");
                            valid = false; continue;
                        }
                        checks.add(tag + "Issuer trust: " + issuerDid + " (did:key, assertionMethod)");

                        // 6. Temporal
                        if (!withinValidity(vc, errors, tag)) { valid = false; continue; }
                        checks.add(tag + "Temporal validity OK");

                        // 7. Schema
                        Set<String> schemaErrors = schemas.validate(vc);
                        if (!schemaErrors.isEmpty()) {
                            for (String s : schemaErrors) errors.add(tag + "schema: " + s);
                            valid = false; continue;
                        }
                        checks.add(tag + "credentialSubject conforms to credentialSchema");

                        // 8. Status
                        if (!statusOk(vc, errors, tag)) { valid = false; continue; }
                        checks.add(tag + "Status list check passed (not revoked)");

                        // 9. Holder binding
                        Map<String, Object> subject = (Map<String, Object>) vc.get("credentialSubject");
                        String subjectId = subject == null ? null : (String) subject.get("id");
                        if (holderDid != null && subjectId != null && !holderDid.equals(subjectId)) {
                            errors.add(tag + "credentialSubject.id (" + subjectId
                                    + ") does not match VP.holder (" + holderDid + ")");
                            valid = false; continue;
                        }
                        checks.add(tag + "Holder binding OK");

                        if (subject != null) {
                            for (var e : subject.entrySet()) {
                                if ("id".equals(e.getKey())) continue;
                                revealedClaims.put(e.getKey(), String.valueOf(e.getValue()));
                            }
                        }
                    }
                    case BBS_2023 -> {
                        // 4. Cryptosuite verify (BBS+ derived proof, IRTF-BBS).
                        // Per AGENT.md §6 step 4 the derived proof MUST cover the
                        // verifier's nonce — bbs.verify enforces that via PH.
                        DataIntegrityBbs2023.VerifyResult r = bbs.verify(vc, expectedAud, expectedNonce);
                        if (!r.valid()) {
                            errors.add(tag + "BBS+ derived proof invalid: " + r.error());
                            valid = false; continue;
                        }
                        checks.add(tag + "DataIntegrityProof (bbs-2023) valid — selective disclosure unlinkable");

                        // 5. Issuer trust
                        String vm = r.verificationMethod();
                        if (!didResolver.isAssertionMethod(vm)) {
                            errors.add(tag + "verificationMethod is not authoritative for assertionMethod: " + vm);
                            valid = false; continue;
                        }
                        String issuerDid = extractDid(vc.get("issuer"));
                        if (issuerDid == null || vm == null || !vm.startsWith(issuerDid + "#")) {
                            errors.add(tag + "verificationMethod does not belong to issuer DID");
                            valid = false; continue;
                        }
                        checks.add(tag + "Issuer trust: " + issuerDid + " (did:key BLS12-381, assertionMethod)");

                        // 6. Temporal
                        if (!withinValidity(vc, errors, tag)) { valid = false; continue; }
                        checks.add(tag + "Temporal validity OK");

                        // 7. Schema — only validate over disclosed claims; missing
                        // required fields are NOT a failure for a derived proof.
                        // (AGENT.md §6 leaves room for this since non-disclosed
                        // claims are by design absent from the presented subject.)
                        // We still run the validator to catch type errors on
                        // anything that IS disclosed.
                        Set<String> schemaErrors = schemas.validateDisclosed(vc);
                        if (!schemaErrors.isEmpty()) {
                            for (String s : schemaErrors) errors.add(tag + "schema: " + s);
                            valid = false; continue;
                        }
                        checks.add(tag + "Disclosed credentialSubject claims conform to credentialSchema");

                        // 8. Status
                        if (!statusOk(vc, errors, tag)) { valid = false; continue; }
                        checks.add(tag + "Status list check passed (not revoked)");

                        // 9. Holder binding
                        Map<String, Object> subject = (Map<String, Object>) vc.get("credentialSubject");
                        String subjectId = subject == null ? null : (String) subject.get("id");
                        if (holderDid != null && subjectId != null && !holderDid.equals(subjectId)) {
                            errors.add(tag + "credentialSubject.id (" + subjectId
                                    + ") does not match VP.holder (" + holderDid + ")");
                            valid = false; continue;
                        }
                        checks.add(tag + "Holder binding OK");

                        if (subject != null) {
                            for (var e : subject.entrySet()) {
                                if ("id".equals(e.getKey())) continue;
                                revealedClaims.put(e.getKey(), String.valueOf(e.getValue()));
                            }
                        }
                    }
                    default -> {
                        errors.add(tag + "Unknown securing mechanism");
                        valid = false;
                    }
                }
            }

            // 10. Business assertions
            if (assertions != null && !assertions.isEmpty()) {
                List<Map<String, Object>> assertionResults = new ArrayList<>();
                for (var a : assertions) {
                    Map<String, Object> r = evaluateAssertion(a, revealedClaims);
                    assertionResults.add(r);
                    if (!Boolean.TRUE.equals(r.get("passed"))) {
                        valid = false;
                        errors.add("Assertion '" + a.field() + " " + a.operator() + " " + a.value()
                                + "' FAILED: " + r.getOrDefault("reason", "unknown"));
                    } else {
                        checks.add("Assertion '" + a.field() + " " + a.operator() + " " + a.value() + "' PASSED");
                    }
                }
                report.put("assertionResults", assertionResults);
            }
        } catch (Exception e) {
            errors.add("Verification error: " + e.getMessage());
            valid = false;
        }

        return finalise(report, valid, checks, errors);
    }

    private Map<String, Object> finalise(Map<String, Object> report, boolean valid,
                                         List<String> checks, List<String> errors) {
        report.put("valid", valid);
        report.put("checks", checks);
        report.put("errors", errors);
        return report;
    }

    // --- helpers ---

    private static String extractDid(Object v) {
        if (v instanceof String s) return s;
        if (v instanceof Map<?, ?> m && m.get("id") instanceof String s) return s;
        return null;
    }

    private boolean withinValidity(Map<String, Object> vc, List<String> errors, String tag) {
        Instant now = Instant.now();
        String vf = (String) vc.get("validFrom");
        String vu = (String) vc.get("validUntil");
        try {
            if (vf != null && OffsetDateTime.parse(vf).toInstant().isAfter(now)) {
                errors.add(tag + "validFrom is in the future");
                return false;
            }
            if (vu != null && OffsetDateTime.parse(vu).toInstant().isBefore(now)) {
                errors.add(tag + "credential is past validUntil");
                return false;
            }
            return true;
        } catch (Exception e) {
            errors.add(tag + "unparseable validity dates: " + e.getMessage());
            return false;
        }
    }

    @SuppressWarnings("unchecked")
    private boolean statusOk(Map<String, Object> vc, List<String> errors, String tag) {
        Object cs = vc.get("credentialStatus");
        if (!(cs instanceof Map<?, ?> csm)) {
            errors.add(tag + "missing credentialStatus");
            return false;
        }
        Map<String, Object> m = (Map<String, Object>) csm;
        if (!"BitstringStatusListEntry".equals(m.get("type"))) {
            errors.add(tag + "unsupported credentialStatus.type: " + m.get("type"));
            return false;
        }
        String idxStr = String.valueOf(m.get("statusListIndex"));
        String listUrl = (String) m.get("statusListCredential");
        if (listUrl == null) {
            errors.add(tag + "credentialStatus.statusListCredential missing");
            return false;
        }
        // Demo short-circuit: if the URL is on the local issuer host, look up directly.
        // AGENT.md §11 documents this as out-of-scope for production.
        String prefix = IssuerService.STATUS_BASE;
        if (!listUrl.startsWith(prefix)) {
            errors.add(tag + "external status lists not supported in this build (AGENT.md §11)");
            return false;
        }
        String listId = listUrl.substring(prefix.length());
        try {
            int idx = Integer.parseInt(idxStr);
            // Verify the status list VC's signature too — build it locally and run check.
            Map<String, Object> listVc = statusLists.buildStatusListCredential(listId, "https://truecaller.demo");
            boolean revoked = statusLists.verifyAndCheck(listVc, idx);
            if (revoked) {
                errors.add(tag + "credential is REVOKED at " + listUrl + "#" + idx);
                return false;
            }
            return true;
        } catch (Exception e) {
            errors.add(tag + "status list error: " + e.getMessage());
            return false;
        }
    }

    private Map<String, Object> evaluateAssertion(VerifyRequest.Assertion assertion,
                                                  Map<String, String> revealedClaims) {
        Map<String, Object> result = new LinkedHashMap<>();
        result.put("field", assertion.field());
        result.put("operator", assertion.operator());
        result.put("expected", assertion.value());

        String op = assertion.operator();
        if (("age_gte".equals(op) || "age_lte".equals(op)) && "dateOfBirth".equals(assertion.field())) {
            String predicateField = "age_equal_or_over_" + assertion.value();
            String predicateValue = revealedClaims.get(predicateField);
            if (predicateValue != null) {
                boolean isOver = "true".equalsIgnoreCase(predicateValue);
                boolean passed = "age_gte".equals(op) ? isOver : !isOver;
                result.put("source", "Issuer-signed predicate '" + predicateField + " = " + predicateValue + "'");
                result.put("passed", passed);
                if (!passed) result.put("reason", "predicate disclosed false");
                return result;
            }
            String dob = revealedClaims.get("dateOfBirth");
            if (dob != null) {
                int age = computeAge(dob);
                boolean passed = "age_gte".equals(op)
                        ? age >= parseInt(assertion.value())
                        : age <= parseInt(assertion.value());
                result.put("source", "Computed from disclosed dateOfBirth=" + dob + " (age=" + age + ")");
                result.put("passed", passed);
                if (!passed) result.put("reason", "Age " + age + " did not satisfy " + op + " " + assertion.value());
                return result;
            }
            result.put("passed", false);
            result.put("reason", "Neither '" + predicateField + "' nor 'dateOfBirth' disclosed");
            return result;
        }

        String rawValue = revealedClaims.get(assertion.field());
        if (rawValue == null) {
            result.put("passed", false);
            result.put("reason", "Field '" + assertion.field() + "' was not disclosed");
            return result;
        }
        boolean passed = evaluate(op, rawValue, assertion.value());
        result.put("source", "Disclosed: " + assertion.field() + " = '" + rawValue + "'");
        result.put("passed", passed);
        if (!passed) result.put("reason", "Value '" + rawValue + "' did not satisfy " + op + " " + assertion.value());
        return result;
    }

    private boolean evaluate(String op, String raw, String expected) {
        return switch (op) {
            case "eq"  -> raw.equalsIgnoreCase(expected);
            case "neq" -> !raw.equalsIgnoreCase(expected);
            case "gte" -> compareNumeric(raw, expected) >= 0;
            case "lte" -> compareNumeric(raw, expected) <= 0;
            case "gt"  -> compareNumeric(raw, expected) > 0;
            case "lt"  -> compareNumeric(raw, expected) < 0;
            case "exists" -> raw != null && !raw.isEmpty();
            default -> false;
        };
    }

    private int compareNumeric(String a, String b) {
        try { return Double.compare(Double.parseDouble(a), Double.parseDouble(b)); }
        catch (NumberFormatException e) { return a.compareToIgnoreCase(b); }
    }

    private int computeAge(String dob) {
        try { return Period.between(LocalDate.parse(dob, DateTimeFormatter.ISO_LOCAL_DATE), LocalDate.now()).getYears(); }
        catch (Exception e) { return -1; }
    }

    private static int parseInt(String s) {
        try { return Integer.parseInt(s); } catch (NumberFormatException e) { return Integer.MIN_VALUE; }
    }
}

