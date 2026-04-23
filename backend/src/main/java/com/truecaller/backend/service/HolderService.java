package com.truecaller.backend.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.json.JsonMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.truecaller.backend.dto.PresentRequest;
import com.truecaller.backend.service.proof.DataIntegrityBbs2023;
import com.truecaller.backend.service.proof.DataIntegrityEddsaJcs2022;
import com.truecaller.backend.service.proof.ProofRouter;
import org.springframework.stereotype.Service;

import java.util.*;

/**
 * Builds VCDM 2.0 Verifiable Presentations.
 *
 * <p>The wallet decides per-VC how to satisfy each proof request item per
 * AGENT.md §7:
 * <ul>
 *   <li><b>bbs-2023</b> — runs the BBS+ {@code deriveProof} algorithm to
 *       produce an unlinkable selective-disclosure proof bound to the
 *       verifier's domain+challenge.</li>
 *   <li><b>SD-JWT VC</b> — selectively disclose either a precomputed
 *       {@code age_equal_or_over_NN} predicate or the raw claim; refuse if
 *       neither is available.</li>
 *   <li><b>eddsa-jcs-2022</b> — the credential is all-or-nothing; the whole
 *       signed VC is included.</li>
 * </ul>
 *
 * <p>The VP itself is signed with {@code eddsa-jcs-2022} carrying
 * {@code proofPurpose=authentication}, and {@code domain}/{@code challenge}
 * bound to the verifier — VCDM 2.0 §6.2.1.
 */
@Service
public class HolderService {

    private static final String VCDM_V2_CONTEXT = "https://www.w3.org/ns/credentials/v2";

    private final ProofRouter router;
    private final DataIntegrityEddsaJcs2022 eddsa;
    private final DataIntegrityBbs2023 bbsProof;
    private final ObjectMapper mapper = JsonMapper.builder().build();

    public HolderService(ProofRouter router, DataIntegrityEddsaJcs2022 eddsa,
                         DataIntegrityBbs2023 bbsProof) {
        this.router = router;
        this.eddsa = eddsa;
        this.bbsProof = bbsProof;
    }

    /** Returns {@code {verifiableCredential: <VP>, _walletHints: <preview>}}. */
    public Map<String, Object> createPresentation(
            String holderDid,
            List<Map<String, Object>> storedCredentials,
            List<PresentRequest.ProofRequestItem> proofRequest,
            String verifierDid,
            String nonce
    ) {
        // Plan disclosure per stored VC.
        // For each VC we collect the set of fields that need disclosure (SD-JWT)
        // OR the marker "INCLUDE_FULL" for an eddsa-jcs-2022 VC.
        // We keep the order of `storedCredentials` so the wallet UI is deterministic.
        List<DisclosurePlan> plans = planDisclosure(storedCredentials, proofRequest);

        // Build VP per VCDM 2.0 §5.
        ObjectNode vp = mapper.createObjectNode();
        ArrayNode vpContext = vp.putArray("@context");
        vpContext.add(VCDM_V2_CONTEXT);
        vp.put("id", "urn:uuid:" + UUID.randomUUID());
        ArrayNode vpType = vp.putArray("type");
        vpType.add("VerifiablePresentation");
        if (holderDid != null) vp.put("holder", holderDid);

        ArrayNode vcArray = vp.putArray("verifiableCredential");
        List<Map<String, Object>> walletPreview = new ArrayList<>();

        for (DisclosurePlan plan : plans) {
            switch (plan.mechanism) {
                case SD_JWT_VC -> {
                    String sdJwt = plan.sourceSdJwt;
                    String selective = router.sdJwt().present(
                            sdJwt, plan.fieldsToReveal, holderDid, verifierDid, nonce);
                    ObjectNode envelope = mapper.createObjectNode();
                    ArrayNode envelopeCtx = envelope.putArray("@context");
                    envelopeCtx.add(VCDM_V2_CONTEXT);
                    envelope.put("type", "EnvelopedVerifiableCredential");
                    envelope.put("id", ProofRouter.SD_JWT_DATA_URI_PREFIX + selective);
                    vcArray.add(envelope);
                    walletPreview.add(buildPreview(plan, plan.fieldsToReveal));
                }
                case EDDSA_JCS_2022 -> {
                    // No selective disclosure possible — include the whole VC verbatim.
                    vcArray.add(mapper.valueToTree(plan.fullVc));
                    walletPreview.add(buildPreview(plan, plan.allFields));
                }
                case BBS_2023 -> {
                    // Real BBS+ derived proof: rewrite credentialSubject to expose
                    // only the requested fields, replace base proof with derived
                    // proof, bind verifier domain+challenge into PH (AGENT.md §2.1).
                    ObjectNode derived = (ObjectNode) mapper.valueToTree(plan.fullVc);
                    Set<String> reveal = plan.fieldsToReveal.isEmpty() ? plan.allFields : plan.fieldsToReveal;
                    bbsProof.deriveProof(derived, reveal, verifierDid, nonce);
                    vcArray.add(derived);
                    walletPreview.add(buildPreview(plan, reveal));
                }
                case UNKNOWN -> { /* skip silently */ }
            }
        }

        // VP signature MUST carry domain + challenge per VCDM 2.0 §6.2.1.
        if (holderDid != null) {
            eddsa.attachProof(vp, holderDid, "authentication", verifierDid, nonce);
        }

        Map<String, Object> result = new LinkedHashMap<>();
        result.put("verifiableCredential", mapper.convertValue(vp, Map.class));
        Map<String, Object> hints = new LinkedHashMap<>();
        hints.put("disclosurePreview", walletPreview);
        hints.put("verifierDid", verifierDid);
        hints.put("nonce", nonce);
        result.put("_walletHints", hints);
        return result;
    }

    // ---------------------------------------------------------------------
    // Disclosure planning per AGENT.md §7
    // ---------------------------------------------------------------------
    private List<DisclosurePlan> planDisclosure(List<Map<String, Object>> storedCredentials,
                                                List<PresentRequest.ProofRequestItem> proofRequest) {
        List<DisclosurePlan> plans = new ArrayList<>();
        if (storedCredentials == null) return plans;

        // For each item, find the first VC that can satisfy it; record the plan.
        // A VC is included iff at least one item resolves against it.
        Map<String, DisclosurePlan> byVcId = new LinkedHashMap<>();

        for (Map<String, Object> stored : storedCredentials) {
            DisclosurePlan p = inspect(stored);
            if (p != null) byVcId.put(p.credentialId, p);
        }

        Set<String> includeIds = new LinkedHashSet<>();

        boolean hasItems = proofRequest != null && !proofRequest.isEmpty();
        if (hasItems) {
            for (var item : proofRequest) {
                for (DisclosurePlan p : byVcId.values()) {
                    String resolved = chooseDisclosureField(p, item);
                    if (resolved == null) continue;
                    if (resolved.equals("$FULL$")) {
                        // eddsa-jcs-2022 — mark inclusion; nothing else to add.
                        includeIds.add(p.credentialId);
                    } else {
                        p.fieldsToReveal.add(resolved);
                        includeIds.add(p.credentialId);
                    }
                    break; // first match wins per item
                }
            }
        } else {
            // No proof request items: include every stored VC (debug / preview).
            includeIds.addAll(byVcId.keySet());
            for (DisclosurePlan p : byVcId.values()) {
                if (p.mechanism == ProofRouter.Mechanism.SD_JWT_VC) {
                    p.fieldsToReveal.addAll(p.allFields);
                }
            }
        }

        for (DisclosurePlan p : byVcId.values()) {
            if (includeIds.contains(p.credentialId)) plans.add(p);
        }
        return plans;
    }

    /**
     * The wallet's §7 decision routine. Returns the SD-JWT field name to
     * disclose, the sentinel {@code "$FULL$"} for an all-or-nothing
     * eddsa-jcs-2022 inclusion, or {@code null} if this VC cannot satisfy
     * the item.
     */
    private static String chooseDisclosureField(DisclosurePlan p, PresentRequest.ProofRequestItem item) {
        switch (p.mechanism) {
            case SD_JWT_VC -> {
                String op = item.operator();
                if (("age_gte".equals(op) || "age_lte".equals(op)) && "dateOfBirth".equals(item.field())) {
                    String predicate = "age_equal_or_over_" + item.value();
                    if (p.allFields.contains(predicate)) return predicate;
                }
                if (item.field() != null && p.allFields.contains(item.field())) return item.field();
                return null;
            }
            case EDDSA_JCS_2022 -> {
                if (item.field() != null && p.allFields.contains(item.field())) return "$FULL$";
                return null;
            }
            case BBS_2023 -> {
                // BBS+ supports selective disclosure of any signed claim. The age
                // threshold predicates the issuer pre-signed (age_equal_or_over_NN)
                // satisfy "age_gte" requests without ever revealing dateOfBirth.
                String op = item.operator();
                if (("age_gte".equals(op) || "age_lte".equals(op)) && "dateOfBirth".equals(item.field())) {
                    String predicate = "age_equal_or_over_" + item.value();
                    if (p.allFields.contains(predicate)) return predicate;
                }
                if (item.field() != null && p.allFields.contains(item.field())) return item.field();
                return null;
            }
            default -> { return null; }
        }
    }

    // ---------------------------------------------------------------------
    // Plan / preview helpers
    // ---------------------------------------------------------------------

    private static final class DisclosurePlan {
        final ProofRouter.Mechanism mechanism;
        final String credentialId;
        final String credentialType;
        final String issuerDid;
        final Set<String> allFields = new LinkedHashSet<>();
        final Set<String> fieldsToReveal = new LinkedHashSet<>();
        /** Only set for SD-JWT VC — the full SD-JWT pulled from the envelope. */
        final String sourceSdJwt;
        /** Only set for eddsa-jcs-2022 — the full VC object verbatim. */
        final Map<String, Object> fullVc;

        DisclosurePlan(ProofRouter.Mechanism mech, String credentialId, String type, String issuer,
                       String sdJwt, Map<String, Object> fullVc) {
            this.mechanism = mech;
            this.credentialId = credentialId;
            this.credentialType = type;
            this.issuerDid = issuer;
            this.sourceSdJwt = sdJwt;
            this.fullVc = fullVc;
        }
    }

    /** Reads a stored VC (already in {@code verifiableCredential}-shape) and extracts
     *  the metadata the planner needs. Returns null for unsupported entries. */
    @SuppressWarnings("unchecked")
    private DisclosurePlan inspect(Map<String, Object> stored) {
        if (stored == null) return null;
        ProofRouter.Mechanism mech = router.mechanismOf(stored);
        switch (mech) {
            case SD_JWT_VC -> {
                String id = (String) stored.get("id");
                String sdJwt = id == null ? null
                        : id.substring(ProofRouter.SD_JWT_DATA_URI_PREFIX.length());
                if (sdJwt == null) return null;
                Map<String, Object> jwtPayload = decodeJwtPayload(sdJwt);
                String credId = (String) jwtPayload.getOrDefault("jti", id);
                String issuer = (String) jwtPayload.get("iss");
                String type = (String) jwtPayload.get("vct");
                Set<String> fields = new LinkedHashSet<>(decodeSdJwtFieldNames(sdJwt));
                DisclosurePlan p = new DisclosurePlan(mech, credId, type, issuer, sdJwt, null);
                p.allFields.addAll(fields);
                return p;
            }
            case EDDSA_JCS_2022 -> {
                String credId = (String) stored.get("id");
                String issuer = stored.get("issuer") instanceof Map<?, ?> m
                        ? (String) ((Map<String, Object>) m).get("id")
                        : (String) stored.get("issuer");
                List<String> typeList = (List<String>) stored.get("type");
                String type = typeList != null && typeList.size() > 1 ? typeList.get(1) : "VerifiableCredential";
                Map<String, Object> subject = (Map<String, Object>) stored.get("credentialSubject");
                DisclosurePlan p = new DisclosurePlan(mech, credId, type, issuer, null, stored);
                if (subject != null) p.allFields.addAll(subject.keySet());
                return p;
            }
            case BBS_2023 -> {
                String credId = (String) stored.get("id");
                String issuer = stored.get("issuer") instanceof Map<?, ?> m
                        ? (String) ((Map<String, Object>) m).get("id")
                        : (String) stored.get("issuer");
                List<String> typeList = (List<String>) stored.get("type");
                String type = typeList != null && typeList.size() > 1 ? typeList.get(1) : "VerifiableCredential";
                Map<String, Object> subject = (Map<String, Object>) stored.get("credentialSubject");
                DisclosurePlan p = new DisclosurePlan(mech, credId, type, issuer, null, stored);
                if (subject != null) {
                    for (String k : subject.keySet()) if (!"id".equals(k)) p.allFields.add(k);
                }
                return p;
            }
            default -> { return null; }
        }
    }

    /** Re-decodes disclosure field names from a stored SD-JWT (jwt~d1~d2~...~). */
    @SuppressWarnings("unchecked")
    private List<String> decodeSdJwtFieldNames(String fullSdJwt) {
        try {
            String[] parts = fullSdJwt.split("~", -1);
            List<String> names = new ArrayList<>();
            for (int i = 1; i < parts.length; i++) {
                String d = parts[i];
                if (d.isEmpty()) continue;
                byte[] dec = com.nimbusds.jose.util.Base64URL.from(d).decode();
                List<Object> arr = mapper.readValue(dec, List.class);
                if (arr.size() >= 2 && arr.get(1) instanceof String s) names.add(s);
            }
            return names;
        } catch (Exception e) {
            return List.of();
        }
    }

    /** Decodes only the JWT payload portion of an SD-JWT — no signature check. */
    @SuppressWarnings("unchecked")
    private Map<String, Object> decodeJwtPayload(String fullSdJwt) {
        try {
            String jwt = fullSdJwt.split("~", -1)[0];
            String[] segs = jwt.split("\\.", -1);
            if (segs.length < 2) return Map.of();
            byte[] payload = com.nimbusds.jose.util.Base64URL.from(segs[1]).decode();
            return mapper.readValue(payload, LinkedHashMap.class);
        } catch (Exception e) {
            return Map.of();
        }
    }

    private Map<String, Object> buildPreview(DisclosurePlan plan, Set<String> revealed) {
        Map<String, Object> p = new LinkedHashMap<>();
        p.put("credentialId", plan.credentialId);
        p.put("credentialType", plan.credentialType);
        p.put("issuerDid", plan.issuerDid);
        p.put("mechanism", switch (plan.mechanism) {
            case SD_JWT_VC -> "sd-jwt-vc";
            case EDDSA_JCS_2022 -> "eddsa-jcs-2022";
            case BBS_2023 -> "bbs-2023";
            default -> "unknown";
        });
        p.put("revealedFields", new ArrayList<>(revealed));
        List<String> hidden = new ArrayList<>();
        for (String f : plan.allFields) if (!revealed.contains(f)) hidden.add(f);
        p.put("hiddenFields", hidden);
        return p;
    }
}

