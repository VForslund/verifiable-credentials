package com.truecaller.backend.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.json.JsonMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.truecaller.backend.service.crypto.BlsKeyService;
import com.truecaller.backend.service.crypto.Ed25519KeyService;
import com.truecaller.backend.service.proof.DataIntegrityBbs2023;
import com.truecaller.backend.service.proof.DataIntegrityEddsaJcs2022;
import com.truecaller.backend.service.proof.SdJwtVcService;
import com.truecaller.backend.service.status.BitstringStatusListService;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.time.LocalDate;
import java.time.Period;
import java.time.format.DateTimeFormatter;
import java.time.temporal.ChronoUnit;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Issues VCDM 2.0 Verifiable Credentials in the shape mandated by AGENT.md §5.1
 * and returns them per §5.2 as {@code {verifiableCredential, _walletHints}}.
 *
 * <p>Three securing mechanisms (AGENT.md §2.3):
 * <ul>
 *   <li>{@code bbs-2023} — JSON-LD VC with embedded BBS+ DataIntegrityProof
 *       (default; supports unlinkable derived selective-disclosure proofs).</li>
 *   <li>{@code eddsa-jcs-2022} — JSON-LD VC with embedded Ed25519 DataIntegrityProof.</li>
 *   <li>{@code sd-jwt-vc} — wrapped in an EnvelopedVerifiableCredential.</li>
 * </ul>
 */
@Service
public class IssuerService {

    public static final String VCDM_V2_CONTEXT = "https://www.w3.org/ns/credentials/v2";
    public static final String IDENTITY_CTX    = "https://truecaller.demo/contexts/identity/v1";
    public static final String SCHEMAS_BASE    = "https://truecaller.demo/schemas/";
    public static final String STATUS_BASE     = "https://truecaller.demo/status/";
    public static final String SD_JWT_VC_MEDIA_TYPE = "application/vc+sd-jwt";
    /** Local namespace for vct URIs — production would resolve to type metadata. */
    public static final String VCT_BASE = "https://truecaller.demo/vct/";

    private static final String DEFAULT_STATUS_LIST = "1";
    private static final int[] AGE_THRESHOLDS = {13, 16, 18, 21, 25, 65, 85};

    record IssuerMeta(String displayName, String credentialType, String icon, int validDays, String defaultMechanism) {}

    private static final Map<String, IssuerMeta> ISSUERS = Map.of(
            "university", new IssuerMeta("Stockholm University",                "UniversityDegreeCredential",   "🎓", 1825, "sd-jwt-vc"),
            "government", new IssuerMeta("Swedish Government (Skatteverket)",   "GovernmentIdentityCredential", "🏛️", 3650, "bbs-2023"),
            "medical",    new IssuerMeta("Karolinska University Hospital",      "MedicalRecordCredential",      "🏥", 365,  "sd-jwt-vc"),
            "telecom",    new IssuerMeta("Telia",                               "VerifiedPhoneCredential",      "📱", 730,  "eddsa-jcs-2022")
    );


    private final Ed25519KeyService ed25519;
    private final BlsKeyService bls;
    private final SdJwtVcService sdJwt;
    private final DataIntegrityEddsaJcs2022 eddsa;
    private final DataIntegrityBbs2023 bbs;
    private final BitstringStatusListService status;
    private final ObjectMapper mapper = JsonMapper.builder().build();

    private final Map<String, String> ed25519Dids = new ConcurrentHashMap<>();
    private final Map<String, String> blsDids     = new ConcurrentHashMap<>();

    public IssuerService(Ed25519KeyService ed25519, BlsKeyService bls,
                         SdJwtVcService sdJwt, DataIntegrityEddsaJcs2022 eddsa,
                         DataIntegrityBbs2023 bbs, BitstringStatusListService status) {
        this.ed25519 = ed25519; this.bls = bls; this.sdJwt = sdJwt;
        this.eddsa = eddsa; this.bbs = bbs; this.status = status;
    }

    public synchronized String getOrCreateEd25519IssuerDid(String issuerType) {
        return ed25519Dids.computeIfAbsent(issuerType, _ -> ed25519.generateKeyPair().did());
    }

    /** Lazily mints (and caches) a BBS+ issuer DID for {@code bbs-2023}. */
    public synchronized String getOrCreateBlsIssuerDid(String issuerType) {
        return blsDids.computeIfAbsent(issuerType, _ -> bls.generateKeyPair().did());
    }

    public Map<String, Object> getAvailableIssuers() {
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("university", Map.of("name", "Stockholm University",                "icon", "🎓", "description", "Issue academic degree credentials",  "fields", new String[]{"studentName", "degree", "fieldOfStudy", "graduationYear"}, "defaultMechanism", "sd-jwt-vc"));
        out.put("government", Map.of("name", "Swedish Government (Skatteverket)",   "icon", "🏛️", "description", "Issue national identity credentials","fields", new String[]{"fullName", "dateOfBirth", "personalNumber", "nationality"}, "defaultMechanism", "bbs-2023"));
        out.put("medical",    Map.of("name", "Karolinska University Hospital",      "icon", "🏥", "description", "Issue medical record credentials",   "fields", new String[]{"patientName", "height", "weight", "bloodType"}, "defaultMechanism", "sd-jwt-vc"));
        out.put("telecom",    Map.of("name", "Telia",                               "icon", "📱", "description", "Issue verified phone identity credentials", "fields", new String[]{"subscriberName", "phoneNumber", "verifiedSince"}, "defaultMechanism", "eddsa-jcs-2022"));
        return out;
    }

    /** Returns {@code {verifiableCredential, _walletHints}} per AGENT.md §5.2. */
    public Map<String, Object> issueCredential(String issuerType, String holderDid,
                                               Map<String, String> userClaims, String securingMechanism) {
        IssuerMeta meta = ISSUERS.get(issuerType);
        if (meta == null) throw new IllegalArgumentException("Unknown issuer type: " + issuerType);

        // Fall back to the issuer's configured default when no mechanism is specified.
        if (securingMechanism == null || securingMechanism.isBlank()) {
            securingMechanism = meta.defaultMechanism();
        }

        Instant now = Instant.now().truncatedTo(ChronoUnit.SECONDS);
        Instant expires = now.plus(meta.validDays(), ChronoUnit.DAYS);
        String credentialId = "urn:uuid:" + UUID.randomUUID();

        return switch (securingMechanism) {
            case "sd-jwt-vc"      -> issueSdJwtVc(issuerType, meta, holderDid, userClaims, now, expires, credentialId);
            case "eddsa-jcs-2022" -> issueEddsaJcs2022(issuerType, meta, holderDid, userClaims, now, expires, credentialId);
            case "bbs-2023"       -> issueBbs2023(issuerType, meta, holderDid, userClaims, now, expires, credentialId);
            default               -> throw new IllegalArgumentException("Unknown securingMechanism: " + securingMechanism);
        };
    }

    // -------- bbs-2023 --------
    private Map<String, Object> issueBbs2023(String issuerType, IssuerMeta meta, String holderDid,
                                             Map<String, String> userClaims,
                                             Instant now, Instant expires, String credentialId) {
        String issuerDid = getOrCreateBlsIssuerDid(issuerType);
        int statusIndex = status.allocateEntry(DEFAULT_STATUS_LIST, issuerDid);

        // BBS+ selective disclosure lets the holder reveal only chosen claims.
        // We pre-compute age_equal_or_over_NN booleans so the holder can
        // disclose e.g. age_equal_or_over_21=true WITHOUT revealing dateOfBirth.
        Map<String, String> allClaims = new LinkedHashMap<>(userClaims);
        addAgePredicateClaims(allClaims);

        ObjectNode vc = mapper.createObjectNode();
        ArrayNode ctx = vc.putArray("@context");
        ctx.add(VCDM_V2_CONTEXT);
        ctx.add(IDENTITY_CTX);
        vc.put("id", credentialId);
        ArrayNode type = vc.putArray("type");
        type.add("VerifiableCredential");
        type.add(meta.credentialType());
        vc.put("issuer", issuerDid);
        vc.put("validFrom", now.toString());
        vc.put("validUntil", expires.toString());

        ObjectNode subject = mapper.createObjectNode();
        if (holderDid != null) subject.put("id", holderDid);
        for (var e : allClaims.entrySet()) subject.put(e.getKey(), e.getValue());
        vc.set("credentialSubject", subject);

        ObjectNode credSchema = mapper.createObjectNode();
        credSchema.put("id", SCHEMAS_BASE + meta.credentialType() + ".json");
        credSchema.put("type", "JsonSchema");
        vc.set("credentialSchema", credSchema);

        ObjectNode credStatus = mapper.createObjectNode();
        credStatus.put("id", STATUS_BASE + DEFAULT_STATUS_LIST + "#" + statusIndex);
        credStatus.put("type", "BitstringStatusListEntry");
        credStatus.put("statusPurpose", "revocation");
        credStatus.put("statusListIndex", String.valueOf(statusIndex));
        credStatus.put("statusListCredential", STATUS_BASE + DEFAULT_STATUS_LIST);
        vc.set("credentialStatus", credStatus);

        bbs.attachBaseProof(vc, issuerDid);

        Map<String, Object> hints = walletHints(meta, issuerDid, credentialId, holderDid,
                now, expires, userClaims, /* sd field names = all signed claim names */
                new ArrayList<>(allClaims.keySet()), "bbs-2023");
        hints.put("statusListId", DEFAULT_STATUS_LIST);
        hints.put("statusListIndex", statusIndex);
        return wrap(mapper.convertValue(vc, Map.class), hints);
    }

    // -------- SD-JWT VC --------
    private Map<String, Object> issueSdJwtVc(String issuerType, IssuerMeta meta, String holderDid,
                                             Map<String, String> userClaims,
                                             Instant now, Instant expires, String credentialId) {
        String issuerDid = getOrCreateEd25519IssuerDid(issuerType);
        String vct = VCT_BASE + meta.credentialType() + "/v1";

        Map<String, String> claims = new LinkedHashMap<>(userClaims);
        addAgePredicateClaims(claims);

        SdJwtVcService.SdJwtResult sdResult = sdJwt.issue(
                issuerDid, holderDid, credentialId, vct, meta.displayName(), now, expires, claims);

        Map<String, Object> envelope = new LinkedHashMap<>();
        envelope.put("@context", List.of(VCDM_V2_CONTEXT));
        envelope.put("type", "EnvelopedVerifiableCredential");
        envelope.put("id", "data:" + SD_JWT_VC_MEDIA_TYPE + "," + sdResult.sdJwt());

        return wrap(envelope, walletHints(meta, issuerDid, credentialId, holderDid, now, expires,
                userClaims, sdResult.sdFields(), "sd-jwt-vc"));
    }

    // -------- eddsa-jcs-2022 --------
    private Map<String, Object> issueEddsaJcs2022(String issuerType, IssuerMeta meta, String holderDid,
                                                  Map<String, String> userClaims,
                                                  Instant now, Instant expires, String credentialId) {
        String issuerDid = getOrCreateEd25519IssuerDid(issuerType);
        int statusIndex = status.allocateEntry(DEFAULT_STATUS_LIST, issuerDid);

        ObjectNode vc = mapper.createObjectNode();
        ArrayNode ctx = vc.putArray("@context");
        ctx.add(VCDM_V2_CONTEXT);
        ctx.add(IDENTITY_CTX);
        vc.put("id", credentialId);
        ArrayNode type = vc.putArray("type");
        type.add("VerifiableCredential");
        type.add(meta.credentialType());
        vc.put("issuer", issuerDid);
        vc.put("validFrom", now.toString());
        vc.put("validUntil", expires.toString());

        ObjectNode subject = mapper.createObjectNode();
        if (holderDid != null) subject.put("id", holderDid);
        for (var e : userClaims.entrySet()) subject.put(e.getKey(), e.getValue());
        vc.set("credentialSubject", subject);

        ObjectNode credSchema = mapper.createObjectNode();
        credSchema.put("id", SCHEMAS_BASE + meta.credentialType() + ".json");
        credSchema.put("type", "JsonSchema");
        vc.set("credentialSchema", credSchema);

        ObjectNode credStatus = mapper.createObjectNode();
        credStatus.put("id", STATUS_BASE + DEFAULT_STATUS_LIST + "#" + statusIndex);
        credStatus.put("type", "BitstringStatusListEntry");
        credStatus.put("statusPurpose", "revocation");
        credStatus.put("statusListIndex", String.valueOf(statusIndex));
        credStatus.put("statusListCredential", STATUS_BASE + DEFAULT_STATUS_LIST);
        vc.set("credentialStatus", credStatus);

        eddsa.attachProof(vc, issuerDid, "assertionMethod", null, null);

        Map<String, Object> hints = walletHints(meta, issuerDid, credentialId, holderDid,
                now, expires, userClaims, List.of(), "eddsa-jcs-2022");
        hints.put("statusListId", DEFAULT_STATUS_LIST);
        hints.put("statusListIndex", statusIndex);
        return wrap(mapper.convertValue(vc, Map.class), hints);
    }

    // -------- helpers --------
    private static Map<String, Object> wrap(Map<String, Object> vc, Map<String, Object> hints) {
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("verifiableCredential", vc);
        out.put("_walletHints", hints);
        return out;
    }

    private Map<String, Object> walletHints(IssuerMeta meta, String issuerDid, String credentialId,
                                            String holderDid, Instant validFrom, Instant validUntil,
                                            Map<String, String> userClaims, List<String> sdFieldNames,
                                            String securingMechanism) {
        Map<String, Object> hints = new LinkedHashMap<>();
        hints.put("issuerDisplayName", meta.displayName());
        hints.put("issuerDid", issuerDid);
        hints.put("icon", meta.icon());
        hints.put("credentialId", credentialId);
        hints.put("credentialType", meta.credentialType());
        hints.put("holderDid", holderDid);
        hints.put("validFrom", validFrom.toString());
        hints.put("validUntil", validUntil.toString());
        hints.put("subjectPreview", new LinkedHashMap<>(userClaims));
        hints.put("sdFieldNames", sdFieldNames);
        hints.put("derivedPredicates", deriveablePredicateNames(userClaims));
        hints.put("securingMechanism", securingMechanism);
        return hints;
    }

    private void addAgePredicateClaims(Map<String, String> claims) {
        String dob = claims.get("dateOfBirth");
        if (dob == null || dob.isEmpty()) return;
        try {
            LocalDate birth = LocalDate.parse(dob, DateTimeFormatter.ISO_LOCAL_DATE);
            int years = Period.between(birth, LocalDate.now()).getYears();
            for (int t : AGE_THRESHOLDS) claims.put("age_equal_or_over_" + t, String.valueOf(years >= t));
        } catch (Exception ignored) { /* unparseable DOB — skip */ }
    }

    private List<String> deriveablePredicateNames(Map<String, String> userClaims) {
        if (!userClaims.containsKey("dateOfBirth")) return List.of();
        List<String> out = new ArrayList<>();
        for (int t : AGE_THRESHOLDS) out.add("age_equal_or_over_" + t);
        return out;
    }
}

