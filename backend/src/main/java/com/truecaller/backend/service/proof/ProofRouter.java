package com.truecaller.backend.service.proof;

import org.springframework.stereotype.Service;

import java.util.Map;

/**
 * Picks the right cryptosuite implementation based on either
 * {@code proof.cryptosuite} (for embedded Data Integrity proofs) or the
 * envelope media type (for {@code EnvelopedVerifiableCredential}s).
 *
 * <p>VCDM 2.0 §4.12 explicitly allows mixing securing mechanisms inside a
 * single {@code VerifiablePresentation.verifiableCredential} array — this
 * router is what makes that work in practice.
 */
@Service
public class ProofRouter {

    public enum Mechanism { EDDSA_JCS_2022, BBS_2023, SD_JWT_VC, UNKNOWN }

    public static final String SD_JWT_VC_MEDIA_TYPE = "application/vc+sd-jwt";
    public static final String SD_JWT_DATA_URI_PREFIX = "data:" + SD_JWT_VC_MEDIA_TYPE + ",";

    private final DataIntegrityEddsaJcs2022 eddsa;
    private final DataIntegrityBbs2023 bbs;
    private final SdJwtVcService sdJwt;

    public ProofRouter(DataIntegrityEddsaJcs2022 eddsa,
                       DataIntegrityBbs2023 bbs,
                       SdJwtVcService sdJwt) {
        this.eddsa = eddsa;
        this.bbs = bbs;
        this.sdJwt = sdJwt;
    }

    /** Identifies the securing mechanism of a single VC entry from a VP. */
    @SuppressWarnings("unchecked")
    public Mechanism mechanismOf(Map<String, Object> vc) {
        if (vc == null) return Mechanism.UNKNOWN;
        Object type = vc.get("type");
        Object id = vc.get("id");
        if ("EnvelopedVerifiableCredential".equals(type)
                && id instanceof String s && s.startsWith(SD_JWT_DATA_URI_PREFIX)) {
            return Mechanism.SD_JWT_VC;
        }
        Object proof = vc.get("proof");
        if (proof instanceof Map<?, ?> p) {
            Object suite = ((Map<String, Object>) p).get("cryptosuite");
            if (DataIntegrityEddsaJcs2022.CRYPTOSUITE.equals(suite)) return Mechanism.EDDSA_JCS_2022;
            if (DataIntegrityBbs2023.CRYPTOSUITE.equals(suite)) return Mechanism.BBS_2023;
        }
        return Mechanism.UNKNOWN;
    }

    public DataIntegrityEddsaJcs2022 eddsa() { return eddsa; }
    public DataIntegrityBbs2023      bbs()   { return bbs; }
    public SdJwtVcService            sdJwt() { return sdJwt; }
}

