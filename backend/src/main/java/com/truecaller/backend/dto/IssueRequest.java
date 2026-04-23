package com.truecaller.backend.dto;

import java.util.Map;

/**
 * Issuer request body.
 *
 * @param securingMechanism One of {@code "bbs-2023"} (default per AGENT.md §2.3 —
 *                          currently 501, see {@code DataIntegrityBbs2023}),
 *                          {@code "sd-jwt-vc"}, or {@code "eddsa-jcs-2022"}.
 */
public record IssueRequest(
        String issuerType,
        String holderDid,
        Map<String, String> claims,
        String securingMechanism
) {
    public String securingMechanismOrDefault() {
        return securingMechanism == null || securingMechanism.isBlank()
                ? "bbs-2023" : securingMechanism;
    }
}
