import { Injectable } from '@angular/core';
import { StoredCredential } from './vc-state.service';

/**
 * Pure client-side decoder, per AGENT.md §9.
 *
 * <p>The wallet display MUST be derived locally from the credential, NOT
 * from a server-supplied mirror. Given a stored credential
 * (BBS-secured JSON-LD or {@code EnvelopedVerifiableCredential}) this
 * returns a flat view-model the templates can bind to. The underlying DID
 * is always exposed alongside any display string per the §12 rule 5
 * "Definition of Done" check.
 */
export interface DecodedCredential {
  /** The credential's @id (urn:uuid:... or jti for SD-JWT VC). */
  id: string;
  /** The non-VerifiableCredential type — e.g. GovernmentIdentityCredential. */
  type: string;
  /** Issuer DID — the only string that should ever be shown without a DID alongside it. */
  issuerDid: string;
  /** Optional issuer display name from _walletHints. Always shown alongside issuerDid. */
  issuerDisplayName?: string;
  validFrom?: string;
  validUntil?: string;
  /** Subject claims as the wallet last saw them (from _walletHints.subjectPreview). */
  subjectPreview: Record<string, string>;
  /** Names of selectively-disclosable fields (SD-JWT VC). */
  sdFieldNames: string[];
  /** Names of derived predicate booleans available (e.g. age_equal_or_over_21). */
  derivedPredicates: string[];
  /** "sd-jwt-vc" | "eddsa-jcs-2022" | "bbs-2023". */
  securingMechanism: string;
}

@Injectable({ providedIn: 'root' })
export class CredentialDecoderService {

  decode(stored: StoredCredential): DecodedCredential {
    const vc = stored.verifiableCredential ?? {};
    const hints = stored._walletHints ?? {};

    // Mechanism fingerprint — we *could* trust _walletHints.securingMechanism but
    // we re-derive it locally from the credential bytes to honour AGENT.md §9.
    let mechanism = 'unknown';
    if (vc.type === 'EnvelopedVerifiableCredential' && typeof vc.id === 'string'
        && vc.id.startsWith('data:application/vc+sd-jwt,')) {
      mechanism = 'sd-jwt-vc';
    } else if (vc.proof && vc.proof.cryptosuite === 'eddsa-jcs-2022') {
      mechanism = 'eddsa-jcs-2022';
    } else if (vc.proof && vc.proof.cryptosuite === 'bbs-2023') {
      mechanism = 'bbs-2023';
    }

    let id: string;
    let type: string;
    let issuerDid: string;
    let validFrom: string | undefined;
    let validUntil: string | undefined;

    if (mechanism === 'sd-jwt-vc') {
      const sdJwt = (vc.id as string).substring('data:application/vc+sd-jwt,'.length);
      const payload = decodeJwtPayload(sdJwt);
      id = payload.jti ?? hints.credentialId ?? vc.id ?? '';
      type = humanType(payload.vct) || hints.credentialType || 'VerifiableCredential';
      issuerDid = payload.iss ?? hints.issuerDid ?? '';
      validFrom = payload.iat ? new Date(payload.iat * 1000).toISOString() : hints.validFrom;
      validUntil = payload.exp ? new Date(payload.exp * 1000).toISOString() : hints.validUntil;
    } else {
      id = vc.id ?? hints.credentialId ?? '';
      const types: string[] = Array.isArray(vc.type) ? vc.type : [];
      type = types.find(t => t !== 'VerifiableCredential') ?? hints.credentialType ?? 'VerifiableCredential';
      issuerDid = typeof vc.issuer === 'string'
        ? vc.issuer
        : (vc.issuer && vc.issuer.id) ?? hints.issuerDid ?? '';
      validFrom = vc.validFrom ?? hints.validFrom;
      validUntil = vc.validUntil ?? hints.validUntil;
    }

    return {
      id,
      type,
      issuerDid,
      issuerDisplayName: hints.issuerDisplayName,
      validFrom,
      validUntil,
      subjectPreview: hints.subjectPreview ?? {},
      sdFieldNames: hints.sdFieldNames ?? [],
      derivedPredicates: hints.derivedPredicates ?? [],
      securingMechanism: mechanism,
    };
  }
}

function decodeJwtPayload(sdJwt: string): any {
  try {
    const jwt = sdJwt.split('~', 1)[0];
    const segs = jwt.split('.');
    if (segs.length < 2) return {};
    const json = atob(segs[1].replace(/-/g, '+').replace(/_/g, '/'));
    return JSON.parse(json);
  } catch {
    return {};
  }
}

function humanType(vct: string | undefined): string | undefined {
  if (!vct) return undefined;
  // vct = "https://truecaller.demo/vct/GovernmentIdentityCredential/v1" → keep just the type segment.
  const m = vct.match(/\/vct\/([^/]+)/);
  return m ? m[1] : vct;
}

