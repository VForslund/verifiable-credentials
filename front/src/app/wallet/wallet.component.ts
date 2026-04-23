import { Component, inject, signal } from '@angular/core';
import { JsonPipe, SlicePipe } from '@angular/common';
import { VcApiService } from '../services/vc-api.service';
import { VcStateService, StoredCredential } from '../services/vc-state.service';
import { CredentialDecoderService, DecodedCredential } from '../services/credential-decoder.service';

@Component({
  selector: 'app-wallet',
  standalone: true,
  imports: [JsonPipe, SlicePipe],
  templateUrl: './wallet.component.html'
})
export class WalletComponent {
  state = inject(VcStateService);
  private api = inject(VcApiService);
  private decoder = inject(CredentialDecoderService);
  loading = signal(false);
  previewLoading = signal(false);
  vpPreview = signal<any>(null);
  walletHints = signal<any>(null);

  /** Track which credentials are showing decoded view vs raw JSON. Key = credential id */
  decodedViewOpen = new Map<string, boolean>();

  decode(stored: StoredCredential): DecodedCredential {
    return this.decoder.decode(stored);
  }

  setupHolder() {
    this.api.generateKeys().subscribe(res => {
      this.state.holderDid.set(res.did);
    });
  }

  goToIssuer() {
    this.state.activePersona.set('ISSUER');
  }

  /** Pull a fresh challenge if we don't already have one, then run cb(challenge). */
  private withChallenge(cb: (verifierDid: string, nonce: string) => void) {
    const existing = this.state.currentChallenge();
    if (existing) { cb(existing.verifierDid, existing.nonce); return; }
    this.api.getChallenge().subscribe(ch => {
      this.state.currentChallenge.set(ch);
      cb(ch.verifierDid, ch.nonce);
    });
  }

  generatePreview() {
    const req = this.state.pendingVerificationRequest();
    const holderDid = this.state.holderDid();
    const creds = this.state.storedCredentials();
    if (!req || !holderDid || creds.length === 0) return;

    this.previewLoading.set(true);
    this.withChallenge((verifierDid, nonce) => {
      const vcs = creds.map(c => c.verifiableCredential);
      this.api.createPresentation(holderDid, vcs, req.proofRequest, verifierDid, nonce).subscribe({
        next: wrapped => {
          this.vpPreview.set(wrapped.verifiableCredential);
          this.walletHints.set(wrapped._walletHints);
          this.previewLoading.set(false);
        },
        error: () => this.previewLoading.set(false)
      });
    });
  }

  approveAndSend() {
    if (this.vpPreview()) {
      this.state.generatedPresentation.set(this.vpPreview());
      this.state.pendingVerificationRequest.set(null);
      this.vpPreview.set(null);
      this.state.activePersona.set('VERIFIER');
      return;
    }

    const req = this.state.pendingVerificationRequest();
    const holderDid = this.state.holderDid();
    const creds = this.state.storedCredentials();
    if (!req || !holderDid || creds.length === 0) return;

    this.loading.set(true);
    this.withChallenge((verifierDid, nonce) => {
      const vcs = creds.map(c => c.verifiableCredential);
      this.api.createPresentation(holderDid, vcs, req.proofRequest, verifierDid, nonce).subscribe({
        next: wrapped => {
          this.state.generatedPresentation.set(wrapped.verifiableCredential);
          this.state.pendingVerificationRequest.set(null);
          this.loading.set(false);
          this.state.activePersona.set('VERIFIER');
        },
        error: () => this.loading.set(false)
      });
    });
  }

  denyRequest() {
    this.state.pendingVerificationRequest.set(null);
    this.vpPreview.set(null);
    this.walletHints.set(null);
  }

  goToVerifier() {
    this.state.activePersona.set('VERIFIER');
  }

  operatorLabel(op: string): string {
    const labels: Record<string, string> = {
      eq: '=', neq: '≠', gte: '≥', lte: '≤', gt: '>', lt: '<',
      age_gte: '(age) ≥', age_lte: '(age) ≤', exists: 'exists'
    };
    return labels[op] || op;
  }

  getClaimEntries(subject: any): [string, string][] {
    if (!subject) return [];
    return Object.entries(subject).filter(([k]) => k !== 'id') as [string, string][];
  }

  /** Distinct securing mechanisms across all stored credentials */
  get storedMechanisms(): Set<string> {
    return new Set(this.state.storedCredentials().map(c => this.decode(c).securingMechanism));
  }

  toggleDecodedView(credId: string) {
    this.decodedViewOpen.set(credId, !this.decodedViewOpen.get(credId));
  }

  isDecodedViewOpen(credId: string): boolean {
    return this.decodedViewOpen.get(credId) ?? false;
  }

  /** Decode the SD-JWT envelope into its JWT payload + disclosures */
  decodeEnvelope(vc: any): { header: any; payload: any; disclosures: any[] } | null {
    if (vc?.type !== 'EnvelopedVerifiableCredential' || typeof vc?.id !== 'string'
        || !vc.id.startsWith('data:application/vc+sd-jwt,')) {
      return null;
    }
    try {
      const sdJwt = vc.id.substring('data:application/vc+sd-jwt,'.length);
      const parts = sdJwt.split('~');
      const jwt = parts[0];
      const segs = jwt.split('.');
      const header = JSON.parse(atob(segs[0].replace(/-/g, '+').replace(/_/g, '/')));
      const payload = JSON.parse(atob(segs[1].replace(/-/g, '+').replace(/_/g, '/')));
      const disclosures = parts.slice(1).filter(Boolean).map((d: string) => {
        try {
          return JSON.parse(atob(d.replace(/-/g, '+').replace(/_/g, '/')));
        } catch {
          return d;
        }
      });
      return { header, payload, disclosures };
    } catch {
      return null;
    }
  }
}
