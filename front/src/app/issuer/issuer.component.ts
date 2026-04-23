import { Component, inject, signal } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { JsonPipe } from '@angular/common';

import { VcStateService } from '../services/vc-state.service';
import {VcApiService} from '../services/vc-api.service';

interface IssuerPortal {
  key: string;
  name: string;
  icon: string;
  color: string;
  bgColor: string;
  borderColor: string;
  description: string;
  defaultMechanism: 'bbs-2023' | 'sd-jwt-vc' | 'eddsa-jcs-2022';
  fields: { key: string; label: string; placeholder: string; prefill: string }[];
}

const ISSUER_PORTALS: IssuerPortal[] = [
  {
    key: 'university', name: 'Stockholm University', icon: '🎓',
    color: 'text-blue-800', bgColor: 'bg-blue-50', borderColor: 'border-blue-200',
    defaultMechanism: 'sd-jwt-vc',
    description: 'You are logged into the university student portal. Request your academic degree as a Verifiable Credential.',
    fields: [
      { key: 'studentName', label: 'Student Name', placeholder: 'Alice Johnson', prefill: 'Alice Johnson' },
      { key: 'degree', label: 'Degree', placeholder: 'Bachelor of Science', prefill: 'Bachelor of Science' },
      { key: 'fieldOfStudy', label: 'Field of Study', placeholder: 'Computer Science', prefill: 'Computer Science' },
      { key: 'graduationYear', label: 'Graduation Year', placeholder: '2025', prefill: '2025' },
    ]
  },
  {
    key: 'government', name: 'Skatteverket (Swedish Gov)', icon: '🏛️',
    color: 'text-yellow-800', bgColor: 'bg-yellow-50', borderColor: 'border-yellow-200',
    defaultMechanism: 'bbs-2023',
    description: 'You are logged into the Swedish government identity portal via BankID. Download your national identity credential — secured with BBS+ for unlinkable selective disclosure.',
    fields: [
      { key: 'fullName', label: 'Full Name', placeholder: 'Alice Johnson', prefill: 'Alice Johnson' },
      { key: 'dateOfBirth', label: 'Date of Birth', placeholder: '1998-03-15', prefill: '1998-03-15' },
      { key: 'personalNumber', label: 'Personal Number', placeholder: '199803151234', prefill: '199803151234' },
      { key: 'nationality', label: 'Nationality', placeholder: 'Swedish', prefill: 'Swedish' },
    ]
  },
  {
    key: 'medical', name: 'Karolinska University Hospital', icon: '🏥',
    color: 'text-red-800', bgColor: 'bg-red-50', borderColor: 'border-red-200',
    defaultMechanism: 'sd-jwt-vc',
    description: 'You are logged into the patient portal (1177.se). Export your latest health summary as a credential.',
    fields: [
      { key: 'patientName', label: 'Patient Name', placeholder: 'Alice Johnson', prefill: 'Alice Johnson' },
      { key: 'height', label: 'Height (cm)', placeholder: '170', prefill: '170' },
      { key: 'weight', label: 'Weight (kg)', placeholder: '65', prefill: '65' },
      { key: 'bloodType', label: 'Blood Type', placeholder: 'A+', prefill: 'A+' },
    ]
  },
  {
    key: 'telecom', name: 'Telia', icon: '📱',
    color: 'text-purple-800', bgColor: 'bg-purple-50', borderColor: 'border-purple-200',
    defaultMechanism: 'eddsa-jcs-2022',
    description: 'You are logged into the Telia subscriber portal. Verify your phone number and get a portable identity credential — signed with EdDSA (no selective disclosure).',
    fields: [
      { key: 'subscriberName', label: 'Subscriber Name', placeholder: 'Alice Johnson', prefill: 'Alice Johnson' },
      { key: 'phoneNumber', label: 'Phone Number', placeholder: '+46701234567', prefill: '+46701234567' },
      { key: 'verifiedSince', label: 'Verified Since', placeholder: '2020-01-15', prefill: '2020-01-15' },
    ]
  },
];

@Component({
  selector: 'app-issuer',
  standalone: true,
  imports: [FormsModule, JsonPipe],
  templateUrl: './issuer.component.html'
})
export class IssuerComponent {
  private api: VcApiService = inject(VcApiService);
  state: VcStateService = inject(VcStateService);

  portals = ISSUER_PORTALS;
  selectedPortal = signal<IssuerPortal | null>(null);
  claims = signal<Record<string, string>>({});
  issuing = signal(false);
  lastIssuedVc = signal<any>(null);
  lastIssuedPortal = signal<string | null>(null);


  selectPortal(portal: IssuerPortal) {
    this.selectedPortal.set(portal);
    this.lastIssuedVc.set(null);
    // Pre-fill claims
    const prefilled: Record<string, string> = {};
    portal.fields.forEach(f => prefilled[f.key] = f.prefill);
    this.claims.set(prefilled);
  }

  getClaimValue(key: string, fallback: string): string {
    return this.claims()[key] ?? fallback;
  }

  setClaim(key: string, value: string) {
    this.claims.update(c => ({ ...c, [key]: value }));
  }

  issueFromPortal(portal: IssuerPortal) {
    const holderDid = this.state.holderDid();
    if (!holderDid) return;

    this.issuing.set(true);
    this.api.issueCredential(portal.key, holderDid, this.claims(), portal.defaultMechanism).subscribe({
      next: stored => {
        this.lastIssuedVc.set(stored);
        this.lastIssuedPortal.set(portal.key);
        this.state.addCredential(stored);
        this.issuing.set(false);
      },
      error: () => this.issuing.set(false)
    });
  }

  goToWallet() {
    this.state.activePersona.set('HOLDER');
  }
}
