import { Component, inject, effect } from '@angular/core';
import { Router, RouterOutlet} from '@angular/router';
import { VcStateService } from './services/vc-state.service';

@Component({
  selector: 'app-root',
  imports: [RouterOutlet],
  templateUrl: './app.html',
  styleUrl: './app.css'
})
export class App {
  state = inject(VcStateService);
  private router = inject(Router);

  constructor() {
    // Navigate when persona changes
    effect(() => {
      const persona = this.state.activePersona();
      const route = persona === 'ISSUER' ? '/issuer' : persona === 'HOLDER' ? '/wallet' : '/verifier';
      this.router.navigateByUrl(route);
    });
  }

  setPersona(p: 'ISSUER' | 'HOLDER' | 'VERIFIER') {
    this.state.activePersona.set(p);
  }
}
