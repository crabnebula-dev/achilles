// Proof that lit resolves through the import map in both hosts. The element
// renders nothing and is never instantiated; the bare `lit` import below is
// what keeps the map, the vendored tree, the build's import validation, and
// the service-worker precache honest until the first real component replaces
// this in L1.
import { LitElement, html } from "lit";

class AchSmoke extends LitElement {
  render() {
    return html``;
  }
}

customElements.define("ach-smoke", AchSmoke);
