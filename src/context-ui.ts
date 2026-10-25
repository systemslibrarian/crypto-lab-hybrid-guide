import { hex, runContext } from './context';

export function mountContext(): void {
  const section = document.createElement('section'); section.id = 'real-context'; section.className = 'section';
  section.innerHTML = `<h2>Real X25519: different public inputs, the same raw secret</h2>
    <p>The earlier playground models component secrets. This separate experiment computes actual X25519 in your browser. A sender produces an ephemeral public coordinate c. An observer can compute c′ = 1/c modulo 2²⁵⁵−19 using only that public coordinate. X25519's clamped scalar removes the order-two difference, so the recipient derives the same raw secret from both.</p>
    <p>Predict: can a key derivation function notice the changed public coordinate if it receives only the unchanged secret?</p>
    <label for="context-case">Public input comparison</label>
    <select id="context-case"><option value="same">Control: the same public input twice</option><option value="inverse">Paper construction: invert the public coordinate</option><option value="fresh">Control: a fresh independent public input</option></select>
    <button id="context-run" type="button">Generate keys and compare real derivations</button>
    <p id="context-status" role="status" aria-live="polite">Choose a case, then run.</p>
    <div id="context-output" hidden>
      <div class="context-scroll" role="region" aria-label="Public context derivation comparison" tabindex="0"><table><caption>Equality measured from the actual bytes</caption><thead><tr><th scope="col">Check</th><th scope="col">Result</th></tr></thead><tbody id="context-rows"></tbody></table></div>
      <details><summary>Inspect public coordinates, raw secrets and derived keys</summary><pre id="context-bytes"></pre></details>
    </div>
    <p>Mechanism: compare HKDF-SHA-256(secret, label) with HKDF-SHA-256(secret, label || c || recipient public key), using a zero salt and fixed 32-byte coordinate fields. For the inverse case, only the bound derivation sees the different transcript.</p>
    <p>Scope: this is a raw-DH binding counterexample and a custom HKDF illustration. It is not X-Wing or HPKE, executes no ML-KEM, and proves no hybrid or multi-user security theorem. It does not recover the recipient's secret key or break X25519's Diffie–Hellman secrecy. An unsupported browser reports an error rather than substituting simulated outputs.</p>
    <p>Sources: <a href="https://eprint.iacr.org/2026/140">On the Necessity of Public Contexts in Hybrid KEMs</a>, §III-B; <a href="https://www.rfc-editor.org/rfc/rfc7748#section-6.1">RFC 7748 §6.1 and §7</a>.</p>`;
  document.querySelector('main')!.append(section);
  const get = <T extends HTMLElement>(id: string) => document.getElementById(id) as T;
  const select = get<HTMLSelectElement>('context-case'), run = get<HTMLButtonElement>('context-run');
  const output = get('context-output'), status = get('context-status');
  let generation = 0, previous = select.value;
  select.addEventListener('change', () => {
    if (select.value === previous) return; previous = select.value; generation++;
    output.hidden = true; get('context-rows').replaceChildren(); get('context-bytes').textContent = '';
    status.textContent = 'Input changed. Previous result retired; run again.';
  });
  run.addEventListener('click', async () => {
    const mine = ++generation; run.disabled = true; output.hidden = true; status.textContent = 'Computing real X25519 and HKDF…';
    try {
      const r = await runContext(select.value as 'same' | 'inverse' | 'fresh');
      if (mine !== generation) return;
      const rows = get('context-rows'); rows.replaceChildren();
      for (const [label, value] of [['Sender/recipient DH agreement', r.agreement], ['Distinct public inputs', r.distinct], ['Equal raw DH secrets', r.rawEqual], ['Equal secret-only KDF outputs', r.unboundEqual], ['Equal context-bound KDF outputs', r.boundEqual]] as const) {
        const row = document.createElement('tr'), heading = document.createElement('th'), cell = document.createElement('td');
        heading.scope = 'row'; heading.textContent = label; cell.textContent = value ? 'YES' : 'NO'; row.append(heading, cell); rows.append(row);
      }
      get('context-bytes').textContent = Object.entries(r).filter(([,v]) => v instanceof Uint8Array).map(([k,v]) => `${k}: ${hex(v as Uint8Array)}`).join('\n');
      output.hidden = false;
      status.textContent = r.distinct && r.rawEqual && r.unboundEqual && !r.boundEqual
        ? 'BINDING COUNTEREXAMPLE — distinct public inputs give equal raw and secret-only outputs; the context-bound keys differ.'
        : 'Control complete. Read the computed equality checks below; this control alone does not establish security.';
    } catch (error) { if (mine === generation) status.textContent = `No result: ${String(error)}. Native X25519 support is required.`; }
    finally { run.disabled = false; }
  });
}
