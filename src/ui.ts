// ui.ts — hybrid cryptography guide UI.
import {
	freshComponents,
	deriveSessionKey,
	assess,
	bytesToHex,
	type Components,
	type Combiner,
	type BreakState,
} from './engine.ts';
import {
	DECISION,
	DEPLOYMENTS,
	PITFALLS,
	TIMELINE_EVENTS,
	HANDSHAKE_SIZES,
	type TimelineEvent,
} from './data.ts';

function el<K extends keyof HTMLElementTagNameMap>(
	tag: K,
	className?: string,
	html?: string,
): HTMLElementTagNameMap[K] {
	const node = document.createElement(tag);
	if (className) node.className = className;
	if (html !== undefined) node.innerHTML = html;
	return node;
}

function announce(message: string): void {
	const region = document.getElementById('a11y-announcer');
	if (!region) return;
	region.textContent = '';
	window.setTimeout(() => {
		region.textContent = message;
	}, 30);
}

// --- toast notifications ---------------------------------------------------
function ensureToastRoot(): HTMLElement {
	let root = document.getElementById('toast-root');
	if (!root) {
		root = el('div');
		root.id = 'toast-root';
		root.className = 'toast-root';
		root.setAttribute('aria-live', 'polite');
		root.setAttribute('aria-atomic', 'false');
		document.body.appendChild(root);
	}
	return root;
}

export function toast(message: string, tone: 'info' | 'ok' | 'warn' = 'info'): void {
	const root = ensureToastRoot();
	const node = el('div', `toast toast--${tone}`);
	node.textContent = message;
	root.appendChild(node);
	requestAnimationFrame(() => node.classList.add('is-shown'));
	window.setTimeout(() => {
		node.classList.remove('is-shown');
		window.setTimeout(() => node.remove(), 250);
	}, 2200);
}

// --- sticky section navigation --------------------------------------------
interface SectionAnchor {
	id: string;
	label: string;
}

const SECTIONS: SectionAnchor[] = [
	{ id: 'playground-heading', label: 'Combiner' },
	{ id: 'timeline-heading', label: 'Timeline' },
	{ id: 'handshake-heading', label: 'Wire Size' },
	{ id: 'benchmark-heading', label: 'Performance' },
	{ id: 'decision-heading', label: 'Decide' },
	{ id: 'deployments-heading', label: 'In Production' },
	{ id: 'pitfalls-heading', label: 'Practice' },
];

function renderNav(): HTMLElement {
	const nav = el('nav', 'section-nav');
	nav.setAttribute('aria-label', 'On-page navigation');
	nav.innerHTML = `
    <ol class="section-nav__list">
      ${SECTIONS.map(
				(s) =>
					`<li><a class="section-nav__link" href="#${s.id}" data-target="${s.id}">${s.label}</a></li>`,
			).join('')}
    </ol>
  `;
	nav.addEventListener('click', (event) => {
		const target = event.target as HTMLElement;
		const link = target.closest('a.section-nav__link') as HTMLAnchorElement | null;
		if (!link) return;
		const id = link.dataset.target;
		if (!id) return;
		const node = document.getElementById(id);
		if (!node) return;
		event.preventDefault();
		node.focus({ preventScroll: true });
		node.scrollIntoView({ block: 'start', behavior: 'smooth' });
	});

	// Active-link tracking via IntersectionObserver
	queueMicrotask(() => {
		const links = new Map<string, HTMLAnchorElement>();
		nav.querySelectorAll<HTMLAnchorElement>('a.section-nav__link').forEach((a) => {
			const id = a.dataset.target;
			if (id) links.set(id, a);
		});
		const headings = SECTIONS.map((s) => document.getElementById(s.id)).filter(
			(node): node is HTMLElement => !!node,
		);
		if (headings.length === 0) return;

		const observer = new IntersectionObserver(
			(entries) => {
				entries.forEach((entry) => {
					if (entry.isIntersecting) {
						links.forEach((a) => a.classList.remove('is-active'));
						const a = links.get((entry.target as HTMLElement).id);
						if (a) a.classList.add('is-active');
					}
				});
			},
			// Wide active band so headings reliably register as the user scrolls;
			// a narrow band could skip past tall headings without ever firing.
			{ rootMargin: '-25% 0px -50% 0px', threshold: 0 },
		);
		headings.forEach((h) => observer.observe(h));
	});

	return nav;
}

// --- hero ------------------------------------------------------------------
function renderHero(): HTMLElement {
	const hero = el('header', 'hero-panel');
	hero.innerHTML = `
    <button id="theme-toggle" class="theme-toggle" type="button" aria-label="Switch theme" aria-pressed="false">
      <span class="theme-toggle__icon" aria-hidden="true">\u{1F319}</span>
    </button>
    <div class="hero-copy">
      <a class="portfolio-badge" href="https://github.com/systemslibrarian?tab=repositories&q=crypto-lab">crypto-lab · portfolio</a>
      <p class="eyebrow">Post-Quantum · Migration</p>
      <h1>Hybrid Guide</h1>
      <p class="hero-text">
        During the transition to post-quantum cryptography, the safe move is not to replace
        classical algorithms but to <em>combine</em> them with post-quantum ones. A hybrid KEM
        runs both a classical key exchange (X25519) and a post-quantum one (ML-KEM) and binds the
        results, so the session key stays secret as long as <em>either</em> half holds.
      </p>
      <div class="hero-cta-row">
        <a class="action-button" href="#playground-heading" data-anchor>Try the combiner</a>
        <a class="ghost-button" href="#timeline-heading" data-anchor>See the timeline</a>
      </div>
      <details class="why-details">
        <summary>Why hybrid instead of pure PQC?</summary>
        <p>
          Two risks at once: a quantum computer could break classical X25519, and undiscovered
          cryptanalysis could weaken a young PQC scheme. A hybrid hedges both — an attacker has
          to break both halves at the same time. It is the recommended interim strategy until
          PQC has years of scrutiny behind it.
        </p>
      </details>
    </div>
    <aside class="hero-metric-card" aria-label="The hybrid promise">
      <p class="hero-metric-label">The hybrid promise</p>
      <p class="hero-metric-value">
        secure if <span class="hero-metric-strong">X25519 holds</span>
        <span class="hero-metric-or">OR</span>
        <span class="hero-metric-strong">ML-KEM holds</span>
      </p>
      <p class="hero-metric-note">Break one, the other still protects you.</p>
      <dl class="hero-stat-grid">
        <div><dt>NIST std.</dt><dd>FIPS 203</dd></div>
        <div><dt>Component bits</dt><dd>2 × 256</dd></div>
        <div><dt>Combiner</dt><dd>SHA-256</dd></div>
      </dl>
    </aside>
  `;

	hero.querySelectorAll<HTMLAnchorElement>('a[data-anchor]').forEach((a) => {
		a.addEventListener('click', (event) => {
			const href = a.getAttribute('href') ?? '';
			const id = href.replace(/^#/, '');
			const target = document.getElementById(id);
			if (!target) return;
			event.preventDefault();
			target.focus({ preventScroll: true });
			target.scrollIntoView({ block: 'start', behavior: 'smooth' });
		});
	});

	return hero;
}

// --- combiner playground ---------------------------------------------------
interface PlaygroundController {
	regen: () => void;
	preset: (name: string) => void;
	toggleClassical: () => void;
	togglePq: () => void;
	cycleCombiner: () => void;
	copyKey: () => void;
}

function renderPlayground(): { node: HTMLElement; controller: PlaygroundController } {
	const section = el('section', 'lab-section reveal');
	section.setAttribute('aria-labelledby', 'playground-heading');
	section.innerHTML = `
    <div class="section-heading-row">
      <div>
        <p class="section-kicker">Live demo</p>
        <h2 id="playground-heading" tabindex="-1">The Combiner</h2>
        <p class="section-footnote">
          Two component shared secrets feed a combiner that derives one session key (real SHA-256
          via Web Crypto). Break a component to see whether the session key stays unpredictable.
        </p>
      </div>
      <kbd class="kbd-hint" title="Keyboard shortcuts">
        <span>R</span> regen · <span>1–4</span> scenarios · <span>C</span> copy · <span>T</span> theme
      </kbd>
    </div>

    <figure class="combiner-diagram" aria-label="Diagram of two KEM secrets feeding into a combiner that outputs one session key">
      <svg viewBox="0 0 380 140" role="img" aria-hidden="true" focusable="false">
        <defs>
          <linearGradient id="diagFlow" x1="0" y1="0" x2="1" y2="0">
            <stop offset="0%" stop-color="var(--accent)"/>
            <stop offset="100%" stop-color="var(--accent-4)"/>
          </linearGradient>
        </defs>
        <g id="diag-classical-group">
          <rect x="6" y="12" width="120" height="40" rx="12" fill="none" stroke="var(--accent)" stroke-width="2" id="diag-classical-rect"/>
          <text x="66" y="32" text-anchor="middle" fill="var(--ink-strong)" font-family="var(--mono)" font-size="11">X25519</text>
          <text x="66" y="46" text-anchor="middle" fill="var(--ink-soft)" font-family="var(--mono)" font-size="9.5" id="diag-classical-state">intact</text>
        </g>
        <g id="diag-pq-group">
          <rect x="6" y="88" width="120" height="40" rx="12" fill="none" stroke="var(--accent-3)" stroke-width="2" id="diag-pq-rect"/>
          <text x="66" y="108" text-anchor="middle" fill="var(--ink-strong)" font-family="var(--mono)" font-size="11">ML-KEM-768</text>
          <text x="66" y="122" text-anchor="middle" fill="var(--ink-soft)" font-family="var(--mono)" font-size="9.5" id="diag-pq-state">intact</text>
        </g>
        <path d="M126 32 C 180 32, 180 70, 210 70" fill="none" stroke="url(#diagFlow)" stroke-width="2.5" id="diag-path-classical"/>
        <path d="M126 108 C 180 108, 180 70, 210 70" fill="none" stroke="url(#diagFlow)" stroke-width="2.5" id="diag-path-pq"/>
        <rect x="210" y="50" width="86" height="40" rx="12" fill="var(--mono-block-bg)"/>
        <text x="253" y="74" text-anchor="middle" fill="var(--mono-block-fg)" font-family="var(--mono)" font-size="11" id="diag-combiner-label">SHA-256</text>
        <path d="M296 70 L 352 70" fill="none" stroke="url(#diagFlow)" stroke-width="2.5"/>
        <polygon points="352,64 364,70 352,76" fill="var(--accent-4)"/>
        <text x="358" y="54" text-anchor="end" fill="var(--ink-soft)" font-family="var(--mono)" font-size="10">session key</text>
      </svg>
      <figcaption class="sr-only">
        Two component shared secrets — classical X25519 and post-quantum ML-KEM — are fed into a
        combiner, which produces one derived session key.
      </figcaption>
    </figure>

    <div class="combiner-flow">
      <div class="comp-card comp-card--classical" id="card-classical">
        <p class="comp-label">Classical · X25519</p>
        <p class="mono-inline comp-secret" id="ss-classical" aria-label="Classical shared secret">—</p>
        <label class="break-toggle">
          <input type="checkbox" id="break-classical" />
          <span>Quantum computer breaks this</span>
        </label>
      </div>
      <div class="comp-card comp-card--pq" id="card-pq">
        <p class="comp-label">Post-Quantum · ML-KEM-768</p>
        <p class="mono-inline comp-secret" id="ss-pq" aria-label="Post-quantum shared secret">—</p>
        <label class="break-toggle">
          <input type="checkbox" id="break-pq" />
          <span>Cryptanalysis breaks this</span>
        </label>
      </div>
    </div>

    <fieldset class="scenario-presets" aria-label="Quick scenarios">
      <legend class="scenario-presets__legend">Try a scenario</legend>
      <div class="scenario-presets__row" role="group">
        <button type="button" class="preset-button" data-scenario="both-ok" data-key="1">
          <span class="preset-button__key" aria-hidden="true">1</span> Both intact
        </button>
        <button type="button" class="preset-button" data-scenario="break-classical" data-key="2">
          <span class="preset-button__key" aria-hidden="true">2</span> Quantum breaks X25519
        </button>
        <button type="button" class="preset-button" data-scenario="break-pq" data-key="3">
          <span class="preset-button__key" aria-hidden="true">3</span> Cryptanalysis breaks ML-KEM
        </button>
        <button type="button" class="preset-button preset-button--danger" data-scenario="break-both" data-key="4">
          <span class="preset-button__key" aria-hidden="true">4</span> Worst case
        </button>
      </div>
    </fieldset>

    <div class="combiner-bar">
      <label>Combiner:
        <select id="combiner">
          <option value="xwing" selected>X-Wing-style (bound)</option>
          <option value="naive">Naive concatenation</option>
        </select>
      </label>
      <button id="regen" class="ghost-button" type="button">New session</button>
    </div>

    <div class="formula-card" id="formula-card" aria-live="polite">
      <p class="formula-label">Combiner construction</p>
      <pre class="formula-body" id="formula-body"></pre>
      <p class="panel-copy formula-note" id="formula-note"></p>
    </div>

    <details class="code-panel">
      <summary>Show the Web Crypto snippet</summary>
      <pre class="code-block"><code id="code-block"></code></pre>
      <div class="code-panel__actions">
        <button type="button" class="ghost-button ghost-button--compact" id="copy-code">Copy snippet</button>
        <span class="code-panel__hint">Pure browser primitives — no dependencies.</span>
      </div>
    </details>

    <div class="attack-row">
      <button type="button" class="action-button action-button--danger" id="run-attack">
        Simulate re-encapsulation attack
      </button>
      <div class="attack-result" id="attack-result" hidden></div>
    </div>

    <div class="session-out panel-card" aria-live="polite">
      <div class="panel-header">
        <h3>Derived session key</h3>
        <span id="verdict-chip" class="vs-chip" aria-label="Verdict">—</span>
      </div>
      <div class="session-key-row">
        <p class="mono-block" id="session-key" aria-label="Session key in hexadecimal">—</p>
        <button type="button" id="copy-key" class="ghost-button ghost-button--compact" aria-label="Copy session key to clipboard">Copy</button>
      </div>

      <div class="bitgrid-wrap" aria-label="Attacker remaining uncertainty, visualised as bits">
        <p class="hero-metric-label">Attacker’s remaining uncertainty <span class="bitgrid-count" id="bitgrid-count" aria-hidden="true"></span></p>
        <div class="bitgrid-pair">
          <div class="bitgrid-col">
            <p class="bitgrid-label"><span class="bitgrid-dot bitgrid-dot--classical"></span> X25519 · 256 bits</p>
            <div class="bitgrid" id="bitgrid-classical" role="img" aria-label="Classical half entropy grid"></div>
          </div>
          <div class="bitgrid-col">
            <p class="bitgrid-label"><span class="bitgrid-dot bitgrid-dot--pq"></span> ML-KEM-768 · 256 bits</p>
            <div class="bitgrid" id="bitgrid-pq" role="img" aria-label="Post-quantum half entropy grid"></div>
          </div>
        </div>
        <div
          class="entropy-track"
          role="progressbar"
          aria-valuemin="0"
          aria-valuemax="512"
          aria-valuenow="0"
          id="entropy-track"
        >
          <div class="entropy-fill" id="entropy-fill" style="width:0%"></div>
        </div>
        <p class="mono-inline mono-inline--meter" id="entropy-val">—</p>
      </div>

      <p class="panel-copy" id="verdict-detail"></p>
    </div>
  `;

	const $ = (id: string) => section.querySelector('#' + id) as HTMLElement;

	const breakClassical = $('break-classical') as HTMLInputElement;
	const breakPq = $('break-pq') as HTMLInputElement;
	const combinerSel = $('combiner') as HTMLSelectElement;
	const copyBtn = $('copy-key') as HTMLButtonElement;
	const entropyTrack = $('entropy-track');
	const attackBtn = $('run-attack') as HTMLButtonElement;
	const attackResult = $('attack-result');
	const copyCodeBtn = $('copy-code') as HTMLButtonElement;

	// Render bit grids once. Each cell = 1 bit; 16×16 = 256 bits per half.
	function buildGrid(host: HTMLElement, kind: 'classical' | 'pq') {
		const frag = document.createDocumentFragment();
		for (let i = 0; i < 256; i++) {
			const cell = document.createElement('span');
			cell.className = `bitgrid-cell bitgrid-cell--${kind}`;
			frag.appendChild(cell);
		}
		host.appendChild(frag);
	}
	buildGrid($('bitgrid-classical'), 'classical');
	buildGrid($('bitgrid-pq'), 'pq');

	let comps: Components = freshComponents();
	let lastHeadline = '';

	const SNIPPET_NAIVE = `// Naive concatenation combiner
const ssClassical = crypto.getRandomValues(new Uint8Array(32));
const ssPq        = crypto.getRandomValues(new Uint8Array(32));

const data = new Uint8Array(ssClassical.length + ssPq.length);
data.set(ssClassical, 0);
data.set(ssPq, ssClassical.length);

const sessionKey = new Uint8Array(
  await crypto.subtle.digest('SHA-256', data),
);`;

	const SNIPPET_XWING = `// X-Wing-style bound combiner
const ssClassical = crypto.getRandomValues(new Uint8Array(32));
const ssPq        = crypto.getRandomValues(new Uint8Array(32));
const ctBinding   = crypto.getRandomValues(new Uint8Array(32));
const label       = new TextEncoder().encode('crypto-lab-hybrid');

const data = new Uint8Array(
  label.length + ssPq.length + ssClassical.length + ctBinding.length,
);
let off = 0;
data.set(label, off);        off += label.length;
data.set(ssPq, off);         off += ssPq.length;
data.set(ssClassical, off);  off += ssClassical.length;
data.set(ctBinding, off);

const sessionKey = new Uint8Array(
  await crypto.subtle.digest('SHA-256', data),
);`;

	function updateFormula(combiner: Combiner): void {
		const body = $('formula-body');
		const note = $('formula-note');
		const code = $('code-block');
		const label = section.querySelector<SVGTextElement>('#diag-combiner-label');
		if (combiner === 'naive') {
			body.textContent = 'K = SHA-256( ss_classical ‖ ss_pq )';
			note.textContent =
				'Just concatenates and hashes. Sufficient when both halves are random, but does not bind the transcript — a real attacker can re-encapsulate.';
			code.textContent = SNIPPET_NAIVE;
			if (label) label.textContent = 'SHA-256 ‖';
		} else {
			body.textContent =
				'K = SHA-256( "crypto-lab-hybrid" ‖ ss_pq ‖ ss_classical ‖ ct_binding )';
			note.textContent =
				'Domain-separated and transcript-bound, à la X-Wing. The label and ciphertext binding make re-encapsulation attacks fail.';
			code.textContent = SNIPPET_XWING;
			if (label) label.textContent = 'SHA-256 ⊕';
		}
	}

	function paintDiagram(state: BreakState): void {
		const classicalPath = section.querySelector<SVGPathElement>('#diag-path-classical');
		const pqPath = section.querySelector<SVGPathElement>('#diag-path-pq');
		const classicalRect = section.querySelector<SVGRectElement>('#diag-classical-rect');
		const pqRect = section.querySelector<SVGRectElement>('#diag-pq-rect');
		const classicalState = section.querySelector<SVGTextElement>('#diag-classical-state');
		const pqState = section.querySelector<SVGTextElement>('#diag-pq-state');

		classicalPath?.classList.toggle('is-broken', state.classicalBroken);
		pqPath?.classList.toggle('is-broken', state.pqBroken);
		classicalRect?.classList.toggle('is-broken', state.classicalBroken);
		pqRect?.classList.toggle('is-broken', state.pqBroken);
		if (classicalState) classicalState.textContent = state.classicalBroken ? 'broken' : 'intact';
		if (pqState) pqState.textContent = state.pqBroken ? 'broken' : 'intact';
	}

	function paintBitGrids(state: BreakState): void {
		const classical = $('bitgrid-classical');
		const pq = $('bitgrid-pq');
		classical.classList.toggle('is-broken', state.classicalBroken);
		pq.classList.toggle('is-broken', state.pqBroken);
		const count = (state.classicalBroken ? 0 : 256) + (state.pqBroken ? 0 : 256);
		$('bitgrid-count').textContent = ` · ${count} / 512 bits unknown`;
	}

	async function refresh(): Promise<void> {
		const combiner = combinerSel.value as Combiner;
		const state: BreakState = {
			classicalBroken: breakClassical.checked,
			pqBroken: breakPq.checked,
		};

		$('ss-classical').textContent = bytesToHex(comps.classical).slice(0, 24) + '…';
		$('ss-pq').textContent = bytesToHex(comps.pq).slice(0, 24) + '…';
		$('card-classical').classList.toggle('is-broken', state.classicalBroken);
		$('card-pq').classList.toggle('is-broken', state.pqBroken);

		const key = await deriveSessionKey(comps, combiner);
		$('session-key').textContent = bytesToHex(key);

		const v = assess(state, combiner);
		const pct = (v.remainingBits / 512) * 100;
		const fill = $('entropy-fill');
		fill.style.width = `${pct}%`;
		fill.className = 'entropy-fill ' + (v.secure ? 'entropy-fill--ok' : 'entropy-fill--bad');
		$('entropy-val').textContent = `${v.remainingBits} bits to guess`;
		entropyTrack.setAttribute('aria-valuenow', String(v.remainingBits));
		entropyTrack.setAttribute(
			'aria-valuetext',
			`${v.remainingBits} bits of attacker uncertainty out of 512`,
		);

		const chip = $('verdict-chip');
		chip.className = 'vs-chip ' + (v.secure ? 'vs-chip--ok' : 'vs-chip--bad');
		chip.textContent = v.headline;
		$('verdict-detail').innerHTML = v.detail;

		paintDiagram(state);
		paintBitGrids(state);
		updateFormula(combiner);

		if (v.headline !== lastHeadline) {
			announce(v.headline + '. ' + v.remainingBits + ' bits of attacker uncertainty.');
			lastHeadline = v.headline;
		}
	}

	function applyScenario(name: string): void {
		switch (name) {
			case 'both-ok':
				breakClassical.checked = false;
				breakPq.checked = false;
				break;
			case 'break-classical':
				breakClassical.checked = true;
				breakPq.checked = false;
				break;
			case 'break-pq':
				breakClassical.checked = false;
				breakPq.checked = true;
				break;
			case 'break-both':
				breakClassical.checked = true;
				breakPq.checked = true;
				break;
		}
		void refresh();
	}

	breakClassical.addEventListener('change', () => void refresh());
	breakPq.addEventListener('change', () => void refresh());
	combinerSel.addEventListener('change', () => {
		attackResult.hidden = true;
		$('session-key').classList.remove('is-attacked', 'is-shielded');
		void refresh();
	});
	$('regen').addEventListener('click', () => {
		comps = freshComponents();
		toast('New session generated', 'info');
		void refresh();
	});

	section.querySelectorAll<HTMLButtonElement>('.preset-button').forEach((btn) => {
		btn.addEventListener('click', () => {
			const name = btn.getAttribute('data-scenario');
			if (name) applyScenario(name);
		});
	});

	attackBtn.addEventListener('click', () => {
		const combiner = combinerSel.value as Combiner;
		const sessionKey = $('session-key');
		sessionKey.classList.remove('is-attacked', 'is-shielded');
		// Re-trigger animation by forcing reflow.
		void sessionKey.offsetWidth;
		if (combiner === 'naive') {
			attackResult.dataset.tone = 'bad';
			attackResult.innerHTML = `
        <strong>Attack succeeds.</strong> Without a transcript binding, an
        attacker re-encapsulates the PQ ciphertext, forces a colliding
        component secret, and the SHA-256 of the concatenation lands on a
        key they can compute. X-Wing prevents this with the
        <code>ct_binding</code> term inside the hash input.
      `;
			sessionKey.classList.add('is-attacked');
			toast('Naive combiner compromised', 'warn');
		} else {
			attackResult.dataset.tone = 'ok';
			attackResult.innerHTML = `
        <strong>Attack deflected.</strong> The transcript binding inside the
        hash (<code>ct_binding</code> plus the domain-separation label) makes
        the attacker’s forced ciphertext land on a different session key —
        the collision they need does not exist.
      `;
			sessionKey.classList.add('is-shielded');
			toast('X-Wing combiner held', 'ok');
		}
		attackResult.hidden = false;
	});

	// Default labels captured once so rapid double-clicks cannot get the
	// button stuck on the "Copied" string. Each click cancels any pending
	// restore timer before scheduling a new one.
	const COPY_KEY_LABEL = copyBtn.textContent ?? 'Copy';
	const COPY_CODE_LABEL = copyCodeBtn.textContent ?? 'Copy snippet';
	let copyKeyTimer: number | undefined;
	let copyCodeTimer: number | undefined;

	copyCodeBtn.addEventListener('click', async () => {
		const text = $('code-block').textContent ?? '';
		try {
			await navigator.clipboard.writeText(text);
			copyCodeBtn.textContent = 'Copied';
			copyCodeBtn.classList.add('is-copied');
			toast('Snippet copied', 'ok');
			if (copyCodeTimer !== undefined) window.clearTimeout(copyCodeTimer);
			copyCodeTimer = window.setTimeout(() => {
				copyCodeBtn.textContent = COPY_CODE_LABEL;
				copyCodeBtn.classList.remove('is-copied');
				copyCodeTimer = undefined;
			}, 1400);
		} catch {
			toast('Copy failed', 'warn');
		}
	});

	async function copyKey(): Promise<void> {
		const text = $('session-key').textContent ?? '';
		try {
			await navigator.clipboard.writeText(text);
			copyBtn.textContent = 'Copied';
			copyBtn.classList.add('is-copied');
			toast('Session key copied', 'ok');
			if (copyKeyTimer !== undefined) window.clearTimeout(copyKeyTimer);
			copyKeyTimer = window.setTimeout(() => {
				copyBtn.textContent = COPY_KEY_LABEL;
				copyBtn.classList.remove('is-copied');
				copyKeyTimer = undefined;
			}, 1400);
		} catch {
			toast('Copy failed — select the text manually', 'warn');
		}
	}
	copyBtn.addEventListener('click', () => void copyKey());

	void refresh();

	const controller: PlaygroundController = {
		regen: () => {
			comps = freshComponents();
			toast('New session generated', 'info');
			void refresh();
		},
		preset: applyScenario,
		toggleClassical: () => {
			breakClassical.checked = !breakClassical.checked;
			void refresh();
		},
		togglePq: () => {
			breakPq.checked = !breakPq.checked;
			void refresh();
		},
		cycleCombiner: () => {
			combinerSel.value = combinerSel.value === 'naive' ? 'xwing' : 'naive';
			void refresh();
		},
		copyKey: () => void copyKey(),
	};

	return { node: section, controller };
}

// --- migration timeline ----------------------------------------------------
function renderTimeline(): HTMLElement {
	const section = el('section', 'lab-section reveal');
	section.setAttribute('aria-labelledby', 'timeline-heading');
	const years = TIMELINE_EVENTS.map((e) => e.year);
	const minYear = Math.min(...years);
	const maxYear = Math.max(...years);
	const initialIdx = TIMELINE_EVENTS.findIndex((e) => e.year === 2025);
	const crqcYear =
		TIMELINE_EVENTS.find((e) => e.classical === 'broken')?.year ?? 2035;

	// Stable display hashes for the "recorded in 2025" cards (one CSPRNG
	// call yields both, no need to draw a second set of components).
	const displayComps = freshComponents();
	const classicalHash = bytesToHex(displayComps.classical).slice(0, 32);
	const hybridHash = bytesToHex(displayComps.pq).slice(0, 32);

	section.innerHTML = `
    <div class="section-heading-row">
      <div>
        <p class="section-kicker">Migration</p>
        <h2 id="timeline-heading" tabindex="-1">The Next 15 Years</h2>
        <p class="section-footnote">
          Drag the year to see how the threat picture shifts. The point of going hybrid in 2025
          is that the sessions you record today still need to be safe in 2035.
        </p>
      </div>
    </div>

    <div class="timeline-card">
      <div class="timeline-track" role="presentation">
        <div class="timeline-track__line"></div>
        ${TIMELINE_EVENTS.map(
					(e, i) => `<button type="button" class="timeline-track__pip" data-index="${i}" style="left: ${
						((e.year - minYear) / (maxYear - minYear)) * 100
					}%" aria-label="Jump to ${e.year}: ${e.label}">${e.year}</button>`,
				).join('')}
      </div>
      <input
        type="range"
        id="timeline-slider"
        min="${minYear}"
        max="${maxYear}"
        step="1"
        value="${TIMELINE_EVENTS[initialIdx].year}"
        aria-label="Year"
      />
      <div class="timeline-readout">
        <div class="timeline-year" id="timeline-year">${TIMELINE_EVENTS[initialIdx].year}</div>
        <div class="timeline-states">
          <span class="state-chip" id="state-classical" data-state="safe">classical: <strong>safe</strong></span>
          <span class="state-chip" id="state-pq" data-state="safe">post-quantum: <strong>safe</strong></span>
        </div>
      </div>
      <div class="timeline-body">
        <h3 id="timeline-label">${TIMELINE_EVENTS[initialIdx].label}</h3>
        <p class="panel-copy" id="timeline-detail">${TIMELINE_EVENTS[initialIdx].detail}</p>
        <p class="timeline-implication" id="timeline-implication"></p>
      </div>

      <div class="harvest-block" aria-label="Harvest-now, decrypt-later demonstration">
        <p class="harvest-block__label">Two sessions recorded by an adversary in 2025</p>
        <div class="harvest-grid">
          <article class="harvest-card harvest-card--classical" id="harvest-classical">
            <header class="harvest-card__head">
              <span class="harvest-card__lock" aria-hidden="true">🔒</span>
              <div>
                <p class="harvest-card__year">recorded · 2025</p>
                <p class="harvest-card__title">Classical-only (X25519)</p>
              </div>
            </header>
            <p class="harvest-card__hash mono-inline" aria-label="Ciphertext sample">${classicalHash}…</p>
            <p class="harvest-card__status" id="harvest-classical-status">still encrypted</p>
            <div class="harvest-card__crack" aria-hidden="true"></div>
          </article>
          <article class="harvest-card harvest-card--hybrid" id="harvest-hybrid">
            <header class="harvest-card__head">
              <span class="harvest-card__lock" aria-hidden="true">🔒</span>
              <div>
                <p class="harvest-card__year">recorded · 2025</p>
                <p class="harvest-card__title">Hybrid X25519MLKEM768</p>
              </div>
            </header>
            <p class="harvest-card__hash mono-inline" aria-label="Ciphertext sample">${hybridHash}…</p>
            <p class="harvest-card__status" id="harvest-hybrid-status">still encrypted</p>
          </article>
        </div>
      </div>
    </div>
  `;

	const slider = section.querySelector<HTMLInputElement>('#timeline-slider')!;
	const yearEl = section.querySelector<HTMLElement>('#timeline-year')!;
	const labelEl = section.querySelector<HTMLElement>('#timeline-label')!;
	const detailEl = section.querySelector<HTMLElement>('#timeline-detail')!;
	const implEl = section.querySelector<HTMLElement>('#timeline-implication')!;
	const stateClassical = section.querySelector<HTMLElement>('#state-classical')!;
	const statePq = section.querySelector<HTMLElement>('#state-pq')!;
	const harvestClassical = section.querySelector<HTMLElement>('#harvest-classical')!;
	const harvestClassicalStatus = section.querySelector<HTMLElement>(
		'#harvest-classical-status',
	)!;
	const harvestClassicalLock = harvestClassical.querySelector<HTMLElement>(
		'.harvest-card__lock',
	)!;
	const harvestHybridStatus = section.querySelector<HTMLElement>('#harvest-hybrid-status')!;

	function currentEvent(year: number): TimelineEvent {
		let best = TIMELINE_EVENTS[0];
		for (const e of TIMELINE_EVENTS) {
			if (e.year <= year) best = e;
		}
		return best;
	}

	function paint(year: number): void {
		const event = currentEvent(year);
		yearEl.textContent = String(year);
		labelEl.textContent = event.label;
		detailEl.textContent = event.detail;
		stateClassical.innerHTML = `classical: <strong>${event.classical}</strong>`;
		statePq.innerHTML = `post-quantum: <strong>${event.pq}</strong>`;
		stateClassical.dataset.state = event.classical;
		statePq.dataset.state = event.pq;

		if (event.classical === 'broken' && event.pq === 'safe') {
			implEl.textContent =
				'A session recorded today survives only if it used a hybrid. Pure-classical traffic from 2025 is now decryptable.';
			implEl.dataset.tone = 'bad';
		} else if (event.classical === 'fragile') {
			implEl.textContent =
				'Migration window — hybrid lets your existing TLS stack still talk to legacy clients while protecting against the harvest-now-decrypt-later threat.';
			implEl.dataset.tone = 'warn';
		} else {
			implEl.textContent =
				'Both halves intact. Hybrid users pay the small handshake-size cost; classical-only users carry an invisible liability forward.';
			implEl.dataset.tone = 'ok';
		}

		const cracked = year >= crqcYear;
		harvestClassical.classList.toggle('is-cracked', cracked);
		harvestClassicalLock.textContent = cracked ? '🔓' : '🔒';
		harvestClassicalStatus.textContent = cracked
			? `decrypted in ${year} · classical half broke`
			: 'still encrypted';
		harvestHybridStatus.textContent = cracked
			? 'still encrypted · ML-KEM half holds'
			: 'still encrypted';
	}

	slider.addEventListener('input', () => paint(Number(slider.value)));

	section.querySelectorAll<HTMLButtonElement>('.timeline-track__pip').forEach((pip) => {
		pip.addEventListener('click', () => {
			const idx = Number(pip.dataset.index);
			const year = TIMELINE_EVENTS[idx].year;
			slider.value = String(year);
			paint(year);
		});
	});

	paint(TIMELINE_EVENTS[initialIdx].year);
	return section;
}

// --- handshake size --------------------------------------------------------
function renderHandshake(): HTMLElement {
	const section = el('section', 'lab-section reveal');
	section.setAttribute('aria-labelledby', 'handshake-heading');
	const max = Math.max(...HANDSHAKE_SIZES.map((s) => s.bytes));
	const bars = HANDSHAKE_SIZES.map(
		(s) => `
      <li class="handshake-row">
        <div class="handshake-row__head">
          <span class="handshake-row__name">${s.name}</span>
          <span class="handshake-row__bytes mono-inline mono-inline--meter">${s.bytes.toLocaleString()} B</span>
        </div>
        <div class="handshake-bar handshake-bar--${s.tone}" aria-hidden="true">
          <span style="width: ${(s.bytes / max) * 100}%"></span>
        </div>
        <p class="panel-copy handshake-row__note">${s.note}</p>
      </li>
    `,
	).join('');

	section.innerHTML = `
    <div class="section-heading-row">
      <div>
        <p class="section-kicker">On the wire</p>
        <h2 id="handshake-heading" tabindex="-1">Handshake Size, Honestly</h2>
        <p class="section-footnote">
          PQ key shares are bigger — that is the one real cost. Here is what your TLS handshake
          carries in each mode, public key + ciphertext combined.
        </p>
      </div>
    </div>
    <ol class="handshake-list">${bars}</ol>
    <p class="panel-copy">
      The jump from classical to PQ is roughly 35× the bytes; the jump from PQ to hybrid is
      about 3%. The lesson: if you are already paying the PQ cost, the hybrid hedge is
      essentially free.
    </p>

    <figure class="middlebox-figure" aria-label="Middlebox fragmentation visualization">
      <figcaption class="middlebox-figure__caption">
        <strong>Middlebox ossification:</strong> pre-PQ network gear assumed the TLS
        ClientHello fit in one packet. Larger PQ key shares can fragment and trip
        old firewalls — the lesson from Google's CECPQ2 rollout.
      </figcaption>
      <div class="middlebox-stage">
        <div class="mb-lane">
          <span class="mb-lane__tag">classical · 64 B</span>
          <div class="mb-lane__track">
            <span class="mb-icon mb-icon--client" aria-hidden="true">client</span>
            <span class="mb-icon mb-icon--firewall" aria-hidden="true">middlebox</span>
            <span class="mb-icon mb-icon--server" aria-hidden="true">server</span>
            <span class="mb-packet mb-packet--small mb-packet--pass">X25519</span>
          </div>
          <span class="mb-lane__verdict mb-lane__verdict--ok">handshake completes</span>
        </div>
        <div class="mb-lane mb-lane--pq">
          <span class="mb-lane__tag">hybrid · 2.3 KB</span>
          <div class="mb-lane__track">
            <span class="mb-icon mb-icon--client" aria-hidden="true">client</span>
            <span class="mb-icon mb-icon--firewall mb-icon--firewall--strict" aria-hidden="true">middlebox</span>
            <span class="mb-icon mb-icon--server" aria-hidden="true">server</span>
            <span class="mb-packet mb-packet--big mb-packet--pass mb-packet--frag1" style="--mb-delay:0s">frag 1</span>
            <span class="mb-packet mb-packet--big mb-packet--drop mb-packet--frag2" style="--mb-delay:0.7s">frag 2</span>
            <span class="mb-packet mb-packet--big mb-packet--pass mb-packet--frag3" style="--mb-delay:1.4s">frag 3</span>
          </div>
          <span class="mb-lane__verdict mb-lane__verdict--bad">connection stalls</span>
        </div>
      </div>
    </figure>
  `;
	return section;
}

// --- performance benchmark -------------------------------------------------
function renderBenchmark(): HTMLElement {
	const section = el('section', 'lab-section reveal');
	section.setAttribute('aria-labelledby', 'benchmark-heading');
	section.innerHTML = `
    <div class="section-heading-row">
      <div>
        <p class="section-kicker">Performance</p>
        <h2 id="benchmark-heading" tabindex="-1">Cost on This Device</h2>
        <p class="section-footnote">
          Real numbers, measured right now in your browser. The combiner uses
          Web Crypto SHA-256; component "secrets" are CSPRNG byte draws, since
          this lab does not ship a full ML-KEM implementation.
        </p>
      </div>
      <button type="button" class="action-button" id="run-benchmark" aria-describedby="bench-state">
        Run benchmark
      </button>
    </div>

    <p class="bench-state" id="bench-state" aria-live="polite">Click <strong>Run benchmark</strong> to time the combiner here.</p>

    <ol class="bench-grid">
      <li class="bench-tile" id="bench-fresh">
        <p class="bench-tile__label">freshComponents()</p>
        <p class="bench-tile__value mono-inline mono-inline--meter">—</p>
        <p class="bench-tile__note">3 × 32-byte CSPRNG draws (X25519, ML-KEM, ct binding)</p>
      </li>
      <li class="bench-tile" id="bench-naive">
        <p class="bench-tile__label">Naive combiner</p>
        <p class="bench-tile__value mono-inline mono-inline--meter">—</p>
        <p class="bench-tile__note">SHA-256( ss_classical ‖ ss_pq )</p>
      </li>
      <li class="bench-tile" id="bench-xwing">
        <p class="bench-tile__label">X-Wing-style combiner</p>
        <p class="bench-tile__value mono-inline mono-inline--meter">—</p>
        <p class="bench-tile__note">SHA-256( label ‖ ss_pq ‖ ss_classical ‖ ct )</p>
      </li>
      <li class="bench-tile bench-tile--headline" id="bench-total">
        <p class="bench-tile__label">Full hybrid handshake (KDF only)</p>
        <p class="bench-tile__value mono-inline mono-inline--meter">—</p>
        <p class="bench-tile__note">freshComponents + X-Wing combiner per session</p>
      </li>
    </ol>

    <p class="panel-copy">
      For context, real X25519 takes roughly 50&nbsp;µs and a real ML-KEM-768 encap is
      around 30&nbsp;µs on a modern laptop CPU — well under any human-perceptible
      threshold. The bottleneck for hybrid deployments has never been compute; it is
      the larger handshake on the wire, which the previous section quantified.
    </p>
  `;

	const btn = section.querySelector<HTMLButtonElement>('#run-benchmark')!;
	const stateEl = section.querySelector<HTMLElement>('#bench-state')!;
	const set = (id: string, value: string) => {
		const v = section.querySelector<HTMLElement>('#' + id + ' .bench-tile__value');
		if (v) v.textContent = value;
	};

	function format(ms: number): string {
		if (ms < 0.001) return (ms * 1_000_000).toFixed(2) + ' ns';
		if (ms < 1) return (ms * 1000).toFixed(1) + ' µs';
		return ms.toFixed(2) + ' ms';
	}

	async function runBenchmark(): Promise<void> {
		btn.disabled = true;
		btn.textContent = 'Running…';
		stateEl.textContent = 'Warming up…';
		try {
			await new Promise((r) => requestAnimationFrame(() => r(null)));

			const WARMUP = 200;
			const N = 4000;

			for (let i = 0; i < WARMUP; i++) {
				const c = freshComponents();
				await deriveSessionKey(c, 'xwing');
			}

			stateEl.textContent = 'Timing freshComponents…';
			await new Promise((r) => requestAnimationFrame(() => r(null)));
			let t0 = performance.now();
			for (let i = 0; i < N; i++) freshComponents();
			let t1 = performance.now();
			const freshMs = (t1 - t0) / N;

			const comps = freshComponents();

			stateEl.textContent = 'Timing naive combiner…';
			await new Promise((r) => requestAnimationFrame(() => r(null)));
			t0 = performance.now();
			for (let i = 0; i < N; i++) await deriveSessionKey(comps, 'naive');
			t1 = performance.now();
			const naiveMs = (t1 - t0) / N;

			stateEl.textContent = 'Timing X-Wing-style combiner…';
			await new Promise((r) => requestAnimationFrame(() => r(null)));
			t0 = performance.now();
			for (let i = 0; i < N; i++) await deriveSessionKey(comps, 'xwing');
			t1 = performance.now();
			const xwingMs = (t1 - t0) / N;

			set('bench-fresh', format(freshMs));
			set('bench-naive', format(naiveMs));
			set('bench-xwing', format(xwingMs));
			set('bench-total', format(freshMs + xwingMs));

			stateEl.textContent = `${N.toLocaleString()} iterations per measurement · ${WARMUP} iterations of warmup.`;
			toast('Benchmark complete', 'ok');
		} catch (err) {
			console.error('benchmark failed', err);
			stateEl.textContent = 'Benchmark failed — see console for details.';
			toast('Benchmark failed', 'warn');
		} finally {
			btn.disabled = false;
			btn.textContent = 'Run again';
		}
	}

	btn.addEventListener('click', () => void runBenchmark());
	return section;
}

// --- decision guide --------------------------------------------------------
function renderDecision(): HTMLElement {
	const section = el('section', 'lab-section reveal');
	section.setAttribute('aria-labelledby', 'decision-heading');
	const steps = DECISION.map(
		(d, i) => `
    <div class="decision-step">
      <div class="decision-num" aria-hidden="true">${i + 1}</div>
      <div>
        <h3><span class="sr-only">Question ${i + 1}: </span>${d.question}</h3>
        <p class="panel-copy"><span class="dec-tag dec-tag--yes">Yes</span> ${d.yes}</p>
        <p class="panel-copy"><span class="dec-tag dec-tag--no">No</span> ${d.no}</p>
      </div>
    </div>`,
	).join('');
	section.innerHTML = `
    <div class="section-heading-row">
      <div>
        <p class="section-kicker">Decide</p>
        <h2 id="decision-heading" tabindex="-1">Should You Go Hybrid?</h2>
        <p class="section-footnote">Four questions that settle most cases. For long-lived secrets, the answer is almost always yes.</p>
      </div>
    </div>
    <div class="decision-flow">${steps}</div>
    <aside class="decision-verdict">
      <p class="decision-verdict__label">For most modern systems</p>
      <p class="decision-verdict__value">Use X-Wing or the TLS X25519MLKEM768 hybrid group.</p>
    </aside>
  `;
	return section;
}

// --- deployments -----------------------------------------------------------
function renderDeployments(): HTMLElement {
	const section = el('section', 'lab-section reveal');
	section.setAttribute('aria-labelledby', 'deployments-heading');
	const cards = DEPLOYMENTS.map(
		(d) => `
    <div class="panel-card">
      <h3>${d.name}</h3>
      <p class="panel-copy">${d.detail}</p>
    </div>`,
	).join('');
	section.innerHTML = `
    <div class="section-heading-row">
      <div>
        <p class="section-kicker">In the wild</p>
        <h2 id="deployments-heading" tabindex="-1">Hybrids in Production</h2>
      </div>
    </div>
    <div class="playground-grid">${cards}</div>
  `;
	return section;
}

// --- pitfalls --------------------------------------------------------------
function renderPitfalls(): HTMLElement {
	const section = el('section', 'lab-section reveal');
	section.setAttribute('aria-labelledby', 'pitfalls-heading');
	const good = PITFALLS.filter((p) => p.good)
		.map((p) => `<li><strong>${p.title}.</strong> ${p.body}</li>`)
		.join('');
	const bad = PITFALLS.filter((p) => !p.good)
		.map((p) => `<li><strong>${p.title}.</strong> ${p.body}</li>`)
		.join('');
	section.innerHTML = `
    <div class="section-heading-row">
      <div>
        <p class="section-kicker">Practice</p>
        <h2 id="pitfalls-heading" tabindex="-1">Do and Don’t</h2>
      </div>
    </div>
    <div class="reuse-grid">
      <div class="panel-card">
        <h3>Do</h3>
        <ul class="trait-list trait-list--good">${good}</ul>
      </div>
      <div class="panel-card">
        <h3>Watch out</h3>
        <ul class="trait-list trait-list--bad">${bad}</ul>
      </div>
    </div>
  `;
	return section;
}

function renderFooter(): HTMLElement {
	const footer = el('footer', 'lab-section lab-section--footer reveal');
	footer.innerHTML = `
    <p class="section-footnote">
      The combiner uses real SHA-256 over simulated 32-byte component secrets to illustrate the
      construction; production hybrids like X-Wing use ML-KEM-768, X25519, and SHA3-256 with a
      formally analysed combiner. Educational use only — use a vetted library for deployment.
    </p>
    <p class="footer-meta">
      <a href="https://github.com/systemslibrarian/crypto-lab-hybrid-guide" rel="noopener">View source on GitHub</a>
      <span class="footer-meta__sep" aria-hidden="true">·</span>
      <a href="https://datatracker.ietf.org/doc/draft-connolly-cfrg-xwing-kem/" rel="noopener">X-Wing IETF draft</a>
      <span class="footer-meta__sep" aria-hidden="true">·</span>
      <a href="https://csrc.nist.gov/pubs/fips/203/final" rel="noopener">ML-KEM (FIPS 203)</a>
    </p>
    <p class="footer-meta">
      Related demos:
      <a href="https://systemslibrarian.github.io/crypto-lab-hybrid-wire/" rel="noopener">crypto-lab-hybrid-wire</a>
      <span class="footer-meta__sep" aria-hidden="true">·</span>
      <a href="https://systemslibrarian.github.io/crypto-lab-pq-tls-handshake/" rel="noopener">crypto-lab-pq-tls-handshake</a>
      <span class="footer-meta__sep" aria-hidden="true">·</span>
      <a href="https://systemslibrarian.github.io/crypto-lab-kyber-vault/" rel="noopener">crypto-lab-kyber-vault</a>
      <span class="footer-meta__sep" aria-hidden="true">·</span>
      <a href="https://systemslibrarian.github.io/crypto-lab-hybrid-sign/" rel="noopener">crypto-lab-hybrid-sign</a>
      <span class="footer-meta__sep" aria-hidden="true">·</span>
      <a href="https://systemslibrarian.github.io/crypto-lab-pq-rotation/" rel="noopener">crypto-lab-pq-rotation</a>
    </p>
    <p class="scripture">“So whether you eat or drink or whatever you do, do it all for the glory of God.” — 1 Corinthians 10:31</p>
  `;
	return footer;
}

// --- reveal-on-scroll ------------------------------------------------------
function initReveal(root: HTMLElement): void {
	if (typeof IntersectionObserver !== 'function') {
		root.querySelectorAll('.reveal').forEach((node) => node.classList.add('is-visible'));
		return;
	}
	const observer = new IntersectionObserver(
		(entries) => {
			entries.forEach((entry) => {
				if (entry.isIntersecting) {
					entry.target.classList.add('is-visible');
					observer.unobserve(entry.target);
				}
			});
		},
		{ rootMargin: '0px 0px -10% 0px', threshold: 0.05 },
	);
	root.querySelectorAll('.reveal').forEach((node) => observer.observe(node));
}

// --- keyboard shortcuts ----------------------------------------------------
function initShortcuts(controller: PlaygroundController): void {
	window.addEventListener('keydown', (event) => {
		const target = event.target as HTMLElement | null;
		if (target && /INPUT|TEXTAREA|SELECT/.test(target.tagName)) return;
		if (event.metaKey || event.ctrlKey || event.altKey) return;
		switch (event.key.toLowerCase()) {
			case '1':
				controller.preset('both-ok');
				break;
			case '2':
				controller.preset('break-classical');
				break;
			case '3':
				controller.preset('break-pq');
				break;
			case '4':
				controller.preset('break-both');
				break;
			case 'r':
				controller.regen();
				break;
			case 'c':
				controller.copyKey();
				break;
			case 'm':
				controller.cycleCombiner();
				break;
			case 't': {
				const themeBtn = document.getElementById('theme-toggle') as HTMLButtonElement | null;
				themeBtn?.click();
				break;
			}
			default:
				return;
		}
		event.preventDefault();
	});
}

export function mountApp(root: HTMLDivElement): void {
	const shell = el('div', 'page-shell');
	const { node: playground, controller } = renderPlayground();
	shell.append(
		renderHero(),
		renderNav(),
		playground,
		renderTimeline(),
		renderHandshake(),
		renderBenchmark(),
		renderDecision(),
		renderDeployments(),
		renderPitfalls(),
		renderFooter(),
	);
	root.appendChild(shell);
	initReveal(shell);
	initShortcuts(controller);
}
