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
			{ rootMargin: '-40% 0px -55% 0px', threshold: 0 },
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
	section.id = 'section-playground';
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

	function updateFormula(combiner: Combiner): void {
		const body = $('formula-body');
		const note = $('formula-note');
		const label = section.querySelector<SVGTextElement>('#diag-combiner-label');
		if (combiner === 'naive') {
			body.textContent = 'K = SHA-256( ss_classical ‖ ss_pq )';
			note.textContent =
				'Just concatenates and hashes. Sufficient when both halves are random, but does not bind the transcript — a real attacker can re-encapsulate.';
			if (label) label.textContent = 'SHA-256 ‖';
		} else {
			body.textContent =
				'K = SHA-256( "crypto-lab-hybrid" ‖ ss_pq ‖ ss_classical ‖ ct_binding )';
			note.textContent =
				'Domain-separated and transcript-bound, à la X-Wing. The label and ciphertext binding make re-encapsulation attacks fail.';
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

		if (classicalPath)
			classicalPath.setAttribute('stroke', state.classicalBroken ? 'var(--accent-2)' : 'url(#diagFlow)');
		if (pqPath)
			pqPath.setAttribute('stroke', state.pqBroken ? 'var(--accent-2)' : 'url(#diagFlow)');
		if (classicalPath)
			classicalPath.setAttribute('stroke-dasharray', state.classicalBroken ? '4 4' : '0');
		if (pqPath) pqPath.setAttribute('stroke-dasharray', state.pqBroken ? '4 4' : '0');
		if (classicalRect)
			classicalRect.setAttribute('stroke', state.classicalBroken ? 'var(--accent-2)' : 'var(--accent)');
		if (pqRect) pqRect.setAttribute('stroke', state.pqBroken ? 'var(--accent-2)' : 'var(--accent-3)');
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
	combinerSel.addEventListener('change', () => void refresh());
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

	async function copyKey(): Promise<void> {
		const text = $('session-key').textContent ?? '';
		try {
			await navigator.clipboard.writeText(text);
			const original = copyBtn.textContent;
			copyBtn.textContent = 'Copied';
			copyBtn.classList.add('is-copied');
			toast('Session key copied', 'ok');
			window.setTimeout(() => {
				copyBtn.textContent = original;
				copyBtn.classList.remove('is-copied');
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
          <span class="state-chip state-chip--classical" id="state-classical">classical: <strong>safe</strong></span>
          <span class="state-chip state-chip--pq" id="state-pq">post-quantum: <strong>safe</strong></span>
        </div>
      </div>
      <div class="timeline-body">
        <h3 id="timeline-label">${TIMELINE_EVENTS[initialIdx].label}</h3>
        <p class="panel-copy" id="timeline-detail">${TIMELINE_EVENTS[initialIdx].detail}</p>
        <p class="timeline-implication" id="timeline-implication"></p>
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

	function currentEvent(year: number): TimelineEvent {
		let best = TIMELINE_EVENTS[0];
		for (const e of TIMELINE_EVENTS) {
			if (e.year <= year) best = e;
		}
		return best;
	}

	function stateLabel(s: 'safe' | 'fragile' | 'broken'): string {
		return s === 'safe' ? 'safe' : s === 'fragile' ? 'fragile' : 'broken';
	}

	function paint(year: number): void {
		const event = currentEvent(year);
		yearEl.textContent = String(year);
		labelEl.textContent = event.label;
		detailEl.textContent = event.detail;
		stateClassical.innerHTML = `classical: <strong>${stateLabel(event.classical)}</strong>`;
		statePq.innerHTML = `post-quantum: <strong>${stateLabel(event.pq)}</strong>`;
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
  `;
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
		renderDecision(),
		renderDeployments(),
		renderPitfalls(),
		renderFooter(),
	);
	root.appendChild(shell);
	initReveal(shell);
	initShortcuts(controller);
}
