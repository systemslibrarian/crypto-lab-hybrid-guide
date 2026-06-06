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
import { DECISION, DEPLOYMENTS, PITFALLS } from './data.ts';

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
	// Toggle textContent so consecutive identical messages still announce.
	region.textContent = '';
	window.setTimeout(() => {
		region.textContent = message;
	}, 30);
}

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
        results, so the session key stays secret as long as <em>either</em> half holds. This lab
        shows how the combiner works, lets you break each half to see the hedge in action, and
        walks through when and how to deploy hybrids.
      </p>
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
    </aside>
  `;
	return hero;
}

// --- combiner playground ---------------------------------------------------
function renderPlayground(): HTMLElement {
	const section = el('section', 'lab-section');
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
    </div>

    <figure class="combiner-diagram" aria-label="Diagram of two KEM secrets feeding into a combiner that outputs one session key">
      <svg viewBox="0 0 360 120" role="img" aria-hidden="true" focusable="false">
        <defs>
          <linearGradient id="diagFlow" x1="0" y1="0" x2="1" y2="0">
            <stop offset="0%" stop-color="var(--accent)"/>
            <stop offset="100%" stop-color="var(--accent-4)"/>
          </linearGradient>
        </defs>
        <rect x="6" y="10" width="110" height="36" rx="10" fill="none" stroke="var(--accent)" stroke-width="2"/>
        <text x="61" y="33" text-anchor="middle" fill="var(--ink-strong)" font-family="var(--mono)" font-size="11">X25519 ss</text>
        <rect x="6" y="74" width="110" height="36" rx="10" fill="none" stroke="var(--accent-3)" stroke-width="2"/>
        <text x="61" y="97" text-anchor="middle" fill="var(--ink-strong)" font-family="var(--mono)" font-size="11">ML-KEM ss</text>
        <path d="M116 28 C 160 28, 160 60, 200 60" fill="none" stroke="url(#diagFlow)" stroke-width="2"/>
        <path d="M116 92 C 160 92, 160 60, 200 60" fill="none" stroke="url(#diagFlow)" stroke-width="2"/>
        <rect x="200" y="40" width="70" height="40" rx="10" fill="var(--mono-block-bg)"/>
        <text x="235" y="64" text-anchor="middle" fill="var(--mono-block-fg)" font-family="var(--mono)" font-size="11">combiner</text>
        <path d="M270 60 L 330 60" fill="none" stroke="url(#diagFlow)" stroke-width="2"/>
        <polygon points="330,55 340,60 330,65" fill="var(--accent-4)"/>
        <text x="335" y="44" text-anchor="end" fill="var(--ink-soft)" font-family="var(--mono)" font-size="10">session key</text>
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
        <button type="button" class="preset-button" data-scenario="both-ok">Both intact</button>
        <button type="button" class="preset-button" data-scenario="break-classical">Quantum breaks X25519</button>
        <button type="button" class="preset-button" data-scenario="break-pq">Cryptanalysis breaks ML-KEM</button>
        <button type="button" class="preset-button preset-button--danger" data-scenario="break-both">Worst case</button>
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

    <div class="session-out panel-card" aria-live="polite">
      <div class="panel-header">
        <h3>Derived session key</h3>
        <span id="verdict-chip" class="vs-chip" aria-label="Verdict">—</span>
      </div>
      <div class="session-key-row">
        <p class="mono-block" id="session-key" aria-label="Session key in hexadecimal">—</p>
        <button type="button" id="copy-key" class="ghost-button ghost-button--compact" aria-label="Copy session key to clipboard">Copy</button>
      </div>
      <div class="entropy" aria-label="Attacker remaining uncertainty meter">
        <p class="hero-metric-label">Attacker’s remaining uncertainty</p>
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
	let comps: Components = freshComponents();

	const breakClassical = $('break-classical') as HTMLInputElement;
	const breakPq = $('break-pq') as HTMLInputElement;
	const combinerSel = $('combiner') as HTMLSelectElement;
	const copyBtn = $('copy-key') as HTMLButtonElement;
	const entropyTrack = $('entropy-track');

	let lastHeadline = '';

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
		announce('Generated a fresh session.');
		void refresh();
	});

	section.querySelectorAll<HTMLButtonElement>('.preset-button').forEach((btn) => {
		btn.addEventListener('click', () => {
			const name = btn.getAttribute('data-scenario');
			if (name) applyScenario(name);
		});
	});

	copyBtn.addEventListener('click', async () => {
		const text = $('session-key').textContent ?? '';
		try {
			await navigator.clipboard.writeText(text);
			const original = copyBtn.textContent;
			copyBtn.textContent = 'Copied';
			copyBtn.classList.add('is-copied');
			announce('Session key copied to clipboard.');
			window.setTimeout(() => {
				copyBtn.textContent = original;
				copyBtn.classList.remove('is-copied');
			}, 1400);
		} catch {
			announce('Copy failed. Select the text manually.');
		}
	});

	void refresh();
	return section;
}

// --- decision guide --------------------------------------------------------
function renderDecision(): HTMLElement {
	const section = el('section', 'lab-section');
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
        <h2>Should You Go Hybrid?</h2>
        <p class="section-footnote">Four questions that settle most cases. For long-lived secrets, the answer is almost always yes.</p>
      </div>
    </div>
    <div class="decision-flow">${steps}</div>
  `;
	return section;
}

// --- deployments -----------------------------------------------------------
function renderDeployments(): HTMLElement {
	const section = el('section', 'lab-section');
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
        <h2>Hybrids in Production</h2>
      </div>
    </div>
    <div class="playground-grid">${cards}</div>
  `;
	return section;
}

// --- pitfalls --------------------------------------------------------------
function renderPitfalls(): HTMLElement {
	const section = el('section', 'lab-section');
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
        <h2>Do and Don’t</h2>
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
	const footer = el('footer', 'lab-section lab-section--footer');
	footer.innerHTML = `
    <p class="section-footnote">
      The combiner uses real SHA-256 over simulated 32-byte component secrets to illustrate the
      construction; production hybrids like X-Wing use ML-KEM-768, X25519, and SHA3-256 with a
      formally analysed combiner. Educational use only — use a vetted library for deployment.
    </p>
    <p class="footer-meta">
      <a href="https://github.com/systemslibrarian/crypto-lab-hybrid-guide" rel="noopener">View source on GitHub</a>
    </p>
    <p class="scripture">“So whether you eat or drink or whatever you do, do it all for the glory of God.” — 1 Corinthians 10:31</p>
  `;
	return footer;
}

export function mountApp(root: HTMLDivElement): void {
	const shell = el('div', 'page-shell');
	shell.append(
		renderHero(),
		renderPlayground(),
		renderDecision(),
		renderDeployments(),
		renderPitfalls(),
		renderFooter(),
	);
	root.appendChild(shell);
}
