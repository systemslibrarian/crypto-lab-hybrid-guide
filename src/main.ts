import './style.css';
import './extra.css';
import { freshComponents, deriveSessionKey, assess, bytesToHex } from './engine.ts';
import { mountApp } from './ui.ts';

(async function selfTest() {
	console.group('crypto-lab-hybrid-guide: combiner self-test');
	const c = freshComponents();
	const key = await deriveSessionKey(c, 'xwing');
	console.log('Components: X25519 + ML-KEM-768 (simulated 32-byte secrets)');
	console.log('Session key (X-Wing-style):', bytesToHex(key).slice(0, 32) + '…');
	for (const [cb, pb, label] of [
		[false, false, 'both intact'],
		[true, false, 'classical broken'],
		[false, true, 'PQ broken'],
		[true, true, 'both broken'],
	] as [boolean, boolean, string][]) {
		const v = assess({ classicalBroken: cb, pqBroken: pb }, 'xwing');
		console.log(`  ${label}: ${v.remainingBits} bits, secure=${v.secure}`);
	}
	console.groupEnd();
})();

mountApp(document.querySelector<HTMLDivElement>('#app')!);

(function initThemeToggle() {
	const button = document.getElementById('theme-toggle') as HTMLButtonElement | null;
	if (!button) return;
	const iconEl = button.querySelector('.theme-toggle__icon') as HTMLElement | null;
	function apply(theme: string): void {
		document.documentElement.setAttribute('data-theme', theme);
		try {
			localStorage.setItem('theme', theme);
		} catch {
			/* localStorage may be unavailable in private mode */
		}
		const isDark = theme === 'dark';
		if (iconEl) iconEl.textContent = isDark ? '\u{1F319}' : '☀️';
		button!.setAttribute('aria-label', isDark ? 'Switch to light mode' : 'Switch to dark mode');
		button!.setAttribute('aria-pressed', isDark ? 'true' : 'false');
	}
	const current = document.documentElement.getAttribute('data-theme') ?? 'dark';
	apply(current);
	button.addEventListener('click', () => {
		const next = document.documentElement.getAttribute('data-theme') === 'dark' ? 'light' : 'dark';
		apply(next);
	});
})();

(function initSkipLink() {
	const link = document.querySelector<HTMLAnchorElement>('.skip-link');
	if (!link) return;
	link.addEventListener('click', (event) => {
		const id = (link.getAttribute('href') ?? '').replace(/^#/, '');
		const target = document.getElementById(id);
		if (!target) return;
		event.preventDefault();
		// preventScroll on focus so the focus call doesn't snap the page
		// instantly before scrollIntoView's smooth animation begins.
		target.focus({ preventScroll: true });
		target.scrollIntoView({ block: 'start', behavior: 'smooth' });
	});
})();
