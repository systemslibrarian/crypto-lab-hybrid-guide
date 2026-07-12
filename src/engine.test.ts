import { describe, it, expect } from 'vitest';
import {
	assess,
	bytesToHex,
	deriveSessionKey,
	freshComponents,
	randomBytes,
	reencapPair,
	reencapsulationAttack,
	sha256,
	type Components,
} from './engine.ts';

// Fixed component secrets for known-answer tests.
function fixedComponents(): Components {
	const classical = new Uint8Array(32);
	const pq = new Uint8Array(32);
	const ctBinding = new Uint8Array(32);
	for (let i = 0; i < 32; i++) {
		classical[i] = i; // 0x00..0x1f
		pq[i] = 0x20 + i; // 0x20..0x3f
		ctBinding[i] = 0x40 + i; // 0x40..0x5f
	}
	return { classical, pq, ctBinding };
}

describe('bytesToHex', () => {
	it('returns lowercase hex of the right length', () => {
		const a = new Uint8Array([0x00, 0x0f, 0xab, 0xff]);
		expect(bytesToHex(a)).toBe('000fabff');
	});

	it('returns an empty string for an empty input', () => {
		expect(bytesToHex(new Uint8Array(0))).toBe('');
	});

	it('round-trips through a known fixed sample', () => {
		const a = new Uint8Array([0x12, 0x34, 0x56, 0x78, 0x90, 0xab, 0xcd, 0xef]);
		expect(bytesToHex(a)).toBe('1234567890abcdef');
	});
});

describe('randomBytes', () => {
	it('returns a Uint8Array of the requested length', () => {
		const out = randomBytes(32);
		expect(out).toBeInstanceOf(Uint8Array);
		expect(out.length).toBe(32);
	});

	it('produces fresh randomness on each call', () => {
		const a = randomBytes(32);
		const b = randomBytes(32);
		// 32 byte collision under CSPRNG is astronomically unlikely.
		expect(bytesToHex(a)).not.toBe(bytesToHex(b));
	});
});

describe('freshComponents', () => {
	it('returns three 32-byte fields', () => {
		const c = freshComponents();
		expect(c.classical.length).toBe(32);
		expect(c.pq.length).toBe(32);
		expect(c.ctBinding.length).toBe(32);
	});

	it('produces independent randomness across the three fields', () => {
		const c = freshComponents();
		expect(bytesToHex(c.classical)).not.toBe(bytesToHex(c.pq));
		expect(bytesToHex(c.pq)).not.toBe(bytesToHex(c.ctBinding));
		expect(bytesToHex(c.classical)).not.toBe(bytesToHex(c.ctBinding));
	});
});

describe('sha256', () => {
	it('produces 32 bytes', async () => {
		const out = await sha256(new Uint8Array([1, 2, 3]));
		expect(out.length).toBe(32);
	});

	it('is deterministic for identical input', async () => {
		const input = new Uint8Array([9, 9, 9, 9]);
		const a = await sha256(input);
		const b = await sha256(input);
		expect(bytesToHex(a)).toBe(bytesToHex(b));
	});

	it('matches the published SHA-256 of the empty string', async () => {
		const out = await sha256(new Uint8Array(0));
		expect(bytesToHex(out)).toBe(
			'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
		);
	});
});

describe('deriveSessionKey', () => {
	it('returns a 32-byte session key for both combiners', async () => {
		const c = freshComponents();
		const naive = await deriveSessionKey(c, 'naive');
		const xwing = await deriveSessionKey(c, 'xwing');
		expect(naive.length).toBe(32);
		expect(xwing.length).toBe(32);
	});

	it('is deterministic for fixed components and combiner', async () => {
		const c = freshComponents();
		const a = await deriveSessionKey(c, 'xwing');
		const b = await deriveSessionKey(c, 'xwing');
		expect(bytesToHex(a)).toBe(bytesToHex(b));
	});

	it('produces different keys for the two combiners on the same components', async () => {
		const c = freshComponents();
		const naive = await deriveSessionKey(c, 'naive');
		const xwing = await deriveSessionKey(c, 'xwing');
		expect(bytesToHex(naive)).not.toBe(bytesToHex(xwing));
	});

	it('changes when only the classical secret changes', async () => {
		const c1 = freshComponents();
		const c2 = { ...c1, classical: randomBytes(32) };
		const a = await deriveSessionKey(c1, 'xwing');
		const b = await deriveSessionKey(c2, 'xwing');
		expect(bytesToHex(a)).not.toBe(bytesToHex(b));
	});

	it('changes when only the PQ secret changes', async () => {
		const c1 = freshComponents();
		const c2 = { ...c1, pq: randomBytes(32) };
		const a = await deriveSessionKey(c1, 'xwing');
		const b = await deriveSessionKey(c2, 'xwing');
		expect(bytesToHex(a)).not.toBe(bytesToHex(b));
	});

	it('only the X-Wing combiner depends on ct_binding (naive ignores it)', async () => {
		const c1 = freshComponents();
		const c2 = { ...c1, ctBinding: randomBytes(32) };
		const naive1 = await deriveSessionKey(c1, 'naive');
		const naive2 = await deriveSessionKey(c2, 'naive');
		const xwing1 = await deriveSessionKey(c1, 'xwing');
		const xwing2 = await deriveSessionKey(c2, 'xwing');
		expect(bytesToHex(naive1)).toBe(bytesToHex(naive2));
		expect(bytesToHex(xwing1)).not.toBe(bytesToHex(xwing2));
	});
});

describe('assess verdicts (X-Wing combiner)', () => {
	it('both halves intact ⇒ 512 bits, secure, "Fully secure"', () => {
		const v = assess({ classicalBroken: false, pqBroken: false }, 'xwing');
		expect(v.remainingBits).toBe(512);
		expect(v.secure).toBe(true);
		expect(v.headline).toBe('Fully secure');
	});

	it('classical broken only ⇒ 256 bits, still secure, PQ-holds headline', () => {
		const v = assess({ classicalBroken: true, pqBroken: false }, 'xwing');
		expect(v.remainingBits).toBe(256);
		expect(v.secure).toBe(true);
		expect(v.headline).toBe('Still secure (PQ holds)');
	});

	it('PQ broken only ⇒ 256 bits, still secure, classical-holds headline', () => {
		const v = assess({ classicalBroken: false, pqBroken: true }, 'xwing');
		expect(v.remainingBits).toBe(256);
		expect(v.secure).toBe(true);
		expect(v.headline).toBe('Still secure (classical holds)');
	});

	it('both broken ⇒ 0 bits, insecure, broken headline', () => {
		const v = assess({ classicalBroken: true, pqBroken: true }, 'xwing');
		expect(v.remainingBits).toBe(0);
		expect(v.secure).toBe(false);
		expect(v.headline.startsWith('Broken')).toBe(true);
	});
});

describe('assess naive combiner caveat', () => {
	it('appends a robust-combiner note when naive is selected and the verdict is still secure', () => {
		const v = assess({ classicalBroken: false, pqBroken: false }, 'naive');
		expect(v.detail).toMatch(/robust combiner|re-encapsulation/);
	});

	it('does NOT append the naive caveat for the X-Wing combiner', () => {
		const v = assess({ classicalBroken: false, pqBroken: false }, 'xwing');
		expect(v.detail).not.toMatch(/robust combiner/);
	});

	it('does NOT append the naive caveat when both halves are broken (already insecure)', () => {
		const v = assess({ classicalBroken: true, pqBroken: true }, 'naive');
		expect(v.detail).not.toMatch(/robust combiner/);
	});
});

// Known-answer tests pin the EXACT output of each combiner for fixed inputs.
// These lock the labelled construction in place: if the label, field ordering,
// or hash ever changes, these fail. They also document that this SHA-256 +
// "crypto-lab-hybrid" label construction is INTENTIONALLY non-interoperable
// with real X-Wing (which uses SHA3-256 and a fixed 6-byte label) — these
// vectors will never match an X-Wing reference vector, and that is by design.
describe('combiner known-answer tests (labelled construction)', () => {
	it('naive combiner: H(ss_classical ‖ ss_pq) matches its fixed KAT', async () => {
		const key = await deriveSessionKey(fixedComponents(), 'naive');
		expect(bytesToHex(key)).toBe(
			'fdeab9acf3710362bd2658cdc9a29e8f9c757fcf9811603a8c447cd1d9151108',
		);
	});

	it('X-Wing-style combiner: H(label ‖ ss_pq ‖ ss_classical ‖ ct) matches its fixed KAT', async () => {
		const key = await deriveSessionKey(fixedComponents(), 'xwing');
		expect(bytesToHex(key)).toBe(
			'01d9273724d30153c2a37d41062ae25ca8beb516739471776f6f9d7f5613b523',
		);
	});

	it('the two KATs differ, proving the label/binding actually change the output', async () => {
		const naive = await deriveSessionKey(fixedComponents(), 'naive');
		const xwing = await deriveSessionKey(fixedComponents(), 'xwing');
		expect(bytesToHex(naive)).not.toBe(bytesToHex(xwing));
	});
});

// The core honesty fix: a REAL, computed re-encapsulation attack. Two protocol
// runs share their component secrets but differ only in ct_binding (transcript).
// A sound combiner must derive DIFFERENT keys; an unbound one collides.
describe('re-encapsulation attack (transcript binding)', () => {
	it('reencapPair: shares component secrets but differs in ct_binding', () => {
		const { honest, forged } = reencapPair();
		expect(bytesToHex(honest.classical)).toBe(bytesToHex(forged.classical));
		expect(bytesToHex(honest.pq)).toBe(bytesToHex(forged.pq));
		expect(bytesToHex(honest.ctBinding)).not.toBe(bytesToHex(forged.ctBinding));
	});

	it('NAIVE combiner is broken: forged transcript yields the SAME key ⇒ attack succeeds', async () => {
		const { honest, forged } = reencapPair();
		const r = await reencapsulationAttack(honest, forged, 'naive');
		expect(bytesToHex(r.honestKey)).toBe(bytesToHex(r.forgedKey));
		expect(r.keysCollide).toBe(true);
		expect(r.attackSucceeds).toBe(true);
	});

	it('X-WING combiner defends: forged transcript yields a DIFFERENT key ⇒ attack fails', async () => {
		const { honest, forged } = reencapPair();
		const r = await reencapsulationAttack(honest, forged, 'xwing');
		expect(bytesToHex(r.honestKey)).not.toBe(bytesToHex(r.forgedKey));
		expect(r.keysCollide).toBe(false);
		expect(r.attackSucceeds).toBe(false);
	});

	it('the attack outcome is measured, not asserted: naive collides across many trials', async () => {
		for (let i = 0; i < 25; i++) {
			const { honest, forged } = reencapPair();
			const naive = await reencapsulationAttack(honest, forged, 'naive');
			const xwing = await reencapsulationAttack(honest, forged, 'xwing');
			expect(naive.attackSucceeds).toBe(true);
			expect(xwing.attackSucceeds).toBe(false);
		}
	});

	it('with fixed inputs the naive collision is exact (honest = forged key)', async () => {
		const classical = randomBytes(32);
		const pq = randomBytes(32);
		const honest: Components = { classical, pq, ctBinding: randomBytes(32) };
		const forged: Components = { classical, pq, ctBinding: randomBytes(32) };
		const naiveHonest = await deriveSessionKey(honest, 'naive');
		const naiveForged = await deriveSessionKey(forged, 'naive');
		expect(bytesToHex(naiveHonest)).toBe(bytesToHex(naiveForged));
	});
});
