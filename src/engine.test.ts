import { describe, it, expect } from 'vitest';
import {
	assess,
	attemptKeyRecovery,
	bytesToHex,
	deriveSessionKey,
	freshComponents,
	openSession,
	randomBytes,
	transcriptPair,
	transcriptBindingExperiment,
	sha256,
	tryDecryptRecord,
	RECORD_PLAINTEXT,
	type Combiner,
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

// These verdicts used to be selected from the two break flags (remainingBits =
// unbroken * 256, headline chosen by an if-chain over the checkbox states).
// Actual candidate guesses are tested against AES-GCM. Observed failure is
// distinct from security, and withheld input width is distinct from output width.
describe('key recovery is really attempted', () => {
	async function run(classicalBroken: boolean, pqBroken: boolean, combiner: Combiner = 'xwing') {
		const session = await openSession(freshComponents(), combiner);
		const recovery = await attemptKeyRecovery(session, { classicalBroken, pqBroken });
		return { session, recovery, verdict: assess(recovery, combiner) };
	}

	it('records the plaintext under the derived key, and the honest key opens it', async () => {
		const session = await openSession(freshComponents(), 'xwing');
		expect(await tryDecryptRecord(session, session.sessionKey)).toBe(RECORD_PLAINTEXT);
	});

	it('a wrong key does not open the record (the GCM tag is the oracle)', async () => {
		const session = await openSession(freshComponents(), 'xwing');
		expect(await tryDecryptRecord(session, randomBytes(32))).toBeNull();
	});

	it('both halves intact ⇒ the attack runs, fails, and the verdict reports no recovery', async () => {
		const { recovery, verdict } = await run(false, false);
		expect(recovery.attempts).toBeGreaterThan(1);
		expect(recovery.successes).toBe(0);
		expect(recovery.recovered).toBe(false);
		expect(recovery.unknownComponents).toEqual(['classical', 'pq']);
		expect(verdict.withheldBytes).toBe(64);
		expect(verdict.observedNoRecovery).toBe(true);
		expect(verdict.headline).toBe('Not recovered in this run');
	});

	it('classical broken ⇒ the attacker holds that secret, still cannot decrypt', async () => {
		const { recovery, verdict } = await run(true, false);
		expect(recovery.successes).toBe(0);
		expect(recovery.recoveredPlaintext).toBeNull();
		expect(recovery.unknownComponents).toEqual(['pq']);
		expect(verdict.withheldBytes).toBe(32);
		expect(verdict.observedNoRecovery).toBe(true);
		expect(verdict.headline).toBe('Not recovered in this run');
	});

	it('PQ broken ⇒ the attacker holds that secret, still cannot decrypt', async () => {
		const { recovery, verdict } = await run(false, true);
		expect(recovery.successes).toBe(0);
		expect(recovery.unknownComponents).toEqual(['classical']);
		expect(verdict.withheldBytes).toBe(32);
		expect(verdict.observedNoRecovery).toBe(true);
		expect(verdict.headline).toBe('Not recovered in this run');
	});

	// The negative path: with nothing withheld the attack must actually work,
	// end to end, and hand back the plaintext. If this ever stops succeeding the
	// "still secure" results above would be worthless.
	it('both broken ⇒ the attack SUCCEEDS: one derivation, record decrypted', async () => {
		const { session, recovery, verdict } = await run(true, true);
		expect(recovery.attempts).toBe(1);
		expect(recovery.successes).toBe(1);
		expect(recovery.recovered).toBe(true);
		expect(recovery.recoveredPlaintext).toBe(RECORD_PLAINTEXT);
		expect(recovery.trueKeyKnownToAttacker).toBe(true);
		expect(recovery.firstCandidateKeyHex).toBe(bytesToHex(session.sessionKey));
		expect(recovery.bestBytesMatched).toBe(32);
		expect(verdict.withheldBytes).toBe(0);
		expect(verdict.observedNoRecovery).toBe(false);
		expect(verdict.headline).toBe('Record recovered');
	});

	it('the surviving half really is guessed, not assumed: candidates differ each attempt', async () => {
		const session = await openSession(freshComponents(), 'xwing');
		const a = await attemptKeyRecovery(session, { classicalBroken: true, pqBroken: false });
		const b = await attemptKeyRecovery(session, { classicalBroken: true, pqBroken: false });
		expect(a.firstCandidateKeyHex).not.toBe(b.firstCandidateKeyHex);
		expect(a.firstCandidateKeyHex).not.toBe(bytesToHex(session.sessionKey));
	});

	it('holds for the naive combiner too — the attack is combiner-agnostic', async () => {
		const secure = await run(true, false, 'naive');
		expect(secure.recovery.recovered).toBe(false);
		expect(secure.verdict.observedNoRecovery).toBe(true);
		const broken = await run(true, true, 'naive');
		expect(broken.recovery.recovered).toBe(true);
		expect(broken.verdict.observedNoRecovery).toBe(false);
	});

	it('the measurement string reports what the run did', async () => {
		const secure = await run(false, false);
		expect(secure.verdict.measurement).toMatch(/0 decrypted the record/);
		const broken = await run(true, true);
		expect(broken.verdict.measurement).toMatch(/record decrypted/);
	});
});

describe('assess naive combiner caveat', () => {
	async function verdictFor(classicalBroken: boolean, pqBroken: boolean, combiner: Combiner) {
		const session = await openSession(freshComponents(), combiner);
		return assess(await attemptKeyRecovery(session, { classicalBroken, pqBroken }), combiner);
	}

	it('appends a robust-combiner note when naive is selected and the run reports no recovery', async () => {
		const v = await verdictFor(false, false, 'naive');
		expect(v.detail).toMatch(/robust combiner|re-encapsulation/);
	});

	it('does NOT append the naive caveat for the X-Wing combiner', async () => {
		const v = await verdictFor(false, false, 'xwing');
		expect(v.detail).not.toMatch(/robust combiner/);
	});

	it('does NOT append the naive caveat when both halves are broken (already recovered)', async () => {
		const v = await verdictFor(true, true, 'naive');
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

// Assumed equal secrets and different public binding inputs; compare outputs.
// These controls do not construct ciphertexts or establish a KEM attack.
describe('transcript-binding experiment', () => {
	it('transcriptPair: shares component secrets but differs in ct_binding', () => {
		const { honest, forged } = transcriptPair();
		expect(bytesToHex(honest.classical)).toBe(bytesToHex(forged.classical));
		expect(bytesToHex(honest.pq)).toBe(bytesToHex(forged.pq));
		expect(bytesToHex(honest.ctBinding)).not.toBe(bytesToHex(forged.ctBinding));
	});

	it('Unbound hash ignores different binding inputs when secrets are supplied equal', async () => {
		const { honest, forged } = transcriptPair();
		const r = await transcriptBindingExperiment(honest, forged, 'naive');
		expect(bytesToHex(r.honestKey)).toBe(bytesToHex(r.forgedKey));
		expect(r.keysCollide).toBe(true);
	});

	it('Custom bound hash yields different keys for the assumed pair', async () => {
		const { honest, forged } = transcriptPair();
		const r = await transcriptBindingExperiment(honest, forged, 'xwing');
		expect(bytesToHex(r.honestKey)).not.toBe(bytesToHex(r.forgedKey));
		expect(r.keysCollide).toBe(false);
	});

	it('key equality is computed under the same-secret premise across 25 chosen pairs', async () => {
		for (let i = 0; i < 25; i++) {
			const { honest, forged } = transcriptPair();
			const naive = await transcriptBindingExperiment(honest, forged, 'naive');
			const xwing = await transcriptBindingExperiment(honest, forged, 'xwing');
			expect(naive.keysCollide).toBe(true);
			expect(xwing.keysCollide).toBe(false);
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

describe('bounded teaching measurements', () => {
	it.each([-1, .5, NaN, Infinity, Number.MAX_SAFE_INTEGER + 1])('invalid attempt budget %s cannot fabricate a failed-guess observation', async attempts => {
		const session = await openSession(fixedComponents(), 'xwing');
		await expect(attemptKeyRecovery(session, { classicalBroken: false, pqBroken: false }, attempts)).rejects.toThrow(RangeError);
	});
	it.each(['naive', 'xwing'] as const)('separates withheld input bytes from %s output width and finite observations', async combiner => {
		const session = await openSession(fixedComponents(), combiner);
		const recovery = await attemptKeyRecovery(session, { classicalBroken: false, pqBroken: false }, 1);
		const verdict = assess(recovery, combiner);
		expect(session.sessionKey.length).toBe(32);
		expect(recovery).toHaveProperty('withheldBytes', 64);
		expect(verdict).toHaveProperty('keySpaceCapBits', 256);
		expect(verdict).not.toHaveProperty('secure');
		expect(verdict.headline).toBe('Not recovered in this run');
		expect(verdict.detail).toContain('do not measure security strength');
		expect(verdict.detail).toContain('128-bit classical');
	});

	it('zero attempts are inconclusive rather than evidence of security', async () => {
		const session = await openSession(fixedComponents(), 'xwing');
		const recovery = await attemptKeyRecovery(session, { classicalBroken: false, pqBroken: false }, 0);
		const v = assess(recovery, 'xwing');
		expect(recovery.attempts).toBe(0);
		expect(v).toHaveProperty('observedNoRecovery', false);
		expect(v.headline).toContain('Inconclusive');
	});

	it('failure after handing over every secret is an inconsistent-session control', async () => {
		const session = await openSession(fixedComponents(), 'xwing');
		const unrelated = { ...session, components: freshComponents() };
		const recovery = await attemptKeyRecovery(unrelated, { classicalBroken: true, pqBroken: true });
		expect(recovery.recovered).toBe(false);
		const v = assess(recovery, 'xwing');
		expect(v.headline).toContain('Inconclusive');
		expect(v).toHaveProperty('observedNoRecovery', false);
	});

	it.each(['naive', 'xwing'] as const)('reports the equal-secret/different-binding premise without an attack claim (%s)', async combiner => {
		const { honest, forged } = transcriptPair();
		const result = await transcriptBindingExperiment(honest, forged, combiner);
		expect(result).toHaveProperty('sameComponentSecrets', true);
		expect(result).toHaveProperty('differentBindings', true);
		expect(result).not.toHaveProperty('attackSucceeds');
	});

	it.each(['naive', 'xwing'] as const)('identical inputs give equal outputs without a different-transcript premise (%s)', async combiner => {
		const c = fixedComponents();
		const result = await transcriptBindingExperiment(c, c, combiner);
		expect(result.sameComponentSecrets).toBe(true);
		expect(result.differentBindings).toBe(false);
		expect(result.keysCollide).toBe(true);
	});

	it('different secrets can yield different unbound keys: equality depends on the supplied premise', async () => {
		const first = fixedComponents();
		const second = fixedComponents();
		second.classical[0] ^= 1;
		second.ctBinding[0] ^= 1;
		const result = await transcriptBindingExperiment(first, second, 'naive');
		expect(result.sameComponentSecrets).toBe(false);
		expect(result.differentBindings).toBe(true);
		expect(result.keysCollide).toBe(false);
	});
});
