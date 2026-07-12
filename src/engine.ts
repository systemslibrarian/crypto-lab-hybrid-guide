// engine.ts — a working hybrid KEM combiner demonstration.
//
// We model two component KEMs by their shared secrets (random byte strings):
//   * classical: an X25519-style 32-byte shared secret
//   * pq: an ML-KEM-768-style 32-byte shared secret
// A hybrid KEM combines them into one session key. We show two combiners:
//   * naive: SHA-256( ss_classical || ss_pq )            -- simple concatenation
//   * xwing-style: SHA3/SHA-256( label || ss_pq || ss_classical || ct_binding )
//
// The teaching point: if an attacker breaks ONE component (learns or fixes its
// shared secret), a sound combiner keeps the session key unpredictable as long
// as the OTHER secret is still secret. We demonstrate by zeroing a component
// and measuring how much entropy the attacker would still have to guess.

export type Combiner = 'naive' | 'xwing';

export interface Components {
	classical: Uint8Array; // X25519-style shared secret
	pq: Uint8Array; // ML-KEM-style shared secret
	ctBinding: Uint8Array; // a transcript/ciphertext binding value
}

const enc = new TextEncoder();

export function randomBytes(n: number): Uint8Array {
	const a = new Uint8Array(n);
	crypto.getRandomValues(a);
	return a;
}

export function freshComponents(): Components {
	return {
		classical: randomBytes(32),
		pq: randomBytes(32),
		ctBinding: randomBytes(32),
	};
}

function concat(...arrs: Uint8Array[]): Uint8Array {
	const total = arrs.reduce((n, a) => n + a.length, 0);
	const out = new Uint8Array(total);
	let off = 0;
	for (const a of arrs) {
		out.set(a, off);
		off += a.length;
	}
	return out;
}

export async function sha256(data: Uint8Array): Promise<Uint8Array> {
	const buf = await crypto.subtle.digest('SHA-256', data as BufferSource);
	return new Uint8Array(buf);
}

// Derive the hybrid session key under the chosen combiner.
export async function deriveSessionKey(c: Components, combiner: Combiner): Promise<Uint8Array> {
	if (combiner === 'naive') {
		return sha256(concat(c.classical, c.pq));
	}
	// X-Wing-style: domain-separation label, PQ secret first, then classical,
	// then a transcript/ciphertext binding. (Real X-Wing uses SHA3-256 and a
	// fixed 6-byte label; SHA-256 here keeps it to Web Crypto primitives.)
	const label = enc.encode('crypto-lab-hybrid');
	return sha256(concat(label, c.pq, c.classical, c.ctBinding));
}

export function bytesToHex(a: Uint8Array): string {
	return Array.from(a)
		.map((b) => b.toString(16).padStart(2, '0'))
		.join('');
}

// --- attacker model --------------------------------------------------------
// "Breaking" a component means the attacker learns its shared secret (we model
// the *worst case*: they know it exactly, so from their view it is fixed/zeroed
// as an unknown). Remaining attacker uncertainty = entropy of the secrets they
// still do NOT know. Each unbroken 32-byte secret contributes 256 bits.

export interface BreakState {
	classicalBroken: boolean; // e.g. a future quantum computer breaks X25519
	pqBroken: boolean; // e.g. cryptanalysis weakens ML-KEM
}

export interface Verdict {
	remainingBits: number;
	secure: boolean;
	headline: string;
	detail: string;
}

export function assess(state: BreakState, combiner: Combiner): Verdict {
	const unbroken =
		(state.classicalBroken ? 0 : 1) + (state.pqBroken ? 0 : 1);
	const remainingBits = unbroken * 256;

	// A sound combiner is secure if AT LEAST ONE component is unbroken.
	// The naive concatenation combiner is also secure in this simple model
	// (SHA-256 over both), but we flag its real-world caveat separately.
	const secure = remainingBits > 0;

	let headline: string;
	let detail: string;
	if (!state.classicalBroken && !state.pqBroken) {
		headline = 'Fully secure';
		detail =
			'Neither component is broken. The session key has the full strength of both halves \u2014 this is the normal operating state.';
	} else if (state.classicalBroken && !state.pqBroken) {
		headline = 'Still secure (PQ holds)';
		detail =
			'A quantum computer has broken the classical X25519 half, but ML-KEM is intact. The session key is still unpredictable \u2014 this is exactly the future scenario hybrids are built for.';
	} else if (!state.classicalBroken && state.pqBroken) {
		headline = 'Still secure (classical holds)';
		detail =
			'Cryptanalysis has weakened the post-quantum half, but classical X25519 is intact. The session key is still safe today \u2014 this is the hedge against a young PQC scheme being broken.';
	} else {
		headline = 'Broken \u2014 both halves down';
		detail =
			'Both components are broken simultaneously. No combiner can save you here; the whole point of a hybrid is that this should be far harder than breaking either one alone.';
	}

	if (combiner === 'naive' && secure) {
		detail +=
			' Note: simple concatenation works here, but a robust combiner also binds the ciphertexts/transcript to prevent re-encapsulation and related attacks \u2014 which is why X-Wing uses a structured construction.';
	}

	return { remainingBits, secure, headline, detail };
}

// --- re-encapsulation / transcript-binding demonstration -------------------
//
// This is a REAL, computed demonstration (not a scripted animation) of why an
// unbound combiner is dangerous.
//
// Setup: two runs of the protocol share the SAME component shared secrets
// (ss_classical, ss_pq) but differ in their transcript / ciphertext binding.
// This is precisely the situation a re-encapsulation attacker engineers: KEM
// ciphertexts are not, in general, bound to their shared secret, so an attacker
// who can re-encapsulate produces a DIFFERENT ciphertext transcript that still
// decapsulates to the SAME shared secret at the honest party.
//
//   * The NAIVE combiner K = H(ss_c \u2016 ss_pq) ignores the transcript entirely,
//     so BOTH runs derive the IDENTICAL session key. The key is not bound to
//     the handshake the parties think they ran \u2014 the attack succeeds.
//
//   * The X-WING-style combiner folds ct_binding into the hash, so the two
//     transcripts derive DIFFERENT session keys \u2014 the collision the attacker
//     needs does not exist. The attack fails.
//
// We prove the outcome by actually deriving both keys and comparing them, so
// the verdict below is measured, never asserted.

export interface ReencapResult {
	combiner: Combiner;
	honestKey: Uint8Array; // key from the honest transcript
	forgedKey: Uint8Array; // key from the attacker's re-encapsulated transcript
	keysCollide: boolean; // true \u21d2 same key under both transcripts
	attackSucceeds: boolean; // true \u21d2 unbound: attacker recovers the honest key
}

// Run the re-encapsulation experiment for a given combiner. `honest` and
// `forged` share their component secrets but carry different ct bindings.
export async function reencapsulationAttack(
	honest: Components,
	forged: Components,
	combiner: Combiner,
): Promise<ReencapResult> {
	const honestKey = await deriveSessionKey(honest, combiner);
	const forgedKey = await deriveSessionKey(forged, combiner);
	const keysCollide = bytesToHex(honestKey) === bytesToHex(forgedKey);
	return {
		combiner,
		honestKey,
		forgedKey,
		// The attack "succeeds" when the attacker's re-encapsulated (forged)
		// transcript yields the same session key as the honest one \u2014 i.e. the
		// key is NOT bound to the transcript.
		attackSucceeds: keysCollide,
		keysCollide,
	};
}

// Build an honest/forged transcript pair that shares component secrets but
// differs only in ct_binding \u2014 the exact input a re-encapsulation attacker
// controls. Component secrets are reused deliberately; ct_binding differs.
export function reencapPair(): { honest: Components; forged: Components } {
	const classical = randomBytes(32);
	const pq = randomBytes(32);
	const honest: Components = { classical, pq, ctBinding: randomBytes(32) };
	// Same shared secrets, different transcript (a re-encapsulated ciphertext).
	let forgedBinding = randomBytes(32);
	// Vanishingly unlikely, but keep the two transcripts distinct.
	while (bytesToHex(forgedBinding) === bytesToHex(honest.ctBinding)) {
		forgedBinding = randomBytes(32);
	}
	const forged: Components = { classical, pq, ctBinding: forgedBinding };
	return { honest, forged };
}
