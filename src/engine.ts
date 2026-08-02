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
// "Breaking" a component means the attacker learns its shared secret exactly
// (worst case). Everything below is *run*, not asserted: the session encrypts a
// known record under the derived key, and the attacker is handed only the
// secrets they have broken plus the public transcript. They then derive
// candidate session keys with the real combiner and try to decrypt the
// intercepted record with each one. The verdict is whatever that decryption
// actually did.

export interface BreakState {
	classicalBroken: boolean; // e.g. a future quantum computer breaks X25519
	pqBroken: boolean; // e.g. cryptanalysis weakens ML-KEM
}

// The plaintext of the record the two parties exchange under the session key.
// The attacker's goal is to produce this string.
export const RECORD_PLAINTEXT = 'hybrid session record';

export interface Session {
	components: Components;
	combiner: Combiner;
	sessionKey: Uint8Array;
	iv: Uint8Array;
	record: Uint8Array; // AES-256-GCM( sessionKey, iv, RECORD_PLAINTEXT )
}

async function aesKey(raw: Uint8Array): Promise<CryptoKey> {
	return crypto.subtle.importKey('raw', raw as BufferSource, 'AES-GCM', false, [
		'encrypt',
		'decrypt',
	]);
}

// Derive the session key and encrypt one record under it. This record is what
// the attacker intercepts, and decrypting it is the only definition of
// "recovered the key" this lab uses.
export async function openSession(
	components: Components,
	combiner: Combiner,
): Promise<Session> {
	const sessionKey = await deriveSessionKey(components, combiner);
	const iv = randomBytes(12);
	const ct = await crypto.subtle.encrypt(
		{ name: 'AES-GCM', iv: iv as BufferSource },
		await aesKey(sessionKey),
		enc.encode(RECORD_PLAINTEXT) as BufferSource,
	);
	return { components, combiner, sessionKey, iv, record: new Uint8Array(ct) };
}

// Attempt to decrypt the intercepted record with a candidate key. Returns the
// plaintext when the GCM tag verifies and null when it does not \u2014 no shortcuts,
// the tag check is the oracle.
export async function tryDecryptRecord(
	session: Session,
	candidateKey: Uint8Array,
): Promise<string | null> {
	try {
		const pt = await crypto.subtle.decrypt(
			{ name: 'AES-GCM', iv: session.iv as BufferSource },
			await aesKey(candidateKey),
			session.record as BufferSource,
		);
		return new TextDecoder().decode(pt);
	} catch {
		return null;
	}
}

export type ComponentName = 'classical' | 'pq';

export interface RecoveryResult {
	attempts: number; // candidate keys actually derived and tested
	successes: number; // candidates whose key decrypted the record
	recovered: boolean; // successes > 0
	recoveredPlaintext: string | null;
	unknownComponents: ComponentName[]; // secrets withheld from the attacker
	unknownBits: number; // measured: 8 x withheld secret bytes
	bestBytesMatched: number; // best candidate/true key agreement, of 32
	firstCandidateKeyHex: string;
	trueKeyKnownToAttacker: boolean; // candidate key equalled the real key
}

function bytesMatched(a: Uint8Array, b: Uint8Array): number {
	let n = 0;
	for (let i = 0; i < Math.min(a.length, b.length); i++) if (a[i] === b[i]) n++;
	return n;
}

// Run the key-recovery attack. The attacker gets the transcript binding (public)
// and the shared secrets of whichever components are broken; for every component
// still standing they must guess, so we actually draw a guess and derive a real
// candidate session key from it, then test it against the intercepted record.
//
// This runs at REAL parameters: an unbroken component contributes a 256-bit
// secret, so a wrong guess is wrong with probability 1 - 2^-256. The failure is
// therefore observed, not stipulated.
export async function attemptKeyRecovery(
	session: Session,
	state: BreakState,
	attempts = 16,
): Promise<RecoveryResult> {
	const truth = session.components;
	const unknownComponents: ComponentName[] = [];
	if (!state.classicalBroken) unknownComponents.push('classical');
	if (!state.pqBroken) unknownComponents.push('pq');

	// Uncertainty is counted off the actual secrets withheld from the attacker,
	// not off the checkbox states.
	const unknownBits = unknownComponents.reduce(
		(bits, name) => bits + truth[name].length * 8,
		0,
	);

	let successes = 0;
	let recoveredPlaintext: string | null = null;
	let bestBytesMatched = 0;
	let firstCandidateKeyHex = '';
	let trueKeyKnownToAttacker = false;
	let performed = 0;

	// With nothing withheld the attacker has a single deterministic candidate;
	// one derivation settles it. Otherwise they take repeated shots in the dark.
	const budget = unknownComponents.length === 0 ? 1 : attempts;

	for (let i = 0; i < budget; i++) {
		const guess: Components = {
			classical: state.classicalBroken ? truth.classical : randomBytes(truth.classical.length),
			pq: state.pqBroken ? truth.pq : randomBytes(truth.pq.length),
			// The transcript binding is public \u2014 the attacker always has it.
			ctBinding: truth.ctBinding,
		};
		const candidate = await deriveSessionKey(guess, session.combiner);
		performed++;
		if (i === 0) firstCandidateKeyHex = bytesToHex(candidate);
		bestBytesMatched = Math.max(bestBytesMatched, bytesMatched(candidate, session.sessionKey));
		if (bytesToHex(candidate) === bytesToHex(session.sessionKey)) trueKeyKnownToAttacker = true;
		const pt = await tryDecryptRecord(session, candidate);
		if (pt !== null) {
			successes++;
			recoveredPlaintext = pt;
			break;
		}
	}

	return {
		attempts: performed,
		successes,
		recovered: successes > 0,
		recoveredPlaintext,
		unknownComponents,
		unknownBits,
		bestBytesMatched,
		firstCandidateKeyHex,
		trueKeyKnownToAttacker,
	};
}

export interface Verdict {
	remainingBits: number;
	secure: boolean;
	headline: string;
	detail: string;
	measurement: string;
}

// Turn a completed recovery run into the on-screen verdict. Every claim here is
// read off the run: `secure` is "the attacker's derived keys did not decrypt the
// record", and `remainingBits` is the entropy actually withheld from them.
export function assess(recovery: RecoveryResult, combiner: Combiner): Verdict {
	const holding = recovery.unknownComponents;
	// Secure means two things both observed in the run: the attacker's derived
	// keys failed to open the record, and there was real entropy they had to
	// guess. Neither is read off a checkbox.
	const secure = !recovery.recovered && holding.length > 0;
	const remainingBits = recovery.unknownBits;

	const measurement = recovery.recovered
		? `attacker: ${recovery.attempts} derivation${recovery.attempts === 1 ? '' : 's'} \u00b7 record decrypted \u00b7 key matched 32/32 bytes`
		: `attacker: ${recovery.attempts} derivations \u00b7 0 decrypted the record \u00b7 best candidate matched ${recovery.bestBytesMatched}/32 bytes`;

	let headline: string;
	let detail: string;
	if (recovery.recovered) {
		headline = 'Broken \u2014 both halves down';
		detail = `The attacker re-derived the session key and the intercepted record decrypted to \u201c${recovery.recoveredPlaintext}\u201d. No combiner can save you here; the whole point of a hybrid is that this should be far harder than breaking either one alone.`;
	} else if (holding.length === 0) {
		// Every secret was handed over yet the record survived: the derivation
		// and the record disagree, which is a fault in the lab, not a hedge.
		headline = 'Inconclusive \u2014 derivation mismatch';
		detail =
			'The attacker was given every component secret but their derived key did not open the intercepted record. That is not a security property; it means the session key and the record were produced from different inputs.';
	} else if (holding.length === 2) {
		headline = 'Fully secure';
		detail =
			'Neither component is broken. The session key has the full strength of both halves \u2014 this is the normal operating state.';
	} else if (holding.includes('pq')) {
		headline = 'Still secure (PQ holds)';
		detail =
			'A quantum computer has broken the classical X25519 half, but ML-KEM is intact. The attacker still had to guess the surviving secret, and the record stayed encrypted \u2014 this is exactly the future scenario hybrids are built for.';
	} else {
		headline = 'Still secure (classical holds)';
		detail =
			'Cryptanalysis has weakened the post-quantum half, but classical X25519 is intact. The attacker still had to guess the surviving secret, and the record stayed encrypted \u2014 this is the hedge against a young PQC scheme being broken.';
	}

	detail += ` Measured this run \u2014 ${measurement}.`;

	if (combiner === 'naive' && secure) {
		detail +=
			' Note: simple concatenation works here, but a robust combiner also binds the ciphertexts/transcript to prevent re-encapsulation and related attacks \u2014 which is why X-Wing uses a structured construction.';
	}

	return { remainingBits, secure, headline, detail, measurement };
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
