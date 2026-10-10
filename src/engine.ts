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
// as the OTHER secret is still secret. We illustrate by revealing a component
// and counting withheld input bytes separately from observed recovery attempts.

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
	withheldBytes: number; // input bytes withheld in this random-secret model
	keyBytes: number; // actual derived output width, not a security estimate
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
// These are uniformly random simulated secrets, not real KEM parameters.
// Failed finite guesses are observations, not a measurement of security.
export async function attemptKeyRecovery(
	session: Session,
	state: BreakState,
	attempts = 16,
): Promise<RecoveryResult> {
	if (!Number.isSafeInteger(attempts) || attempts < 0) throw new RangeError('Attempt budget must be a nonnegative safe integer.');
	const truth = session.components;
	const unknownComponents: ComponentName[] = [];
	if (!state.classicalBroken) unknownComponents.push('classical');
	if (!state.pqBroken) unknownComponents.push('pq');

	// Count withheld bytes; neither input width nor finite failures measure security.
	const withheldBytes = unknownComponents.reduce(
		(bytes, name) => bytes + truth[name].length,
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
		withheldBytes,
		keyBytes: session.sessionKey.length,
		bestBytesMatched,
		firstCandidateKeyHex,
		trueKeyKnownToAttacker,
	};
}

export interface Verdict {
	withheldBytes: number;
	keySpaceCapBits: number; // output-width upper bound, never a strength guarantee
	observedNoRecovery: boolean;
	headline: string;
	detail: string;
	measurement: string;
}

// Report the run's observation and separately state model limits. No boolean
// here equates failed guesses with cryptographic security.
export function assess(recovery: RecoveryResult, combiner: Combiner): Verdict {
	const observedNoRecovery = recovery.attempts > 0 && !recovery.recovered && recovery.unknownComponents.length > 0;
	const measurement = recovery.recovered
		? `attacker: ${recovery.attempts} derivation${recovery.attempts === 1 ? '' : 's'} · record decrypted · best key match ${recovery.bestBytesMatched}/${recovery.keyBytes} bytes`
		: `attacker: ${recovery.attempts} derivations · 0 decrypted the record · best candidate matched ${recovery.bestBytesMatched}/${recovery.keyBytes} bytes`;
	let headline: string;
	let detail: string;
	if (recovery.recovered) {
		headline = 'Record recovered';
		detail = `A derived candidate decrypted the intercepted record to “${recovery.recoveredPlaintext}”. This reports the computation, not a break of real X25519 or ML-KEM.`;
	} else if (recovery.attempts === 0) {
		headline = 'Inconclusive — no attempts';
		detail = 'No candidate key was tested; no recovery result is established.';
	} else if (recovery.unknownComponents.length === 0) {
		headline = 'Inconclusive — derivation mismatch';
		detail = 'Every component secret was supplied but the derived key failed to decrypt. The session inputs and record disagree; this is a lab fault, not a security property.';
	} else {
		headline = 'Not recovered in this run';
		detail = `${recovery.withheldBytes} bytes of independent random simulated input were withheld. The finite failed guesses do not measure security strength.`;
	}
	detail += ` Output: ${recovery.keyBytes} bytes, so the session-key space is at most 2^${recovery.keyBytes * 8}; this is an upper bound, not guaranteed security. Real X25519 targets approximately 128-bit classical security (RFC 7748). Real component KEMs are not implemented here. Observed this run: ${measurement}.`;
	if (combiner === 'naive' && observedNoRecovery) {
		detail += ' The unbound hash ignores the public binding input; the separate transcript-binding experiment assumes equal component secrets. It does not demonstrate a realizable KEM attack or a robust combiner proof.';
	}
	return { withheldBytes: recovery.withheldBytes, keySpaceCapBits: recovery.keyBytes * 8,
		observedNoRecovery, headline, detail, measurement };
}

// --- transcript-binding experiment ---------------------------------------
// Assumption supplied by the fixture: equal component secrets, different public
// binding inputs. Compare derived keys under that premise only. This does not
// construct ciphertexts or show an attacker obtaining the same KEM secrets.

export interface TranscriptBindingResult {
	combiner: Combiner;
	honestKey: Uint8Array; // key from the honest transcript
	forgedKey: Uint8Array; // key from the second simulated transcript
	keysCollide: boolean; // observed equality for these inputs only
	sameComponentSecrets: boolean;
	differentBindings: boolean;
}

// Compute key equality and the input premise; no attack-success verdict.
export async function transcriptBindingExperiment(
	honest: Components,
	forged: Components,
	combiner: Combiner,
): Promise<TranscriptBindingResult> {
	const honestKey = await deriveSessionKey(honest, combiner);
	const forgedKey = await deriveSessionKey(forged, combiner);
	const keysCollide = bytesToHex(honestKey) === bytesToHex(forgedKey);
	return {
		combiner,
		honestKey,
		forgedKey,
		sameComponentSecrets: bytesToHex(honest.classical) === bytesToHex(forged.classical) &&
			bytesToHex(honest.pq) === bytesToHex(forged.pq),
		differentBindings: bytesToHex(honest.ctBinding) !== bytesToHex(forged.ctBinding),
		keysCollide,
	};
}

// Deliberately supply equal simulated secrets and distinct public bindings.
export function transcriptPair(): { honest: Components; forged: Components } {
	const classical = randomBytes(32);
	const pq = randomBytes(32);
	const honest: Components = { classical, pq, ctBinding: randomBytes(32) };
	// This is an assumed input pair, not a generated KEM ciphertext pair.
	let forgedBinding = randomBytes(32);
	// Vanishingly unlikely, but keep the two transcripts distinct.
	while (bytesToHex(forgedBinding) === bytesToHex(honest.ctBinding)) {
		forgedBinding = randomBytes(32);
	}
	const forged: Components = { classical, pq, ctBinding: forgedBinding };
	return { honest, forged };
}
