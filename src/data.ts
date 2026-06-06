// data.ts — narrative content for the hybrid cryptography guide.

export interface DecisionStep {
	question: string;
	yes: string;
	no: string;
}

export const DECISION: DecisionStep[] = [
	{
		question: 'Does any data need to stay secret for years (past ~2030)?',
		yes: 'Go hybrid now — harvest-now-decrypt-later means today’s traffic can be recorded and decrypted later by a quantum computer.',
		no: 'Hybrid is lower priority, but still wise for new long-lived systems.',
	},
	{
		question: 'Is the post-quantum scheme young / recently standardised?',
		yes: 'Hybrid hedges the risk — if the PQC scheme is later weakened, the classical half still protects you.',
		no: 'Even mature PQC benefits from a classical hedge during transition.',
	},
	{
		question: 'Can your stack tolerate larger handshakes?',
		yes: 'Use a hybrid KEM like X-Wing (X25519 + ML-KEM-768).',
		no: 'Test for middlebox ossification first — larger ClientHello messages have historically tripped old network gear.',
	},
	{
		question: 'Do you need a single, simple, vetted choice?',
		yes: 'Use X-Wing — it fixes the components, combiner, and hash so you don’t have to.',
		no: 'A generic KEM combiner lets you pick components, but you must use a sound (dual-PRF / split-key) construction.',
	},
];

export interface Deployment {
	name: string;
	detail: string;
}

export const DEPLOYMENTS: Deployment[] = [
	{ name: 'TLS 1.3 (X25519MLKEM768)', detail: 'The IETF-named hybrid group combining X25519 with ML-KEM-768, negotiated during the handshake. Widely supported in modern browsers and servers.' },
	{ name: 'Cloudflare edge', detail: 'Reported that roughly 38% of human HTTPS traffic on its network used hybrid post-quantum key exchange by March 2025.' },
	{ name: 'X-Wing (IETF draft)', detail: 'A general-purpose hybrid KEM (X25519 + ML-KEM-768, SHA3-256 combiner) by Connolly, Schwabe, and Westerbaan — designed as the sensible default for most applications.' },
	{ name: 'CECPQ1 / CECPQ2 (Google)', detail: 'Early Google/Cloudflare hybrid experiments (2016, 2018) that first surfaced real-world middlebox and packet-size issues with post-quantum handshakes.' },
	{ name: 'Signal PQXDH', detail: 'Signal’s post-quantum extended Diffie–Hellman augments its classical key agreement with a PQC KEM for its messaging key establishment.' },
	{ name: 'iMessage PQ3', detail: 'Apple’s iMessage upgraded to a Level 3 post-quantum protocol in 2024, combining ECC and PQ KEMs with periodic rekeying for forward-secrecy beyond compromise.' },
];

export interface Pitfall {
	good: boolean;
	title: string;
	body: string;
}

export const PITFALLS: Pitfall[] = [
	{ good: true, title: 'Combine, don’t replace', body: 'Run the classical and PQ key exchanges in parallel and bind both results; the session key holds if either component survives.' },
	{ good: true, title: 'Use a sound combiner', body: 'A dual-PRF or split-key-PRF combiner (as in X-Wing) preserves IND-CCA security; bind ciphertexts/transcript to stop re-encapsulation attacks.' },
	{ good: true, title: 'Test for ossification', body: 'Larger PQ key shares can push the ClientHello past one packet; verify middleboxes and old firewalls handle it before broad rollout.' },
	{ good: false, title: 'XOR-ing raw secrets', body: 'Naively XOR-ing or truncating shared secrets can destroy security guarantees; always run them through a proper KDF/combiner.' },
	{ good: false, title: 'Assuming hybrid = slow', body: 'Hybrid handshakes are nearly as fast as classical ones; the bottleneck is usually message size and middleboxes, not CPU.' },
	{ good: false, title: 'Forgetting to remove the hedge later', body: 'Hybrids are a transition tool. Once PQC has years of cryptanalysis behind it, plan a path to PQ-native to avoid carrying classical weakness forever.' },
];

export interface TimelineEvent {
	year: number;
	classical: 'safe' | 'fragile' | 'broken';
	pq: 'safe' | 'fragile' | 'broken';
	label: string;
	detail: string;
}

export const TIMELINE_EVENTS: TimelineEvent[] = [
	{
		year: 2024,
		classical: 'safe',
		pq: 'safe',
		label: 'NIST standardises ML-KEM (FIPS 203)',
		detail: 'The Kyber-derived ML-KEM-768 becomes the first standardised PQ KEM; major browsers begin shipping hybrid key exchange in TLS 1.3.',
	},
	{
		year: 2025,
		classical: 'safe',
		pq: 'safe',
		label: 'Hybrid key exchange goes mainstream',
		detail: 'Cloudflare reports roughly 38% of human HTTPS traffic uses hybrid post-quantum key exchange. Anything recorded today without hybrid is harvest-now bait.',
	},
	{
		year: 2028,
		classical: 'fragile',
		pq: 'safe',
		label: 'Classical key sizes downgraded',
		detail: 'NIST formally deprecates 112-bit-equivalent classical algorithms. Hybrid deployments protect long-lived secrets while migration continues.',
	},
	{
		year: 2030,
		classical: 'fragile',
		pq: 'safe',
		label: 'CRQC capability projected (low-end)',
		detail: 'Mainstream forecasts begin placing a cryptographically relevant quantum computer in reach. Classical-only sessions recorded today become a future liability.',
	},
	{
		year: 2035,
		classical: 'broken',
		pq: 'safe',
		label: 'Estimated CRQC arrival',
		detail: 'Most expert surveys cluster their 50% probability for a CRQC around the mid-2030s. Hybrid sessions are still safe because ML-KEM holds; pure-classical sessions are exposed.',
	},
	{
		year: 2040,
		classical: 'broken',
		pq: 'safe',
		label: 'Pure-PQ becomes the recommended default',
		detail: 'With a decade of cryptanalysis behind ML-KEM and its successors, hybrids start being retired in favour of pure-PQ defaults — but the systems that went hybrid in 2025 had a smooth ride here.',
	},
];

export interface HandshakeSize {
	name: string;
	bytes: number;
	tone: 'classical' | 'pq' | 'hybrid';
	note: string;
}

// Rough wire sizes for the public key + ciphertext pair in a TLS-like flow.
// Numbers reflect published parameter sizes for each scheme.
export const HANDSHAKE_SIZES: HandshakeSize[] = [
	{
		name: 'Classical X25519 only',
		bytes: 64,
		tone: 'classical',
		note: 'Two 32-byte key shares. Cheap on the wire — and fully exposed to a future quantum attacker.',
	},
	{
		name: 'ML-KEM-768 only',
		bytes: 2272,
		tone: 'pq',
		note: '1184-byte public key + 1088-byte ciphertext. Quantum-resistant, but trusts a young scheme on its own.',
	},
	{
		name: 'Hybrid X25519MLKEM768',
		bytes: 2336,
		tone: 'hybrid',
		note: 'X25519 + ML-KEM-768. About 3% larger than ML-KEM alone, with both safety nets in place.',
	},
];
