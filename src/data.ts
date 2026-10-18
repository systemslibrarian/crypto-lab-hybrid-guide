// data.ts — narrative content for the hybrid cryptography guide.

export interface DecisionStep {
	question: string;
	yes: string;
	no: string;
}

export const DECISION: DecisionStep[] = [
	{
		question: 'Does any data need to stay secret for years?',
		yes: 'Prioritize post-quantum protection now. For TLS 1.3, choose a supported hybrid or pure-PQ configuration that meets your policy and interoperability needs.',
		no: 'Assess the lifetime of the system as well as its data; plan a supported PQ migration path.',
	},
	{
		question: 'Is the post-quantum scheme young / recently standardised?',
		yes: 'Hybrid hedges the risk — if the PQC scheme is later weakened, the classical half still protects you.',
		no: 'Pure-PQ can be appropriate where policy and interoperability permit; a classical hedge adds complexity as well as a fallback assumption.',
	},
	{
		question: 'Can your stack tolerate larger handshakes?',
		yes: 'Test the protocol-defined PQ or hybrid group your peers support. X-Wing is a general-purpose KEM, not a substitute for a TLS named group.',
		no: 'Test for middlebox ossification first — larger ClientHello messages have historically tripped old network gear.',
	},
	{
		question: 'Do you need a single, simple, vetted choice?',
		yes: 'Use a vetted implementation of the configuration specified for your protocol and policy. Hybrid and pure-PQ TLS are both options.',
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
	{ good: true, title: 'Choose for your protocol', body: 'An analyzed hybrid can hedge against failure of one component. Pure-PQ is also a recommended TLS option in NCSC guidance; choose according to policy, supported implementations and interoperability.' },
	{ good: true, title: 'Use a sound combiner', body: 'Use an analyzed combiner with its exact component and proof assumptions. The custom transcript experiment is not a proof that adding a binding hash makes arbitrary KEM combinations IND-CCA secure.' },
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
		detail: 'Cloudflare reports roughly 38% of human HTTPS traffic uses hybrid post-quantum key exchange. Recorded classical-only key exchanges can face harvest-now-decrypt-later risk; both suitable hybrid and pure-PQ key establishment can address it.',
	},
	{
		year: 2026,
		classical: 'safe',
		pq: 'safe',
		label: 'NCSC recommends hybrid and pure-PQ TLS',
		detail: 'Published guidance, 15 October 2026: both choices are recommended for TLS 1.3. Hybrid RFC 10024 is published; pure-PQ options are available in libraries while their final RFC is pending. This concerns key establishment, not a post-quantum authentication recommendation.',
	},
	{
		year: 2028,
		classical: 'fragile',
		pq: 'safe',
		label: 'Illustrative migration checkpoint',
		detail: 'Scenario assumption, not an official deadline: migration is underway. PQ or hybrid key establishment protects new sessions; it cannot protect copies previously harvested from classical-only sessions.',
	},
	{
		year: 2030,
		classical: 'fragile',
		pq: 'safe',
		label: 'Illustrative early quantum-threat scenario',
		detail: 'Scenario assumption, not a forecast: the quantum threat draws closer. This chosen date illustrates why data lifetime matters; it does not predict when a cryptographically relevant quantum computer will exist.',
	},
	{
		year: 2035,
		classical: 'broken',
		pq: 'safe',
		label: 'Assumed quantum break for this scenario',
		detail: 'Scenario assumption: a quantum computer breaks the classical component while ML-KEM remains secure. Suitable hybrid and pure-PQ key establishment retain confidentiality under that assumption; classical-only recordings are exposed.',
	},
	{
		year: 2040,
		classical: 'broken',
		pq: 'safe',
		label: 'Illustrative review of the classical hedge',
		detail: 'Scenario assumption, not a scheduled standards decision: reassess whether the classical hedge is still needed. Pure-PQ TLS is already recommended by NCSC in 2026; do not wait until 2040 solely because of this illustration.',
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
