// data.ts — narrative content for the hybrid cryptography guide.

export interface DecisionStep {
	question: string;
	yes: string;
	no: string;
}

export const DECISION: DecisionStep[] = [
	{
		question: 'Does any data need to stay secret for years (past ~2030)?',
		yes: 'Go hybrid now \u2014 harvest-now-decrypt-later means today\u2019s traffic can be recorded and decrypted later by a quantum computer.',
		no: 'Hybrid is lower priority, but still wise for new long-lived systems.',
	},
	{
		question: 'Is the post-quantum scheme young / recently standardised?',
		yes: 'Hybrid hedges the risk \u2014 if the PQC scheme is later weakened, the classical half still protects you.',
		no: 'Even mature PQC benefits from a classical hedge during transition.',
	},
	{
		question: 'Can your stack tolerate larger handshakes?',
		yes: 'Use a hybrid KEM like X-Wing (X25519 + ML-KEM-768).',
		no: 'Test for middlebox ossification first \u2014 larger ClientHello messages have historically tripped old network gear.',
	},
	{
		question: 'Do you need a single, simple, vetted choice?',
		yes: 'Use X-Wing \u2014 it fixes the components, combiner, and hash so you don\u2019t have to.',
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
	{ name: 'X-Wing (IETF draft)', detail: 'A general-purpose hybrid KEM (X25519 + ML-KEM-768, SHA3-256 combiner) by Connolly, Schwabe, and Westerbaan \u2014 designed as the sensible default for most applications.' },
	{ name: 'CECPQ1 / CECPQ2 (Google)', detail: 'Early Google/Cloudflare hybrid experiments (2016, 2018) that first surfaced real-world middlebox and packet-size issues with post-quantum handshakes.' },
	{ name: 'Signal PQXDH', detail: 'Signal\u2019s post-quantum extended Diffie\u2013Hellman augments its classical key agreement with a PQC KEM for its messaging key establishment.' },
];

export interface Pitfall {
	good: boolean;
	title: string;
	body: string;
}

export const PITFALLS: Pitfall[] = [
	{ good: true, title: 'Combine, don\u2019t replace', body: 'Run the classical and PQ key exchanges in parallel and bind both results; the session key holds if either component survives.' },
	{ good: true, title: 'Use a sound combiner', body: 'A dual-PRF or split-key-PRF combiner (as in X-Wing) preserves IND-CCA security; bind ciphertexts/transcript to stop re-encapsulation attacks.' },
	{ good: true, title: 'Test for ossification', body: 'Larger PQ key shares can push the ClientHello past one packet; verify middleboxes and old firewalls handle it before broad rollout.' },
	{ good: false, title: 'XOR-ing raw secrets', body: 'Naively XOR-ing or truncating shared secrets can destroy security guarantees; always run them through a proper KDF/combiner.' },
	{ good: false, title: 'Assuming hybrid = slow', body: 'Hybrid handshakes are nearly as fast as classical ones; the bottleneck is usually message size and middleboxes, not CPU.' },
	{ good: false, title: 'Forgetting to remove the hedge later', body: 'Hybrids are a transition tool. Once PQC has years of cryptanalysis behind it, plan a path to PQ-native to avoid carrying classical weakness forever.' },
];
