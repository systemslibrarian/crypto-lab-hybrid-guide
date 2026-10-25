# crypto-lab-hybrid-guide

## What It Is

An interactive guide to hybrid cryptography and the post-quantum transition. An analyzed hybrid combiner can preserve confidentiality if one component remains secure under its stated assumptions. This lab uses random simulated component secrets, real SHA-256 and AES-256-GCM, and candidate decryption attempts. A separate **transcript-binding experiment** deliberately supplies equal component secrets under different public bindings and compares outputs. It does not establish a realizable re-encapsulation or key-recovery attack against X25519, ML-KEM or X-Wing.

> **Scope and honesty note.** In the original playground, both component inputs are independent random 32-byte strings; neither X25519 nor ML-KEM runs in that playground. A separate real-X25519 context-binding exhibit is described below. Withholding both inputs means 64 input bytes, not 512 bits of session-key strength. Both hash constructions produce a 32-byte key: the key space is at most 2^256, an upper bound rather than a security guarantee. Real X25519 targets approximately 128-bit classical security ([RFC 7748](https://www.rfc-editor.org/rfc/rfc7748)). Finite failed candidate guesses do not measure security strength; the verdict reports only whether this run decrypted the record. The custom bound hash uses SHA-256 and a custom label/public binding, not interoperable X-Wing. [X-Wing draft-11 §§5.3/6](https://datatracker.ietf.org/doc/html/draft-connolly-cfrg-xwing-kem-11) specifies SHA3-256, exact X25519 ciphertext/public-key inputs, and component-specific proof assumptions; this demonstration does not supply that proof. Known-answer tests preserve the custom constructions.

## When to Use It

- **Deciding whether to go hybrid** — a four-question guide weighing policy, interoperability and a classical hedge; long-lived secrets need PQ protection, which may use hybrid or pure-PQ TLS.
- **Explaining the conditional "either half holds" hedge** — inspect which simulated secrets are supplied and which candidate decryption attempts succeed; explain the separate assumptions of an analyzed real combiner.
- **Teaching KEM combiners** — contrast naive concatenation with a bound, X-Wing-style construction and see why the difference matters.
- **Planning a migration** — understand the phases, the harvest-now-decrypt-later threat, and real deployment pitfalls like middlebox ossification.
- **Do NOT use this code in production** — it uses simulated secrets and SHA-256 to illustrate the construction; deploy a vetted library implementing X-Wing or a standardised hybrid group.

## Live Demo

**[systemslibrarian.github.io/crypto-lab-hybrid-guide](https://systemslibrarian.github.io/crypto-lab-hybrid-guide/)**

Generate a session from two simulated 32-byte inputs. Its 32-byte SHA-256 output encrypts a record with AES-256-GCM. Each break toggle supplies that component secret to the guesser; candidate keys are derived and tested against the record. The verdict, byte-count meter and measurement line show the actual finite attempts, never a security guarantee. With both secrets supplied, one derivation reproduces the key and prints the recovered plaintext. With either or both withheld, failure to recover is only a result of this run.

**Run transcript-binding experiment** explicitly assumes the same component secrets with distinct public binding inputs. The unbound hash ignores that input and produces equal keys; the custom bound hash produces different keys for the chosen pair. The fixture supplies the equal-secret premise rather than generating real KEM ciphertexts. Key equality does not prove an attacker can obtain a secret, and differing keys do not prove robust-combiner security. The rest of the page offers a decision guide, deployment context and migration considerations.

## What Can Go Wrong

- **Treating hybrid as mandatory** — an analyzed hybrid can preserve a classical hedge under its specific assumptions, but suitable pure-PQ TLS is also recommended by NCSC. Choose according to protocol, policy and interoperability; component security bits do not add together.
- **XOR-ing or truncating raw secrets** — naively mixing shared secrets can destroy the security proof; always run components through a sound KDF/combiner.
- **Using an unbound combiner** — the custom unbound hash ignores our public binding input. Production security requires an analyzed construction and its exact component-specific assumptions; adding a transcript hash alone is not a proof.
- **Middlebox ossification** — larger post-quantum key shares can push the TLS ClientHello past one packet; Google's CECPQ2 experiment showed old network gear may drop or mishandle these connections.
- **Carrying the classical hedge forever** — hybrids are a transition tool; once PQC has years of cryptanalysis behind it, plan a path to PQ-native rather than permanently inheriting classical weakness.

## Real-World Usage

- **TLS 1.3 hybrid key exchange** — the IETF-named X25519MLKEM768 group combines classical and post-quantum KEMs in the handshake, now widely supported in browsers and servers.
- **X-Wing** — a general-purpose hybrid KEM (X25519 + ML-KEM-768 with a SHA3-256 combiner) designed as the sensible default, with a security proof reducing to ML-KEM-768 and the strong Diffie-Hellman assumption.
- **Cloudflare edge** — reported that roughly 38% of human HTTPS traffic on its network used hybrid post-quantum key exchange by March 2025.
- **Signal PQXDH** — augments Signal's classical extended Diffie-Hellman with a post-quantum KEM for messaging key establishment.
- **Harvest-now-decrypt-later defense** — organisations enable hybrids today so traffic recorded now cannot be decrypted later once large-scale quantum computers exist.

## Deployment guidance reviewed 18 October 2026

[NCSC, 15 October 2026](https://www.ncsc.gov.uk/blogs/post-quantum-updates-to-our-tls-guidance), recommends both hybrid and pure-PQ TLS 1.3 configurations for general use and government OFFICIAL information. Hybrid RFC 10024 is published; the pure-PQ RFC is still pending, with stable library options available. This concerns key establishment, not post-quantum authentication. The visible decision guide links this source. Future timeline dates and the assumed quantum break are teaching scenarios, not forecasts or official deadlines; pure-PQ is not postponed to 2040. The illustrative engine remains unchanged.

## How to Run Locally

```bash
git clone https://github.com/systemslibrarian/crypto-lab-hybrid-guide
cd crypto-lab-hybrid-guide
npm install
npm run dev
```

## Related Demos

- [crypto-lab-hybrid-wire](https://systemslibrarian.github.io/crypto-lab-hybrid-wire/) — the same X25519 + ML-KEM-768 hybrid driving an end-to-end encrypted session.
- [crypto-lab-pq-tls-handshake](https://systemslibrarian.github.io/crypto-lab-pq-tls-handshake/) — the X25519MLKEM768 hybrid inside a real TLS 1.3 key schedule.
- [crypto-lab-kyber-vault](https://systemslibrarian.github.io/crypto-lab-kyber-vault/) — ML-KEM (FIPS 203), the post-quantum half of the combiner.
- [crypto-lab-hybrid-sign](https://systemslibrarian.github.io/crypto-lab-hybrid-sign/) — the same defense-in-depth idea applied to signatures.
- [crypto-lab-pq-rotation](https://systemslibrarian.github.io/crypto-lab-pq-rotation/) — planning the hybrid X.509 / CNSA 2.0 migration this guide motivates.

## Tech

Vite + TypeScript, zero runtime dependencies. `src/engine.ts` implements the KEM combiners (real SHA-256 via Web Crypto) and bounded recovery observations; `src/data.ts` holds the decision guide, deployments, and pitfalls; `src/ui.ts` is the interactive playground. Dark mode throughout.

```bash
npm install
npm run dev      # local dev server
npm run build    # type-check + production build to dist/
```

---

*Part of the [Crypto Lab](https://crypto-lab.systemslibrarian.dev/) suite.*

*"So whether you eat or drink or whatever you do, do it all for the glory of God." — 1 Corinthians 10:31*


## Real public-context binding

A separate experiment executes the inverse-coordinate construction from
[On the Necessity of Public Contexts in Hybrid KEMs](https://eprint.iacr.org/2026/140),
§III-B. Native WebCrypto X25519 derives the same raw secret from `c` and
`1/c mod (2^255−19)`. The public transformation receives no private key.
A custom HKDF-SHA-256 comparison shows equal secret-only keys but different
keys when the exact public coordinate and recipient public key are included.
The same-input and fresh-input controls run the same code. Changing the selected
case retires stale results, including computations still in flight.

This is not X-Wing or HPKE, runs no ML-KEM, and supplies no hybrid or multi-user
security theorem. The native primitive is checked against RFC 7748 §6.1's known
answer; the tests also verify DH agreement, the field-inverse identity, the
collision, recipient binding and low-order rejection. The UI shows actual bytes
and never substitutes simulated outputs when native X25519 is unavailable.

Validation: 55 unit tests, build and 23 browser/accessibility tests pass, including
all three new cases at desktop and 380px. Run
`node tools/check-context-mutations.mjs` to verify that successful-build changes
to the public transformation, KDF context and negative scope claim are caught,
then restore the exact source and baseline bundle.
