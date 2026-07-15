# crypto-lab-hybrid-guide

## What It Is

An interactive guide to hybrid cryptography, the recommended strategy for the transition to post-quantum security. During this transition the safe move is not to replace classical algorithms but to combine them with post-quantum ones: a hybrid key-encapsulation mechanism (KEM) runs a classical key exchange (X25519) and a post-quantum one (ML-KEM-768) in parallel and binds the results, so the derived session key stays confidential as long as either half holds. This lab shows how the combiner works using real SHA-256 over simulated component secrets, lets you "break" each half to watch the hedge hold or fail, and — importantly — runs a **real, computed re-encapsulation attack** that shows the naive concatenation combiner actually failing while the transcript-bound combiner holds. It walks through when to deploy a hybrid, which construction to choose, and how to migrate. It is modelled on X-Wing, the IETF hybrid KEM by Connolly, Schwabe, and Westerbaan that fixes a single sensible set of choices for most applications.

> **Scope and honesty note.** This lab teaches the *combiner*, not the component KEMs. The X25519 and ML-KEM-768 shared secrets are modelled as random 32-byte strings (there is no real X25519 or ML-KEM here), and the combiner uses SHA-256 with a custom `"crypto-lab-hybrid"` label rather than real X-Wing's SHA3-256 and fixed 6-byte label. It is therefore **intentionally non-interoperable with real X-Wing** — the known-answer tests in `src/engine.test.ts` pin our construction's exact output precisely so this stays true. What *is* real and demonstrated end to end: SHA-256 via Web Crypto, and the transcript-binding property — the difference between a bound and an unbound combiner is proven by deriving and comparing actual keys, not narrated.

## When to Use It

- **Deciding whether to go hybrid** — a four-question guide that settles most cases; for long-lived secrets the answer is almost always yes.
- **Explaining the "either half holds" guarantee** — break the classical or post-quantum component and watch the session key stay unpredictable.
- **Teaching KEM combiners** — contrast naive concatenation with a bound, X-Wing-style construction and see why the difference matters.
- **Planning a migration** — understand the phases, the harvest-now-decrypt-later threat, and real deployment pitfalls like middlebox ossification.
- **Do NOT use this code in production** — it uses simulated secrets and SHA-256 to illustrate the construction; deploy a vetted library implementing X-Wing or a standardised hybrid group.

## Live Demo

**[systemslibrarian.github.io/crypto-lab-hybrid-guide](https://systemslibrarian.github.io/crypto-lab-hybrid-guide/)**

Generate a fresh session and watch two component shared secrets — classical X25519 and post-quantum ML-KEM-768 — feed a combiner that derives one session key via Web Crypto. Toggle "quantum computer breaks this" on the classical half or "cryptanalysis breaks this" on the post-quantum half: the verdict and the attacker's remaining-uncertainty bar update live, showing the session key stays secure until both halves fall. Switch between a naive concatenation combiner and an X-Wing-style bound combiner to see the construction difference — then click **Run re-encapsulation attack** to have the lab actually compute two session keys from one shared-secret pair under two different transcripts and compare them: the naive combiner's keys collide (attack succeeds), the bound combiner's keys differ (attack fails). Below the playground, a decision guide, a list of real production deployments (TLS 1.3 X25519MLKEM768, Cloudflare, X-Wing, Google's CECPQ experiments, Signal PQXDH), and a do/watch-out practice section complete the picture.

## What Can Go Wrong

- **Replacing instead of combining** — switching straight to a young PQC scheme removes the classical safety net; a hybrid keeps both so an attacker must break both at once.
- **XOR-ing or truncating raw secrets** — naively mixing shared secrets can destroy the security proof; always run components through a sound KDF/combiner.
- **Using an unbound combiner** — a robust combiner binds the ciphertexts/transcript to prevent re-encapsulation and related attacks, which is why X-Wing uses a structured construction rather than plain concatenation.
- **Middlebox ossification** — larger post-quantum key shares can push the TLS ClientHello past one packet; Google's CECPQ2 experiment showed old network gear may drop or mishandle these connections.
- **Carrying the classical hedge forever** — hybrids are a transition tool; once PQC has years of cryptanalysis behind it, plan a path to PQ-native rather than permanently inheriting classical weakness.

## Real-World Usage

- **TLS 1.3 hybrid key exchange** — the IETF-named X25519MLKEM768 group combines classical and post-quantum KEMs in the handshake, now widely supported in browsers and servers.
- **X-Wing** — a general-purpose hybrid KEM (X25519 + ML-KEM-768 with a SHA3-256 combiner) designed as the sensible default, with a security proof reducing to ML-KEM-768 and the strong Diffie-Hellman assumption.
- **Cloudflare edge** — reported that roughly 38% of human HTTPS traffic on its network used hybrid post-quantum key exchange by March 2025.
- **Signal PQXDH** — augments Signal's classical extended Diffie-Hellman with a post-quantum KEM for messaging key establishment.
- **Harvest-now-decrypt-later defense** — organisations enable hybrids today so traffic recorded now cannot be decrypted later once large-scale quantum computers exist.

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

Vite + TypeScript, zero runtime dependencies. `src/engine.ts` implements the KEM combiners (real SHA-256 via Web Crypto) and the break-state assessment; `src/data.ts` holds the decision guide, deployments, and pitfalls; `src/ui.ts` is the interactive playground. Dark mode by default with a persisted theme toggle.

```bash
npm install
npm run dev      # local dev server
npm run build    # type-check + production build to dist/
```

---

*"So whether you eat or drink or whatever you do, do it all for the glory of God." — 1 Corinthians 10:31*
