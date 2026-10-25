/** Real raw-X25519 collision from ePrint 2026/140 §III-B.
 * The KDF comparison is a separately labelled HKDF teaching composition,
 * not X-Wing, HPKE, or a complete post-quantum hybrid KEM.
 */
export const FIELD = (1n << 255n) - 19n;
const buffer = (x: Uint8Array) => new Uint8Array(x).buffer;
export const hex = (x: Uint8Array) => Array.from(x, n => n.toString(16).padStart(2, '0')).join('');
export const fromHex = (x: string) => Uint8Array.from(x.match(/../g) ?? [], h => Number.parseInt(h, 16));
export function decode(x: Uint8Array): bigint {
  if (x.length !== 32) throw new Error('coordinate must have 32 bytes');
  let n = 0n; for (let i = 31; i >= 0; i--) n = (n << 8n) | BigInt(x[i]);
  if (n >= FIELD) throw new Error('this demonstration requires canonical coordinates');
  return n;
}
export function inverseCoordinate(x: Uint8Array): Uint8Array {
  let a = decode(x); if (a === 0n) throw new Error('zero has no inverse');
  let exponent = FIELD - 2n, result = 1n;
  while (exponent > 0n) { if (exponent & 1n) result = result * a % FIELD; a = a * a % FIELD; exponent >>= 1n; }
  const out = new Uint8Array(32);
  for (let i = 0; i < 32; i++) { out[i] = Number(result & 255n); result >>= 8n; }
  return out;
}
export async function rawDh(privateKey: CryptoKey, coordinate: Uint8Array): Promise<Uint8Array> {
  const publicKey = await crypto.subtle.importKey('raw', buffer(coordinate), 'X25519', false, []);
  const secret = new Uint8Array(await crypto.subtle.deriveBits({ name: 'X25519', public: publicKey }, privateKey, 256));
  if (secret.every(b => b === 0)) throw new Error('all-zero DH output rejected');
  return secret;
}
export async function contextKdf(secret: Uint8Array, ct: Uint8Array, pk: Uint8Array, bind: boolean) {
  const label = new TextEncoder().encode('crypto-lab-hybrid-guide/raw-dh-binding/v1');
  const info = new Uint8Array(label.length + (bind ? 64 : 0)); info.set(label);
  if (bind) { info.set(ct, label.length); info.set(pk, label.length + 32); }
  const material = await crypto.subtle.importKey('raw', buffer(secret), 'HKDF', false, ['deriveBits']);
  return new Uint8Array(await crypto.subtle.deriveBits({ name: 'HKDF', hash: 'SHA-256', salt: new Uint8Array(32), info }, material, 256));
}
export async function runContext(mode: 'same' | 'inverse' | 'fresh') {
  const recipient = await crypto.subtle.generateKey('X25519', true, ['deriveBits']) as CryptoKeyPair;
  const ephemeral = await crypto.subtle.generateKey('X25519', true, ['deriveBits']) as CryptoKeyPair;
  const pk = new Uint8Array(await crypto.subtle.exportKey('raw', recipient.publicKey));
  const ctA = new Uint8Array(await crypto.subtle.exportKey('raw', ephemeral.publicKey));
  let ctB: Uint8Array = ctA.slice();
  if (mode === 'inverse') ctB = inverseCoordinate(ctA);
  if (mode === 'fresh') {
    const other = await crypto.subtle.generateKey('X25519', true, ['deriveBits']) as CryptoKeyPair;
    ctB = new Uint8Array(await crypto.subtle.exportKey('raw', other.publicKey));
  }
  const secretA = await rawDh(recipient.privateKey, ctA), secretB = await rawDh(recipient.privateKey, ctB);
  const senderSecret = await rawDh(ephemeral.privateKey, pk);
  const unboundA = await contextKdf(secretA, ctA, pk, false), unboundB = await contextKdf(secretB, ctB, pk, false);
  const boundA = await contextKdf(secretA, ctA, pk, true), boundB = await contextKdf(secretB, ctB, pk, true);
  return { pk, ctA, ctB, secretA, secretB, unboundA, unboundB, boundA, boundB,
    agreement: hex(senderSecret) === hex(secretA), distinct: hex(ctA) !== hex(ctB),
    rawEqual: hex(secretA) === hex(secretB), unboundEqual: hex(unboundA) === hex(unboundB), boundEqual: hex(boundA) === hex(boundB) };
}
