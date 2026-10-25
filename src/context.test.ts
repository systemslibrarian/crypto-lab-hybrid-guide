import { expect, test } from 'vitest';
import { FIELD, contextKdf, decode, fromHex, hex, inverseCoordinate, rawDh, runContext } from './context';

test('native X25519 reproduces RFC 7748 §6.1 and the inverse-coordinate collision', async () => {
  const pkcs8 = fromHex('302e020100300506032b656e0422042077076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a');
  const key = await crypto.subtle.importKey('pkcs8', pkcs8, 'X25519', false, ['deriveBits']);
  const bob = fromHex('de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f');
  const expected = '4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742';
  expect(hex(await rawDh(key, bob))).toBe(expected);
  const inverse = inverseCoordinate(bob);
  expect(hex(inverse)).not.toBe(hex(bob));
  expect(decode(bob) * decode(inverse) % FIELD).toBe(1n);
  expect(hex(await rawDh(key, inverse))).toBe(expected);
  await expect(rawDh(key, new Uint8Array(32))).rejects.toThrow();
});
for (const mode of ['same', 'inverse', 'fresh'] as const) test(`computed raw and KDF equality for ${mode}`, async () => {
  const r = await runContext(mode);
  expect(r.agreement).toBe(true);
  expect(r.distinct).toBe(mode !== 'same');
  expect(r.rawEqual).toBe(mode !== 'fresh');
  expect(r.unboundEqual).toBe(mode !== 'fresh');
  expect(r.boundEqual).toBe(mode === 'same');
});
test('recipient public context is bound too; inversion rejects zero', async () => {
  const secret = new Uint8Array(32).fill(7), ct = new Uint8Array(32).fill(8);
  const pk = new Uint8Array(32).fill(9), different = pk.slice(); different[0] ^= 1;
  expect(await contextKdf(secret, ct, pk, true)).not.toEqual(await contextKdf(secret, ct, different, true));
  expect(() => inverseCoordinate(new Uint8Array(32))).toThrow('zero');
});
