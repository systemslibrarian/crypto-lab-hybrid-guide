import { expect, test } from '@playwright/test';

test('native X25519 collision survives secret-only derivation but not transcript binding', async ({ page }) => {
  await page.goto('.');
  await expect(page.locator('#context-case')).toHaveValue('same');
  for (const mode of ['same', 'inverse', 'fresh']) {
    await page.selectOption('#context-case', mode);
    await page.click('#context-run');
    await expect(page.locator('#context-output')).toBeVisible();
    expect(await page.locator('#context-rows td').allTextContents()).toEqual([
      'YES', mode === 'same' ? 'NO' : 'YES', mode === 'fresh' ? 'NO' : 'YES', mode === 'fresh' ? 'NO' : 'YES', mode === 'same' ? 'YES' : 'NO',
    ]);
    const raw = (await page.locator('#context-bytes').textContent())!;
    const read = (key: string) => raw.split('\n').find(s => s.startsWith(key + ': '))!.slice(key.length + 2);
    for (const key of ['ctA','ctB','secretA','secretB','unboundA','unboundB','boundA','boundB']) expect(read(key)).toMatch(/^[a-f0-9]{64}$/);
    expect(read('secretA') === read('secretB')).toBe(mode !== 'fresh');
    expect(read('unboundA') === read('unboundB')).toBe(mode !== 'fresh');
    expect(read('boundA') === read('boundB')).toBe(mode === 'same');
    if (mode === 'inverse') {
      const little = (h: string) => BigInt('0x' + h.match(/../g)!.reverse().join(''));
      expect(little(read('ctA')) * little(read('ctB')) % ((1n << 255n) - 19n)).toBe(1n);
      await expect(page.locator('#context-status')).toContainText('BINDING COUNTEREXAMPLE');
    }
    await page.locator('#context-case').dispatchEvent('change');
    await expect(page.locator('#context-output')).toBeVisible();
  }
  await page.selectOption('#context-case', 'same');
  await expect(page.locator('#context-output')).toBeHidden();
  await expect(page.locator('#context-status')).toContainText('retired');
  await expect(page.locator('#real-context')).toContainText('executes no ML-KEM');
  await expect(page.locator('#real-context')).toContainText('not recover the recipient');
});
