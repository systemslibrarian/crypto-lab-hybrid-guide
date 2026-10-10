import { expect, test, type Page } from '@playwright/test';

/**
 * Verdict regression gate.
 *
 * The security headline and the attacker-uncertainty meter used to be selected
 * from the two "broken" checkboxes (remainingBits = unbroken * 256, headline
 * chosen by an if-chain over the flags). They are now produced by actually
 * running a key-recovery attack: the session encrypts a record under the
 * derived key with AES-256-GCM, the attacker is handed only the broken halves'
 * secrets, derives candidate keys with the real combiner, and tries to decrypt.
 *
 * These tests assert the page reports what that attack did — including the
 * negative case, where the attack must genuinely succeed and print the
 * recovered plaintext.
 */

const RECORD_PLAINTEXT = 'hybrid session record';

const chip = (page: Page) => page.locator('#verdict-chip');
const detail = (page: Page) => page.locator('#verdict-detail');
const meter = (page: Page) => page.locator('#entropy-val');
const recovery = (page: Page) => page.locator('#recovery-line');
const bitcount = (page: Page) => page.locator('#bitgrid-count');

test.beforeEach(async ({ page }) => {
  await page.goto('.');
  await expect(chip(page)).toHaveText('Not recovered in this run');
});

test('both halves intact: the attack runs and fails, meter shows withheld bytes and bounded key width', async ({
  page,
}) => {
  await expect(chip(page)).toHaveText('Not recovered in this run');
  await expect(chip(page)).toHaveClass(/vs-chip--ok/);
  await expect(meter(page)).toHaveText('64 input bytes withheld · key-space cap 256 bits');
  await expect(bitcount(page)).toHaveText(/64 \/ 64 input bytes withheld/);
  // Proof the attempts happened rather than being skipped.
  await expect(recovery(page)).toHaveText(/attacker: \d+ derivations · 0 decrypted the record/);
  await expect(detail(page)).toContainText('0 decrypted the record');
  await expect(detail(page)).not.toContainText(RECORD_PLAINTEXT);
});

test('classical broken: PQ-holds verdict comes from a failed finite guess, not a security claim', async ({
  page,
}) => {
  await page.locator('#break-classical').check();
  await expect(chip(page)).toHaveText('Not recovered in this run');
  await expect(chip(page)).toHaveClass(/vs-chip--ok/);
  await expect(meter(page)).toHaveText('32 input bytes withheld · key-space cap 256 bits');
  await expect(recovery(page)).toHaveText(/0 decrypted the record/);
  await expect(page.locator('#entropy-track')).toHaveAttribute('aria-valuenow', '32');
});

test('PQ broken: classical-holds verdict comes from a failed decryption', async ({ page }) => {
  await page.locator('#break-pq').check();
  await expect(chip(page)).toHaveText('Not recovered in this run');
  await expect(meter(page)).toHaveText('32 input bytes withheld · key-space cap 256 bits');
  await expect(recovery(page)).toHaveText(/0 decrypted the record/);
});

// The negative verdict. This must be reachable and must be reached by the
// attack actually working: the page can only print the plaintext if the
// attacker's derived key opened the AES-GCM record.
test('both halves broken: the attack SUCCEEDS and the page prints the recovered plaintext', async ({
  page,
}) => {
  await page.locator('#break-classical').check();
  await page.locator('#break-pq').check();
  await expect(chip(page)).toHaveText('Record recovered');
  await expect(chip(page)).toHaveClass(/vs-chip--bad/);
  await expect(meter(page)).toHaveText('0 input bytes withheld · key-space cap 256 bits');
  await expect(bitcount(page)).toHaveText(/0 \/ 64 input bytes withheld/);
  await expect(recovery(page)).toHaveText(/record decrypted · best key match 32\/32 bytes/);
  await expect(detail(page)).toContainText(RECORD_PLAINTEXT);
});

test('the worst-case preset reaches the same computed negative verdict', async ({ page }) => {
  await page.locator('.preset-button[data-scenario="break-both"]').click();
  await expect(chip(page)).toHaveText('Record recovered');
  await expect(recovery(page)).toHaveText(/record decrypted/);
  // And recovering from it restores the computed positive verdict.
  await page.locator('.preset-button[data-scenario="both-ok"]').click();
  await expect(chip(page)).toHaveText('Not recovered in this run');
  await expect(recovery(page)).toHaveText(/0 decrypted the record/);
});

test('the naive combiner reaches both verdicts through the same real attack', async ({ page }) => {
  await page.locator('#combiner').selectOption('naive');
  await expect(chip(page)).toHaveText('Not recovered in this run');
  await expect(recovery(page)).toHaveText(/0 decrypted the record/);
  await page.locator('#break-classical').check();
  await page.locator('#break-pq').check();
  await expect(chip(page)).toHaveText('Record recovered');
  await expect(detail(page)).toContainText(RECORD_PLAINTEXT);
});

test('a new session re-runs the attack rather than reusing the last verdict', async ({ page }) => {
  await page.locator('#break-classical').check();
  await page.locator('#break-pq').check();
  await expect(chip(page)).toHaveText('Record recovered');
  const keyBefore = await page.locator('#session-key').textContent();
  await page.locator('#regen').click();
  await expect(page.locator('#session-key')).not.toHaveText(keyBefore ?? '');
  // Still broken, but only because the attack was run again on the new secrets.
  await expect(chip(page)).toHaveText('Record recovered');
  await expect(recovery(page)).toHaveText(/record decrypted/);
});

test('the transcript-binding experiment states its premise and computed result', async ({ page }) => {
  await page.locator('#combiner').selectOption('naive');
  await page.locator('#run-attack').click();
  await expect(page.locator('#attack-result')).toContainText('Keys match in this experiment');
  await page.locator('#combiner').selectOption('xwing');
  await page.locator('#run-attack').click();
  await expect(page.locator('#attack-result')).toContainText('Keys differ in this experiment');
});

for (const width of [1280, 380]) {
  test(`input bytes, output bound and transcript premise remain distinct at width ${width}`, async ({ page }) => {
    await page.setViewportSize({ width, height: 900 });
    await page.locator('#regen').click();
    await expect(page.locator('#session-key')).toHaveText(/^[0-9a-f]{64}$/);
    await expect(meter(page)).toHaveText('64 input bytes withheld · key-space cap 256 bits');
    await expect(page.locator('#entropy-track')).toHaveAttribute('aria-valuemax', '64');
    await expect(detail(page)).toContainText('finite failed guesses do not measure security strength');
    await expect(detail(page)).toContainText('32 bytes');
    await expect(detail(page)).toContainText('128-bit classical');
    await expect(page.locator('.attack-intro')).toContainText('assume two runs have equal simulated component');
    await page.locator('#run-attack').click();
    await expect(page.locator('#attack-result')).toContainText('Keys differ in this experiment');
    await expect(page.locator('#attack-result')).toContainText('not an IND-CCA');
    await page.locator('#combiner').selectOption('naive');
    await page.locator('#run-attack').click();
    await expect(page.locator('#attack-result')).toContainText('Keys match in this experiment');
    await expect(page.locator('#attack-result')).toContainText('Equal secrets were supplied deliberately');
    const overflow = await page.evaluate(() => document.documentElement.scrollWidth > innerWidth + 1);
    expect(overflow).toBe(false);
  });
}
