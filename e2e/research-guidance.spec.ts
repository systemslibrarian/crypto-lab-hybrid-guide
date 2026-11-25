import { test, expect } from '@playwright/test';

test('PQ guidance stays accurate as the reader changes the timeline', async ({ page }) => {
  await page.goto('./');
  const note = page.locator('#pqc-guidance-note');
  await expect(note).toContainText('both hybrid and pure-PQ');
  await expect(note.locator('a')).toHaveAttribute('href', 'https://www.ncsc.gov.uk/blogs/post-quantum-updates-to-our-tls-guidance');
  await expect(note).toContainText('authentication guidance is separate');
  for (const year of ['2026', '2035', '2040']) {
    await page.getByRole('button', { name: new RegExp(`^Jump to ${year}:`) }).click();
    await expect(page.locator('#timeline-year')).toHaveText(year);
    await expect(page.locator('#timeline-detail')).toContainText(/pure-PQ/i);
    if (year !== '2026') await expect(page.locator('#timeline-detail')).toContainText(/assumption/i);
  }
  await expect(page.locator('#timeline-implication')).toContainText('hybrid or pure-PQ');
  await expect(page.locator('body')).not.toContainText('survives only if it used a hybrid');
});

test('a failed benchmark clears all earlier timings and a retry measures again', async ({ page }) => {
  await page.goto('./');
  const run = page.locator('#run-benchmark');
  const state = page.locator('#bench-state');
  const meters = page.locator('.bench-tile__value');
  await expect(page.locator('#bench-total')).toContainText('Sum of the separately measured averages');
  await run.click();
  await expect(state).toContainText('iterations per measurement');
  await expect(meters).toHaveCount(4);
  for (const meter of await meters.all()) await expect(meter).toHaveText(/\d/);
  await page.evaluate(() => {
    const digest = crypto.subtle.digest.bind(crypto.subtle);
    crypto.subtle.digest = () => {
      crypto.subtle.digest = digest;
      return Promise.reject(new Error('digest unavailable for this measurement'));
    };
  });
  await run.click();
  await expect(state).toContainText('Benchmark failed');
  await expect(meters).toHaveText(['—', '—', '—', '—']);
  await run.click();
  await expect(state).toContainText('iterations per measurement');
  for (const meter of await meters.all()) await expect(meter).toHaveText(/\d/);
});
