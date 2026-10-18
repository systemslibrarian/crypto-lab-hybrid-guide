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
