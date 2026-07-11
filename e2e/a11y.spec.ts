import AxeBuilder from '@axe-core/playwright';
import { expect, test, type Page } from '@playwright/test';

/**
 * WCAG regression gate. Deploys are gated on the engine unit tests; this gates
 * them on accessibility the same way. Scans the full page in both themes with
 * every collapsible / hidden region revealed and animations neutralized.
 *
 * Collapsibles here: two <details> (the "why hybrid" note and the Web Crypto
 * snippet panel), a [hidden] re-encapsulation attack result, and the
 * .reveal sections that fade in on scroll (opacity animation). We open every
 * <details>, drop [hidden], force .reveal → .is-visible, and neutralize
 * animation/transition/opacity so nothing is scanned mid-flight.
 */

const TAGS = ['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa'];

async function neutralizeMotion(page: Page): Promise<void> {
  await page.addStyleTag({
    content:
      '*, *::before, *::after { animation: none !important; transition: none !important; }\n' +
      '.reveal, .reveal.is-visible { opacity: 1 !important; transform: none !important; }',
  });
}

async function revealAll(page: Page): Promise<void> {
  await page.evaluate(() => {
    for (const details of document.querySelectorAll('details')) {
      (details as HTMLDetailsElement).open = true;
    }
    // Reveal-on-scroll sections start hidden until the observer fires.
    for (const el of document.querySelectorAll('.reveal')) {
      el.classList.add('is-visible');
    }
    // Drop the [hidden] attack-result panel so its contents are scanned.
    for (const el of document.querySelectorAll<HTMLElement>('[hidden]')) {
      el.hidden = false;
      el.removeAttribute('hidden');
    }
    // Any inline display:none regions.
    for (const el of document.querySelectorAll<HTMLElement>('[style*="display"]')) {
      if (el.style && el.style.display === 'none') el.style.display = '';
    }
  });
}

async function scan(page: Page): Promise<void> {
  const results = await new AxeBuilder({ page }).withTags(TAGS).analyze();
  const summary = results.violations.map((v) => ({
    id: v.id,
    impact: v.impact,
    help: v.help,
    nodes: v.nodes.map((n) => n.target.join(' ')).slice(0, 5),
  }));
  expect(summary).toEqual([]);
}

async function runSuite(page: Page): Promise<void> {
  await revealAll(page);
  await neutralizeMotion(page);
  await scan(page);
}

test('no WCAG A/AA violations in dark theme', async ({ page }) => {
  await page.goto('.');
  await expect(page.locator('html')).toHaveAttribute('data-theme', 'dark');
  await runSuite(page);
});

test('no WCAG A/AA violations in light theme', async ({ page }) => {
  await page.goto('.');
  await page.locator('#cl-theme-toggle').click();
  await expect(page.locator('html')).toHaveAttribute('data-theme', 'light');
  await runSuite(page);
});
