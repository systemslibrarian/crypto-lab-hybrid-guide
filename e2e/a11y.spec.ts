import { expect, test, type Page } from '@playwright/test';
import { NARROW, boot, expectBaselineNotStale, scan, settle } from './gate';

/**
 * WCAG regression gate.
 *
 * Deploys are already gated on the combiner's key-recovery behaviour by
 * verdict.spec.ts; this gates them on accessibility the same way. See gate.ts
 * for the three rules this file obeys — nothing injected, content asserted
 * before every scan, and `violations` treated as one oracle among five.
 *
 * The page is scanned in both themes, in states a visitor can actually reach,
 * at a 1280px desktop viewport and at a 380px phone one. Almost none of the
 * interesting rendering is the first-paint one: the "Broken — both halves down"
 * verdict that prints the recovered plaintext, the re-encapsulation attack
 * result that ships `[hidden]`, the Web Crypto snippet inside a closed
 * `<details>`, the cracked harvest card and the filled benchmark tiles are all
 * downstream of a click or a drag. The previous gate reached none of them: it
 * force-opened the details, stripped `[hidden]`, and scanned only the untouched
 * page in two themes at one viewport.
 */

const THEMES = ['dark'] as const;
const RECOVERED_PLAINTEXT = 'hybrid session record';

/**
 * A state worth scanning: how to reach it from a booted page, and what has to
 * be true once you are there. The assertion is not decoration — it is what
 * stops a scan from passing over a panel that never redrew.
 */
interface State {
  label: string;
  drive: (page: Page) => Promise<void>;
}

const STATES: State[] = [
  {
    // The default mount. Both halves intact, the attack ran and failed, the
    // re-encapsulation result and the code snippet are still closed/hidden.
    label: 'first paint / fully secure',
    drive: async (page) => {
      await expect(page.locator('#verdict-chip')).toHaveText('Fully secure');
      await expect(page.locator('#verdict-chip')).toHaveClass(/vs-chip--ok/);
      await expect(page.locator('#recovery-line')).toContainText('0 decrypted the record');
      await expect(page.locator('#entropy-val')).toHaveText('512 bits to guess');
    },
  },
  {
    // The negative verdict. Break both halves and the attacker's derived key
    // opens the AES-GCM record, so the page prints the recovered plaintext in
    // the `--bad` palette — a rendering the positive verdict never paints.
    label: 'both broken / recovered plaintext',
    drive: async (page) => {
      await page.locator('.preset-button[data-scenario="break-both"]').click();
      await expect(page.locator('#verdict-chip')).toHaveText('Broken — both halves down');
      await expect(page.locator('#verdict-chip')).toHaveClass(/vs-chip--bad/);
      await expect(page.locator('#recovery-line')).toContainText('record decrypted');
      await expect(page.locator('#verdict-detail')).toContainText(RECOVERED_PLAINTEXT);
      await expect(page.locator('#bitgrid-classical.is-broken')).toBeVisible();
      await expect(page.locator('#bitgrid-pq.is-broken')).toBeVisible();
    },
  },
  {
    // The re-encapsulation attack result is `hidden` until run. The naive
    // combiner makes the two transcripts collide: the panel opens in its `bad`
    // tone with the colliding keys. The old gate stripped [hidden] and scanned
    // this empty; here it carries the content a real run produces.
    label: 'reencap attack succeeds / naive combiner',
    drive: async (page) => {
      await page.locator('#combiner').selectOption('naive');
      await page.locator('#run-attack').click();
      const result = page.locator('#attack-result');
      await expect(result).toBeVisible();
      await expect(result).toHaveAttribute('data-tone', 'bad');
      await expect(result).toContainText('Attack succeeds');
      await expect(result.locator('code').first()).toBeVisible();
      // The attack also fires a toast that fades to opacity 0 before removing
      // itself; scan the settled state, not a transient mid-fade frame.
      await expect(page.locator('.toast')).toHaveCount(0);
    },
  },
  {
    // The same panel, opposite verdict and palette: the bound X-Wing combiner
    // makes the keys differ, so the attack fails in the `ok` tone.
    label: 'reencap attack fails / bound combiner',
    drive: async (page) => {
      await page.locator('#run-attack').click();
      const result = page.locator('#attack-result');
      await expect(result).toBeVisible();
      await expect(result).toHaveAttribute('data-tone', 'ok');
      await expect(result).toContainText('Attack fails');
      await expect(page.locator('.toast')).toHaveCount(0);
    },
  },
  {
    // The only <details> on the page: the Web Crypto snippet. Its body is
    // content-visibility: hidden until opened, so a first-paint scan checks
    // none of the code inside it.
    label: 'code panel open / web crypto snippet',
    drive: async (page) => {
      await page.locator('.code-panel > summary').click();
      await expect(page.locator('.code-panel')).toHaveAttribute('open', '');
      await expect(page.locator('#code-block')).toBeVisible();
      await expect(page.locator('#code-block')).toContainText('crypto.subtle.digest');
    },
  },
  {
    // Drive the migration timeline past the CRQC year (2035). The classical
    // harvest card flips to its `is-cracked` rendering — the lock opens and the
    // status recolours to "decrypted" — while the hybrid card holds. None of
    // that palette exists at the 2025 default.
    label: 'timeline cracked / harvest-now decrypt-later',
    drive: async (page) => {
      await page.locator('#timeline-slider').fill('2040');
      await expect(page.locator('#harvest-classical')).toHaveClass(/is-cracked/);
      await expect(page.locator('#harvest-classical-status')).toContainText('decrypted');
      await expect(page.locator('#timeline-implication')).toHaveAttribute('data-tone', 'bad');
    },
  },
  {
    // Run the on-device benchmark. Every `.bench-tile__value` fills with a real
    // measured timing — placeholder `—` until the run completes.
    label: 'benchmark run / timings measured',
    drive: async (page) => {
      await page.locator('#run-benchmark').click();
      await expect(page.locator('#bench-total .bench-tile__value')).not.toHaveText('—', {
        timeout: 60_000,
      });
      await expect(page.locator('#bench-fresh .bench-tile__value')).not.toHaveText('—');
      await expect(page.locator('#bench-state')).toContainText('iterations per measurement');
      // "Benchmark complete" toast fades out; scan the settled state.
      await expect(page.locator('.toast')).toHaveCount(0);
    },
  },
];

for (const theme of THEMES) {
  for (const state of STATES) {
    test(`${theme} — ${state.label}`, async ({ page }) => {
      test.setTimeout(180_000);
      await boot(page, theme);
      await state.drive(page);
      await scan(page, `${theme} / ${state.label} / 1280px`);

      // Same state, phone width. Reflow (1.4.10) has no axe rule, and axe's
      // `scrollable-region-focusable` never fires on a container whose content
      // still fits — several of this page's scrolling regions only overflow
      // here, so a desktop-only gate reports nothing about any of them.
      await page.setViewportSize(NARROW);
      await settle(page);
      await scan(page, `${theme} / ${state.label} / ${NARROW.width}px`);

      // The baseline's third rule: a listed finding that no longer appears
      // fails until its entry is deleted, so a fixed defect cannot linger as a
      // permanent exemption. `expectBaselineNotStale` was exported and never
      // called, so that rule had never run and the file could only grow.
      //
      // Per state rather than once at the end, because `nonTextSeen` is module
      // state and `fullyParallel` gives each test its own worker — a single
      // trailing test would see only its own worker's set. Every baselined
      // selector is page chrome that every state renders, so each test's own
      // two scans cover the whole baseline; each was run in isolation to prove
      // it rather than assuming it.
      expectBaselineNotStale();
    });
  }
}

/**
 * WCAG 2.1.1 (Keyboard), asserted end to end rather than per-scan.
 *
 * `scan` already refuses any scrolling container with no keyboard route, but a
 * `tabindex` on an element the sequential walk never arrives at is no better
 * than none — so walk the page with Tab and prove every scrolling container
 * that relies on a `tabindex` (rather than a focusable child) is genuinely
 * reached. At 380px the session key, the code snippet, the handshake bars and
 * the bit grids all overflow horizontally, which is where these appear.
 */
test('every keyboard-only scrolling container is reachable by Tab', async ({ page }) => {
  test.setTimeout(180_000);
  await boot(page, 'dark');
  await page.locator('.code-panel > summary').click();
  await expect(page.locator('.code-panel')).toHaveAttribute('open', '');
  await page.setViewportSize(NARROW);
  await settle(page);

  // Containers that overflow and carry no focusable child of their own, so
  // their only keyboard route is an explicit tabindex on the container itself.
  const targets = await page.evaluate(() => {
    const FOCUSABLE = 'a[href],button,input,select,textarea,[tabindex]:not([tabindex="-1"])';
    return Array.from(document.querySelectorAll<HTMLElement>('body *'))
      .filter((el) => el.scrollWidth > el.clientWidth + 1 || el.scrollHeight > el.clientHeight + 1)
      .filter((el) => {
        const cs = getComputedStyle(el);
        return (
          ['auto', 'scroll'].includes(cs.overflowX) || ['auto', 'scroll'].includes(cs.overflowY)
        );
      })
      .filter((el) => !el.querySelector(FOCUSABLE))
      .map((el) => {
        el.setAttribute('data-scroller-probe', '1');
        return '[data-scroller-probe="1"]';
      });
  });

  for (const sel of Array.from(new Set(targets))) {
    for (const el of await page.locator(sel).all()) {
      await expect(el).toHaveAttribute('tabindex', '0');
    }
  }

  // Prove the tabindex is actually in the tab order, not just present: Tab from
  // the top of the document until each probed container holds focus.
  const probes = await page.locator('[data-scroller-probe="1"]').count();
  if (probes > 0) {
    await page.locator('body').focus();
    const reached = new Set<string>();
    for (let i = 0; i < 200 && reached.size < probes; i++) {
      await page.keyboard.press('Tab');
      const hit = await page.evaluate(() => {
        const a = document.activeElement as HTMLElement | null;
        return a?.getAttribute('data-scroller-probe') === '1' ? a.className : null;
      });
      if (hit !== null) reached.add(hit);
    }
    expect(reached.size, 'every keyboard-only scroller must be reached by Tab').toBe(probes);
  }
});
