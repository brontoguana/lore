const { chromium } = require('playwright');

(async () => {
  const browser = await chromium.launch();
  const baseURL = 'http://127.0.0.1:9876';

  const page = await browser.newPage({ viewport: { width: 1280, height: 800 } });
  await page.goto(`${baseURL}/login`);
  await page.fill('input[name="username"]', 'admin');
  await page.fill('input[name="password"]', 'correct-horse-battery');
  await page.click('button[type="submit"]');
  await page.waitForURL(/\/ui/);

  for (const name of ['Alpha Project', 'Beta Project', 'Gamma Docs']) {
    await page.click('text=New project');
    await page.fill('input[name="project_name"]', name);
    await page.click('.tree-create-row button[type="submit"]');
    await page.waitForURL(/\/ui\/[a-z]/);
    await page.goto(`${baseURL}/ui`);
  }

  const addDocBtn = page.locator('.tree-node[data-slug="alpha-project"] .tree-add-child').first();
  await addDocBtn.click();
  await page.fill('input[name="name"]', 'Getting Started');
  await page.click('.tree-doc-inline-create button[type="submit"]');
  await page.waitForTimeout(500);
  await page.goto(`${baseURL}/ui`);
  await page.waitForTimeout(500);

  const expand = page.locator('.tree-node[data-slug="alpha-project"] .tree-expand-btn').first();
  if (await expand.isVisible()) {
    await expand.click();
    await page.waitForTimeout(300);
  }

  await page.screenshot({ path: '/tmp/tree-desktop.png', fullPage: true });
  console.log('Desktop saved');

  const mobile = await browser.newPage({ viewport: { width: 375, height: 812 } });
  await mobile.goto(`${baseURL}/login`);
  await mobile.fill('input[name="username"]', 'admin');
  await mobile.fill('input[name="password"]', 'correct-horse-battery');
  await mobile.click('button[type="submit"]');
  await mobile.waitForURL(/\/ui/);

  const mExpand = mobile.locator('.tree-node[data-slug="alpha-project"] .tree-expand-btn').first();
  if (await mExpand.isVisible()) {
    await mExpand.click();
    await mobile.waitForTimeout(300);
  }

  await mobile.screenshot({ path: '/tmp/tree-mobile.png', fullPage: true });
  console.log('Mobile saved');

  await browser.close();
})();
