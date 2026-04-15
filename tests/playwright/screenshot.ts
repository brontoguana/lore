import { chromium } from 'playwright';

(async () => {
  const browser = await chromium.launch();
  const page = await browser.newPage({ viewport: { width: 1280, height: 800 } });
  const baseURL = process.env.LORE_URL || 'http://127.0.0.1:39669';

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

  await page.goto(`${baseURL}/ui`);
  await page.waitForTimeout(500);
  await page.screenshot({ path: '/tmp/projects-page.png', fullPage: true });
  console.log('Screenshot saved');
  await browser.close();
})();
