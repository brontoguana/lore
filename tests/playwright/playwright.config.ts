import { defineConfig } from '@playwright/test';

export default defineConfig({
  testDir: '.',
  timeout: 30000,
  retries: 0,
  use: {
    headless: true,
    baseURL: process.env.LORE_URL || 'http://127.0.0.1:7043',
  },
  projects: [
    { name: 'chromium', use: { browserName: 'chromium' } },
  ],
});
