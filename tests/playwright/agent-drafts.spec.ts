import { test, expect } from '@playwright/test';
import { startMockLlm, MockLlmServer } from './helpers/mock-llm';
import {
  login,
  newAdminClient,
  openAgentChat,
  startAgentLoop,
  AgentLoop,
} from './helpers/lore';

let mock: MockLlmServer;

test.describe('Agent drafts', () => {
  let loops: AgentLoop[] = [];

  function uniq(prefix: string): string {
    return `${prefix}${Math.random().toString(36).slice(2, 8)}`;
  }

  test.beforeAll(async () => {
    mock = await startMockLlm();
  });

  test.afterAll(async () => {
    await mock.stop();
  });

  test.afterEach(async () => {
    await Promise.all(loops.map((loop) => loop.stop()));
    loops = [];
  });

  test('composer drafts persist per agent across switches', async ({ page, baseURL }) => {
    const admin = await newAdminClient(baseURL!);
    await login(page);

    const ep = await admin.createEndpoint({ name: uniq('ep'), url: mock.completionsUrl, kind: 'openai' });
    const projA = await admin.createProject(uniq('proj'));
    const projB = await admin.createProject(uniq('proj'));
    const agentA = await admin.createAgentToken({ name: uniq('agt'), projectSlug: projA.slug, endpointId: ep.id });
    const agentB = await admin.createAgentToken({ name: uniq('agt'), projectSlug: projB.slug, endpointId: ep.id });
    loops.push(startAgentLoop(baseURL!, agentA.token));
    loops.push(startAgentLoop(baseURL!, agentB.token));

    await openAgentChat(page, agentA.name);
    await page.locator('#chat-input').fill('draft for agent A');

    await page.click(`.chat-agent-item[data-agent="${agentB.name}"]`);
    await expect(page.locator('.chat-header-name').first()).toContainText(agentB.name);
    await expect(page.locator('#chat-input')).toHaveValue('');
    await page.locator('#chat-input').fill('draft for agent B');

    await page.click(`.chat-agent-item[data-agent="${agentA.name}"]`);
    await expect(page.locator('.chat-header-name').first()).toContainText(agentA.name);
    await expect(page.locator('#chat-input')).toHaveValue('draft for agent A');

    await page.click(`.chat-agent-item[data-agent="${agentB.name}"]`);
    await expect(page.locator('#chat-input')).toHaveValue('draft for agent B');

    await page.reload();
    await page.waitForSelector('#chat-messages', { state: 'visible' });
    await expect(page.locator('#chat-input')).toHaveValue('draft for agent B');
  });
});
