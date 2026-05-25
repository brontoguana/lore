import { test, expect } from '@playwright/test';
import { startMockLlm, MockLlmServer } from './helpers/mock-llm';
import {
  attachPageHealthChecks,
  login,
  newAdminClient,
  AdminClient,
  openAgentChat,
  sendChatMessage,
  waitForAssistantReply,
  startAgentLoop,
  AgentLoop,
} from './helpers/lore';

let mock: MockLlmServer;
let admin: AdminClient;

test.beforeAll(async ({ baseURL }) => {
  mock = await startMockLlm();
  admin = await newAdminClient(baseURL!);
});

test.afterAll(async () => {
  await mock.stop();
});

function uniq(prefix: string): string {
  return `${prefix}${Math.random().toString(36).slice(2, 8)}`;
}

async function setupAgent(baseURL: string): Promise<{ agentName: string; loop: AgentLoop }> {
  const ep = await admin.createEndpoint({ name: uniq('ep'), url: mock.completionsUrl, kind: 'openai' });
  const proj = await admin.createProject(uniq('proj'));
  const agent = await admin.createAgentToken({ name: uniq('agt'), projectSlug: proj.slug, endpointId: ep.id });
  const loop = startAgentLoop(baseURL, agent.token);
  return { agentName: agent.name, loop };
}

test.describe('Chat smoke', () => {
  test('chat page boots cleanly and renders sent and received messages', async ({ page, baseURL }) => {
    const health = attachPageHealthChecks(page);
    await login(page);
    mock.clear();
    mock.queue({ text: 'Smoke reply from mock agent' });

    const { agentName, loop } = await setupAgent(baseURL!);
    try {
      await openAgentChat(page, agentName);
      const agentRow = page.locator(`#chat-agent-list .chat-agent-item[data-agent="${agentName}"]`);

      await expect(page.locator('#chat-agent-list')).toBeVisible();
      await expect(page.locator('#chat-messages')).toBeVisible();
      await expect(page.locator('#chat-input')).toBeVisible();
      await expect(page.locator('.chat-send-btn')).toBeVisible();

      await sendChatMessage(page, 'smoke ping');
      const reply = await waitForAssistantReply(page);
      expect(reply).toContain('Smoke reply from mock agent');

      await expect(agentRow).toContainText('Smoke reply from mock agent');

      await page.reload();
      await page.waitForSelector('#chat-messages .chat-msg-user');
      await expect(page.locator('#chat-messages .chat-msg-user').last()).toContainText('smoke ping');
      await expect(page.locator('#chat-messages .chat-msg-assistant').last()).toContainText('Smoke reply from mock agent');
      await expect(agentRow).toContainText('Smoke reply from mock agent');

      expect(health.errors()).toEqual([]);
    } finally {
      await loop.stop();
    }
  });

  test('chat markdown keeps ordered list numbering across item body text', async ({ page, baseURL }) => {
    const health = attachPageHealthChecks(page);
    await login(page);
    mock.clear();
    mock.queue({
      text: '1. First item\nDetail for first item.\n1. Second item\nDetail for second item.\n1. Third item',
    });

    const { agentName, loop } = await setupAgent(baseURL!);
    try {
      await openAgentChat(page, agentName);
      await sendChatMessage(page, 'numbered list please');
      await waitForAssistantReply(page);

      const assistant = page.locator('#chat-messages .chat-msg-assistant').last();
      await expect(assistant.locator('ol')).toHaveCount(1);
      await expect(assistant.locator('ol > li')).toHaveCount(3);
      await expect(assistant.locator('ol > li').nth(0)).toContainText('Detail for first item.');
      await expect(assistant.locator('ol > li').nth(1)).toContainText('Second item');

      expect(health.errors()).toEqual([]);
    } finally {
      await loop.stop();
    }
  });
});
