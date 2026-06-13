import { test, expect } from '@playwright/test';
import { startMockLlm, MockLlmServer } from './helpers/mock-llm';
import {
  login, newAdminClient, AdminClient,
  openAgentChat, sendChatMessage, waitForAssistantReply,
  countAssistantBubbles, countToolBubbles,
  startAgentLoop, AgentLoop,
  configureManager, getManagerStatus,
} from './helpers/lore';
import { execSync } from 'node:child_process';

let mock: MockLlmServer;
let admin: AdminClient;

test.beforeAll(async ({ baseURL }) => {
  mock = await startMockLlm();
  admin = await newAdminClient(baseURL!);
});

test.afterAll(async () => {
  await mock.stop();
});

test.describe('Agent flow', () => {
  // Fresh agent/endpoint per test so they don't share state.
  function uniq(prefix: string): string {
    return `${prefix}${Math.random().toString(36).slice(2, 8)}`;
  }

  async function setupAgent(page: any, baseURL: string, opts: { agentName?: string; endpointName?: string } = {}): Promise<{ agentName: string; endpointId: string; loop: AgentLoop }> {
    const agentName = opts.agentName ?? uniq('agt');
    const endpointName = opts.endpointName ?? uniq('ep');
    const ep = await admin.createEndpoint({ name: endpointName, url: mock.completionsUrl, kind: 'openai' });
    const proj = await admin.createProject(uniq('proj'));
    const agent = await admin.createAgentToken({ name: agentName, projectSlug: proj.slug, endpointId: ep.id });
    const loop = startAgentLoop(baseURL, agent.token);
    return { agentName: agent.name, endpointId: ep.id, loop };
  }

  test('1. happy path: send message, receive reply, persists', async ({ page, baseURL }) => {
    await login(page);
    mock.clear();
    mock.queue({ text: 'Hello from mock-1' });

    const { agentName, loop } = await setupAgent(page, baseURL!);
    try {
      await openAgentChat(page, agentName);
      await sendChatMessage(page, 'ping');
      const reply = await waitForAssistantReply(page);
      expect(reply).toContain('Hello from mock-1');

      // Verify persistence: reload the page, bubble still present.
      await page.reload();
      await page.waitForSelector('#chat-messages .chat-msg-assistant');
      const afterReload = await page.locator('#chat-messages .chat-msg-assistant').last().innerText();
      expect(afterReload).toContain('Hello from mock-1');
    } finally {
      await loop.stop();
    }
  });

  test('2. tool-call bubbles persist across tab and agent switches', async ({ page, baseURL }) => {
    await login(page);
    mock.clear();
    // Agent A: tool call, then tool result, then final text.
    mock.queue([
      { tool: { name: 'list_projects', args: '{}' } },
      { text: 'done-A' },
    ]);
    const a = await setupAgent(page, baseURL!);
    try {
      await openAgentChat(page, a.agentName);
      await sendChatMessage(page, 'please list projects');
      await waitForAssistantReply(page);

      await page.waitForSelector('#chat-messages .chat-msg-tool', { timeout: 10_000 });
      const toolBefore = await countToolBubbles(page);
      expect(toolBefore).toBeGreaterThan(0);
      const toolText = await page.locator('#chat-messages .chat-msg-tool').first().innerText();
      expect(toolText).toContain('list_projects');

      // Set up agent B, switch away, send there, switch back.
      mock.queue({ text: 'hi from B' });
      const b = await setupAgent(page, baseURL!);
      try {
        await openAgentChat(page, b.agentName);
        await sendChatMessage(page, 'hi B');
        await waitForAssistantReply(page);

        // Navigate to Agents tab, then back to Chat for A.
        await page.click('nav >> text=Agents');
        await page.waitForURL(/\/ui\/agents/);
        await openAgentChat(page, a.agentName);
        await page.waitForSelector('#chat-messages .chat-msg-tool', { timeout: 10_000 });
        const toolAfter = await countToolBubbles(page);
        expect(toolAfter).toBe(toolBefore);
        const toolTextAfter = await page.locator('#chat-messages .chat-msg-tool').first().innerText();
        expect(toolTextAfter).toContain('list_projects');
      } finally {
        await b.loop.stop();
      }
    } finally {
      await a.loop.stop();
    }
  });

  test('7. backend switch mid-conversation routes to new endpoint', async ({ page, baseURL }) => {
    await login(page);
    mock.clear();
    // Shared mock LLM, but we create two endpoints (both point to it) and verify
    // that switching the agent's endpoint_id does preserve history and uses
    // the new selection for subsequent turns.
    const epA = await admin.createEndpoint({ name: uniq('ep-A'), url: mock.completionsUrl, kind: 'openai' });
    const epB = await admin.createEndpoint({ name: uniq('ep-B'), url: mock.completionsUrl, kind: 'openai' });
    const proj = await admin.createProject(uniq('proj'));
    const agent = await admin.createAgentToken({ name: uniq('agt'), projectSlug: proj.slug, endpointId: epA.id });
    const loop = startAgentLoop(baseURL!, agent.token);
    try {
      await openAgentChat(page, agent.name);

      mock.queue({ text: 'reply-from-A-1' });
      await sendChatMessage(page, 'first');
      await waitForAssistantReply(page);
      const firstReceived = mock.received.length;
      expect(firstReceived).toBeGreaterThanOrEqual(1);

      // Switch endpoint via the chat config panel.
      await page.click('#chat-config-btn');
      await page.waitForSelector('#cfg-backend', { state: 'visible' });
      await page.selectOption('#cfg-backend', `ep:${epB.id}`);
      // Wait for save to round-trip, then close the panel so the input re-appears.
      await page.waitForTimeout(400);
      await page.click('#chat-config-btn');
      await page.waitForSelector('#chat-input', { state: 'visible' });

      mock.queue({ text: 'reply-from-B-1' });
      await sendChatMessage(page, 'second');
      const reply = await waitForAssistantReply(page, { after: 1 });
      expect(reply).toContain('reply-from-B-1');
      expect(mock.received.length).toBeGreaterThan(firstReceived);

      // Verify the earlier A bubble is still rendered.
      const allAssistant = await page.locator('#chat-messages .chat-msg-assistant').allInnerTexts();
      expect(allAssistant.some((t) => t.includes('reply-from-A-1'))).toBe(true);
    } finally {
      await loop.stop();
    }
  });

  test('3. manager guidance appears as manager-tagged messages', async ({ page, baseURL }) => {
    await login(page);
    mock.clear();
    // Agent, then manager, in that order per turn.
    mock.queue([
      { text: 'agent answer' },
      { text: 'keep going, looks good' },
    ]);
    const { agentName, endpointId, loop } = await setupAgent(page, baseURL!);
    try {
      await openAgentChat(page, agentName);
      await configureManager(page, agentName, {
        endpointId,
        goals: 'be helpful',
        stopping: 'when the user says done',
      });
      await sendChatMessage(page, 'hi');
      await waitForAssistantReply(page);

      // Manager message is persisted but live SSE doesn't render it;
      // reload to force UI to pull from storage.
      await page.reload();
      await page.waitForSelector('#chat-messages .chat-msg-user');
      const allUser = await page.locator('#chat-messages .chat-msg-user').allInnerTexts();
      const managerAskBubble = allUser.find((t) => t.startsWith('👔 asking manager to '));
      expect(managerAskBubble).toBeTruthy();
      expect(managerAskBubble).toContain('review the latest output');

      const managerBubble = allUser.find(
        (t) => t.startsWith('👔 ') && !t.startsWith('👔 asking manager to ')
      );
      expect(managerBubble).toBeTruthy();
      expect(managerBubble).toContain('keep going');

      const status = await getManagerStatus(page, agentName);
      expect(status.enabled).toBe(true);
      expect(status.turn_counter).toBeGreaterThanOrEqual(1);
    } finally {
      await loop.stop();
    }
  });

  test('4. periodic checks fire on turn 3 of the 5-turn cycle', async ({ page, baseURL }) => {
    await login(page);
    mock.clear();
    // 4 agent-manager pairs. Manager prompts vary by turn_in_cycle but the
    // mock LLM echoes user text, so its content doesn't prove the cycle. Instead
    // we verify the manager's own received prompts: on turn 3, the system_prompt
    // from the server must contain the periodic_checks fragment.
    const { agentName, endpointId, loop } = await setupAgent(page, baseURL!);
    const CHECK_TOKEN = 'VERIFY-DISK-USAGE-TOKEN';
    try {
      await openAgentChat(page, agentName);
      await configureManager(page, agentName, {
        endpointId,
        goals: 'be helpful',
        checks: `Please verify: ${CHECK_TOKEN}`,
      });

      for (let i = 0; i < 4; i++) {
        mock.queue([{ text: `agent turn ${i}` }, { text: `manager ok ${i}` }]);
        await sendChatMessage(page, `turn ${i}`);
        await waitForAssistantReply(page, { after: i });
      }

      // Each manager LLM call gets a system message. The 4th call (turn_counter=3)
      // should include the CHECK_TOKEN. Find manager requests by looking at the
      // mock LLM's received log and filtering those with the manager-specific
      // phrase from build_manager_prompt (contains "the agent"). Simpler: every
      // manager call has the periodic_checks field in its prompt on turn 3.
      const managerReqs = mock.received.filter((r) =>
        (r.messages ?? []).some((m: any) => typeof m.content === 'string' && m.content.includes('STOPPING_POINT'))
      );
      expect(managerReqs.length).toBeGreaterThanOrEqual(4);
      const turn3 = managerReqs[3];
      const systemMsg = turn3.messages.find((m: any) => m.role === 'system')?.content ?? '';
      expect(systemMsg).toContain(CHECK_TOKEN);
    } finally {
      await loop.stop();
    }
  });

  test('5. manager stops on STOPPING_POINT sentinel', async ({ page, baseURL }) => {
    await login(page);
    mock.clear();
    mock.queue([
      { text: 'agent says done' },
      { text: 'STOPPING_POINT: The agent says done.\nReport that the task is complete.' },
    ]);
    const { agentName, endpointId, loop } = await setupAgent(page, baseURL!);
    try {
      await openAgentChat(page, agentName);
      await configureManager(page, agentName, {
        endpointId,
        stopping: 'when the agent says done',
      });
      await sendChatMessage(page, 'are we done?');
      await waitForAssistantReply(page);

      // Give the manager turn time to land.
      await page.waitForTimeout(500);
      const status = await getManagerStatus(page, agentName);
      expect(status.enabled).toBe(false);
    } finally {
      await loop.stop();
    }
  });

  test('6. manager stops on RED_FLAG_POINT sentinel', async ({ page, baseURL }) => {
    await login(page);
    mock.clear();
    mock.queue([
      { text: 'agent wandered off' },
      { text: 'RED_FLAG_POINT: The agent wandered off.\nStop and report the issue.' },
    ]);
    const { agentName, endpointId, loop } = await setupAgent(page, baseURL!);
    try {
      await openAgentChat(page, agentName);
      await configureManager(page, agentName, {
        endpointId,
        redFlags: 'if the agent wanders off',
      });
      await sendChatMessage(page, 'carry on');
      await waitForAssistantReply(page);

      await page.waitForTimeout(500);
      const status = await getManagerStatus(page, agentName);
      expect(status.enabled).toBe(false);
    } finally {
      await loop.stop();
    }
  });

  test('8. conversation survives server restart', async ({ page, baseURL }) => {
    await login(page);
    mock.clear();
    mock.queue({ text: 'pre-restart-reply' });

    const { agentName, loop } = await setupAgent(page, baseURL!);
    try {
      await openAgentChat(page, agentName);
      await sendChatMessage(page, 'before restart');
      const reply = await waitForAssistantReply(page);
      expect(reply).toContain('pre-restart-reply');

      const bubblesBefore = await countAssistantBubbles(page);
      const userBubblesBefore = await page.locator('#chat-messages .chat-msg-user').count();

      // Restart the server out-of-band. Requires run-all.sh to export
      // LORE_RESTART_CMD pointing to a helper script.
      const restart = process.env.LORE_RESTART_CMD;
      test.skip(!restart, 'LORE_RESTART_CMD not set (add to run-all.sh for this test)');
      execSync(restart!, { stdio: 'inherit' });

      // Reload the page.
      await page.reload();
      await page.waitForSelector('#chat-messages .chat-msg-assistant', { timeout: 10_000 });
      expect(await countAssistantBubbles(page)).toBe(bubblesBefore);
      expect(await page.locator('#chat-messages .chat-msg-user').count()).toBe(userBubblesBefore);
      const afterReply = await page.locator('#chat-messages .chat-msg-assistant').last().innerText();
      expect(afterReply).toContain('pre-restart-reply');
    } finally {
      await loop.stop();
    }
  });
});
