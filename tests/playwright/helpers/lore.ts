import { Page, APIRequestContext, request as pwRequest } from '@playwright/test';
import fs from 'node:fs';
import path from 'node:path';

export const ADMIN_USER = 'admin';
export const ADMIN_PASS = 'correct-horse-battery';

const basicAuth = () =>
  'Basic ' + Buffer.from(`${ADMIN_USER}:${ADMIN_PASS}`).toString('base64');

export async function login(page: Page): Promise<void> {
  await page.goto('/login');
  await page.fill('input[name="username"]', ADMIN_USER);
  await page.fill('input[name="password"]', ADMIN_PASS);
  await page.click('button[type="submit"]');
  await page.waitForURL(/\/ui/);
}

export interface AdminClient {
  baseURL: string;
  req: APIRequestContext;
  createEndpoint(opts: { name: string; url: string; model?: string; kind?: string }): Promise<{ id: string; name: string }>;
  createProject(name: string): Promise<{ slug: string }>;
  createAgentToken(opts: { name: string; projectSlug: string; endpointId?: string }): Promise<{ token: string; name: string }>;
  setAgentEndpoint(session: Page, agentName: string, endpointId: string): Promise<void>;
}

export async function newAdminClient(baseURL: string): Promise<AdminClient> {
  const req = await pwRequest.newContext({ baseURL });
  return {
    baseURL,
    req,
    async createEndpoint({ name, url, model = 'mock-model', kind }) {
      const body: any = { name, url, model, api_key: 'test-key' };
      if (kind) body.kind = kind;
      const r = await req.post('/v1/admin/endpoints', {
        headers: { authorization: basicAuth(), 'content-type': 'application/json' },
        data: body,
      });
      if (!r.ok()) throw new Error(`createEndpoint: ${r.status()} ${await r.text()}`);
      return r.json();
    },
    async createProject(name) {
      // No REST endpoint; create via UI form. Needs a session, so use a
      // one-shot login through the shared APIRequestContext.
      const login = await req.post('/login', {
        form: { username: ADMIN_USER, password: ADMIN_PASS },
      });
      if (!login.ok() && login.status() !== 303 && login.status() !== 302) {
        throw new Error(`admin login: ${login.status()} ${await login.text()}`);
      }
      // Get csrf from /ui
      const home = await req.get('/ui');
      const html = await home.text();
      const match = html.match(/name="csrf_token"\s+value="([^"]+)"/);
      if (!match) throw new Error('could not find csrf_token on /ui');
      const csrf = match[1];
      const r = await req.post('/ui/projects', {
        form: { csrf_token: csrf, project_name: name, parent: '' },
        maxRedirects: 0,
      });
      if (r.status() !== 303 && r.status() !== 302) {
        throw new Error(`createProject: ${r.status()} ${await r.text()}`);
      }
      const loc = r.headers()['location'] || '';
      const slug = loc.replace(/^\/ui\//, '').split('?')[0] || name.toLowerCase().replace(/[^a-z0-9]+/g, '-');
      return { slug };
    },
    async createAgentToken({ name, projectSlug, endpointId }) {
      const data: any = {
        name,
        owner: ADMIN_USER,
        grants: [{ project: projectSlug, permission: 'read_write' }],
        backend: 'claude',
      };
      if (endpointId) data.endpoint_id = endpointId;
      const r = await req.post('/v1/admin/agent-tokens', {
        headers: { authorization: basicAuth(), 'content-type': 'application/json' },
        data,
      });
      if (!r.ok()) throw new Error(`createAgentToken: ${r.status()} ${await r.text()}`);
      const body = await r.json();
      return { token: body.token, name: body.summary?.name ?? name };
    },
    async setAgentEndpoint(page, agentName, endpointId) {
      // Use the UI session to save config (requires csrf from /ui cookies).
      const csrf = await extractCsrf(page);
      const r = await page.request.post(`/ui/chat/${agentName}/config`, {
        form: { csrf_token: csrf, endpoint_id: endpointId, backend: 'claude' },
      });
      if (!r.ok()) throw new Error(`setAgentEndpoint: ${r.status()} ${await r.text()}`);
    },
  };
}

async function extractCsrf(page: Page): Promise<string> {
  // /ui (projects page) always has a csrf_token hidden input on its forms.
  await page.goto('/ui');
  const token = await page
    .locator('input[name="csrf_token"]')
    .first()
    .getAttribute('value');
  if (!token) throw new Error('no csrf token found on /ui');
  return token;
}

// ---------------------------------------------------------------------------
// Chat UI helpers
// ---------------------------------------------------------------------------

export async function openAgentChat(page: Page, agentName: string): Promise<void> {
  await page.goto(`/ui/chat?agent=${encodeURIComponent(agentName)}`);
  await page.waitForSelector('#chat-messages', { state: 'visible' });
}

export async function sendChatMessage(page: Page, text: string): Promise<void> {
  const input = page.locator('#chat-input');
  await input.fill(text);
  await page.click('.chat-send-btn');
  // Wait until the user bubble has rendered.
  await page.waitForFunction((t) => {
    const msgs = document.querySelectorAll('#chat-messages .chat-msg-user');
    return Array.from(msgs).some((n) => n.textContent?.includes(t));
  }, text, { timeout: 10_000 });
}

export async function waitForAssistantReply(page: Page, opts: { after?: number; timeout?: number } = {}): Promise<string> {
  const { after = 0, timeout = 30_000 } = opts;
  await page.waitForFunction((n) => {
    const msgs = document.querySelectorAll('#chat-messages .chat-msg-assistant');
    return msgs.length > n;
  }, after, { timeout });
  const handle = await page.locator('#chat-messages .chat-msg-assistant').last();
  return (await handle.innerText()).trim();
}

export async function countAssistantBubbles(page: Page): Promise<number> {
  return await page.locator('#chat-messages .chat-msg-assistant').count();
}

export async function countToolBubbles(page: Page): Promise<number> {
  return await page.locator('#chat-messages .chat-msg-tool').count();
}

export interface ManagerConfigOpts {
  goals?: string;
  stopping?: string;
  checks?: string;
  redFlags?: string;
  endpointId: string;
}

export async function configureManager(page: Page, agentName: string, opts: ManagerConfigOpts): Promise<void> {
  // Extract CSRF from page JS globals (already on /ui/chat after openAgentChat).
  const csrf = await page.evaluate(() => (window as any).csrfToken as string);
  const form = {
    csrf_token: csrf,
    backend: '',
    endpoint_id: opts.endpointId,
    goals: opts.goals ?? '',
    stopping_point: opts.stopping ?? '',
    periodic_checks: opts.checks ?? '',
    red_flags: opts.redFlags ?? '',
  };
  const r1 = await page.request.post(`/ui/chat/${encodeURIComponent(agentName)}/manage`, { form });
  if (!r1.ok()) throw new Error(`save manage: ${r1.status()} ${await r1.text()}`);
  const r2 = await page.request.post(`/ui/chat/${encodeURIComponent(agentName)}/manage`, {
    form: { csrf_token: csrf, enabled: 'true' },
  });
  if (!r2.ok()) throw new Error(`enable manage: ${r2.status()} ${await r2.text()}`);
}

export async function getManagerStatus(page: Page, agentName: string): Promise<{ enabled: boolean; turn_counter: number }> {
  const r = await page.request.get(`/ui/chat/${encodeURIComponent(agentName)}/manage`);
  if (!r.ok()) throw new Error(`get manage: ${r.status()}`);
  const body = await r.json();
  return { enabled: !!body.enabled, turn_counter: body.turn_counter ?? 0 };
}

export async function waitForManagerMessage(page: Page, opts: { after?: number; timeout?: number } = {}): Promise<string> {
  const { after = 0, timeout = 30_000 } = opts;
  // Manager messages are stored as ChatRole::User with content '[manager] ...'.
  // They render as chat-msg-user bubbles.
  await page.waitForFunction((n) => {
    const all = document.querySelectorAll('#chat-messages .chat-msg-user');
    let managerCount = 0;
    all.forEach((node) => { if (node.textContent?.startsWith('[manager]')) managerCount++; });
    return managerCount > n;
  }, after, { timeout });
  const all = await page.locator('#chat-messages .chat-msg-user').allInnerTexts();
  const managerMsgs = all.filter((t) => t.startsWith('[manager]'));
  return managerMsgs[managerMsgs.length - 1];
}

// ---------------------------------------------------------------------------
// Node-side agent loop (mimics lore agent daemon: poll -> complete -> respond)
// ---------------------------------------------------------------------------

export interface AgentLoop {
  stop(): Promise<void>;
}

export function startAgentLoop(baseURL: string, agentToken: string, opts: { verbose?: boolean } = {}): AgentLoop {
  let stopped = false;
  const headers = { 'x-lore-key': agentToken, 'x-lore-version': '0.1.65', 'x-lore-machine': 'test-machine' };
  const verbose = opts.verbose || process.env.AGENT_LOOP_DEBUG === '1';
  const log = (...args: any[]) => verbose && console.log('[agent-loop]', ...args);

  (async () => {
    while (!stopped) {
      try {
        const pollResp = await fetch(`${baseURL}/v1/chat/poll`, { headers });
        if (!pollResp.ok) {
          log('poll failed', pollResp.status);
          await sleep(500);
          continue;
        }
        const poll = await pollResp.json() as any;
        const msgs: any[] = Array.isArray(poll.messages) ? poll.messages : [];
        if (msgs.length === 0) continue; // long-poll returned empty, immediately re-poll
        log('got', msgs.length, 'pending messages');

        const endpointId = poll.endpoint_id;
        if (!endpointId) {
          log('no endpoint configured, dropping msgs');
          await postRespond(baseURL, agentToken, { content: '[no endpoint]' });
          continue;
        }

        const userText = msgs.map((m) => m.content).join('\n');
        try {
          await runTurn(baseURL, agentToken, userText, log);
        } catch (e) {
          log('runTurn error', e);
        }
      } catch (e) {
        if (!stopped) log('loop error', e);
        await sleep(500);
      }
    }
  })();

  return {
    async stop() {
      stopped = true;
      await sleep(50);
    },
  };
}

async function runTurn(baseURL: string, agentToken: string, userText: string, log: (...a: any[]) => void = () => {}): Promise<void> {
  const conversation: any[] = [
    { role: 'system', content: 'test agent' },
    { role: 'user', content: userText },
  ];

  for (let turn = 0; turn < 8; turn++) {
    const resp = await fetch(`${baseURL}/v1/chat/completions`, {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        'x-lore-key': agentToken,
      },
      body: JSON.stringify({ messages: conversation, tools: [], stream: false, max_tokens: 1024 }),
    });
    if (!resp.ok) {
      await postRespond(baseURL, agentToken, { content: `[completion error ${resp.status}]`, complete: true });
      return;
    }
    const body: any = await resp.json();
    const msg = body?.choices?.[0]?.message;
    if (!msg) {
      await postRespond(baseURL, agentToken, { content: '[no message]' });
      return;
    }
    if (Array.isArray(msg.tool_calls) && msg.tool_calls.length > 0) {
      for (const tc of msg.tool_calls) {
        await postRespond(baseURL, agentToken, {
          tool_use: `${tc.function?.name}(${tc.function?.arguments || ''})`,
        });
      }
      conversation.push(msg);
      for (const tc of msg.tool_calls) {
        conversation.push({
          role: 'tool',
          tool_call_id: tc.id,
          content: '{"ok":true}',
        });
      }
      continue;
    }
    const content = typeof msg.content === 'string' ? msg.content : '';
    await postRespond(baseURL, agentToken, { text: content, content, complete: true });
    await runManagerTurnIfEnabled(baseURL, agentToken);
    return;
  }
  await postRespond(baseURL, agentToken, { text: '[max turns]', content: '[max turns]', complete: true });
}

async function runManagerTurnIfEnabled(baseURL: string, agentToken: string): Promise<void> {
  const manageResp = await fetch(`${baseURL}/v1/chat/manage`, {
    headers: { 'x-lore-key': agentToken },
  });
  if (!manageResp.ok) return;
  const manage: any = await manageResp.json();
  if (!manage.enabled) return;

  const sys = manage.system_prompt ?? '';
  const recent = Array.isArray(manage.messages) ? manage.messages : [];
  const body = {
    messages: [
      { role: 'system', content: sys },
      ...recent.map((m: any) => ({ role: m.role === 'assistant' ? 'assistant' : 'user', content: m.content })),
    ],
    stream: false,
    max_tokens: 1024,
  };
  let content = '';
  if (manage.has_endpoint) {
    const r = await fetch(`${baseURL}/v1/chat/manager/completions`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', 'x-lore-key': agentToken },
      body: JSON.stringify(body),
    });
    if (r.ok) {
      const js: any = await r.json();
      content = js?.choices?.[0]?.message?.content ?? '';
    } else {
      content = `[manager error ${r.status}]`;
    }
  }
  const stopped = content.includes('STOPPING_POINT') || content.includes('RED_FLAG_POINT');
  await fetch(`${baseURL}/v1/chat/manager`, {
    method: 'POST',
    headers: { 'content-type': 'application/json', 'x-lore-key': agentToken },
    body: JSON.stringify({ content, stopped }),
  });
}

async function postRespond(baseURL: string, agentToken: string, body: any): Promise<void> {
  await fetch(`${baseURL}/v1/chat/respond`, {
    method: 'POST',
    headers: {
      'content-type': 'application/json',
      'x-lore-key': agentToken,
    },
    body: JSON.stringify(body),
  });
}

const sleep = (ms: number) => new Promise<void>((ok) => setTimeout(ok, ms));

// ---------------------------------------------------------------------------
// Server data-dir inspection (no HTTP). run-all.sh exports LORE_DATA_DIR.
// ---------------------------------------------------------------------------

export function readServerFile(relpath: string): string | null {
  const dir = process.env.LORE_DATA_DIR;
  if (!dir) return null;
  const p = path.join(dir, relpath);
  try {
    return fs.readFileSync(p, 'utf8');
  } catch {
    return null;
  }
}

export function dataDir(): string {
  const dir = process.env.LORE_DATA_DIR;
  if (!dir) throw new Error('LORE_DATA_DIR not set');
  return dir;
}
