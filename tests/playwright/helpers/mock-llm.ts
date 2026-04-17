import http from 'node:http';
import { AddressInfo } from 'node:net';

// A scripted mock LLM compatible with OpenAI /v1/chat/completions.
// Queue responses via the exposed `queue(...)` method or the control
// endpoint POST /__mock/queue. Each inbound completions request pops
// the next queued response. If the queue is empty, a default echo
// reply is returned.
//
// Queue entry shapes:
//   { text: "hello" }                                  // plain assistant reply
//   { tool: { name: "list_projects", args: "{}" } }    // tool_call reply
//   { raw: { choices: [...] } }                        // full body override

export type QueueEntry =
  | { text: string }
  | { tool: { name: string; args: string; id?: string } }
  | { raw: any };

export interface MockLlmServer {
  url: string;
  completionsUrl: string;
  port: number;
  received: any[];               // all inbound completion request bodies
  queue(entry: QueueEntry | QueueEntry[]): void;
  clear(): void;
  stop(): Promise<void>;
}

export async function startMockLlm(): Promise<MockLlmServer> {
  const queued: QueueEntry[] = [];
  const received: any[] = [];

  const server = http.createServer(async (req, res) => {
    const chunks: Buffer[] = [];
    req.on('data', (c: Buffer) => chunks.push(c));
    req.on('end', () => {
      const raw = Buffer.concat(chunks).toString('utf8');
      let body: any = {};
      try { body = raw ? JSON.parse(raw) : {}; } catch {}

      if (req.url === '/__mock/queue' && req.method === 'POST') {
        if (Array.isArray(body)) queued.push(...body);
        else queued.push(body);
        res.writeHead(204).end();
        return;
      }
      if (req.url === '/__mock/received' && req.method === 'GET') {
        res.writeHead(200, { 'content-type': 'application/json' });
        res.end(JSON.stringify(received));
        return;
      }
      if (req.url === '/__mock/clear' && req.method === 'POST') {
        queued.length = 0;
        received.length = 0;
        res.writeHead(204).end();
        return;
      }

      if (req.url === '/v1/chat/completions' && req.method === 'POST') {
        received.push(body);
        const entry = queued.shift();
        res.writeHead(200, { 'content-type': 'application/json' });
        res.end(JSON.stringify(buildCompletion(entry, body)));
        return;
      }

      if (req.url === '/v1/models' && req.method === 'GET') {
        res.writeHead(200, { 'content-type': 'application/json' });
        res.end(JSON.stringify({ data: [{ id: 'mock-model' }] }));
        return;
      }

      res.writeHead(404).end();
    });
  });

  await new Promise<void>((ok) => server.listen(0, '127.0.0.1', ok));
  const addr = server.address() as AddressInfo;
  const url = `http://127.0.0.1:${addr.port}`;

  return {
    url,
    completionsUrl: `${url}/v1/chat/completions`,
    port: addr.port,
    received,
    queue(entry) {
      if (Array.isArray(entry)) queued.push(...entry);
      else queued.push(entry);
    },
    clear() { queued.length = 0; received.length = 0; },
    stop() {
      return new Promise<void>((ok) => server.close(() => ok()));
    },
  };
}

function buildCompletion(entry: QueueEntry | undefined, req: any) {
  const lastUser = Array.isArray(req?.messages)
    ? (req.messages[req.messages.length - 1]?.content ?? '')
    : '';
  if (!entry) {
    return wrapAssistant(`mock reply to: ${String(lastUser).slice(0, 200)}`);
  }
  if ('raw' in entry) return entry.raw;
  if ('tool' in entry) {
    const id = entry.tool.id ?? `call_${Math.random().toString(36).slice(2, 10)}`;
    return {
      id: `chatcmpl-${Math.random().toString(36).slice(2, 10)}`,
      object: 'chat.completion',
      model: req?.model || 'mock-model',
      choices: [{
        index: 0,
        message: {
          role: 'assistant',
          content: null,
          tool_calls: [{
            id,
            type: 'function',
            function: { name: entry.tool.name, arguments: entry.tool.args },
          }],
        },
        finish_reason: 'tool_calls',
      }],
      usage: { prompt_tokens: 10, completion_tokens: 10, total_tokens: 20 },
    };
  }
  return wrapAssistant(entry.text);
}

function wrapAssistant(text: string) {
  return {
    id: `chatcmpl-${Math.random().toString(36).slice(2, 10)}`,
    object: 'chat.completion',
    model: 'mock-model',
    choices: [{
      index: 0,
      message: { role: 'assistant', content: text },
      finish_reason: 'stop',
    }],
    usage: { prompt_tokens: 10, completion_tokens: 10, total_tokens: 20 },
  };
}
