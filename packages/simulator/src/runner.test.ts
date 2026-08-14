import http from 'node:http';
import type { AddressInfo } from 'node:net';
import { afterEach, describe, expect, it } from 'vitest';
import { runScenario } from './runner.js';
import type { Scenario } from './scenario.js';
import { duplicateDeliveryV1, proofAIntrusionV1 } from './scenarios/index.js';

interface MockServer {
  readonly url: string;
  close(): Promise<void>;
}

async function startServer(handler: http.RequestListener): Promise<MockServer> {
  const server = http.createServer(handler);
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  const address = server.address() as AddressInfo;
  return {
    url: `http://127.0.0.1:${address.port}`,
    close: () =>
      new Promise<void>((resolve, reject) => {
        server.close((err) => (err ? reject(err) : resolve()));
      }),
  };
}

function readJsonBody(req: http.IncomingMessage): Promise<unknown> {
  return new Promise((resolve, reject) => {
    let raw = '';
    req.on('data', (chunk: Buffer) => {
      raw += chunk.toString('utf8');
    });
    req.on('end', () => {
      try {
        resolve(raw.length > 0 ? JSON.parse(raw) : undefined);
      } catch (err) {
        reject(err instanceof Error ? err : new Error(String(err)));
      }
    });
    req.on('error', reject);
  });
}

function sendJson(res: http.ServerResponse, status: number, body: unknown): void {
  res.writeHead(status, { 'content-type': 'application/json' });
  res.end(JSON.stringify(body));
}

describe('runScenario against a local mock ingestion server', () => {
  let closeServer: (() => Promise<void>) | undefined;

  afterEach(async () => {
    if (closeServer) {
      await closeServer();
      closeServer = undefined;
    }
  });

  it('sends events in ascending offset order, one result per step (ordering guarantee)', async () => {
    const arrivalOrder: string[] = [];

    const server = await startServer((req, res) => {
      void readJsonBody(req).then((body) => {
        const event = body as { event_id: string };
        arrivalOrder.push(event.event_id);
        sendJson(res, 200, { duplicate: false });
      });
    });
    closeServer = server.close;

    const result = await runScenario(proofAIntrusionV1, {
      baseUrl: server.url,
      orgId: 'org_1',
      siteId: 'site_1',
      zoneIds: { vault_corridor: 'zone_1' },
      speed: Infinity,
    });

    expect(result.results).toHaveLength(4);
    expect(result.results.every((r) => r.ok)).toBe(true);

    // Results are reported in step order...
    expect(result.results.map((r) => r.step_index)).toEqual([0, 1, 2, 3]);
    // ...and were actually SENT to the server in that same order.
    expect(arrivalOrder).toEqual(result.results.map((r) => r.event_id));
    expect(arrivalOrder).toEqual([
      'evt_proof-a-intrusion-001',
      'evt_proof-a-intrusion-002',
      'evt_proof-a-intrusion-003',
      'evt_proof-a-intrusion-004',
    ]);
  });

  it('respects step offsets relative to speed', async () => {
    const arrivalsMs: number[] = [];
    const start = Date.now();

    const server = await startServer((req, res) => {
      req.resume();
      req.on('end', () => {
        arrivalsMs.push(Date.now() - start);
        sendJson(res, 200, { duplicate: false });
      });
    });
    closeServer = server.close;

    const speed = 20; // proof-a offsets 0/4000/9000/14000ms -> real waits 0/200/250/250ms
    await runScenario(proofAIntrusionV1, {
      baseUrl: server.url,
      orgId: 'org_1',
      siteId: 'site_1',
      zoneIds: { vault_corridor: 'zone_1' },
      speed,
    });

    expect(arrivalsMs).toHaveLength(4);
    for (let i = 1; i < arrivalsMs.length; i++) {
      expect(arrivalsMs[i]).toBeGreaterThanOrEqual(arrivalsMs[i - 1]);
    }

    const expectedTotalMs = 14_000 / speed; // last step's offset / speed
    expect(arrivalsMs[3]).toBeGreaterThanOrEqual(expectedTotalMs - 100);
    expect(arrivalsMs[3]).toBeLessThan(expectedTotalMs + 3_000);
  }, 10_000);

  it('retries a 500 response and reports success with the attempt count', async () => {
    let calls = 0;

    const server = await startServer((req, res) => {
      void readJsonBody(req).then(() => {
        calls++;
        if (calls < 3) {
          sendJson(res, 500, { error: 'temporary' });
          return;
        }
        sendJson(res, 200, { duplicate: false });
      });
    });
    closeServer = server.close;

    const singleStepScenario: Scenario = {
      name: 'retry-then-success-probe',
      version: 1,
      description: 'single-step retry probe',
      steps: [proofAIntrusionV1.steps[0]],
    };

    const result = await runScenario(singleStepScenario, {
      baseUrl: server.url,
      orgId: 'org_1',
      siteId: 'site_1',
      zoneIds: { vault_corridor: 'zone_1' },
      speed: Infinity,
      retryBaseDelayMs: 5,
    });

    expect(calls).toBe(3);
    expect(result.results).toHaveLength(1);
    expect(result.results[0].ok).toBe(true);
    expect(result.results[0].attempts).toBe(3);
    expect(result.results[0].status).toBe(200);
  });

  it('gives up after maxRetries on a persistently failing server', async () => {
    let calls = 0;

    const server = await startServer((req, res) => {
      void readJsonBody(req).then(() => {
        calls++;
        sendJson(res, 500, { error: 'down' });
      });
    });
    closeServer = server.close;

    const singleStepScenario: Scenario = {
      name: 'retry-exhaustion-probe',
      version: 1,
      description: 'single-step retry-exhaustion probe',
      steps: [proofAIntrusionV1.steps[0]],
    };

    const result = await runScenario(singleStepScenario, {
      baseUrl: server.url,
      orgId: 'org_1',
      siteId: 'site_1',
      zoneIds: { vault_corridor: 'zone_1' },
      speed: Infinity,
      maxRetries: 2,
      retryBaseDelayMs: 5,
    });

    expect(calls).toBe(3); // 1 initial attempt + 2 retries
    expect(result.results[0].ok).toBe(false);
    expect(result.results[0].attempts).toBe(3);
    expect(result.results[0].status).toBe(500);
  });

  it('does not retry a 4xx response (terminal, non-transient)', async () => {
    let calls = 0;

    const server = await startServer((req, res) => {
      void readJsonBody(req).then(() => {
        calls++;
        sendJson(res, 400, { error: 'bad request' });
      });
    });
    closeServer = server.close;

    const singleStepScenario: Scenario = {
      name: 'terminal-4xx-probe',
      version: 1,
      description: 'single-step terminal-error probe',
      steps: [proofAIntrusionV1.steps[0]],
    };

    const result = await runScenario(singleStepScenario, {
      baseUrl: server.url,
      orgId: 'org_1',
      siteId: 'site_1',
      zoneIds: { vault_corridor: 'zone_1' },
      speed: Infinity,
    });

    expect(calls).toBe(1);
    expect(result.results[0].ok).toBe(false);
    expect(result.results[0].status).toBe(400);
  });

  it('passes through duplicate:true and original_event_id from the mock server', async () => {
    const server = await startServer((req, res) => {
      void readJsonBody(req).then(() => {
        sendJson(res, 200, { duplicate: true, original_event_id: 'evt_duplicate-delivery-001' });
      });
    });
    closeServer = server.close;

    const result = await runScenario(duplicateDeliveryV1, {
      baseUrl: server.url,
      orgId: 'org_1',
      siteId: 'site_1',
      zoneIds: { lobby: 'zone_lobby' },
      speed: Infinity,
    });

    expect(result.results).toHaveLength(3);
    for (const r of result.results) {
      expect(r.ok).toBe(true);
      expect(r.duplicate).toBe(true);
      expect(r.original_event_id).toBe('evt_duplicate-delivery-001');
    }
  });

  it('never sends an event that fails contracts validation after placeholder resolution', async () => {
    let calls = 0;
    const server = await startServer((_req, res) => {
      calls++;
      sendJson(res, 200, { duplicate: false });
    });
    closeServer = server.close;

    const invalidScenario: Scenario = {
      name: 'invalid-template-probe',
      version: 1,
      description: 'one intentionally invalid template (confidence out of range)',
      steps: [
        {
          at_offset_ms: 0,
          event: { ...proofAIntrusionV1.steps[0].event, confidence: 42 },
        },
      ],
    };

    const result = await runScenario(invalidScenario, {
      baseUrl: server.url,
      orgId: 'org_1',
      siteId: 'site_1',
      zoneIds: { vault_corridor: 'zone_1' },
      speed: Infinity,
    });

    expect(calls).toBe(0);
    expect(result.results).toHaveLength(1);
    expect(result.results[0].ok).toBe(false);
    expect(result.results[0].attempts).toBe(0);
    expect(result.results[0].error).toMatch(/validation/i);
  });

  it('rejects out-of-order scenario steps up front', async () => {
    const outOfOrder: Scenario = {
      name: 'out-of-order-probe',
      version: 1,
      description: 'steps not sorted by at_offset_ms',
      steps: [proofAIntrusionV1.steps[1], proofAIntrusionV1.steps[0]],
    };

    await expect(
      runScenario(outOfOrder, {
        baseUrl: 'http://127.0.0.1:1',
        orgId: 'org_1',
        siteId: 'site_1',
        zoneIds: { vault_corridor: 'zone_1' },
        speed: Infinity,
      })
    ).rejects.toThrow(/non-decreasing/i);
  });
});
