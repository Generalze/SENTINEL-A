// =============================================================================
// SENTINEL WAN-LINK — the controllable segment of the WAN path, and the
// harness's authoritative witness to what happened on it.
//
// WHY THIS EXISTS: A BLUNT DISCONNECT CANNOT EXPRESS THE CASE THAT MATTERS.
// -------------------------------------------------------------------------
// `docker network disconnect` produces a real outage and is the right tool for
// most of Proof D. It is symmetric: nothing goes out, nothing comes back, and
// central never hears the request. That covers "the WAN is down".
//
// It cannot cover the hardest phase of the scenario, and the hardest phase is
// the one worth proving:
//
//     THE REQUEST ARRIVES. CENTRAL COMMITS. THE RESPONSE IS LOST.
//
// That is the case in which the client's knowledge and the server's state
// genuinely diverge — the client holds no evidence its operation happened, and
// central holds an effect. Every duplicate-suppression argument in the system
// exists for exactly this window, and no symmetric cut can create it, because
// a symmetric cut also stops the request. Expressing it requires something ON
// the path that can treat the two directions differently.
//
// This process is that something. It is an HTTP reverse proxy with four modes
// and a journal, and it is deliberately the smallest thing that can do the
// job: no dependencies, no build step, no image of its own. It is bind-mounted
// into a stock Node image, so there is nothing between the source you are
// reading and the bytes that run.
//
// WHY IT IS ALSO THE WITNESS.
// ---------------------------
// After a dropped response the client knows only that its socket died. Central
// knows it committed something, but central's logs cannot prove the RESPONSE
// never arrived — central emitted one, and that is the last thing it can
// observe. Only the process that made the decision can testify to it. So this
// proxy journals every disposition with the timestamps at which it happened,
// and the harness reads that journal as the authoritative record of "the
// request landed at T1 and its response was destroyed at T2".
//
// TIMESTAMPS, NEVER DURATIONS.
// ----------------------------
// Every field this journal records is an ISO-8601 instant. It records no
// elapsed times and computes no differences, because a test that asserts on a
// duration is a test that fails on a loaded CI runner for reasons that have
// nothing to do with the system under test. Callers that need an interval have
// two instants and can say so; callers that want to assert an interval are
// asking the wrong question. This repository spent three work items removing
// timing dependence from its suites and this file does not reintroduce it.
//
// NOT A SECURITY DEVICE. This proxy terminates nothing, authenticates nothing
// and forwards headers verbatim. It exists only inside the WAN-loss harness
// topology, it is never built into an image, and no compose file outside
// `docker-compose.wan-loss.yml` references it.
// =============================================================================

import http from 'node:http';

// -----------------------------------------------------------------------------
// CONFIGURATION. Every value is required and none has a plausible default:
// a WAN link that guessed its own upstream would silently proxy to the wrong
// central, and the resulting test would pass while proving nothing.
// -----------------------------------------------------------------------------
const DATA_PORT = requireInt('WAN_LINK_DATA_PORT');
const CONTROL_PORT = requireInt('WAN_LINK_CONTROL_PORT');
const UPSTREAM_HOST = requireString('WAN_LINK_UPSTREAM_HOST');
const UPSTREAM_PORT = requireInt('WAN_LINK_UPSTREAM_PORT');

function requireString(name) {
  const value = process.env[name];
  if (typeof value !== 'string' || value.length === 0) {
    console.error(`wan-link: ${name} is required`);
    process.exit(1);
  }
  return value;
}

function requireInt(name) {
  const raw = requireString(name);
  const value = Number.parseInt(raw, 10);
  if (!Number.isInteger(value) || value <= 0) {
    console.error(`wan-link: ${name} must be a positive integer, got ${raw}`);
    process.exit(1);
  }
  return value;
}

// -----------------------------------------------------------------------------
// THE MODES. Four, and the set is closed on purpose — an unknown mode is
// rejected rather than defaulted, so a typo in a test fails the test instead of
// silently running the scenario in `pass`.
//
//   pass                Ordinary forwarding. The link is up.
//
//   drop_response       Requests are forwarded and awaited to COMPLETION —
//                       central commits — and then the response is destroyed
//                       without a byte reaching the client. The client observes
//                       a dead socket, which is the honest UNKNOWN. Every
//                       request behaves this way until the mode changes.
//
//   drop_response_once  The same, for exactly ONE request, after which the link
//                       reverts to `pass` ON ITS OWN. This is the mode the
//                       phase-8 scenario uses, and the self-revert is what
//                       makes it deterministic: the retry cannot race a second
//                       control call, because there is no second control call.
//                       A test that had to disarm the toxin between the two
//                       attempts would have a window in which the outcome
//                       depended on scheduling.
//
//   blackhole           The request is NOT forwarded and no response is sent;
//                       the connection is held open until the client's own
//                       timeout fires. Central never hears it. This is the
//                       distinct partner case to `drop_response` — "the
//                       request never landed" versus "the request landed and
//                       the answer was lost" — and a scenario that cannot tell
//                       those apart is not testing recovery, it is testing
//                       retry.
//
// `blackhole` OVERLAPS WITH, BUT DOES NOT REPLACE, THE DOCKER NETWORK CUT, and
// the harness uses the network cut as its authoritative outage. The difference
// is honest and worth keeping: a network cut removes the route, so the Edge
// cannot open a socket at all; `blackhole` leaves the route intact and swallows
// traffic, which is what a real WAN failure upstream of the site looks like
// from inside. Proving the system survives only the second would be proving
// less than the acceptance definition asks for.
// -----------------------------------------------------------------------------
const MODES = ['pass', 'drop_response', 'drop_response_once', 'blackhole'];

/** @type {{ mode: string, since: string, journal: object[], nextSeq: number }} */
const state = {
  mode: 'pass',
  since: new Date().toISOString(),
  journal: [],
  nextSeq: 1,
};

// A journal that grows without bound is a memory leak in a long-lived
// container. The cap is generous relative to any single scenario and the
// harness resets between tests; when it is hit, the OLDEST entry is dropped,
// because in a failure investigation the most recent dispositions are the ones
// being asked about.
const JOURNAL_CAP = 2000;

function record(entry) {
  const full = { seq: state.nextSeq++, ...entry };
  state.journal.push(full);
  if (state.journal.length > JOURNAL_CAP) state.journal.shift();
  return full;
}

// -----------------------------------------------------------------------------
// THE DATA PLANE.
// -----------------------------------------------------------------------------
const dataServer = http.createServer((clientReq, clientRes) => {
  const requestReceivedAt = new Date().toISOString();
  const mode = state.mode;

  // `drop_response_once` disarms HERE — at the moment the request is accepted,
  // before anything is forwarded — rather than after the response is dropped.
  // If it disarmed later, a second request arriving while the first was still
  // upstream would ALSO be dropped, and the test would have silently exercised
  // a different scenario than the one it named.
  if (mode === 'drop_response_once') {
    state.mode = 'pass';
    state.since = new Date().toISOString();
  }

  if (mode === 'blackhole') {
    record({
      at: requestReceivedAt,
      mode,
      method: clientReq.method,
      path: clientReq.url,
      disposition: 'NOT_FORWARDED',
      upstream_status: null,
      request_forwarded_at: null,
      upstream_responded_at: null,
      decided_at: new Date().toISOString(),
    });
    // Consume the body so the client's write does not stall on backpressure —
    // a client blocked on WRITING is a different failure from one waiting on a
    // READ, and this mode is meant to model the second. Then simply never
    // answer: the socket stays open and the CLIENT's timeout is what ends it,
    // which is the behaviour a swallowed WAN produces.
    clientReq.resume();
    return;
  }

  // Stamped before the request is constructed rather than after, so the
  // journal's `request_forwarded_at` can never be later than an upstream
  // response it is supposed to precede. The callbacks below close over it.
  const forwardedAt = new Date().toISOString();

  const upstreamReq = http.request(
    {
      host: UPSTREAM_HOST,
      port: UPSTREAM_PORT,
      method: clientReq.method,
      path: clientReq.url,
      headers: clientReq.headers,
    },
    (upstreamRes) => {
      if (mode === 'pass') {
        record({
          at: requestReceivedAt,
          mode,
          method: clientReq.method,
          path: clientReq.url,
          disposition: 'RESPONSE_DELIVERED',
          upstream_status: upstreamRes.statusCode ?? null,
          request_forwarded_at: forwardedAt,
          upstream_responded_at: new Date().toISOString(),
          decided_at: new Date().toISOString(),
        });
        clientRes.writeHead(upstreamRes.statusCode ?? 502, upstreamRes.headers);
        upstreamRes.pipe(clientRes);
        return;
      }

      // -----------------------------------------------------------------------
      // THE ASYMMETRIC DROP, AND WHY THE RESPONSE IS DRAINED FIRST.
      //
      // The claim this mode has to be able to make is "CENTRAL COMMITTED". If
      // the socket were destroyed the instant the response headers arrived,
      // central might still be mid-write — with a handler that had begun
      // responding before its transaction settled, or a Node stream that had
      // not flushed — and the harness would be asserting a commit it had not
      // actually witnessed. Consuming the response to `end` means the upstream
      // handler ran to completion. Only then is the answer thrown away.
      //
      // The bytes are counted and discarded rather than buffered: nothing in
      // this process has any business holding a copy of a response nobody is
      // allowed to see, and a proxy that accumulated dropped payloads would
      // grow without bound in exactly the scenario it exists for.
      // -----------------------------------------------------------------------
      let bytes = 0;
      upstreamRes.on('data', (chunk) => {
        bytes += chunk.length;
      });
      upstreamRes.on('end', () => {
        record({
          at: requestReceivedAt,
          mode,
          method: clientReq.method,
          path: clientReq.url,
          disposition: 'RESPONSE_DROPPED',
          upstream_status: upstreamRes.statusCode ?? null,
          upstream_response_bytes: bytes,
          request_forwarded_at: forwardedAt,
          upstream_responded_at: new Date().toISOString(),
          decided_at: new Date().toISOString(),
        });
        // DESTROY, never `end()`. `clientRes.end()` would send a well-formed
        // zero-length 200 and the client would read a SUCCESSFUL response —
        // the opposite of a lost one. Destroying the socket gives the client
        // ECONNRESET with no status at all, which is what a link that failed
        // mid-answer actually does, and it is the only outcome from which the
        // client can conclude nothing.
        clientRes.socket?.destroy();
      });
    },
  );

  upstreamReq.on('error', (error) => {
    record({
      at: requestReceivedAt,
      mode,
      method: clientReq.method,
      path: clientReq.url,
      disposition: 'UPSTREAM_ERROR',
      upstream_status: null,
      upstream_error: error.code ?? error.message,
      request_forwarded_at: forwardedAt,
      upstream_responded_at: null,
      decided_at: new Date().toISOString(),
    });
    // A genuine upstream failure is reported as one. This proxy fabricates no
    // outcome it did not observe: 502 says "the link worked and central did
    // not answer", which is a different fact from a dropped response and must
    // not be disguised as one.
    if (!clientRes.headersSent) clientRes.writeHead(502, { 'content-type': 'application/json' });
    clientRes.end(JSON.stringify({ error: 'wan_link_upstream_error', code: error.code ?? null }));
  });

  clientReq.pipe(upstreamReq);
});

// -----------------------------------------------------------------------------
// THE CONTROL PLANE — a SEPARATE LISTENER ON A SEPARATE PORT.
//
// Not a magic path on the data port, which would be indistinguishable from a
// real request to central and would mean any client behind the WAN could
// change the state of the WAN. Two ports, and in the compose topology they sit
// on different networks: the data port faces the severable segment, the
// control port faces the harness. The Edge cannot reach the control plane at
// all, which is the correct shape — a node under test must not be able to
// operate the instrument measuring it.
// -----------------------------------------------------------------------------
const controlServer = http.createServer((req, res) => {
  const url = new URL(req.url ?? '/', 'http://control.invalid');

  const json = (status, body) => {
    res.writeHead(status, { 'content-type': 'application/json' });
    res.end(JSON.stringify(body));
  };

  if (req.method === 'GET' && url.pathname === '/control/state') {
    json(200, {
      mode: state.mode,
      since: state.since,
      journal_entries: state.journal.length,
      upstream: `${UPSTREAM_HOST}:${UPSTREAM_PORT}`,
      observed_at: new Date().toISOString(),
    });
    return;
  }

  if (req.method === 'GET' && url.pathname === '/control/journal') {
    json(200, { entries: state.journal, observed_at: new Date().toISOString() });
    return;
  }

  if (req.method === 'POST' && url.pathname === '/control/journal/reset') {
    // Sequence numbers are NOT reset with the entries. A journal that restarted
    // at 1 could not distinguish "no requests since the reset" from "the reset
    // did not happen", and every scenario in this harness owns its own
    // namespace precisely so that ambiguities like that cannot arise.
    state.journal = [];
    json(200, { cleared: true, next_seq: state.nextSeq, observed_at: new Date().toISOString() });
    return;
  }

  if (req.method === 'POST' && url.pathname === '/control/mode') {
    let body = '';
    req.on('data', (chunk) => {
      body += chunk;
    });
    req.on('end', () => {
      let requested;
      try {
        requested = JSON.parse(body || '{}').mode;
      } catch {
        json(400, { error: 'invalid_json' });
        return;
      }
      if (!MODES.includes(requested)) {
        json(400, { error: 'unknown_mode', requested, supported: MODES });
        return;
      }
      const previous = state.mode;
      state.mode = requested;
      state.since = new Date().toISOString();
      json(200, { mode: state.mode, previous, since: state.since });
    });
    return;
  }

  json(404, { error: 'not_found', path: url.pathname });
});

dataServer.listen(DATA_PORT, '0.0.0.0', () => {
  console.log(`wan-link data plane on :${DATA_PORT} -> ${UPSTREAM_HOST}:${UPSTREAM_PORT}`);
});
controlServer.listen(CONTROL_PORT, '0.0.0.0', () => {
  console.log(`wan-link control plane on :${CONTROL_PORT}`);
});

// Exec-form entrypoint means this process is PID 1 and receives SIGTERM
// directly. Closing both listeners lets `docker compose down` finish promptly
// instead of waiting out the 10-second kill timer on every harness teardown.
for (const signal of ['SIGTERM', 'SIGINT']) {
  process.on(signal, () => {
    dataServer.close();
    controlServer.close();
    process.exit(0);
  });
}
