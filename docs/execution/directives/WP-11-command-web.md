# Directive WP-11 — Command Web (Milestone-1 shell)

**Lane:** Core (Sonnet) with Haiku for mechanical components · **Wave:** 4 · **Depends:** WP-07, WP-12
**Review chain:** Sonnet peer/Opus spot review → Lead merge gate

## Spec references
§9 (Command purpose; single workspace, no page-hopping during an incident), §66.1 (screen states), §66.2 (operator safeguards — predictions visually distinct from verified observations; classifications visually distinct).

## Deliverables (`apps/command-web`)
1. **Stack:** React 18 + Vite + TanStack Query + socket.io-client + Tailwind (approved deps). Dev-auth: user picker writing `x-dev-user-id` to a shared fetch wrapper (dev only, labelled).
2. **Layout per §9.1 (simplified):** header (site, connection state, degraded-mode banner when /health/ready is 503) · left: prioritised incident queue (severity badge, threat state, confidence, age) · centre: selected incident workspace — timeline (append-only, newest last, auto-scroll), related events with supporting/contradicting clearly separated and BOTH always visible (§11.4), response tasks with §76 delivery-state chips · right: presence list.
3. **Live behaviour:** socket events `incident.updated` / `hypothesis.updated` invalidate the right queries — queue and open workspace update without refresh; connection loss shows a truthful "stale since HH:MM:SS" indicator (never silently stale).
4. **Actions:** acknowledge task button (calls WP-07 ack endpoint; optimistic UI forbidden — state changes only on server confirmation, §66.2), close incident with mandatory reason.
5. **Honesty rules (§66.2):** confidence and severity displayed as separate values; contradicting evidence never hidden or collapsed by default; delivery states shown verbatim (REQUESTED/DELIVERED/ACKNOWLEDGED...), no fake "sent ✓".
6. Component tests (vitest + @testing-library/react + jsdom): queue ordering by severity then age; contradiction visibility; delivery-chip rendering; degraded banner logic.

## Acceptance criteria
1. Full flow visible live against the stack: simulator scenario → incident appears in queue → timeline grows → task ack from the UI moves chip to ACKNOWLEDGED.
2. Two-org isolation: switching dev user to another org empties the queue (server-scoped, not client-filtered).
3. Kill the API → stale indicator + degraded banner; recover → live again.
4. Tests green; typecheck/lint clean.

## Out of scope
Maps (Milestone 2), cameras, playbook editing, styling polish beyond a clean operator layout, auth UI.
