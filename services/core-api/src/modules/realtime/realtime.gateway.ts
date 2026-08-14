import { Inject, Injectable, Logger } from '@nestjs/common';
import { WebSocketGateway, WebSocketServer, type OnGatewayConnection, type OnGatewayDisconnect, type OnGatewayInit } from '@nestjs/websockets';
import type { DefaultEventsMap, Server, Socket } from 'socket.io';
import { AppConfigService } from '../../config/config.service';
import { PrismaService } from '../../prisma/prisma.service';
import { PresenceService } from './presence.service';
import { loadRealtimePrincipal } from './realtime-principal.loader';
import { orgRoom, resolveWsCorsOrigin, WS_EVENT_PRESENCE_CHANGED, WS_PATH } from './realtime.constants';
import type { RealtimePrincipal } from './realtime.types';

const DEV_USER_HEADER = 'x-dev-user-id';

interface RealtimeSocketData {
  principal?: RealtimePrincipal;
}

type RealtimeServer = Server<DefaultEventsMap, DefaultEventsMap, DefaultEventsMap, RealtimeSocketData>;
type RealtimeSocket = Socket<DefaultEventsMap, DefaultEventsMap, DefaultEventsMap, RealtimeSocketData>;

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

/**
 * Deliverables #1/#2: Socket.IO gateway on the shared HTTP server.
 *
 * Auth boundary (architecture §44A.11 — "server decides what a client may
 * see"): a `server.use(...)` middleware (registered in `afterInit`) runs
 * for every connection attempt, before Nest's `handleConnection` ever
 * fires. It loads the caller's principal from `x-dev-user-id`
 * (handshake.auth.userId, falling back to the same-named header) via a
 * local, defensive Prisma query (`realtime-principal.loader.ts` — WP-03's
 * identity module is concurrent work and out of this module's lane) and
 * rejects the connection outright (`next(error)`) if the flag is off, the
 * id is missing, or the id doesn't resolve to a real user. A rejected
 * socket never reaches `handleConnection` at all.
 *
 * Room selection: there is no `@SubscribeMessage('join')` handler
 * anywhere in this class — clients have no mechanism to request a room.
 * The ONLY room a socket ever joins is `org:{organisation_id}`, derived
 * in `handleConnection` from the principal the middleware attached to
 * `socket.data`, never from anything client-supplied. That satisfies
 * "cross-org subscription attempts are denied and logged" by construction
 * (denying an attempt that literally cannot be made) rather than by
 * accepting a room request and then checking it.
 */
@Injectable()
@WebSocketGateway({
  path: WS_PATH,
  cors: { origin: resolveWsCorsOrigin(), credentials: true },
})
export class RealtimeGateway implements OnGatewayInit<RealtimeServer>, OnGatewayConnection<RealtimeSocket>, OnGatewayDisconnect<RealtimeSocket> {
  /** Set by Nest once the gateway connects to the shared HTTP server. External callers should use `broadcastToOrg`, not this field directly. */
  @WebSocketServer()
  server?: RealtimeServer;

  private readonly logger = new Logger(RealtimeGateway.name);

  constructor(
    @Inject(PrismaService) private readonly prisma: PrismaService,
    @Inject(AppConfigService) private readonly appConfig: AppConfigService,
    @Inject(PresenceService) private readonly presence: PresenceService,
  ) {}

  afterInit(server: RealtimeServer): void {
    server.use((socket: RealtimeSocket, next: (error?: Error) => void) => {
      this.authenticate(socket).then(
        (principal) => {
          socket.data.principal = principal;
          next();
        },
        (error: unknown) => {
          this.logger.warn(`ws handshake rejected (socket ${socket.id}): ${errorMessage(error)}`);
          next(error instanceof Error ? error : new Error('Unauthorized'));
        },
      );
    });
  }

  async handleConnection(client: RealtimeSocket): Promise<void> {
    const principal = client.data.principal;
    if (!principal) {
      // Defence in depth only: the `afterInit` middleware already rejects
      // every connection without a valid principal before it can reach
      // here. This path should be unreachable in practice.
      this.logger.warn(`socket ${client.id} reached handleConnection with no principal; disconnecting`);
      client.disconnect(true);
      return;
    }

    await client.join(orgRoom(principal.organisation_id));
    this.logger.log(`socket ${client.id} connected: user=${principal.user_id} org=${principal.organisation_id}`);

    const wentOnline = await this.presence.recordConnect(principal.organisation_id, principal.user_id);
    if (wentOnline) {
      this.broadcastToOrg(principal.organisation_id, WS_EVENT_PRESENCE_CHANGED, {
        user_id: principal.user_id,
        online: true,
      });
    }
  }

  async handleDisconnect(client: RealtimeSocket): Promise<void> {
    const principal = client.data.principal;
    if (!principal) {
      return;
    }
    const wentOffline = await this.presence.recordDisconnect(principal.organisation_id, principal.user_id);
    if (wentOffline) {
      this.broadcastToOrg(principal.organisation_id, WS_EVENT_PRESENCE_CHANGED, {
        user_id: principal.user_id,
        online: false,
      });
    }
  }

  /**
   * Deliverables #3/#4: the only way anything (the NATS bridge, presence)
   * sends to an org room. `organisationId` must always come from
   * server-side state (a loaded principal, or a NATS subject) — never
   * from client input.
   */
  broadcastToOrg(organisationId: string, event: string, payload: unknown): void {
    if (!this.server) {
      this.logger.warn(`broadcastToOrg(${event}) dropped: socket.io server not yet initialised`);
      return;
    }
    this.server.to(orgRoom(organisationId)).emit(event, payload);
  }

  private async authenticate(socket: RealtimeSocket): Promise<RealtimePrincipal> {
    if (this.appConfig.values.DEV_AUTH_ENABLED !== true) {
      throw new Error('Authentication is not available (DEV_AUTH_ENABLED=false)');
    }

    const authUserId = socket.handshake.auth.userId;
    const headerUserId = socket.handshake.headers[DEV_USER_HEADER];
    const headerValue = Array.isArray(headerUserId) ? headerUserId[0] : headerUserId;
    const userId = typeof authUserId === 'string' && authUserId.length > 0 ? authUserId : headerValue;

    if (!userId) {
      throw new Error(`Missing user id (handshake.auth.userId or '${DEV_USER_HEADER}' header)`);
    }

    const principal = await loadRealtimePrincipal(this.prisma, userId);
    if (!principal) {
      throw new Error('Unknown dev user');
    }
    return principal;
  }
}
