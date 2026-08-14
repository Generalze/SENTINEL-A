import { CanActivate, ExecutionContext, Inject, Injectable, Logger, UnauthorizedException } from '@nestjs/common';
import { AppConfigService } from '../../config/config.service';
import { PrismaService } from '../../prisma/prisma.service';
import type { RequestWithPrincipal } from './http-types';

const DEV_USER_HEADER = 'x-dev-user-id';

/**
 * ============================================================================
 * DEV-ONLY AUTHENTICATION — Milestone 1 placeholder. DO NOT treat as real
 * auth and DO NOT extend this mechanism.
 *
 * This guard trusts a client-supplied `x-dev-user-id` header outright: it
 * looks the id up and attaches that user's identity/roles to
 * `request.principal`. There is no password, session, token or signature
 * check of any kind — any caller that knows (or guesses) a user id can
 * fully impersonate that user. This is acceptable ONLY because Milestone 1
 * has no real authentication surface yet, and ONLY while
 * `DEV_AUTH_ENABLED=true`, which must never be true outside local/dev
 * environments. When the flag is false, every request this guard sees is
 * rejected with 401 — there is no fallback identity.
 *
 * Real authentication (OIDC) replaces this guard in a later milestone,
 * alongside device trust (Shield). See architecture §38, §62.
 * ============================================================================
 */
@Injectable()
export class DevAuthGuard implements CanActivate {
  private readonly logger = new Logger(DevAuthGuard.name);

  constructor(
    @Inject(AppConfigService) private readonly appConfig: AppConfigService,
    @Inject(PrismaService) private readonly prisma: PrismaService,
  ) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    if (!this.appConfig.values.DEV_AUTH_ENABLED) {
      throw new UnauthorizedException('Authentication is not available (DEV_AUTH_ENABLED=false)');
    }

    const request = context.switchToHttp().getRequest<RequestWithPrincipal>();
    const header = request.headers[DEV_USER_HEADER];
    const userId = Array.isArray(header) ? header[0] : header;
    if (!userId) {
      throw new UnauthorizedException(`Missing required '${DEV_USER_HEADER}' header`);
    }

    const user = await this.prisma.user.findUnique({
      where: { id: userId },
      include: { roles: true },
    });
    if (!user) {
      this.logger.warn(`dev-auth: unknown user id supplied via ${DEV_USER_HEADER}`);
      throw new UnauthorizedException('Unknown dev user');
    }

    request.principal = {
      user,
      roles: user.roles.map((assignment) => ({ role: assignment.role, site_id: assignment.siteId })),
      organisation_id: user.organisationId,
    };
    return true;
  }
}
