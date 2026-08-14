import { BadRequestException, ForbiddenException, Inject, Injectable } from '@nestjs/common';
import type { User, UserRole } from '@prisma/client';
import { PrismaService } from '../../../prisma/prisma.service';
import { ConstitutionService } from '../../constitution/constitution.service';
import { CLASSIFICATION_LEVELS, normaliseApproverId, type Approval, type ApproverRoles } from '../../constitution/constitution.engine';
import type { Principal } from '../principal';
import { intersectSiteScope, resolveListPage, type ListPageQuery, type ListPageResult } from '../list-pagination';
import type { CreateUserDto } from './user.dto';

/** The §62.1 action a user role-grant is gated by (registered in the baseline constitution policy). */
const USER_ROLE_GRANT_ACTION = 'user.role.grant';

/**
 * WP-14/M1 integration glue — maps an Identity §62 role to the Constitution
 * policy role(s) that carry the corresponding authority. The Constitution
 * evaluator speaks its own role vocabulary (platform.admin, org.security.director,
 * ...); Identity speaks §62 roles (admin, site.commander, ...). This is the ONLY
 * place the two are bridged, and it is applied to BOTH the actor and (after
 * server-side resolution) every approver. Milestone-1 minimal; extend as the
 * policy's role vocabulary is aligned in a later wave.
 */
const IDENTITY_TO_CONSTITUTION_ROLES: Readonly<Record<string, readonly string[]>> = {
  admin: ['platform.admin'],
  'site.commander': ['site.commander'],
  'evidence.custodian': ['evidence.custodian'],
};

function toConstitutionRoles(identityRoles: readonly string[]): string[] {
  return [...new Set(identityRoles.flatMap((role) => [...(IDENTITY_TO_CONSTITUTION_ROLES[role] ?? [])]))];
}

@Injectable()
export class UsersService {
  constructor(
    @Inject(PrismaService) private readonly prisma: PrismaService,
    @Inject(ConstitutionService) private readonly constitution: ConstitutionService,
  ) {}

  /**
   * WP-14 — user creation is a privileged, gated operation.
   *
   *  H3: clearance ceiling (`dto.clearance <= creator.clearance`) and every
   *      role `site_id` must belong to the creator's organisation.
   *  M1: the grant is evaluated against the Constitution for `user.role.grant`;
   *      the decision GATES the write (non-ALLOW → rejected) and the evaluation
   *      always lands in the Decision Ledger (ConstitutionService.evaluate).
   *  M2: approver authority is resolved SERVER-SIDE from Identity — the request
   *      body names approver user ids only, never their roles.
   *
   * All checks run before any write; a rejected grant persists nothing.
   */
  async create(principal: Principal, dto: CreateUserDto): Promise<User & { roles: UserRole[] }> {
    // H3.1 — clearance ceiling.
    if (dto.clearance > principal.user.clearance) {
      throw new ForbiddenException('Cannot create a user with a clearance above your own');
    }
    // H3.2 — every role site must be in the creator's org.
    await this.assertRoleSitesInOrganisation(principal, dto);

    // M1/M2 — Constitution gate on the role grant.
    const approverRoles = await this.resolveApproverRoles(principal, dto);
    const decision = await this.constitution.evaluate({
      action: USER_ROLE_GRANT_ACTION,
      actor: {
        userId: principal.user.id,
        roles: toConstitutionRoles(principal.roles.map((r) => r.role)),
        organisationId: principal.organisation_id,
        clearance: principal.user.clearance,
        deviceTrust: 'TRUSTED',
      },
      target: {
        organisationId: principal.organisation_id,
        classification: 'INTERNAL',
        classificationLevel: CLASSIFICATION_LEVELS.INTERNAL ?? 1,
      },
      approvals: this.buildApprovals(dto),
      approver_roles: approverRoles,
    });
    if (decision.decision !== 'ALLOW') {
      throw new ForbiddenException({
        message: `Constitution did not authorise ${USER_ROLE_GRANT_ACTION}`,
        decision: decision.decision,
        reasons: decision.reasons,
      });
    }

    return this.prisma.user.create({
      data: {
        organisationId: principal.organisation_id,
        email: dto.email,
        displayName: dto.display_name,
        clearance: dto.clearance,
        roles: {
          create: dto.roles.map((assignment) => ({ role: assignment.role, siteId: assignment.site_id ?? null })),
        },
      },
      include: { roles: true },
    });
  }

  private buildApprovals(dto: CreateUserDto): Approval[] {
    const at = new Date().toISOString();
    return (dto.approvals ?? []).map((a) => ({ userId: a.user_id, role: 'resolved-server-side', at }));
  }

  /**
   * M2: resolve each named approver's authority from Identity (their §62 roles
   * mapped to Constitution roles), keyed by the normalised user id the engine
   * compares on. Approvers must exist inside the creator's organisation; an
   * unknown or cross-org approver simply contributes no authority (fails closed).
   */
  private async resolveApproverRoles(principal: Principal, dto: CreateUserDto): Promise<ApproverRoles> {
    const ids = [...new Set((dto.approvals ?? []).map((a) => a.user_id))];
    if (ids.length === 0) return {};

    const approvers = await this.prisma.user.findMany({
      where: { id: { in: ids }, organisationId: principal.organisation_id },
      include: { roles: true },
    });

    const resolved: Record<string, string[]> = {};
    for (const approver of approvers) {
      resolved[normaliseApproverId(approver.id)] = toConstitutionRoles(approver.roles.map((r) => r.role));
    }
    return resolved;
  }

  /** Every site named in a role assignment must exist inside the principal's organisation (H3). */
  private async assertRoleSitesInOrganisation(principal: Principal, dto: CreateUserDto): Promise<void> {
    const siteIds = [...new Set(dto.roles.map((r) => r.site_id).filter((id): id is string => typeof id === 'string' && id.length > 0))];
    if (siteIds.length === 0) return;

    const found = await this.prisma.site.findMany({
      where: { id: { in: siteIds }, organisationId: principal.organisation_id },
      select: { id: true },
    });
    if (found.length !== siteIds.length) {
      const known = new Set(found.map((s) => s.id));
      const invalid = siteIds.filter((id) => !known.has(id));
      throw new BadRequestException(`site_id(s) not in your organisation: ${invalid.join(', ')}`);
    }
  }

  /**
   * WP-14/M4+M6: tenant-scoped, site-scope-intersected, capped + cursor-paged.
   * A user is visible to a `user.admin`-scoped principal when the principal
   * holds an org-wide (site_id null) user.admin grant, OR the user carries a
   * role assignment at one of the principal's granted sites.
   */
  async listForOrganisation(principal: Principal, query: ListPageQuery = {}): Promise<ListPageResult<User & { roles: UserRole[] }>> {
    const scope = intersectSiteScope(principal, 'user.admin');
    const page = resolveListPage(query);

    const where = {
      organisationId: principal.organisation_id,
      ...(scope.orgWide ? {} : { roles: { some: { siteId: { in: scope.siteIds } } } }),
    };

    const rows = await this.prisma.user.findMany({
      where,
      include: { roles: true },
      orderBy: [{ createdAt: 'desc' }, { id: 'desc' }],
      take: page.limit + 1,
      ...(page.cursor ? { cursor: { id: page.cursor }, skip: 1 } : {}),
    });

    return page.toResult(rows);
  }
}
