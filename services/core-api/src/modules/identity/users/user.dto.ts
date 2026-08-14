import type { User, UserRole } from '@prisma/client';
import { z } from 'zod';
import { ROLES } from '../roles';

const RoleAssignmentInputSchema = z.object({
  role: z.enum(ROLES),
  /** Omitted or null = organisation-wide assignment. */
  site_id: z.string().min(1).nullable().optional(),
});

export const CreateUserSchema = z.object({
  email: z.string().email('email must be a valid email address'),
  display_name: z.string().min(1, 'display_name is required'),
  /** 0-5, matching the classification scale (architecture §47). */
  clearance: z.number().int().min(0).max(5),
  roles: z.array(RoleAssignmentInputSchema).min(1, 'at least one role is required'),
});
export type CreateUserDto = z.infer<typeof CreateUserSchema>;

export interface UserResponse {
  id: string;
  organisation_id: string;
  email: string;
  display_name: string;
  clearance: number;
  roles: Array<{ role: string; site_id: string | null }>;
  created_at: string;
  updated_at: string;
}

export function toUserResponse(user: User & { roles: UserRole[] }): UserResponse {
  return {
    id: user.id,
    organisation_id: user.organisationId,
    email: user.email,
    display_name: user.displayName,
    clearance: user.clearance,
    roles: user.roles.map((assignment) => ({ role: assignment.role, site_id: assignment.siteId })),
    created_at: user.createdAt.toISOString(),
    updated_at: user.updatedAt.toISOString(),
  };
}
