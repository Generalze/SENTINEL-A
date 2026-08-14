import type { Organisation } from '@prisma/client';
import { z } from 'zod';

export const CreateOrganisationSchema = z.object({
  name: z.string().min(1, 'name is required'),
});
export type CreateOrganisationDto = z.infer<typeof CreateOrganisationSchema>;

/** API responses use snake_case field names, matching the rest of the platform's wire contracts (packages/contracts). */
export interface OrganisationResponse {
  id: string;
  name: string;
  created_at: string;
  updated_at: string;
}

export function toOrganisationResponse(organisation: Organisation): OrganisationResponse {
  return {
    id: organisation.id,
    name: organisation.name,
    created_at: organisation.createdAt.toISOString(),
    updated_at: organisation.updatedAt.toISOString(),
  };
}
