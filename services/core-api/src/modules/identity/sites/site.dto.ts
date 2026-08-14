import type { Site } from '@prisma/client';
import { z } from 'zod';

export const CreateSiteSchema = z.object({
  name: z.string().min(1, 'name is required'),
});
export type CreateSiteDto = z.infer<typeof CreateSiteSchema>;

export interface SiteResponse {
  id: string;
  organisation_id: string;
  name: string;
  created_at: string;
  updated_at: string;
}

export function toSiteResponse(site: Site): SiteResponse {
  return {
    id: site.id,
    organisation_id: site.organisationId,
    name: site.name,
    created_at: site.createdAt.toISOString(),
    updated_at: site.updatedAt.toISOString(),
  };
}
