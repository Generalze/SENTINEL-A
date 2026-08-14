import type { Zone } from '@prisma/client';
import { z } from 'zod';

export const CreateZoneSchema = z.object({
  name: z.string().min(1, 'name is required'),
});
export type CreateZoneDto = z.infer<typeof CreateZoneSchema>;

export interface ZoneResponse {
  id: string;
  site_id: string;
  name: string;
  created_at: string;
  updated_at: string;
}

export function toZoneResponse(zone: Zone): ZoneResponse {
  return {
    id: zone.id,
    site_id: zone.siteId,
    name: zone.name,
    created_at: zone.createdAt.toISOString(),
    updated_at: zone.updatedAt.toISOString(),
  };
}
