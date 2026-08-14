import { BadRequestException } from '@nestjs/common';
import type { ZodSchema } from 'zod';
import { formatZodIssues } from '../../config/env.schema';

/**
 * The global validation pipe (`common/validation.pipe.ts`) is a
 * pass-through placeholder — WP-02 deliberately avoided a
 * class-validator/class-transformer dependency, so every module is
 * expected to validate its own request bodies. This mirrors
 * env.schema.ts's zod-failure formatting for a consistent error shape.
 */
export function parseOrThrow<T>(schema: ZodSchema<T>, value: unknown): T {
  const result = schema.safeParse(value);
  if (!result.success) {
    throw new BadRequestException(formatZodIssues(result.error).join('; '));
  }
  return result.data;
}
