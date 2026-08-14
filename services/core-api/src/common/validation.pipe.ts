import { Injectable, PipeTransform } from '@nestjs/common';

/**
 * Global validation pipe placeholder.
 *
 * WP-02 has no domain DTOs yet ("no domain logic" is explicitly out of
 * scope), so there is nothing to validate today. This is wired globally
 * now purely as plumbing so a future WP can drop in real validation
 * (e.g. zod-schema-based, since `zod` is already an approved dependency)
 * without touching bootstrap wiring.
 *
 * We deliberately do NOT use @nestjs/common's built-in `ValidationPipe`:
 * its constructor eagerly calls `loadPackage('class-validator', ...)`
 * and `loadPackage('class-transformer', ...)`, and Nest's loadPackage
 * helper calls `process.exit(1)` if either is missing. Neither package
 * is on WP-02's approved dependency list, so using the built-in pipe
 * would crash the app on every boot.
 */
@Injectable()
export class GlobalValidationPipe implements PipeTransform {
  transform(value: unknown): unknown {
    return value;
  }
}
