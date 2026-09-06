import { Injectable } from '@nestjs/common';
import type { EdgeIdentityContext } from '@sentinel/contracts';
import { loadConfig, toEdgeIdentityContext, type EdgeConfig } from './env.schema';

/**
 * Validates the environment exactly once, at construction, and exposes the
 * typed result. Because Nest constructs this during bootstrap, a bad
 * configuration aborts boot before any listener starts — an Edge with a
 * malformed identity must not come up half-working and start witnessing.
 */
@Injectable()
export class EdgeConfigService {
  public readonly values: EdgeConfig;

  /**
   * The frozen identity shape, built once at boot. Everything downstream takes
   * this rather than the raw config, so no service can reach a value the
   * `.strict()` identity schema would have refused.
   */
  public readonly identity: EdgeIdentityContext;

  constructor() {
    this.values = loadConfig();
    this.identity = toEdgeIdentityContext(this.values);
  }
}
