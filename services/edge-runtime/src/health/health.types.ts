export type DependencyStatus = 'up' | 'down' | 'not_configured';

/**
 * A named readiness probe. Registered as a multi-provider so a lane that adds a
 * dependency adds its probe beside it, rather than editing a central switch
 * that then has to know about every module.
 */
export interface EdgeReadinessProbe {
  /** Stable key in the readiness body. Never a device, actor or site id. */
  readonly name: string;
  /** Must resolve, never throw — `guardedProbe` enforces that regardless. */
  check(): Promise<DependencyStatus>;
}

export interface ReadinessResult {
  readonly status: 'ok' | 'degraded';
  readonly dependencies: Readonly<Record<string, DependencyStatus>>;
}
