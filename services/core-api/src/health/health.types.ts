export type DependencyStatus = 'up' | 'down' | 'not_configured';

export interface ReadinessDependencies {
  database: DependencyStatus;
  nats: DependencyStatus;
  redis: DependencyStatus;
}

export interface ReadinessResult {
  status: 'ok' | 'degraded';
  dependencies: ReadinessDependencies;
}
