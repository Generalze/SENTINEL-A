import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { describe, expect, it } from 'vitest';

describe('incident append-only invariants', () => {
  it('never updates or deletes timeline rows', () => {
    const source = readFileSync(resolve(process.cwd(), 'src/modules/incidents/incidents.repository.ts'), 'utf8');
    expect(source).not.toMatch(/incidentTimelineEntry\.(update|updateMany|delete|deleteMany)\s*\(/);
    expect(source).toMatch(/incidentTimelineEntry\.create\s*\(/);
  });

  it('has one status transition authority and requires closure reason before close', () => {
    const source = readFileSync(resolve(process.cwd(), 'src/modules/incidents/incidents.service.ts'), 'utf8');
    expect(source).toMatch(/open: \['contained'\]/);
    expect(source).toMatch(/contained: \['closed'\]/);
    expect(source).toMatch(/closure_reason is required/);
  });
});
