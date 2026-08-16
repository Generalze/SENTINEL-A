import { defineConfig } from 'vitest/config';
import { resolve } from 'node:path';

export default defineConfig({
  root: '../../',
  resolve: { alias: {
    '@nestjs/core': resolve('../../services/core-api/node_modules/@nestjs/core'),
    '@nestjs/platform-express': resolve('../../services/core-api/node_modules/@nestjs/platform-express'),
    'socket.io-client': resolve('../../services/core-api/node_modules/socket.io-client'),
  } },
  test: { globals: true, environment: 'node', include: ['tests/integration/proof-a.test.ts'] },
});
