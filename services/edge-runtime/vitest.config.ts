import { resolve } from 'node:path';
import { defineConfig } from 'vitest/config';

export default defineConfig({
  resolve: {
    alias: {
      /**
       * `node:sqlite` IS A PREFIX-ONLY BUILTIN, AND VITE-NODE DOES NOT KNOW IT.
       *
       * It resolves `node:x` by stripping the prefix and asking whether `x` is
       * in `module.builtinModules`. That works for every builtin with a bare
       * alias and fails for the handful that exist only under the prefix —
       * `node:sqlite` is one, exactly as `node:test` is — so the transform
       * pipeline goes looking for a package called `sqlite` and reports that
       * the file does not exist.
       *
       * The alias points at a shim that asks Node itself. It is scoped to the
       * TEST RUN: the production build is `tsc`, which emits a plain
       * `require('node:sqlite')` and never involves Vite, so the store's own
       * source stays free of workarounds for a bundler it does not use.
       */
      // eslint-disable-next-line no-undef -- CommonJS module scope. The shared root ESLint config does not register `__dirname` as a global and this package must not modify root config.
      'node:sqlite': resolve(__dirname, 'test/node-sqlite.shim.ts'),
    },
  },
  test: {
    globals: true,
    environment: 'node',
  },
});
