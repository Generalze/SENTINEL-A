import { createRequire } from 'node:module';

/**
 * A TEST-RUNNER SHIM, AND NOTHING THE RUNTIME EVER LOADS.
 *
 * `node:sqlite` is a PREFIX-ONLY builtin: `module.builtinModules` lists
 * `node:sqlite` and has no bare `sqlite` alias, exactly as with `node:test`.
 * vite-node resolves a `node:x` specifier by stripping the prefix and asking
 * whether `x` is a builtin, so it concludes that `node:sqlite` is a package
 * called `sqlite` and fails to find it.
 *
 * `vitest.config.ts` aliases the specifier to this file for the test run only.
 * All it does is ask NODE to resolve the module, which is the answer vite-node
 * would have reached if it knew about prefix-only builtins.
 *
 * The production build is `tsc`, which emits a plain `require('node:sqlite')`
 * and never sees this file. Nothing about the store's behaviour depends on it —
 * if this shim were wrong, every queue spec would fail immediately rather than
 * pass against something other than SQLite.
 */
const nodeSqlite = createRequire(`${process.cwd()}/`)('node:sqlite') as typeof import('node:sqlite');

export const { DatabaseSync, StatementSync, constants } = nodeSqlite;
