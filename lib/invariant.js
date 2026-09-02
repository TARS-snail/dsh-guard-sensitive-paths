//#region lib/types/invariant.js
/**
* Package-owned invariant companion for `@deepseek-ai/dsh-guard-sensitive-paths`.
* @module @deepseek-ai/dsh-guard-sensitive-paths/invariant
*/
const PACKAGE_NAME = "@deepseek-ai/dsh-guard-sensitive-paths";
/** Cordis companion plugin name. */
const name = "sensitive-paths-invariant";
/** Service required before the companion can reserve package ownership. */
const inject = ["invariants"];
/**
* No runtime invariant: this stateless pre-execute policy owns no package-local event history or mutable
* data relation beyond the approval ask it emits.
*/
const install = () => {};
/**
* Register this package's invariant companion.
* @param ctx - Cordis context carrying the invariant service.
* @returns the installed registration's disposer after setup succeeds.
*/
const apply = (ctx) => Promise.resolve(ctx.invariants.register(PACKAGE_NAME, install));
//#endregion
export { apply, inject, name };
