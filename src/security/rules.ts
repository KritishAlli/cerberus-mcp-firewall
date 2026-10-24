/**
 * OWNER: Winston — matchers and precedence (design doc §7).
 *
 * TODO(Winston): individual rule matchers used by evaluator.ts, e.g.
 *   matchDeniedTool, matchProtectedPath, matchDeniedDestination,
 *   matchDestructiveAction, matchApprovedTool.
 * Each should return a PolicyDecision or undefined ("no opinion").
 * Never rely on naive substring matches alone.
 */
export {};
