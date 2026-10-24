/**
 * Reject-all stand-in for Winston's evaluateFileChanges (src/security/changes.ts),
 * so the staging path can be built and tested before the real evaluator lands.
 * Denies every change, one decision per input, in the same order.
 */
import type { ChangeDecision, EvaluateFileChanges } from '../../shared/contracts.js';

export const evaluateFileChangesStub: EvaluateFileChanges = (changes) =>
  changes.map(
    (change): ChangeDecision => ({
      path: change.path,
      decision: 'DENY',
      ruleId: 'WRITE_NOT_ALLOWED',
      reason: 'Staging evaluator not yet implemented',
    }),
  );
