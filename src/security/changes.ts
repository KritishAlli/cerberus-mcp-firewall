/** Pure staged-file policy evaluation. No I/O, logging, or proxy dependencies. */
import {
  FileChangeSchema,
  FirewallPolicySchema,
  type ChangeDecision,
  type EvaluateFileChanges,
  type FileChange,
  type FirewallPolicy,
} from '../shared/contracts.js';
import { pathMatches } from './normalize.js';
import { containsSecretPattern } from './secrets.js';

const MAX_REASON = 200;

function deny(
  change: FileChange,
  ruleId: ChangeDecision['ruleId'],
  reason: string,
): ChangeDecision {
  return { path: change.path, decision: 'DENY', ruleId, reason: reason.slice(0, MAX_REASON) };
}

function validateInput(changes: FileChange[], policy: FirewallPolicy): boolean {
  return Array.isArray(changes)
    && changes.every((change) => FileChangeSchema.safeParse(change).success)
    && FirewallPolicySchema.safeParse(policy).success;
}

/**
 * Evaluate staged changes in input order. Missing staging policy, malformed input,
 * and oversized batches all deny; no invalid or unknown change can become an ALLOW.
 */
export const evaluateFileChanges: EvaluateFileChanges = (changes, policy) => {
  if (!Array.isArray(changes)) return [];

  if (!validateInput(changes, policy)) {
    // Keep the source path in each result so the proxy's schema/order validation
    // also fails closed if a caller supplied an unrepresentable path.
    return changes.map((change) => {
      if (typeof change !== 'object' || change === null || typeof change.path !== 'string') {
        return {
          path: '__invalid__',
          decision: 'DENY',
          ruleId: 'INVALID_ARGUMENTS',
          reason: 'File change or policy is invalid',
        } as ChangeDecision;
      }
      return deny(change, 'INVALID_ARGUMENTS', 'File change or policy is invalid');
    });
  }

  const staging = policy.staging;
  if (!staging) {
    return changes.map((change) => deny(change, 'WRITE_NOT_ALLOWED', 'Staged writes are not enabled by policy'));
  }

  if (changes.length > staging.maxChangesPerCall) {
    return changes.map((change) => deny(change, 'CHANGE_LIMIT', 'Change batch exceeds the configured limit'));
  }

  return changes.map((change) => evaluateChange(change, policy, staging));
};

function evaluateChange(
  change: FileChange,
  policy: FirewallPolicy,
  staging: NonNullable<FirewallPolicy['staging']>,
): ChangeDecision {
  if (policy.protectedPaths.some((pattern) => pathMatches(change.path, pattern))) {
    return deny(change, 'PROTECTED_PATH', 'Path is protected by policy');
  }

  if (staging.protectedWritePaths.some((pattern) => pathMatches(change.path, pattern))) {
    return deny(change, 'PERSISTENCE_PATH', 'Path is a protected persistence location');
  }

  if (!staging.writablePaths.some((pattern) => pathMatches(change.path, pattern))) {
    return deny(change, 'WRITE_NOT_ALLOWED', 'Path is outside the configured writable paths');
  }

  if (change.kind === 'symlink' || change.kind === 'special') {
    return deny(change, 'SYMLINK_DENIED', 'Symlink and special file changes are not applied');
  }

  if (change.executable === true) {
    return deny(change, 'EXECUTABLE_DENIED', 'Executable file changes are not allowed');
  }

  if (change.size !== undefined && change.size > staging.maxFileBytes) {
    return deny(change, 'CHANGE_LIMIT', 'File exceeds the configured size limit');
  }

  if (typeof change.text === 'string' && containsSecretPattern(change.text)) {
    return deny(change, 'SECRET_DETECTED', 'Sensitive credential material in file changes is blocked');
  }

  return {
    path: change.path,
    decision: 'ALLOW',
    ruleId: 'APPROVED_TOOL',
    reason: 'File change is within the configured writable policy',
  };
}
