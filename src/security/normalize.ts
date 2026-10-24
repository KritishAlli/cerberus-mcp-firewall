/**
 * OWNER: Winston — path, URL and argument normalization (design doc §7).
 *
 * TODO(Winston):
 *   - normalize paths: separators, "..", tilde expansion, case rules for target OS
 *   - extract path arguments using policy.pathArgs (incl. arrays / nested objects)
 *   - parse URLs and normalize hostname/origin for policy.destinationArgs tools
 *   - malformed URL on a destination tool → caller should DENY
 * Document: static argument screening does not defend against symlink/TOCTOU
 * or file access hidden inside a remote tool.
 */
export {};
