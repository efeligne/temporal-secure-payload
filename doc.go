// Package securepayload provides selective payload encryption helpers for the
// Temporal Go SDK.
//
// The package encrypts only values explicitly wrapped with Sensitive(...). All
// other payloads remain unchanged.
//
// To work correctly, the same DataConverter must be configured on both the
// Temporal client (starter/BFF) and worker sides.
//
// Limitations:
//   - Search Attributes, WorkflowID, and logs are not protected by this
//     package.
//   - If a codec endpoint can decrypt payloads, users with access to that
//     endpoint can read decrypted values.
package securepayload
