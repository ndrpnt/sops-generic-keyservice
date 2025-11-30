// Package keyservice exposes a [github.com/getsops/sops/v3/keyservice.KeyServiceServer]
// that delegates encryption to a [generickms.KMS] implementation.
//
// It piggybacks on SOPS '--kms <arn>' flag,
// originally intended for AWS KMS,
// by repurposing it to pass arbitrary configuration
// to the underlying generic KMS implementation.
// This flag was chosen because:
//   - It is cleaner from a user perspective
//     than more technology-specific flags like '--gcp-kms', '--pgp', or '--age',
//   - SOPS applies minimal validation to its corresponding '<arn>' argument,
//     which let us pass arbitrary configuration
//     to the underlying generic KMS implementation.
//     Note that configuration still needs to be base64-encoded
//     to prevent SOPS from corrupting the data
//     by splitting on commas and trimming whitespace.
//
// Protobuf stubs contained in this package are extracted verbatim from [github.com/getsops/sops/v3/keyservice].
package keyservice
