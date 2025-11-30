// Package generickms provides the [KMS] interface,
// to integrate SOPS with custom key management systems.
//
// This package currently provides the following example implementations:
//
//   - [github.com/ndrpnt/sops-generic-keyservice/scwkms]: [Scaleway Key Manager] integration
//   - [github.com/ndrpnt/sops-generic-keyservice/ovhkms]: [OVH Key Management Service] integration
//   - [github.com/ndrpnt/sops-generic-keyservice/noopkms]: No-op implementation for testing (returns data as-is)
//
// # Usage with SOPS
//
// This interface is designed to work with the [github.com/ndrpnt/sops-generic-keyservice/keyservice] package,
// which provides a [SOPS key service]-compatible gRPC server.
// The keyservice package extracts base64-encoded configuration
// from SOPS' '--kms <arn>' argument
// and passes it to the [KMS] implementation,
// allowing custom key management systems to be used with SOPS
// without the need to modify SOPS itself.
//
// [Scaleway Key Manager]: https://www.scaleway.com/en/key-manager
// [SOPS key service]: https://github.com/getsops/sops#key-service
// [OVH Key Management Service]: https://www.ovhcloud.com/en/identity-security-operations/key-management-service
package generickms
