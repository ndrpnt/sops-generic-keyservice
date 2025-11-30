package generickms

import "context"

// KMS is the interface that external key management systems must satisfy
// to integrate with SOPS.
//
// Implementations should handle provider-specific key information
// through the keyInfo parameter.
// keyInfo typically contains JSON-encoded configuration
// such as key ID, and additional associated data.
type KMS interface {
	// Encrypt encrypts the given plaintext using the key specified in keyInfo.
	Encrypt(ctx context.Context, keyInfo, plaintext []byte) (ciphertext []byte, err error)

	// Decrypt decrypts the given ciphertext using the key specified in keyInfo.
	Decrypt(ctx context.Context, keyInfo, ciphertext []byte) (plaintext []byte, err error)
}
