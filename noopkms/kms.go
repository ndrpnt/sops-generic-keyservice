// A [generickms] no-op implementation for testing.
package noopkms

import (
	"context"

	"github.com/ndrpnt/sops-generic-keyservice/generickms"
)

type noopKMS struct{}

func New() generickms.KMS { return &noopKMS{} }

func (*noopKMS) Encrypt(_ context.Context, _, plaintext []byte) ([]byte, error) {
	return plaintext, nil
}

func (*noopKMS) Decrypt(_ context.Context, _, ciphertext []byte) ([]byte, error) {
	return ciphertext, nil
}
