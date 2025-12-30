// Package noopkms is a [generickms.KMS] no-op implementation for testing.
package noopkms

import (
	"context"

	"github.com/ndrpnt/sops-generic-keyservice/internal/sops-generic-keyservice/generickms"
)

func New() generickms.KMS { return &kms{} }

type kms struct{}

func (*kms) Encrypt(_ context.Context, _, plaintext []byte) ([]byte, error) {
	return plaintext, nil
}

func (*kms) Decrypt(_ context.Context, _, ciphertext []byte) ([]byte, error) {
	return ciphertext, nil
}
