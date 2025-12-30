package keyservice

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"

	"github.com/ndrpnt/sops-generic-keyservice/internal/sops-generic-keyservice/generickms"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func New(kms generickms.KMS) KeyServiceServer {
	return &server{kms: kms}
}

type server struct {
	UnimplementedKeyServiceServer

	kms generickms.KMS
}

func (s *server) Encrypt(ctx context.Context, req *EncryptRequest) (*EncryptResponse, error) {
	keyInfo, err := extractKeyInfo(req.Key.KeyType)
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}

	ciphertext, err := s.kms.Encrypt(ctx, keyInfo, req.Plaintext)
	if err != nil {
		return nil, status.Errorf(codes.Unknown, "Failed to encrypt: %v", err)
	}

	return &EncryptResponse{Ciphertext: ciphertext}, nil
}

func (s *server) Decrypt(ctx context.Context, req *DecryptRequest) (*DecryptResponse, error) {
	keyInfo, err := extractKeyInfo(req.Key.KeyType)
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}

	plaintext, err := s.kms.Decrypt(ctx, keyInfo, req.Ciphertext)
	if err != nil {
		return nil, status.Errorf(codes.Unknown, "Failed to decrypt: %v", err)
	}

	return &DecryptResponse{Plaintext: plaintext}, nil
}

func extractKeyInfo(kt isKey_KeyType) ([]byte, error) {
	switch k := kt.(type) {
	case *Key_KmsKey:
		keyInfo, err := base64.StdEncoding.DecodeString(k.KmsKey.Arn)
		if err != nil {
			return nil, fmt.Errorf("Failed to base64 decode key info: %v", err)
		}
		return keyInfo, nil
	case *Key_PgpKey, *Key_AgeKey, *Key_GcpKmsKey, *Key_AzureKeyvaultKey, *Key_VaultKey:
		return nil, errors.New("Unsupported key type")
	case nil:
		return nil, errors.New("Missing key type")
	}

	return nil, errors.New("Unknown key type")
}
