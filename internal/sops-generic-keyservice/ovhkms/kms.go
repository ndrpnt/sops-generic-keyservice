// Package ovhkms is a [generickms.KMS] implementation
// for [OVH Key Management Service].
//
// [OVH Key Management Service]: https://www.ovhcloud.com/en/identity-security-operations/key-management-service
package ovhkms

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"

	"github.com/google/uuid"
	"github.com/ndrpnt/sops-generic-keyservice/internal/sops-generic-keyservice/generickms"
	"github.com/ovh/okms-sdk-go"
)

func New(logger *slog.Logger) (generickms.KMS, error) {
	if logger == nil {
		logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	}

	certFile := os.Getenv("OKMS_CLIENT_CERT_FILE")
	keyFile := os.Getenv("OKMS_CLIENT_KEY_FILE")
	if certFile == "" || keyFile == "" {
		return nil, errors.New("OVH KMS requires certificate files: set OKMS_CLIENT_CERT_FILE and OKMS_CLIENT_KEY_FILE")
	}

	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, fmt.Errorf("failed to load TLS certificates (cert: %q, key: %q): %v", err, certFile, keyFile)
	}

	return &kms{
		logger: logger.With("kms", "OVH Key Management Service"),
		client: &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{
					Certificates: []tls.Certificate{cert},
				},
			},
		},
	}, nil
}

type kmsKey struct {
	OkmsID   string `json:"okms_id"`
	KeyID    string `json:"key_id"`
	Endpoint string `json:"endpoint"`
	Context  string `json:"context"`
}

type kms struct {
	logger *slog.Logger
	client *http.Client
}

func (k *kms) Encrypt(ctx context.Context, keyInfo, plaintext []byte) ([]byte, error) {
	logger := k.logger.With("operation", "encrypt", "key_info", keyInfo, "plaintext_size", len(plaintext))
	logger.Debug("Starting encryption operation")

	var key *kmsKey
	err := json.Unmarshal(keyInfo, &key)
	if err != nil {
		logger.Error("Failed to parse key info", "error", err)
		return nil, fmt.Errorf("failed to parse key info: %v", err)
	}
	logger = logger.With("okms_id", key.OkmsID, "key_id", key.KeyID, "endpoint", key.Endpoint, "context", key.Context)
	logger.Debug("Successfully parsed key info")

	okmsUUID, err := uuid.Parse(key.OkmsID)
	if err != nil {
		logger.Error("Failed to parse OKMS ID", "error", err)
		return nil, fmt.Errorf("failed to parse OKMS ID: %v", err)
	}

	keyUUID, err := uuid.Parse(key.KeyID)
	if err != nil {
		logger.Error("Failed to parse key ID", "error", err)
		return nil, fmt.Errorf("failed to parse key ID: %v", err)
	}

	client, err := okms.NewRestAPIClientWithHttp(key.Endpoint, k.client)
	if err != nil {
		logger.Error("Failed to create OVH KMS client", "error", err)
		return nil, fmt.Errorf("failed to create OVH KMS client: %v", err)
	}

	jwe, err := client.Encrypt(ctx, okmsUUID, keyUUID, key.Context, plaintext)
	if err != nil {
		logger.Error("Failed to encrypt with OVH KMS", "error", err)
		return nil, fmt.Errorf("failed to encrypt with OVH KMS: %v", err)
	}

	logger = logger.With("ciphertext_size", len(jwe))
	logger.Info("Successfully encrypted data")
	return []byte(jwe), nil
}

func (k *kms) Decrypt(ctx context.Context, keyInfo, ciphertext []byte) ([]byte, error) {
	logger := k.logger.With("operation", "decrypt", "key_info", keyInfo, "ciphertext_size", len(ciphertext))
	logger.Debug("Starting decryption operation")

	var key *kmsKey
	err := json.Unmarshal(keyInfo, &key)
	if err != nil {
		logger.Error("Failed to parse key info", "error", err)
		return nil, fmt.Errorf("failed to parse key info: %v", err)
	}
	logger = logger.With("okms_id", key.OkmsID, "key_id", key.KeyID, "endpoint", key.Endpoint, "context", key.Context)
	logger.Debug("Successfully parsed key info")

	okmsUUID, err := uuid.Parse(key.OkmsID)
	if err != nil {
		logger.Error("Failed to parse OKMS ID", "error", err)
		return nil, fmt.Errorf("failed to parse OKMS ID: %v", err)
	}

	keyUUID, err := uuid.Parse(key.KeyID)
	if err != nil {
		logger.Error("Failed to parse key ID", "error", err)
		return nil, fmt.Errorf("failed to parse key ID: %v", err)
	}

	client, err := okms.NewRestAPIClientWithHttp(key.Endpoint, k.client)
	if err != nil {
		logger.Error("Failed to create OVH KMS client", "error", err)
		return nil, fmt.Errorf("failed to create OVH KMS client: %v", err)
	}

	plaintext, err := client.Decrypt(ctx, okmsUUID, keyUUID, key.Context, string(ciphertext))
	if err != nil {
		logger.Error("Failed to decrypt with OVH KMS", "error", err)
		return nil, fmt.Errorf("failed to decrypt with OVH KMS: %v", err)
	}

	logger = logger.With("plaintext_size", len(plaintext))
	logger.Info("Successfully decrypted data")
	return plaintext, nil
}
