// A [generickms.KMS] implementation for [Scaleway Key Manager].
//
// [Scaleway Key Manager]: https://www.scaleway.com/en/key-manager
package scwkms

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"

	"github.com/ndrpnt/sops-generic-keyservice/generickms"
	key_manager "github.com/scaleway/scaleway-sdk-go/api/key_manager/v1alpha1"
	"github.com/scaleway/scaleway-sdk-go/scw"
)

func New(logger *slog.Logger) (generickms.KMS, error) {
	if logger == nil {
		logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	}

	// FIXME: quick-and-dirty config loading that is broken in many ways.
	config, err := scw.LoadConfig()
	if err != nil {
		return nil, fmt.Errorf("failed to load Scaleway config: %v", err)
	}

	configProfile, err := config.GetActiveProfile()
	if err != nil {
		return nil, fmt.Errorf("failed to get active Scaleway profile: %v", err)
	}

	profile := scw.MergeProfiles(configProfile, scw.LoadEnvProfile())
	client, err := scw.NewClient(
		scw.WithProfile(profile),
		scw.WithUserAgent("sops-generic-keyservice"),
	)
	if err != nil {
		logger.Error("Failed to create Scaleway client", "error", err)
		return nil, fmt.Errorf("failed to create Scaleway client: %v", err)
	}
	logger.Debug("Successfully created Scaleway client")

	return &kms{
		logger: logger.With("kms", "Scaleway Key Manager"),
		client: key_manager.NewAPI(client),
	}, nil
}

type kmsKey struct {
	ID             string `json:"id"`
	Region         string `json:"region"`
	AssociatedData []byte `json:"associated_data"`
}

type kms struct {
	logger *slog.Logger
	client *key_manager.API
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
	logger = logger.With("key_id", key.ID, "key_region", key.Region, "associated_data", key.AssociatedData)
	logger.Debug("Successfully parsed key info")

	resp, err := k.client.Encrypt(&key_manager.EncryptRequest{
		KeyID:          key.ID,
		Plaintext:      plaintext,
		AssociatedData: &key.AssociatedData,
		Region:         scw.Region(key.Region),
	}, scw.WithContext(ctx))
	if err != nil {
		logger.Error("Failed to encrypt with Scaleway KMS", "error", err)
		return nil, fmt.Errorf("failed to encrypt with Scaleway KMS: %v", err)
	}

	logger = logger.With("ciphertext_size", len(resp.Ciphertext))
	logger.Info("Successfully encrypted data")
	return resp.Ciphertext, nil
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
	logger = logger.With("key_id", key.ID, "key_region", key.Region, "associated_data", key.AssociatedData)
	logger.Debug("Successfully parsed key info")

	resp, err := k.client.Decrypt(&key_manager.DecryptRequest{
		KeyID:          key.ID,
		Ciphertext:     ciphertext,
		AssociatedData: &key.AssociatedData,
		Region:         scw.Region(key.Region),
	}, scw.WithContext(ctx))
	if err != nil {
		logger.Error("Failed to decrypt with Scaleway KMS", "error", err)
		return nil, fmt.Errorf("failed to decrypt with Scaleway KMS: %v", err)
	}

	logger = logger.With("plaintext_size", len(resp.Plaintext))
	logger.Info("Successfully decrypted data")
	return resp.Plaintext, nil
}
