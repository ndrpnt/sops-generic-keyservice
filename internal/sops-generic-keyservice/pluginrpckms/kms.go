// Package pluginrpckms is a [generickms.KMS] implementation
// backed by a plugin system built with [pluginrpc.com/pluginrpc].
package pluginrpckms

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"strings"

	sopsv1 "github.com/ndrpnt/sops-generic-keyservice/internal/gen/sops/v1"
	"github.com/ndrpnt/sops-generic-keyservice/internal/gen/sops/v1/sopsv1pluginrpc"
	"github.com/ndrpnt/sops-generic-keyservice/internal/sops-generic-keyservice/generickms"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/types/known/structpb"
	"pluginrpc.com/pluginrpc"
)

const pluginPrefix = "sops-pluginrpc-kms-"

func New(logger *slog.Logger) (generickms.KMS, error) {
	if logger == nil {
		logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	}

	return &kms{logger: logger.With("kms", "PluginRPC")}, nil
}

type kms struct {
	logger *slog.Logger
}

type kmsKey struct {
	plugin string
	config structpb.Struct
}

func (k *kms) Encrypt(ctx context.Context, keyInfo, plaintext []byte) ([]byte, error) {
	logger := k.logger.With("operation", "encrypt", "key_info", keyInfo, "plaintext_size", len(plaintext))
	logger.Debug("Starting encryption operation")

	key, err := parseKeyInfo(keyInfo)
	if err != nil {
		logger.Error("Failed to parse key info", "error", err)
		return nil, fmt.Errorf("failed to parse key info: %v", err)
	}
	logger = logger.With("plugin", key.plugin)
	logger.Debug("Successfully parsed key info")

	runnerClient := pluginrpc.NewClient(
		pluginrpc.NewExecRunner(pluginPrefix+key.plugin),
		pluginrpc.ClientWithStderr(&SlogWriter{
			logger: logger.With("program", pluginPrefix+key.plugin),
			level:  slog.LevelInfo,
		}),
	)
	client, err := sopsv1pluginrpc.NewKmsServiceClient(runnerClient)
	if err != nil {
		return nil, fmt.Errorf("failed to construct PluginRPC client: %v", err)
	}
	logger.Debug("Successfully created PluginRPC client")

	req := sopsv1.EncryptRequest_builder{
		Plaintext:     plaintext,
		Configuration: &key.config,
	}.Build()
	resp, err := client.Encrypt(context.Background(), req)
	if err != nil {
		logger.Error("Failed to encrypt with PluginRPC KMS", "error", err)
		return nil, fmt.Errorf("failed to encrypt with PluginRPC KMS: %v", err)
	}

	logger = logger.With("ciphertext_size", len(resp.GetCiphertext()))
	logger.Info("Successfully encrypted data")
	return resp.GetCiphertext(), nil
}

func (k *kms) Decrypt(ctx context.Context, keyInfo, ciphertext []byte) ([]byte, error) {
	logger := k.logger.With("operation", "decrypt", "key_info", keyInfo, "ciphertext_size", len(ciphertext))
	logger.Debug("Starting decryption operation")

	key, err := parseKeyInfo(keyInfo)
	if err != nil {
		logger.Error("Failed to parse key info", "error", err)
		return nil, fmt.Errorf("failed to parse key info: %v", err)
	}
	logger = logger.With("plugin", key.plugin)
	logger.Debug("Successfully parsed key info")

	runnerClient := pluginrpc.NewClient(
		pluginrpc.NewExecRunner(pluginPrefix+key.plugin),
		pluginrpc.ClientWithStderr(&SlogWriter{
			logger: logger.With("program", pluginPrefix+key.plugin),
			level:  slog.LevelInfo,
		}),
	)
	client, err := sopsv1pluginrpc.NewKmsServiceClient(runnerClient)
	if err != nil {
		return nil, fmt.Errorf("failed to construct PluginRPC client: %v", err)
	}
	logger.Debug("Successfully created PluginRPC client")

	req := sopsv1.DecryptRequest_builder{
		Ciphertext:    ciphertext,
		Configuration: &key.config,
	}.Build()
	resp, err := client.Decrypt(context.Background(), req)
	if err != nil {
		logger.Error("Failed to decrypt with PluginRPC KMS", "error", err)
		return nil, fmt.Errorf("failed to decrypt with PluginRPC KMS: %v", err)
	}

	logger = logger.With("plaintext_size", len(resp.GetPlaintext()))
	logger.Info("Successfully decrypted data")
	return resp.GetPlaintext(), nil
}

func parseKeyInfo(keyInfo []byte) (*kmsKey, error) {
	var key kmsKey
	err := protojson.Unmarshal(keyInfo, &key.config)
	if err != nil {
		return nil, err
	}

	key.plugin = key.config.GetFields()["plugin"].GetStringValue()
	if key.plugin == "" {
		return nil, errors.New("invalid or missing plugin name")
	}
	delete(key.config.GetFields(), "plugin")

	return &key, nil
}

type SlogWriter struct {
	logger *slog.Logger
	level  slog.Level
}

func (w *SlogWriter) Write(p []byte) (n int, err error) {
	w.logger.Log(context.Background(), w.level, strings.TrimSpace(string(p)))
	return len(p), nil
}
