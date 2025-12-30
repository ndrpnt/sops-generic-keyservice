// A SOPS KMS plugin for [Scaleway Key Manager],
// built with [pluginrpc.com/pluginrpc].
//
// [Scaleway Key Manager]: https://www.scaleway.com/en/key-manager
package main

import (
	"context"
	"encoding/json"
	"fmt"

	sopsv1 "github.com/ndrpnt/sops-generic-keyservice/internal/gen/sops/v1"
	"github.com/ndrpnt/sops-generic-keyservice/internal/gen/sops/v1/sopsv1pluginrpc"
	key_manager "github.com/scaleway/scaleway-sdk-go/api/key_manager/v1alpha1"
	"github.com/scaleway/scaleway-sdk-go/scw"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/types/known/structpb"
	"pluginrpc.com/pluginrpc"
)

func main() {
	pluginrpc.Main(newServer)
}

func newServer() (pluginrpc.Server, error) {
	spec, err := sopsv1pluginrpc.KmsServiceSpecBuilder{
		Encrypt: []pluginrpc.ProcedureOption{pluginrpc.ProcedureWithArgs("encrypt")},
		Decrypt: []pluginrpc.ProcedureOption{pluginrpc.ProcedureWithArgs("decrypt")},
	}.Build()
	if err != nil {
		return nil, fmt.Errorf("failed to build PluginRPC spec: %v", err)
	}

	handler, err := newKmsServiceHandler()
	if err != nil {
		return nil, fmt.Errorf("failed to build KmsService handler: %v", err)
	}

	registrar := pluginrpc.NewServerRegistrar()
	server := sopsv1pluginrpc.NewKmsServiceServer(pluginrpc.NewHandler(spec), handler)
	sopsv1pluginrpc.RegisterKmsServiceServer(registrar, server)

	return pluginrpc.NewServer(
		spec,
		registrar,
		pluginrpc.ServerWithDoc("A SOPS PluginRPC KMS plugin backed by Scaleway Key Manager."),
	)
}

type kmsKeyConfiguration struct {
	ID             string `json:"id"`
	Region         string `json:"region"`
	AssociatedData []byte `json:"associated_data"`
}

func unmarshalConfiguration(pb *structpb.Struct) (*kmsKeyConfiguration, error) {
	jsonBytes, err := protojson.Marshal(pb)
	if err != nil {
		return nil, err
	}

	var config kmsKeyConfiguration
	if err := json.Unmarshal(jsonBytes, &config); err != nil {
		return nil, err
	}

	return &config, nil
}

type kmsServiceHandler struct {
	client *key_manager.API
}

func newKmsServiceHandler() (*kmsServiceHandler, error) {
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
		scw.WithUserAgent("sops-pluginrpc-kms-scaleway"),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create Scaleway client: %v", err)
	}

	return &kmsServiceHandler{client: key_manager.NewAPI(client)}, nil
}

func (h *kmsServiceHandler) Encrypt(ctx context.Context, req *sopsv1.EncryptRequest) (*sopsv1.EncryptResponse, error) {
	config, err := unmarshalConfiguration(req.GetConfiguration())
	if err != nil {
		return nil, pluginrpc.NewError(
			pluginrpc.Code(pluginrpc.CodeInvalidArgument),
			fmt.Errorf("failed to unmarshal configuration: %v", err),
		)
	}

	resp, err := h.client.Encrypt(&key_manager.EncryptRequest{
		KeyID:          config.ID,
		Plaintext:      req.GetPlaintext(),
		AssociatedData: &config.AssociatedData,
		Region:         scw.Region(config.Region),
	}, scw.WithContext(ctx))
	if err != nil {
		return nil, pluginrpc.NewError(
			pluginrpc.Code(pluginrpc.CodeUnknown),
			fmt.Errorf("failed to encrypt with Scaleway KMS: %v", err),
		)
	}

	return sopsv1.EncryptResponse_builder{
		Ciphertext: resp.Ciphertext,
	}.Build(), nil
}

func (h *kmsServiceHandler) Decrypt(ctx context.Context, req *sopsv1.DecryptRequest) (*sopsv1.DecryptResponse, error) {
	config, err := unmarshalConfiguration(req.GetConfiguration())
	if err != nil {
		return nil, pluginrpc.NewError(
			pluginrpc.Code(pluginrpc.CodeInvalidArgument),
			fmt.Errorf("failed to unmarshal configuration: %v", err),
		)
	}

	resp, err := h.client.Decrypt(&key_manager.DecryptRequest{
		KeyID:          config.ID,
		Ciphertext:     req.GetCiphertext(),
		AssociatedData: &config.AssociatedData,
		Region:         scw.Region(config.Region),
	}, scw.WithContext(ctx))
	if err != nil {
		return nil, pluginrpc.NewError(
			pluginrpc.Code(pluginrpc.CodeUnknown),
			fmt.Errorf("failed to decrypt with Scaleway KMS: %v", err),
		)
	}

	return sopsv1.DecryptResponse_builder{
		Plaintext: resp.Plaintext,
	}.Build(), nil
}
