// A noop SOPS KMS plugin for testing,
// built with [pluginrpc.com/pluginrpc].
package main

import (
	"context"
	"fmt"

	sopsv1 "github.com/ndrpnt/sops-generic-keyservice/internal/gen/sops/v1"
	"github.com/ndrpnt/sops-generic-keyservice/internal/gen/sops/v1/sopsv1pluginrpc"
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

	registrar := pluginrpc.NewServerRegistrar()
	server := sopsv1pluginrpc.NewKmsServiceServer(pluginrpc.NewHandler(spec), kmsServiceHandler{})
	sopsv1pluginrpc.RegisterKmsServiceServer(registrar, server)

	return pluginrpc.NewServer(
		spec,
		registrar,
		pluginrpc.ServerWithDoc("A noop SOPS PluginRPC KMS plugin."),
	)
}

type kmsServiceHandler struct{}

func (kmsServiceHandler) Encrypt(_ context.Context, req *sopsv1.EncryptRequest) (*sopsv1.EncryptResponse, error) {
	return sopsv1.EncryptResponse_builder{
		Ciphertext: req.GetPlaintext(),
	}.Build(), nil
}

func (kmsServiceHandler) Decrypt(_ context.Context, req *sopsv1.DecryptRequest) (*sopsv1.DecryptResponse, error) {
	return sopsv1.DecryptResponse_builder{
		Plaintext: req.GetCiphertext(),
	}.Build(), nil
}
