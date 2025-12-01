package cmd

import (
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"syscall"

	"github.com/ndrpnt/sops-generic-keyservice/generickms"
	"github.com/ndrpnt/sops-generic-keyservice/keyservice"
	"github.com/ndrpnt/sops-generic-keyservice/noopkms"
	"github.com/ndrpnt/sops-generic-keyservice/ovhkms"
	"github.com/ndrpnt/sops-generic-keyservice/scwkms"
	"github.com/spf13/cobra"
	"google.golang.org/grpc"
)

var (
	network     string
	address     string
	kmsProvider string
)

var serveCmd = &cobra.Command{
	Use:   "serve",
	Short: "Start the key service server",
	Long: `Start a SOPS-compatible gRPC key service server.
Configure SOPS with: sops --keyservice unix:///tmp/sops.sock`,
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := runServe(cmd, args); err != nil {
			return fmt.Errorf("failed to start keyservice server: %v", err)
		}

		return nil
	},
}

func init() {
	rootCmd.AddCommand(serveCmd)

	serveCmd.Flags().StringVar(&network, "network", "unix", "network type (tcp, unix)")
	serveCmd.Flags().StringVar(&address, "address", "/tmp/sops.sock", "listen address (for tcp) or socket path (for unix)")
	serveCmd.Flags().StringVar(&kmsProvider, "kms-provider", "", "KMS provider to use (scaleway, ovh, noop)")
	serveCmd.MarkFlagRequired("kms-provider")
}

func runServe(cmd *cobra.Command, args []string) error {
	level := int(slog.LevelInfo) - (verbose * 4) + (quiet * 4)
	handler := slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.Level(level),
	})
	logger := slog.New(handler).
		With("network", network, "address", address, "kms-provider", kmsProvider)

	lis, err := net.Listen(network, address)
	if err != nil {
		return fmt.Errorf("failed to listen: %v", err)
	}
	defer lis.Close()

	var kms generickms.KMS
	switch kmsProvider {
	case "scaleway":
		kms, err = scwkms.New(logger)
		if err != nil {
			return fmt.Errorf("failed to instantiate Scaleway Key Manager client: %v", err)
		}
	case "ovh":
		kms, err = ovhkms.New(logger)
		if err != nil {
			return fmt.Errorf("failed to instantiate OVH Key Manager client: %v", err)
		}
	case "noop":
		kms = noopkms.New()
		logger.Warn("Using no-op KMS provider - for testing only, does not provide real encryption")
	default:
		return fmt.Errorf("unknown KMS provider: %s (valid options: scaleway, ovh, noop)", kmsProvider)
	}

	grpcServer := grpc.NewServer()
	keyservice.RegisterKeyServiceServer(grpcServer, keyservice.New(kms))

	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)
	go func(c chan os.Signal) {
		sig := <-c
		logger.Info("Received signal, gracefully stopping keyservice", "signal", sig)
		grpcServer.GracefulStop()
	}(c)

	logger.Info("Starting keyservice")
	if err := grpcServer.Serve(lis); err != nil {
		return fmt.Errorf("failed to serve: %v", err)
	}

	return nil
}
