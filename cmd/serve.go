package cmd

import (
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"slices"
	"strings"
	"syscall"

	"github.com/ndrpnt/sops-generic-keyservice/generickms"
	"github.com/ndrpnt/sops-generic-keyservice/keyservice"
	"github.com/ndrpnt/sops-generic-keyservice/noopkms"
	"github.com/ndrpnt/sops-generic-keyservice/ovhkms"
	"github.com/ndrpnt/sops-generic-keyservice/scwkms"
	"github.com/spf13/cobra"
	"google.golang.org/grpc"
)

type enumValue struct {
	value    string
	variants []string
	typ      string
}

func (e *enumValue) String() string {
	return e.value
}

func (e *enumValue) Set(v string) error {
	if !slices.Contains(e.variants, v) {
		return fmt.Errorf("must be one of [%s]", strings.Join(e.variants, ", "))
	}

	e.value = v
	return nil
}

func (e *enumValue) Type() string {
	return "string"
}

var (
	networkF     = enumValue{value: "unix", variants: []string{"tcp", "unix"}}
	addressF     string
	kmsProviderF = enumValue{variants: []string{"scaleway", "ovh", "noop"}}
	daemonF      bool
)

var serveCmd = &cobra.Command{
	Use:   "serve",
	Short: "Start the key service server",
	Long: `Start a SOPS-compatible gRPC key service server.

When sops-generic-keyservice runs in daemon mode,
it prints the shell commands required to set its environment variables,
which in turn can be evaluated in the calling shell.

For example running "eval $(sops-generic-keyservice serve --kms-provider noop -d)"
configures SOPS to use the keyservice by setting SOPS_KEYSERVICE.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := runServe(cmd, args); err != nil {
			return fmt.Errorf("failed to start keyservice server: %v", err)
		}

		return nil
	},
}

func init() {
	rootCmd.AddCommand(serveCmd)

	serveCmd.Flags().Var(&networkF, "network", "network type (tcp, unix)")
	serveCmd.Flags().StringVar(&addressF, "address", "", "listen address (for tcp) or socket path (for unix) (defaults to a random port on localhost for tcp, or a temporary file for unix)")
	serveCmd.Flags().Var(&kmsProviderF, "kms-provider", "KMS provider to use (scaleway, ovh, noop)")
	serveCmd.Flags().BoolVarP(&daemonF, "daemon", "d", false, "run in daemon mode")
	serveCmd.MarkFlagRequired("kms-provider")
}

func runServe(cmd *cobra.Command, args []string) error {
	kmsProvider := kmsProviderF.String()
	network := networkF.String()
	address, err := selectAddress(network, addressF)
	if err != nil {
		return fmt.Errorf("failed to select an address: %v", err)
	}
	fullAddress := fmt.Sprintf("%s://%s", network, address)

	if daemonF {
		exe, err := os.Executable()
		if err != nil {
			return fmt.Errorf("failed to get executable path: %v", err)
		}

		cmd := exec.Command(exe, "serve",
			"--network", network,
			"--address", address,
			"--kms-provider", kmsProvider,
		)
		cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
		if err := cmd.Start(); err != nil {
			return fmt.Errorf("failed to start daemon: %v", err)
		}

		pid := cmd.Process.Pid
		fmt.Printf("export SOPS_KEYSERVICE=\"$SOPS_KEYSERVICE${SOPS_KEYSERVICE:+,}%s\";\n", fullAddress)
		fmt.Printf("export SOPS_KEYSERVICE_PID=%d;\n", pid)
		fmt.Printf("echo SOPS key service pid %d;\n", pid)

		return nil
	}

	level := int(slog.LevelInfo) - (verboseF * 4) + (quietF * 4)
	handler := slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.Level(level),
	})
	logger := slog.New(handler).With(
		"flag.network", networkF.String(),
		"flag.address", addressF,
		"flag.kms-provider", kmsProviderF.String(),
		"flag.daemon", daemonF,
		"address", fullAddress,
	)

	lis, err := net.Listen(network, address)
	if err != nil {
		return fmt.Errorf("failed to listen: %v", err)
	}
	if network == "unix" {
		defer func() {
			if err := os.Remove(address); err != nil && !os.IsNotExist(err) {
				logger.Warn("Failed to remove socket file", "error", err)
			}
		}()
	}
	defer lis.Close()

	kms, err := initializeKMS(kmsProvider, logger)
	if err != nil {
		return fmt.Errorf("failed to initialize the KMS: %v", err)
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

func initializeKMS(provider string, logger *slog.Logger) (generickms.KMS, error) {
	var kms generickms.KMS
	var err error

	switch provider {
	case "scaleway":
		kms, err = scwkms.New(logger)
		if err != nil {
			return nil, fmt.Errorf("failed to instantiate Scaleway Key Manager client: %v", err)
		}
	case "ovh":
		kms, err = ovhkms.New(logger)
		if err != nil {
			return nil, fmt.Errorf("failed to instantiate OVH Key Manager client: %v", err)
		}
	case "noop":
		kms = noopkms.New()
		logger.Warn("Using no-op KMS provider - for testing only, does not provide real encryption")
	default:
		return nil, fmt.Errorf("unknown KMS provider: %s (valid options: scaleway, ovh, noop)", provider)
	}

	return kms, nil
}

func selectAddress(network string, address string) (string, error) {
	if network == "unix" && address == "" {
		sock := fmt.Sprintf("sops-keyservice-%d.sock", os.Getpid())
		return filepath.Join(os.TempDir(), sock), nil
	}

	if network == "tcp" {
		tmpAddr := "127.0.0.1:0"
		if address != "" {
			tmpAddr = address
		}

		// Bind temporarily to get the actual port
		lis, err := net.Listen("tcp", tmpAddr)
		if err != nil {
			return "", fmt.Errorf("failed to listen: %v", err)
		}
		defer lis.Close()

		return lis.Addr().String(), nil
	}

	return address, nil
}
