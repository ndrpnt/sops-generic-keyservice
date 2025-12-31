package commands

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"syscall"

	"github.com/spf13/cobra"
)

var killCmd = &cobra.Command{
	Use:   "kill",
	Short: "Kill the running key service daemon(s)",
	Long:  `Send SIGTERM to the SOPS key service daemon(s) identified by SOPS_KEYSERVICE_PID.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := runKill(cmd, args); err != nil {
			return fmt.Errorf("failed to kill keyservice: %v", err)
		}

		return nil
	},
}

func init() {
	rootCmd.AddCommand(killCmd)
}

func runKill(cmd *cobra.Command, args []string) error {
	pidEnv := os.Getenv("SOPS_KEYSERVICE_PID")
	if pidEnv == "" {
		return fmt.Errorf("SOPS_KEYSERVICE_PID environment variable is not set")
	}

	pidStrs := strings.Split(pidEnv, ",")
	var killed []int
	var errs []error
	for _, pidStr := range pidStrs {
		pid, err := strconv.Atoi(strings.TrimSpace(pidStr))
		if err != nil {
			errs = append(errs, fmt.Errorf("invalid PID %q in SOPS_KEYSERVICE_PID: %v", pidStr, err))
			continue
		}

		process, err := os.FindProcess(pid)
		if err != nil {
			errs = append(errs, fmt.Errorf("failed to find process %d: %v", pid, err))
			continue
		}

		err = process.Signal(syscall.SIGTERM)
		if err != nil {
			errs = append(errs, fmt.Errorf("failed to send SIGTERM to process %d: %v", pid, err))
			continue
		}

		killed = append(killed, pid)
	}

	fmt.Println("unset SOPS_KEYSERVICE;")
	fmt.Println("unset SOPS_KEYSERVICE_PID;")
	for _, pid := range killed {
		fmt.Printf("echo SOPS key service pid %d killed;\n", pid)
	}

	return errors.Join(errs...)
}
