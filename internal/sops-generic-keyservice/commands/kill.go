package commands

import (
	"fmt"
	"os"
	"strconv"
	"syscall"

	"github.com/spf13/cobra"
)

var killCmd = &cobra.Command{
	Use:   "kill",
	Short: "Kill the running key service daemon",
	Long:  `Send SIGTERM to the SOPS key service daemon identified by SOPS_KEYSERVICE_PID.`,
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
	pidStr := os.Getenv("SOPS_KEYSERVICE_PID")
	if pidStr == "" {
		return fmt.Errorf("SOPS_KEYSERVICE_PID environment variable is not set")
	}

	pid, err := strconv.Atoi(pidStr)
	if err != nil {
		return fmt.Errorf("invalid PID in SOPS_KEYSERVICE_PID: %s", pidStr)
	}

	process, err := os.FindProcess(pid)
	if err != nil {
		return fmt.Errorf("failed to find process %d: %v", pid, err)
	}

	err = process.Signal(syscall.SIGTERM)
	if err != nil {
		return fmt.Errorf("failed to send SIGTERM to process %d: %v", pid, err)
	}

	fmt.Println("unset SOPS_KEYSERVICE;")
	fmt.Println("unset SOPS_KEYSERVICE_PID;")
	fmt.Printf("echo SOPS key service pid %d killed;\n", pid)

	return nil
}
