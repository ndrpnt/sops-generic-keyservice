package commands

import (
	"github.com/spf13/cobra"
)

var verboseF, quietF int

var rootCmd = &cobra.Command{
	Use:          "sops-generic-keyservice",
	Short:        "A SOPS key service server supporting multiple KMS providers",
	SilenceUsage: true,
}

func init() {
	rootCmd.PersistentFlags().CountVarP(&verboseF, "verbose", "v", "increase verbosity")
	rootCmd.PersistentFlags().CountVarP(&quietF, "quiet", "q", "decrease verbosity")
}

func Execute() error {
	return rootCmd.Execute()
}
