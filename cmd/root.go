package cmd

import (
	"github.com/spf13/cobra"
)

var verbose, quiet int

var rootCmd = &cobra.Command{
	Use:   "sops-generic-keyservice",
	Short: "A SOPS key service server supporting multiple KMS providers",
}

func init() {
	rootCmd.PersistentFlags().CountVarP(&verbose, "verbose", "v", "increase verbosity")
	rootCmd.PersistentFlags().CountVarP(&quiet, "quiet", "q", "decrease verbosity")
}

func Execute() error {
	return rootCmd.Execute()
}
