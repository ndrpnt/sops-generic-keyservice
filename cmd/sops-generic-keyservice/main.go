package main

import (
	"os"

	"github.com/ndrpnt/sops-generic-keyservice/internal/sops-generic-keyservice/commands"
)

func main() {
	if err := commands.Execute(); err != nil {
		os.Exit(1)
	}
}
