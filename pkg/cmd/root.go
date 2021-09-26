package cmd

import (
	"github.com/spf13/cobra"
)

// RootCmd
var RootCmd = &cobra.Command{
	Use:           "vtgen",
	Short:         "vuls test JSON generator",
	Long:          "vuls test JSON generator",
	SilenceErrors: true,
	SilenceUsage:  true,
}
