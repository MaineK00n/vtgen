package cmd

import (
	"fmt"

	"github.com/MaineK00n/vtgen/pkg/config"
	"github.com/spf13/cobra"
)

func init() {
	RootCmd.AddCommand(versionCmd)
}

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Show version",
	Long:  `Show version`,
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Printf("vtgen %s %s\n", config.Version, config.Revision)
	},
}
