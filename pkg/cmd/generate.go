package cmd

import (
	"os"
	"path"

	"github.com/MaineK00n/vtgen/pkg/generator"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// generateCmd
var generateCmd = &cobra.Command{
	Use:   "generate",
	Short: "generate json",
	Long:  "generate json",
	RunE:  execute,
}

func init() {
	RootCmd.AddCommand(generateCmd)

	pwd := os.Getenv("PWD")
	RootCmd.PersistentFlags().String("config", path.Join(pwd, "config.toml"), "/path/to/config.toml")
	_ = viper.BindPFlag("config", RootCmd.PersistentFlags().Lookup("config"))

	RootCmd.PersistentFlags().String("output-dir", path.Join(pwd, "results"), "output file dir")
	_ = viper.BindPFlag("output-dir", RootCmd.PersistentFlags().Lookup("output-dir"))

	RootCmd.PersistentFlags().Bool("debug", false, "debug mode")
	_ = viper.BindPFlag("debug", RootCmd.PersistentFlags().Lookup("debug"))
}

func execute(cmd *cobra.Command, args []string) error {
	if err := generator.Generate(viper.GetString("config"), viper.GetString("output-dir")); err != nil {
		return err
	}
	return nil
}
