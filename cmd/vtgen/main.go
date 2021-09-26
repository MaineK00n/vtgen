package main

import (
	"fmt"
	"os"

	"github.com/MaineK00n/vtgen/pkg/cmd"
)

func main() {
	if err := cmd.RootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}
