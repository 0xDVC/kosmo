package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "kosmo",
	Short: "Self-hosted deployment tool",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("usage: kosmo <command>")
	},
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
