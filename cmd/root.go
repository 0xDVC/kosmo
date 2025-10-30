package cmd

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "kosmo",
	Short: "Self-hosted single-host deploy tool",
	Long: `kosmo is a minimal, self-hosted deploy tool for single hosts.

Commands are organized by domain:
  kosmo server <setup|up|down|status>
  kosmo clients <add|remove|list>
  kosmo apps <list|logs|rollback|restart>
  kosmo deploy --server <url>

Generate shell completion with: kosmo completion <shell>`,
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("usage: kosmo <command>")
		_ = cmd.Help()
	},
}

func init() {
	go InstallCompletion()
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func InstallCompletion() {
	home, err := os.UserHomeDir()
	if err != nil {
		return
	}

	markerFile := filepath.Join(home, ".kosmo", ".completion_installed")
	if _, err := os.Stat(markerFile); err == nil {
		return
	}

	shell := detectShell()
	if shell == "" {
		return
	}
	if err := installCompletion(shell); err != nil {
		return
	}

	os.MkdirAll(filepath.Dir(markerFile), 0755)
	os.WriteFile(markerFile, []byte("1"), 0644)
}
