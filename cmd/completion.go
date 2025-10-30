package cmd

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"
)

func init() {
	rootCmd.AddCommand(completionCmd)
}

var completionCmd = &cobra.Command{
	Use:   "completion",
	Short: "Install shell completion for current shell",
	Long: `Automatically detect and install completion for your current shell.

Supported shells: bash, zsh, fish

Detects $SHELL and installs completion to the appropriate location.`,
	Run: func(cmd *cobra.Command, args []string) {
		shell := detectShell()
		if shell == "" {
			fmt.Println("could not detect shell; set SHELL env var or pass shell explicitly")
			fmt.Println("usage: kosmo completion [bash|zsh|fish]")
			os.Exit(1)
		}

		if err := installCompletion(shell); err != nil {
			fmt.Printf("failed to install completion: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("completion installed for %s\n", shell)
		fmt.Println("restart your shell or source the completion file to enable")
	},
	ValidArgs: []string{"bash", "zsh", "fish"},
	Args:      cobra.MaximumNArgs(1),
}

func detectShell() string {
	shellPath := os.Getenv("SHELL")
	if shellPath == "" {
		return ""
	}
	shell := filepath.Base(shellPath)
	switch shell {
	case "bash", "zsh", "fish":
		return shell
	default:
		return ""
	}
}

func installCompletion(shell string) error {
	home, err := os.UserHomeDir()
	if err != nil {
		return err
	}

	var path string
	var genFunc func(*os.File) error

	switch shell {
	case "bash":
		// Try to use bash_completion.d if available
		if _, err := os.Stat("/etc/bash_completion.d"); err == nil {
			path = "/etc/bash_completion.d/kosmo"
		} else if _, err := os.Stat("/usr/local/etc/bash_completion.d"); err == nil {
			path = "/usr/local/etc/bash_completion.d/kosmo"
		} else {
			path = filepath.Join(home, ".bash_completion")
		}
		genFunc = func(f *os.File) error {
			return rootCmd.GenBashCompletion(f)
		}
	case "zsh":
		// Check if .zsh exists, create if not
		zshDir := filepath.Join(home, ".zsh")
		if err := os.MkdirAll(zshDir, 0755); err != nil {
			return err
		}
		path = filepath.Join(zshDir, "_kosmo")
		genFunc = func(f *os.File) error {
			return rootCmd.GenZshCompletion(f)
		}
	case "fish":
		fishDir := filepath.Join(home, ".config", "fish", "completions")
		if err := os.MkdirAll(fishDir, 0755); err != nil {
			return err
		}
		path = filepath.Join(fishDir, "kosmo.fish")
		genFunc = func(f *os.File) error {
			return rootCmd.GenFishCompletion(f, true)
		}
	default:
		return fmt.Errorf("unsupported shell: %s", shell)
	}

	// Check if we can write to system paths, otherwise use home
	if strings.HasPrefix(path, "/etc/") || strings.HasPrefix(path, "/usr/") {
		// Try system path, fallback to home on permission error
		f, err := os.Create(path)
		if err != nil {
			if shell == "bash" {
				path = filepath.Join(home, ".bash_completion")
			}
		} else {
			f.Close()
		}
	}

	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()

	if err := genFunc(f); err != nil {
		return err
	}

	fmt.Printf("wrote completion to: %s\n", path)

	// Provide shell-specific instructions
	switch shell {
	case "bash":
		fmt.Println("\nTo enable completions now, run:")
		fmt.Printf("  source %s\n", path)
	case "zsh":
		fmt.Println("\nAdd to your ~/.zshrc if not already present:")
		fmt.Println("  fpath=(~/.zsh $fpath)")
		fmt.Println("  autoload -U compinit; compinit")
	case "fish":
		fmt.Println("\nCompletions will be loaded automatically on restart")
	}

	return nil
}
