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
		var shell string
		if len(args) > 0 {
			shell = args[0]
		} else {
			shell = detectShell()
		}

		if shell == "" {
			fmt.Println("could not detect shell; set SHELL or pass shell explicitly")
			fmt.Println("usage: kosmo completion [bash|zsh|fish]")
			os.Exit(1)
		}

		if err := installCompletion(shell); err != nil {
			fmt.Printf("failed to install completion: %v\n", err)
			os.Exit(1)
		}
	},
	ValidArgs: []string{"bash", "zsh", "fish"},
	Args:      cobra.MaximumNArgs(1),
}

// parse $SHELL to figure out what shell we are running
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

// write completion script to the right place for each shell
func installCompletion(shell string) error {
	home, err := os.UserHomeDir()
	if err != nil {
		return err
	}

	var path string
	var genFunc func(*os.File) error

	switch shell {
	case "bash":
		// try system dirs first, fall back to home if we cant write there
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
		// zsh needs completion files in fpath, ~/.zsh is added to fpath below
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

	// for bash, check if we can write to system paths, otherwise use home
	if strings.HasPrefix(path, "/etc/") || strings.HasPrefix(path, "/usr/") {
		f, err := os.Create(path)
		if err != nil {
			if shell == "bash" {
				path = filepath.Join(home, ".bash_completion")
			}
		} else {
			f.Close()
		}
	}

	// bail if already installed
	alreadyInstalled := false
	if _, err := os.Stat(path); err == nil {
		alreadyInstalled = true
	}

	if !alreadyInstalled {
		f, err := os.Create(path)
		if err != nil {
			return err
		}
		defer f.Close()

		if err := genFunc(f); err != nil {
			return err
		}
		fmt.Printf("completion installed: %s\n", path)
	}

	// always ensure zsh config is set up, even if completion file already exists
	if shell == "zsh" {
		zshrc := filepath.Join(home, ".zshrc")
		if err := ensureZshConfig(zshrc); err != nil {
			fmt.Printf("warning: could not update .zshrc: %v\n", err)
		}
	}

	if alreadyInstalled {
		fmt.Println("completion already installed")
	}
	fmt.Println("restart your shell to enable")
	return nil
}

// make sure .zshrc has fpath and compinit set up for completion to work
// zsh won't load completions unless ~/.zsh is in fpath and compinit is called
func ensureZshConfig(zshrc string) error {
	data, err := os.ReadFile(zshrc)
	if err != nil && !os.IsNotExist(err) {
		return err
	}

	content := string(data)
	fpathLine := "fpath=(~/.zsh $fpath)"
	compLine := "autoload -U compinit; compinit"

	needsFpath := !strings.Contains(content, "fpath=(~/.zsh")
	needsComp := !strings.Contains(content, "autoload -U compinit")

	if !needsFpath && !needsComp {
		return nil
	}

	f, err := os.OpenFile(zshrc, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0644)
	if err != nil {
		return err
	}
	defer f.Close()

	if needsFpath || needsComp {
		f.WriteString("\n# kosmo completion\n")
	}
	if needsFpath {
		f.WriteString(fpathLine + "\n")
	}
	if needsComp {
		f.WriteString(compLine + "\n")
	}

	return nil
}
