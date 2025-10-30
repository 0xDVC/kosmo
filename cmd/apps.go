package cmd

import (
	"fmt"

	"github.com/0xDVC/kosmo/internal/commands"
	"github.com/spf13/cobra"
)

func init() {
	rootCmd.AddCommand(appsCmd)
	appsCmd.AddCommand(logsCmd)
	appsCmd.AddCommand(rollbackCmd)
	appsCmd.AddCommand(restartCmd)
	appsCmd.AddCommand(listAppsCmd)
}

var appsCmd = &cobra.Command{
	Use:   "apps",
	Short: "Manage running apps",
	Long:  "List and operate on running apps deployed by kosmo.",
}

var listAppsCmd = &cobra.Command{
	Use:   "list",
	Short: "List apps",
	Long:  "Show all known apps and their status, ports, and pids.",
	Run: func(cmd *cobra.Command, args []string) {
		commands.Apps()
	},
}

var logsCmd = &cobra.Command{
	Use:   "logs",
	Short: "Tail app logs",
	Long:  "Tail the stdout/stderr log file for a running app.",
	Example: `  kosmo apps logs --app myapp
  kosmo apps logs myapp`,
	Run: func(cmd *cobra.Command, args []string) {
		app, _ := cmd.Flags().GetString("app")
		argv := []string{}
		if app != "" {
			argv = []string{"--app", app}
		} else if len(args) > 0 {
			argv = []string{"--app", args[0]}
		}
		if len(argv) == 0 {
			fmt.Println("usage: kosmo apps logs --app <name>")
			return
		}
		commands.Logs(argv)
	},
}

var rollbackCmd = &cobra.Command{
	Use:   "rollback",
	Short: "Rollback app to previous version",
	Long:  "Stop current app and start the previous build if available.",
	Run: func(cmd *cobra.Command, args []string) {
		app, _ := cmd.Flags().GetString("app")
		argv := []string{}
		if app != "" {
			argv = []string{"--app", app}
		} else if len(args) > 0 {
			argv = []string{"--app", args[0]}
		}
		commands.Rollback(argv)
	},
}

var restartCmd = &cobra.Command{
	Use:   "restart",
	Short: "Restart an app",
	Long:  "Stop and start the current app build using the same port.",
	Run: func(cmd *cobra.Command, args []string) {
		app, _ := cmd.Flags().GetString("app")
		argv := []string{}
		if app != "" {
			argv = []string{"--app", app}
		} else if len(args) > 0 {
			argv = []string{"--app", args[0]}
		}
		commands.Restart(argv)
	},
}

func init() {
	logsCmd.Flags().String("app", "", "App name")
	rollbackCmd.Flags().String("app", "", "App name")
	restartCmd.Flags().String("app", "", "App name")
}
