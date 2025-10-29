package cmd

import (
	"fmt"

	"github.com/0xDVC/kosmo/internal/auth"
	"github.com/0xDVC/kosmo/internal/commands"
	"github.com/spf13/cobra"
)

func init() {
	rootCmd.AddCommand(serverCmd)
	serverCmd.AddCommand(serverUpCmd)
	serverCmd.AddCommand(serverDownCmd)
	serverCmd.AddCommand(serverStatusCmd)
	serverCmd.AddCommand(serverSetupCmd)

	rootCmd.AddCommand(deployCmd)
}

var serverCmd = &cobra.Command{Use: "server", Short: "Server commands"}

var serverSetupCmd = &cobra.Command{
	Use:   "setup",
	Short: "Initialize server keys and config",
	Run: func(cmd *cobra.Command, args []string) {
		// exposed setup via cobra; uses auth.InitServer under the hood
		auth.InitServer()
	},
}

var serverUpCmd = &cobra.Command{
	Use:   "up",
	Short: "Start kosmo server",
	Run: func(cmd *cobra.Command, args []string) {
		port, _ := cmd.Flags().GetInt("port")
		var argv []string
		if port > 0 {
			argv = []string{"--port", fmt.Sprintf("%d", port)}
		}
		commands.Up(argv)
	},
}

var serverDownCmd = &cobra.Command{
	Use:   "down",
	Short: "Stop kosmo server",
	Run: func(cmd *cobra.Command, args []string) {
		commands.Down()
	},
}

var serverStatusCmd = &cobra.Command{
	Use:   "status",
	Short: "Show server status",
	Run: func(cmd *cobra.Command, args []string) {
		commands.Status()
	},
}

var deployCmd = &cobra.Command{
	Use:   "deploy",
	Short: "Deploy current app to the server",
	Run: func(cmd *cobra.Command, args []string) {
		server, _ := cmd.Flags().GetString("server")
		var argv []string
		if server != "" {
			argv = []string{"--server", server}
		}
		commands.Deploy(argv)
	},
}

func init() {
	serverUpCmd.Flags().IntP("port", "p", 0, "Port to listen on")
	deployCmd.Flags().StringP("server", "s", "", "Server URL, e.g. http://127.0.0.1:8080")
}
