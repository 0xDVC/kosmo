package cmd

import (
	"fmt"

	"github.com/0xDVC/kosmo/internal/commands"
	"github.com/spf13/cobra"
)

func init() {
	rootCmd.AddCommand(upCmd)
	rootCmd.AddCommand(downCmd)
	rootCmd.AddCommand(statusCmd)
	rootCmd.AddCommand(deployCmd)
}

var upCmd = &cobra.Command{
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

var downCmd = &cobra.Command{
	Use:   "down",
	Short: "Stop kosmo server",
	Run: func(cmd *cobra.Command, args []string) {
		commands.Down()
	},
}

var statusCmd = &cobra.Command{
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
	upCmd.Flags().IntP("port", "p", 0, "Port to listen on")
	deployCmd.Flags().StringP("server", "s", "", "Server URL, e.g. http://127.0.0.1:8080")
}
