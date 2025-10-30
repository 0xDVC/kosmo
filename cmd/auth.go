package cmd

import (
	"fmt"

	"github.com/0xDVC/kosmo/internal/auth"
	"github.com/spf13/cobra"
)

func init() {
	rootCmd.AddCommand(authCmd)
	authCmd.AddCommand(authLoginCmd)
}

var authCmd = &cobra.Command{Use: "auth", Short: "Auth commands"}

var authLoginCmd = &cobra.Command{
	Use:     "login",
	Short:   "Configure client keys for a server",
	Long:    "Generate a client keypair and write local config for a target server.",
	Example: `  kosmo auth login --server http://127.0.0.1:8080 --key KOSMO-XXXX`,
	RunE: func(cmd *cobra.Command, args []string) error {
		server, _ := cmd.Flags().GetString("server")
		key, _ := cmd.Flags().GetString("key")
		if server == "" || key == "" {
			return fmt.Errorf("usage: kosmo auth login --server <url> --key <KOSMO-...>")
		}
		auth.InitClient(server, key)
		return nil
	},
}

func init() {
	authLoginCmd.Flags().StringP("server", "s", "", "Server URL")
	authLoginCmd.Flags().StringP("key", "k", "", "Server token (KOSMO-...)")
}
