package cmd

import (
	"fmt"

	"github.com/0xDVC/kosmo/internal/auth"
	"github.com/spf13/cobra"
)

func init() {
	rootCmd.AddCommand(clientsCmd)
	clientsCmd.AddCommand(clientsAddCmd)
	clientsCmd.AddCommand(clientsRemoveCmd)
	clientsCmd.AddCommand(clientsListCmd)
}

var clientsCmd = &cobra.Command{
	Use:   "clients",
	Short: "Manage clients",
	Long:  "Manage allowed client public keys for the server allowlist.",
}

var clientsAddCmd = &cobra.Command{
	Use:   "add <pubkey>",
	Short: "Add client",
	Long:  "Add a client public key to the server allowlist.",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := auth.AddClient(args[0]); err != nil {
			return err
		}
		fmt.Println("client added")
		return nil
	},
}

var clientsRemoveCmd = &cobra.Command{
	Use:   "remove <pubkey>",
	Short: "Remove client",
	Long:  "Remove a client public key from the server allowlist.",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := auth.RemoveClient(args[0]); err != nil {
			return err
		}
		fmt.Println("client removed")
		return nil
	},
}

var clientsListCmd = &cobra.Command{
	Use:   "list",
	Short: "List clients",
	Long:  "List allowed client public keys.",
	RunE: func(cmd *cobra.Command, args []string) error {
		clients, err := auth.ListClients()
		if err != nil {
			return err
		}
		if len(clients) == 0 {
			fmt.Println("no clients added")
			return nil
		}
		for _, c := range clients {
			fmt.Println(c)
		}
		return nil
	},
}
