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
	rootCmd.AddCommand(addCmd)
	rootCmd.AddCommand(removeCmd)
	rootCmd.AddCommand(listCmd)
}

var clientsCmd = &cobra.Command{Use: "clients", Short: "Manage clients"}

var clientsAddCmd = &cobra.Command{
	Use:   "add <pubkey>",
	Short: "Add client",
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

var addCmd = &cobra.Command{
	Use:   "add <pubkey>",
	Short: "Add client (shortcut)",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := auth.AddClient(args[0]); err != nil {
			return err
		}
		fmt.Println("client added")
		return nil
	},
}

var removeCmd = &cobra.Command{
	Use:   "remove <pubkey>",
	Short: "Remove client (shortcut)",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := auth.RemoveClient(args[0]); err != nil {
			return err
		}
		fmt.Println("client removed")
		return nil
	},
}

var listCmd = &cobra.Command{
	Use:   "list",
	Short: "List clients (shortcut)",
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
