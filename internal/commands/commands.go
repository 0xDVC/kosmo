package commands

import (
	"fmt"
	"os"

	"github.com/0xDVC/kosmo/internal/auth"
)

func Setup() {
	auth.Setup()
}

func Login(args []string) {
	serverURL, serverKey := parseArgs(args, "--server", "--key")
	if serverURL == "" || serverKey == "" {
		fmt.Println("usage: kosmo login --server <url> --key <KOSMO-key>")
		os.Exit(1)
	}
	auth.Login(serverURL, serverKey)
}

func AddClient(args []string) {
	pubkey, _ := parseArgs(args, "--pubkey", "")
	if pubkey == "" {
		fmt.Println("usage: kosmo add-client --pubkey <pubkey>")
		os.Exit(1)
	}
	if err := auth.AddClient(pubkey); err != nil {
		fmt.Printf("failed to add client: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("client %s added successfully\n", pubkey[:16]+"...")
}

func RemoveClient(args []string) {
	pubkey, _ := parseArgs(args, "--pubkey", "")
	if pubkey == "" {
		fmt.Println("usage: kosmo remove-client --pubkey <pubkey>")
		os.Exit(1)
	}
	if err := auth.RemoveClient(pubkey); err != nil {
		fmt.Printf("failed to remove client: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("client removed successfully")
}

func ListClients() {
	clients, err := auth.ListClients()
	if err != nil {
		fmt.Printf("failed to list clients: %v\n", err)
		os.Exit(1)
	}
	if len(clients) == 0 {
		fmt.Println("no clients configured")
		return
	}
	fmt.Println("Allowed clients:")
	for _, pubkey := range clients {
		fmt.Printf("  %s\n", pubkey[:16]+"...")
	}
}

func parseArgs(args []string, key1, key2 string) (string, string) {
	var val1, val2 string
	for i, arg := range args {
		if (arg == key1 || (key2 != "" && arg == key2)) && i+1 < len(args) {
			if arg == key1 {
				val1 = args[i+1]
			} else if key2 != "" {
				val2 = args[i+1]
			}
		}
	}
	return val1, val2
}
