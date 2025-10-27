package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

type Config struct {
	ServerURL  string `json:"server_url"`
	ServerKey  string `json:"server_key"`
	ClientPub  string `json:"client_pub"`
	ClientPriv string `json:"client_priv"`
}

func kosmoSetup() {
	home, _ := os.UserHomeDir()
	keyDir := filepath.Join(home, ".kosmo", "keys")
	os.MkdirAll(keyDir, 0700)

	serverPubKeyFile := filepath.Join(keyDir, "server_ed25519.pub")
	serverPrivKeyFile := filepath.Join(keyDir, "server_ed25519")

	// if already exists, skip
	if _, err := os.Stat(serverPrivKeyFile); err == nil {
		fmt.Println("server already initialized.")
		// Still show the token
		pub, _ := os.ReadFile(serverPubKeyFile)
		pubStr := base64.StdEncoding.EncodeToString(pub)
		fmt.Printf("Server token: KOSMO-%s\n", pubStr)
		return
	}

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		fmt.Println("failed to generate key:", err)
		os.Exit(1)
	}

	os.WriteFile(serverPrivKeyFile, priv, 0600)
	os.WriteFile(serverPubKeyFile, pub, 0644)

	pubStr := base64.StdEncoding.EncodeToString(pub)
	fmt.Println("Kosmo setup complete.")
	fmt.Println("Server token (give this to clients):")
	fmt.Printf("KOSMO-%s\n", pubStr)
}

func kosmoLogin(serverURL, serverKey string) {
	// remove KOSMO- prefix 
	serverKey = strings.TrimPrefix(serverKey, "KOSMO-")

	home, _ := os.UserHomeDir()
	keyDir := filepath.Join(home, ".kosmo", "keys")
	os.MkdirAll(keyDir, 0700)

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		fmt.Println("failed to generate client key:", err)
		os.Exit(1)
	}

	cfg := Config{
		ServerURL:  serverURL,
		ServerKey:  serverKey,
		ClientPub:  base64.StdEncoding.EncodeToString(pub),
		ClientPriv: base64.StdEncoding.EncodeToString(priv),
	}

	data, _ := json.MarshalIndent(cfg, "", "  ")
	cfgPath := filepath.Join(home, ".kosmo", "config.json")
	os.WriteFile(cfgPath, data, 0600)

	fmt.Println("kosmo client configured. ready to deploy.")
	fmt.Println("server:", serverURL)
}
