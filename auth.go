package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

var (
	errClientNotAllowed = fmt.Errorf("client not in allowlist")
	errInvalidSignature = fmt.Errorf("signature verification failed")
	errInvalidTimestamp = fmt.Errorf("request too old or from future")
)

type Config struct {
	ServerURL  string `json:"server_url"`
	ServerKey  string `json:"server_key"`
	ClientPub  string `json:"client_pub"`
	ClientPriv string `json:"client_priv"`
}

type ServerConfig struct {
	ServerPubKey   string   `json:"server_pub_key"`
	ServerPrivKey  string   `json:"server_priv_key"`
	AllowedClients []string `json:"allowed_clients"`
}

type AuthRequest struct {
	App       string `json:"app"`
	Timestamp int64  `json:"timestamp"`
	Payload   []byte `json:"payload"`
}

func kosmoSetup() {
	home, _ := os.UserHomeDir()
	keyDir := filepath.Join(home, ".kosmo", "keys")
	os.MkdirAll(keyDir, 0700)

	serverPubKeyFile := filepath.Join(keyDir, "server_ed25519.pub")
	serverPrivKeyFile := filepath.Join(keyDir, "server_ed25519")

	if _, err := os.Stat(serverPrivKeyFile); err == nil {
		pub, _ := os.ReadFile(serverPubKeyFile)
		pubStr := base64.StdEncoding.EncodeToString(pub)
		fmt.Printf("Server token: KOSMO-%s\n", pubStr)
		return
	}

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		fmt.Printf("failed to generate key: %v\n", err)
		os.Exit(1)
	}

	os.WriteFile(serverPrivKeyFile, priv, 0600)
	os.WriteFile(serverPubKeyFile, pub, 0644)

	pubStr := base64.StdEncoding.EncodeToString(pub)

	config := &ServerConfig{
		ServerPubKey:   pubStr,
		ServerPrivKey:  base64.StdEncoding.EncodeToString(priv),
		AllowedClients: []string{},
	}

	if err := saveServerConfig(config); err != nil {
		fmt.Printf("failed to save server config: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("kosmo setup complete.\n")
	fmt.Printf("Server token (give this to clients):\n")
	fmt.Printf("KOSMO-%s\n", pubStr)
	fmt.Printf("\nNext steps:\n")
	fmt.Printf("1. start the server: kosmo start\n")
	fmt.Printf("2. add clients: kosmo add-client --pubkey <client-pubkey>\n")
}

func kosmoLogin(serverURL, serverKey string) {
	serverKey = strings.TrimPrefix(serverKey, "KOSMO-")

	home, _ := os.UserHomeDir()
	keyDir := filepath.Join(home, ".kosmo", "keys")
	os.MkdirAll(keyDir, 0700)

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		fmt.Printf("failed to generate client key: %v\n", err)
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

	fmt.Printf("kosmo client configured. ready to deploy.\n")
	fmt.Printf("server: %s\n", serverURL)
}

func loadServerConfig() (*ServerConfig, error) {
	home, _ := os.UserHomeDir()
	configFile := filepath.Join(home, ".kosmo", "server_config.json")
	data, err := os.ReadFile(configFile)
	if err != nil {
		return nil, err
	}

	var config ServerConfig
	if err := json.Unmarshal(data, &config); err != nil {
		return nil, err
	}

	return &config, nil
}

func saveServerConfig(config *ServerConfig) error {
	home, _ := os.UserHomeDir()
	configDir := filepath.Join(home, ".kosmo")
	os.MkdirAll(configDir, 0700)

	configFile := filepath.Join(configDir, "server_config.json")
	data, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(configFile, data, 0600)
}

func verifyClientAuth(clientPubKey, signature, timestamp, app string, payload []byte) error {
	config, err := loadServerConfig()
	if err != nil {
		return fmt.Errorf("failed to load server config: %w", err)
	}

	allowed := false
	for _, allowedClient := range config.AllowedClients {
		if allowedClient == clientPubKey {
			allowed = true
			break
		}
	}

	if !allowed {
		return errClientNotAllowed
	}

	pubBytes, err := base64.StdEncoding.DecodeString(clientPubKey)
	if err != nil {
		return fmt.Errorf("invalid client public key: %w", err)
	}

	sigBytes, err := base64.StdEncoding.DecodeString(signature)
	if err != nil {
		return fmt.Errorf("invalid signature: %w", err)
	}

	reqTimestamp, err := strconv.ParseInt(timestamp, 10, 64)
	if err != nil {
		return fmt.Errorf("invalid timestamp: %w", err)
	}

	now := time.Now().Unix()
	if now-reqTimestamp > 300 || reqTimestamp-now > 60 {
		return errInvalidTimestamp
	}

	authReq := AuthRequest{
		App:       app,
		Timestamp: reqTimestamp,
		Payload:   payload,
	}

	message, err := json.Marshal(authReq)
	if err != nil {
		return fmt.Errorf("failed to marshal auth request: %w", err)
	}

	if !ed25519.Verify(pubBytes, message, sigBytes) {
		return errInvalidSignature
	}

	return nil
}

func addClient(pubKey string) error {
	config, err := loadServerConfig()
	if err != nil {
		return err
	}

	for _, existing := range config.AllowedClients {
		if existing == pubKey {
			return fmt.Errorf("client already exists")
		}
	}

	config.AllowedClients = append(config.AllowedClients, pubKey)
	return saveServerConfig(config)
}

func removeClient(pubKey string) error {
	config, err := loadServerConfig()
	if err != nil {
		return err
	}

	newClients := make([]string, 0)
	for _, client := range config.AllowedClients {
		if client != pubKey {
			newClients = append(newClients, client)
		}
	}

	config.AllowedClients = newClients
	return saveServerConfig(config)
}

func listClients() ([]string, error) {
	config, err := loadServerConfig()
	if err != nil {
		return nil, err
	}
	return config.AllowedClients, nil
}
