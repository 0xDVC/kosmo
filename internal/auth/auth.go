package auth

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
	ErrClientNotAllowed = fmt.Errorf("client not in allowlist")
	ErrInvalidSignature = fmt.Errorf("signature verification failed")
	ErrInvalidTimestamp = fmt.Errorf("request too old or from future")
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

func InitServer() {
	home, err := os.UserHomeDir()
	if err != nil {
		fmt.Printf("failed to get home dir: %v\n", err)
		os.Exit(1)
	}
	keyDir := filepath.Join(home, ".kosmo", "keys")
	if err := os.MkdirAll(keyDir, 0700); err != nil {
		fmt.Printf("failed to create key dir: %v\n", err)
		os.Exit(1)
	}

	serverPubKeyFile := filepath.Join(keyDir, "server_ed25519.pub")
	serverPrivKeyFile := filepath.Join(keyDir, "server_ed25519")

	// if keys already exist, just print the token
	if _, err := os.Stat(serverPrivKeyFile); err == nil {
		pub, err := os.ReadFile(serverPubKeyFile)
		if err != nil {
			fmt.Printf("failed to read server pubkey: %v\n", err)
			os.Exit(1)
		}
		pubStr := base64.StdEncoding.EncodeToString(pub)
		fmt.Printf("kosmo server already initialized.\n")
		fmt.Printf("\nServer public key:\n")
		fmt.Printf("KOSMO-%s\n", pubStr)
		return
	}

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		fmt.Printf("failed to generate key: %v\n", err)
		os.Exit(1)
	}

	if err := os.WriteFile(serverPrivKeyFile, priv, 0600); err != nil {
		fmt.Printf("failed to write server private key: %v\n", err)
		os.Exit(1)
	}
	if err := os.WriteFile(serverPubKeyFile, pub, 0644); err != nil {
		fmt.Printf("failed to write server public key: %v\n", err)
		os.Exit(1)
	}

	pubStr := base64.StdEncoding.EncodeToString(pub)

	config := &ServerConfig{
		ServerPubKey:   pubStr,
		ServerPrivKey:  base64.StdEncoding.EncodeToString(priv),
		AllowedClients: []string{},
	}

	if err := SaveServerConfig(config); err != nil {
		fmt.Printf("failed to save server config: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("kosmo server initialized.\n")
	fmt.Printf("\nServer public key (give this to clients):\n")
	fmt.Printf("KOSMO-%s\n", pubStr)
	fmt.Printf("\nNext steps:\n")
	fmt.Printf("1. start the server: kosmo server up\n")
	fmt.Printf("2. clients run: kosmo auth login --server <url> --key KOSMO-%s\n", pubStr[:16]+"...")
	fmt.Printf("3. add client keys: kosmo clients add <client-pubkey>\n")
}

func InitClient(serverURL, serverKey string) {
	serverKey = strings.TrimPrefix(serverKey, "KOSMO-")

	home, err := os.UserHomeDir()
	if err != nil {
		fmt.Printf("failed to get home dir: %v\n", err)
		os.Exit(1)
	}
	keyDir := filepath.Join(home, ".kosmo", "keys")
	if err := os.MkdirAll(keyDir, 0700); err != nil {
		fmt.Printf("failed to create key dir: %v\n", err)
		os.Exit(1)
	}

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

	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		fmt.Printf("failed to marshal client config: %v\n", err)
		os.Exit(1)
	}
	cfgPath := filepath.Join(home, ".kosmo", "config.json")
	if err := os.WriteFile(cfgPath, data, 0600); err != nil {
		fmt.Printf("failed to write client config: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("kosmo client configured. ready to deploy.\n")
	fmt.Printf("server: %s\n", serverURL)
	fmt.Printf("\nYour client public key (give this to the server admin):\n")
	fmt.Printf("KOSMO-%s\n", cfg.ClientPub)
	fmt.Printf("\nOn the server, run:\n")
	fmt.Printf("  kosmo clients add KOSMO-%s\n", cfg.ClientPub)
}

func LoadServerConfig() (*ServerConfig, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, err
	}
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

func SaveServerConfig(config *ServerConfig) error {
	home, err := os.UserHomeDir()
	if err != nil {
		return err
	}
	configDir := filepath.Join(home, ".kosmo")
	if err := os.MkdirAll(configDir, 0700); err != nil {
		return err
	}

	configFile := filepath.Join(configDir, "server_config.json")
	data, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(configFile, data, 0600)
}

func Verify(clientPubKey, signature, timestamp, app string, payload []byte) error {
	config, err := LoadServerConfig()
	if err != nil {
		return fmt.Errorf("failed to load server config: %w", err)
	}

	// check client is in allowlist
	allowed := false
	for _, allowedClient := range config.AllowedClients {
		if allowedClient == clientPubKey {
			allowed = true
			break
		}
	}

	if !allowed {
		return ErrClientNotAllowed
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

	// reject requests older than 5min or from the future (clock skew tolerance 1min)
	now := time.Now().Unix()
	if now-reqTimestamp > 300 || reqTimestamp-now > 60 {
		return ErrInvalidTimestamp
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
		return ErrInvalidSignature
	}

	return nil
}

func AddClient(pubKey string) error {
	pubKey = strings.TrimPrefix(pubKey, "KOSMO-")

	config, err := LoadServerConfig()
	if err != nil {
		return err
	}

	for _, existing := range config.AllowedClients {
		if existing == pubKey {
			return fmt.Errorf("client already exists")
		}
	}

	config.AllowedClients = append(config.AllowedClients, pubKey)
	return SaveServerConfig(config)
}

func RemoveClient(pubKey string) error {
	pubKey = strings.TrimPrefix(pubKey, "KOSMO-")
	config, err := LoadServerConfig()
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
	return SaveServerConfig(config)
}

func ListClients() ([]string, error) {
	config, err := LoadServerConfig()
	if err != nil {
		return nil, err
	}
	return config.AllowedClients, nil
}
