package main

import (
	"archive/tar"
	"compress/gzip"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

func main() {
	// welcome, welcome adongo
	if len(os.Args) == 1 {
		fmt.Println("welcome to kosmo! your dev first, self-hosted deployment tool")
		os.Exit(0)
	}

	if len(os.Args) < 2 {
		fmt.Println("kosmo: missing command")
		os.Exit(1)
	}

	cmd := os.Args[1]

	if cmd == "setup" {
		kosmoSetup()
		os.Exit(0)
	}

	if cmd == "login" {
		if len(os.Args) < 4 {
			fmt.Println("usage: kosmo login --server <url> --key <KOSMO-key>")
			os.Exit(1)
		}

		var serverURL, serverKey string
		for i, arg := range os.Args {
			if arg == "--server" && i+1 < len(os.Args) {
				serverURL = os.Args[i+1]
			}
			if arg == "--key" && i+1 < len(os.Args) {
				serverKey = os.Args[i+1]
			}
		}

		if serverURL == "" || serverKey == "" {
			fmt.Println("missing required args: --server and --key")
			os.Exit(1)
		}

		kosmoLogin(serverURL, serverKey)
		os.Exit(0)
	}

	// initialize kosmo
	if cmd == "init" {
		cwd, err := os.Getwd()
		if err != nil {
			fmt.Println("failed to get cwd:", err)
			os.Exit(1)
		}

		kosmoDir := filepath.Join(cwd, ".kosmo")
		buildsDir := filepath.Join(kosmoDir, "builds")

		fmt.Println("initializing kosmo...")

		os.MkdirAll(buildsDir, 0755)

		fmt.Println("kosmo initialized.")
		fmt.Println("-- run 'kosmo deploy --server http://<ip>:8080'")
		os.Exit(0)
	}

	// kosmo start --port 8080
	if cmd == "start" {
		startPort := 8080
		if len(os.Args) > 2 {
			for i := 2; i < len(os.Args); i++ {
				if (os.Args[i] == "--port" || os.Args[i] == "-p") && i+1 < len(os.Args) {
					fmt.Sscanf(os.Args[i+1], "%d", &startPort)
				}
			}
		}

		// Find available port
		port := findAvailablePort(startPort)
		if port != startPort {
			fmt.Printf("port %d in use, using %d instead\n", startPort, port)
		}

		// load state from disk
		loadState()

		fmt.Printf("kosmo server running on port %d\n", port)
		fmt.Println("ready for deployments...")

		http.HandleFunc("/deploy", handleDeploy)

		if err := http.ListenAndServe(fmt.Sprintf(":%d", port), nil); err != nil {
			fmt.Println("server failed:", err)
			os.Exit(1)
		}
		os.Exit(0)
	}

	// kosmo rollback <app>
	if cmd == "rollback" {
		if len(os.Args) < 3 {
			fmt.Println("usage: kosmo rollback <app>")
			os.Exit(1)
		}

		app := os.Args[2]
		server := getServerFromConfig()
		if server == "" {
			fmt.Println("no server configured, run 'kosmo login' first")
			os.Exit(1)
		}

		// TODO: implement rollback logic
		fmt.Printf("rollback for %s not implemented yet\n", app)
		os.Exit(0)
	}

	// kosmo deploy --server http://localhost:8080
	if cmd == "deploy" {
		server := ""
		for i, arg := range os.Args {
			if (arg == "--server" || arg == "-s") && i+1 < len(os.Args) {
				server = os.Args[i+1]
			}
		}

		if server == "" {
			fmt.Println("missing --server <url>")
			os.Exit(1)
		}

		cwd, err := os.Getwd()
		if err != nil {
			fmt.Println("failed to get cwd:", err)
			os.Exit(1)
		}
		app := filepath.Base(cwd)

		fmt.Println("preparing deployment for", app, "...")

		// load client config
		home, _ := os.UserHomeDir()
		cfgPath := filepath.Join(home, ".kosmo", "config.json")
		cfgData, err := os.ReadFile(cfgPath)
		if err != nil {
			fmt.Println("missing kosmo config, run `kosmo login` first")
			os.Exit(1)
		}

		var cfg Config
		json.Unmarshal(cfgData, &cfg)

		// create tarball
		pr, pw := io.Pipe()
		go func() {
			gzw := gzip.NewWriter(pw)
			tw := tar.NewWriter(gzw)

			filepath.Walk(".", func(path string, info os.FileInfo, err error) error {
				if err != nil {
					return err
				}

				// skip .git and .kosmo dirs
				if strings.Contains(path, ".git") || strings.Contains(path, ".kosmo") {
					if info.IsDir() {
						return filepath.SkipDir
					}
					return nil
				}

				hdr, err := tar.FileInfoHeader(info, "")
				if err != nil {
					return err
				}
				hdr.Name = path
				tw.WriteHeader(hdr)

				if !info.IsDir() {
					f, err := os.Open(path)
					if err != nil {
						return err
					}
					io.Copy(tw, f)
					f.Close()
				}
				return nil
			})

			tw.Close()
			gzw.Close()
			pw.Close()
		}()

		// sign the request
		timestamp := time.Now().Unix()
		message := fmt.Sprintf("%s-%d", app, timestamp)
		privBytes, _ := base64.StdEncoding.DecodeString(cfg.ClientPriv)
		sig := ed25519.Sign(privBytes, []byte(message))

		// create authenticated request
		req, err := http.NewRequest("POST", fmt.Sprintf("%s/deploy?app=%s", server, app), pr)
		if err != nil {
			fmt.Println("failed to create request:", err)
			os.Exit(1)
		}
		req.Header.Set("Content-Type", "application/gzip")
		req.Header.Set("X-Kosmo-Pubkey", cfg.ClientPub)
		req.Header.Set("X-Kosmo-Signature", base64.StdEncoding.EncodeToString(sig))
		req.Header.Set("X-Kosmo-Timestamp", fmt.Sprintf("%d", timestamp))

		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			fmt.Println("deploy failed:", err)
			os.Exit(1)
		}
		defer resp.Body.Close()
		io.Copy(os.Stdout, resp.Body)
		os.Exit(0)
	}

	fmt.Printf("kosmo: unknown command '%s'\n", cmd)
	os.Exit(1)
}

var nextPort = 8081
var runningApps = make(map[string]*AppInfo)


// TODO: state isnt being serialized. need to fix this.
// load state on startup
func loadState() {
	stateFile := ".kosmo/state.json"
	if data, err := os.ReadFile(stateFile); err == nil {
		json.Unmarshal(data, &runningApps)
		// find highest port used
		maxPort := 8080
		for _, app := range runningApps {
			if app.Port > maxPort {
				maxPort = app.Port
			}
		}
		nextPort = maxPort + 1
	}
}

// save state to disk
func saveState() {
	stateFile := ".kosmo/state.json"
	os.MkdirAll(".kosmo", 0755)
	if data, err := json.Marshal(runningApps); err == nil {
		os.WriteFile(stateFile, data, 0644)
	}
}

type AppInfo struct {
	Process *os.Process
	Port    int 
	Version string
	Path    string
}

func findAvailablePort(startPort int) int {
	for port := startPort; port < startPort+100; port++ {
		ln, err := net.Listen("tcp", fmt.Sprintf(":%d", port))
		if err == nil {
			ln.Close()
			return port
		}
	}
	return startPort
}

func waitForHealth(url string, timeoutSeconds int) bool {
	for i := 0; i < timeoutSeconds; i++ {
		resp, err := http.Get(url)
		if err == nil && resp.StatusCode == 200 {
			resp.Body.Close()
			return true
		}
		time.Sleep(1*time.Second)
	}
	return false
}

func waitForPort(port int, timeoutSeconds int) bool {
	for i := 0; i < timeoutSeconds; i++ {
		conn, err := net.Dial("tcp", fmt.Sprintf("localhost:%d", port))
		if err == nil {
			conn.Close()
			return true
		}
		time.Sleep(1*time.Second)
	}
	return false
}

func gracefulShutdown(process *os.Process) {
	// send sigterm first
	process.Signal(syscall.SIGTERM)

	for i:= 0; i < 10; i++ { // wait up to 10 seconds
		if process.Signal(syscall.Signal(0)) != nil {
			return
		}
		time.Sleep(1 * time.Second)
	}

	// force kill if still running
	process.Kill()
}

func getServerFromConfig() string {
	home, _ := os.UserHomeDir()
	cfgPath := filepath.Join(home, ".kosmo", "config.json")
	cfgData, err := os.ReadFile(cfgPath)
	if err != nil {
		return ""
	}
	var cfg Config
	if err := json.Unmarshal(cfgData, &cfg); err != nil {
		return ""
	}
	return cfg.ServerURL
}

func handleDeploy(w http.ResponseWriter, r *http.Request) {
	fmt.Println("\n--- deployment request received ---")

	// extract auth headers
	pubB64 := r.Header.Get("X-Kosmo-Pubkey")
	sigB64 := r.Header.Get("X-Kosmo-Signature")
	ts := r.Header.Get("X-Kosmo-Timestamp")

	if pubB64 == "" || sigB64 == "" || ts == "" {
		http.Error(w, "missing auth headers", http.StatusUnauthorized)
		return
	}

	app := r.URL.Query().Get("app")
	if app == "" {
		app = "app"
	}

	// load server key to verify client is using correct server token
	home, _ := os.UserHomeDir()
	serverPubKeyFile := filepath.Join(home, ".kosmo", "keys", "server_ed25519.pub")
	_, err := os.ReadFile(serverPubKeyFile)
	if err != nil {
		http.Error(w, "server not configured", http.StatusInternalServerError)
		return
	}

	// verify signature
	pubBytes, err := base64.StdEncoding.DecodeString(pubB64)
	if err != nil {
		http.Error(w, "invalid pubkey", 400)
		return
	}

	sigBytes, err := base64.StdEncoding.DecodeString(sigB64)
	if err != nil {
		http.Error(w, "invalid signature", 400)
		return
	}

	msg := fmt.Sprintf("%s-%s", app, ts)
	if !ed25519.Verify(pubBytes, []byte(msg), sigBytes) {
		http.Error(w, "signature verification failed", http.StatusForbidden)
		return
	}

	fmt.Println("authenticated deploy from client:", pubB64[:16], "...")

	// create build directory
	kosmoDir := ".kosmo"
	buildsDir := filepath.Join(kosmoDir, "builds")
	timestamp := time.Now().Unix()
	appBuildDir := filepath.Join(buildsDir, fmt.Sprintf("%s-%d", app, timestamp))

	os.MkdirAll(appBuildDir, 0755)

	// decompress and untar the request
	gzr, err := gzip.NewReader(r.Body)
	if err != nil {
		http.Error(w, "failed to read gzip: "+err.Error(), 500)
		return
	}
	defer gzr.Close()

	tr := tar.NewReader(gzr)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			http.Error(w, "failed to read tar: "+err.Error(), 500)
			return
		}
		
		//TODO: traversal check is incomplete
		// prevent path traversal attacks
		target := filepath.Join(appBuildDir, hdr.Name)
		if !strings.HasPrefix(target, appBuildDir) {
			http.Error(w, "invalid file path", 400)
			return
		}

		switch hdr.Typeflag {
		case tar.TypeDir:
			os.MkdirAll(target, os.FileMode(hdr.Mode))
		case tar.TypeReg:
			os.MkdirAll(filepath.Dir(target), 0755)
			f, err := os.Create(target)
			if err != nil {
				http.Error(w, "create file error: "+err.Error(), 500)
				return
			}
			io.Copy(f, tr)
			f.Close()
		}
	}

	fmt.Println("extract done:", appBuildDir)

	// build and run the app
	buildCmd := exec.Command("go", "build", "-o", "app")
	buildCmd.Dir = appBuildDir
	buildCmd.Stdout = os.Stdout
	buildCmd.Stderr = os.Stderr

	fmt.Println("building app...")
	if err := buildCmd.Run(); err != nil {
		http.Error(w, "build failed: "+err.Error(), 500)
		return
	}

	fmt.Println("build done, starting app...")

	// blue-green deployment: start new version first
	newPort := nextPort
	nextPort++

	runCmd := exec.Command(filepath.Join(appBuildDir, "app"))
	runCmd.Dir = appBuildDir
	runCmd.Env = append(os.Environ(), fmt.Sprintf("PORT=%d", newPort))
	runCmd.Stdout = os.Stdout
	runCmd.Stderr = os.Stderr

	// set process group for proper cleanup
	runCmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}

	err = runCmd.Start()
	if err != nil {
		http.Error(w, "failed to start app: "+err.Error(), 500)
		return
	}

	// health check new version 
	fmt.Printf("checking on port %d...\n", newPort)
	healthURL := fmt.Sprintf("http://localhost:%d/health", newPort)
	if !waitForHealth(healthURL, 5) {
		// fallback to port check
		fmt.Println("health endpoint not available, checking port...")
		if !waitForPort(newPort, 5) {
			runCmd.Process.Kill()
			http.Error(w, "app failed to start", 500)
			return
		}
	}

	// switch traffic
	if oldApp, exists := runningApps[app]; exists {
		fmt.Printf("switching from port %d to %d\n", oldApp.Port, newPort)
		gracefulShutdown(oldApp.Process)
	}

	// store new version
	version := fmt.Sprintf("%d", timestamp)
	runningApps[app] = &AppInfo{
		Process: runCmd.Process,
		Port:    newPort,
		Version: version,
		Path:    appBuildDir,
	}

	// save state to disk
	saveState()

	// return the URL
	host := r.Host
	if host == "" {
		host = "localhost"
	}
	url := fmt.Sprintf("http://%s:%d", host, newPort)

	fmt.Fprintf(w, "deployed to %s (version %s)\n", url, version)
}
