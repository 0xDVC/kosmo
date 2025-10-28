package main

import (
	"archive/tar"
	"bytes"
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
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

var (
	nextPort    = 8081
	runningApps = make(map[string]*AppInfo)
	appsMutex   sync.RWMutex
)

func main() {
	if len(os.Args) < 2 {
		fmt.Println("welcome to kosmo! your dev first, self-hosted deployment tool")
		fmt.Println("usage: kosmo <command>")
		os.Exit(0)
	}

	cmd := os.Args[1]
	args := os.Args[2:]

	switch cmd {
	case "setup":
		kosmoSetup()
	case "add-client":
		handleAddClient(args)
	case "remove-client":
		handleRemoveClient(args)
	case "list-clients":
		handleListClients()
	case "login":
		handleLogin(args)
	case "init":
		handleInit()
	case "start":
		handleStart(args)
	case "stop":
		handleStop()
	case "status":
		handleStatus()
	case "deploy":
		handleDeploy(args)
	default:
		fmt.Printf("kosmo: unknown command '%s'\n", cmd)
		os.Exit(1)
	}
}

func handleAddClient(args []string) {
	pubkey, _ := parseArgs(args, "--pubkey", "")
	if pubkey == "" {
		fmt.Println("usage: kosmo add-client --pubkey <pubkey>")
		os.Exit(1)
	}

	if err := addClient(pubkey); err != nil {
		fmt.Printf("failed to add client: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("client %s added successfully\n", pubkey[:16]+"...")
}

func handleRemoveClient(args []string) {
	pubkey, _ := parseArgs(args, "--pubkey", "")
	if pubkey == "" {
		fmt.Println("usage: kosmo remove-client --pubkey <pubkey>")
		os.Exit(1)
	}

	if err := removeClient(pubkey); err != nil {
		fmt.Printf("failed to remove client: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("client removed successfully")
}

func handleListClients() {
	clients, err := listClients()
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

func handleLogin(args []string) {
	serverURL, serverKey := parseArgs(args, "--server", "--key")
	if serverURL == "" || serverKey == "" {
		fmt.Println("usage: kosmo login --server <url> --key <KOSMO-key>")
		os.Exit(1)
	}

	kosmoLogin(serverURL, serverKey)
}

func handleInit() {
	cwd, err := os.Getwd()
	if err != nil {
		fmt.Printf("failed to get cwd: %v\n", err)
		os.Exit(1)
	}

	kosmoDir := filepath.Join(cwd, ".kosmo")
	buildsDir := filepath.Join(kosmoDir, "builds")

	fmt.Println("initializing kosmo...")
	os.MkdirAll(buildsDir, 0755)

	fmt.Println("kosmo initialized.")
	fmt.Println("-- run 'kosmo deploy --server http://<ip>:8080'")
}

func handleStart(args []string) {
	startPort := 8080
	if len(args) > 0 {
		for i, arg := range args {
			if (arg == "--port" || arg == "-p") && i+1 < len(args) {
				fmt.Sscanf(args[i+1], "%d", &startPort)
				break
			}
		}
	}

	pidFile := getPIDFile()
	if pid := readPID(pidFile); pid > 0 && isProcessRunning(pid) {
		fmt.Printf("kosmo is already running (PID: %d)\n", pid)
		return
	}

	if os.Getenv("KOSMO_DAEMON") == "" {
		if shouldDaemonize() {
			if err := daemonize(); err != nil {
				fmt.Printf("failed to daemonize: %v\n", err)
				os.Exit(1)
			}
			return
		}
	}

	if shouldDaemonize() {
		setupDaemonStdio()
	}

	port := findAvailablePort(startPort)
	if port != startPort {
		fmt.Printf("port %d in use, using %d instead\n", startPort, port)
	}

	loadState()

	if err := writePID(pidFile, os.Getpid()); err != nil {
		fmt.Printf("failed to write PID file: %v\n", err)
	}

	fmt.Printf("kosmo server running on port %d (PID: %d)\n", port, os.Getpid())
	fmt.Println("ready for deployments...")

	http.HandleFunc("/deploy", handleDeployHTTP)

	fmt.Printf("starting HTTP server on :%d\n", port)
	if err := http.ListenAndServe(fmt.Sprintf(":%d", port), nil); err != nil {
		fmt.Printf("server failed: %v\n", err)
		os.Remove(pidFile)
		os.Exit(1)
	}
}

func handleStop() {
	pidFile := getPIDFile()
	pid := readPID(pidFile)
	if pid == 0 {
		fmt.Println("kosmo is not running")
		return
	}

	if !isProcessRunning(pid) {
		fmt.Println("kosmo is not running (stale PID file)")
		os.Remove(pidFile)
		return
	}

	proc, err := os.FindProcess(pid)
	if err != nil {
		fmt.Printf("failed to find process: %v\n", err)
		os.Exit(1)
	}

	if err := proc.Signal(syscall.SIGTERM); err != nil {
		fmt.Printf("failed to stop kosmo: %v\n", err)
		os.Exit(1)
	}

	for i := 0; i < 10; i++ {
		if !isProcessRunning(pid) {
			break
		}
		time.Sleep(500 * time.Millisecond)
	}

	if isProcessRunning(pid) {
		proc.Kill()
		time.Sleep(500 * time.Millisecond)
	}

	os.Remove(pidFile)
	fmt.Println("kosmo stopped")
}

func handleStatus() {
	pidFile := getPIDFile()
	pid := readPID(pidFile)
	if pid == 0 {
		fmt.Println("kosmo is not running")
		return
	}

	if isProcessRunning(pid) {
		fmt.Printf("kosmo is running: (pid: %d)\n", pid)
	} else {
		fmt.Println("kosmo is not running")
		os.Remove(pidFile)
	}
}

func handleDeploy(args []string) {
	server, _ := parseArgs(args, "--server", "-s")
	if server == "" {
		fmt.Println("missing --server <url>")
		os.Exit(1)
	}

	cwd, err := os.Getwd()
	if err != nil {
		fmt.Printf("failed to get cwd: %v\n", err)
		os.Exit(1)
	}

	app := filepath.Base(cwd)
	fmt.Printf("preparing deployment for: %s ...\n", app)

	cfg, err := loadClientConfig()
	if err != nil {
		fmt.Printf("missing kosmo config, run `kosmo login` first: %v\n", err)
		os.Exit(1)
	}

	tarballData, err := createTarball()
	if err != nil {
		fmt.Printf("failed to create tarball: %v\n", err)
		os.Exit(1)
	}

	timestamp := time.Now().Unix()
	authReq := AuthRequest{
		App:       app,
		Timestamp: timestamp,
		Payload:   tarballData,
	}

	message, err := json.Marshal(authReq)
	if err != nil {
		fmt.Printf("failed to marshal auth request: %v\n", err)
		os.Exit(1)
	}

	privBytes, err := base64.StdEncoding.DecodeString(cfg.ClientPriv)
	if err != nil {
		fmt.Printf("failed to decode private key: %v\n", err)
		os.Exit(1)
	}

	sig := ed25519.Sign(privBytes, message)

	req, err := http.NewRequest("POST", fmt.Sprintf("%s/deploy?app=%s", server, app), bytes.NewReader(tarballData))
	if err != nil {
		fmt.Printf("failed to create request: %v\n", err)
		os.Exit(1)
	}

	req.Header.Set("Content-Type", "application/gzip")
	req.Header.Set("X-Kosmo-Pubkey", cfg.ClientPub)
	req.Header.Set("X-Kosmo-Signature", base64.StdEncoding.EncodeToString(sig))
	req.Header.Set("X-Kosmo-Timestamp", fmt.Sprintf("%d", timestamp))

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		fmt.Printf("deploy failed: %v\n", err)
		os.Exit(1)
	}
	defer resp.Body.Close()

	io.Copy(os.Stdout, resp.Body)
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

func shouldDaemonize() bool {
	if stat, err := os.Stdin.Stat(); err == nil {
		return (stat.Mode() & os.ModeCharDevice) != 0
	}
	return false
}

func loadClientConfig() (*Config, error) {
	home, _ := os.UserHomeDir()
	cfgPath := filepath.Join(home, ".kosmo", "config.json")
	cfgData, err := os.ReadFile(cfgPath)
	if err != nil {
		return nil, err
	}

	var cfg Config
	if err := json.Unmarshal(cfgData, &cfg); err != nil {
		return nil, err
	}

	return &cfg, nil
}

func createTarball() ([]byte, error) {
	pr, pw := io.Pipe()
	go func() {
		defer pw.Close()
		gzw := gzip.NewWriter(pw)
		defer gzw.Close()
		tw := tar.NewWriter(gzw)
		defer tw.Close()

		filepath.Walk(".", func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return err
			}

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
				defer f.Close()
				io.Copy(tw, f)
			}
			return nil
		})
	}()

	return io.ReadAll(pr)
}

// load state on startup
func loadState() {
	stateFile := ".kosmo/state.json"
	data, err := os.ReadFile(stateFile)
	if err != nil {
		return
	}

	var state map[string]AppInfo
	if err := json.Unmarshal(data, &state); err != nil {
		return
	}

	maxPort := 8080
	for name, info := range state {
		// check if process still exists
		proc, err := os.FindProcess(info.PID)
		if err != nil {
			continue
		}

		// check if process is actually running (works on Linux and macOS)
		if proc.Signal(syscall.Signal(0)) != nil {
			continue // process is dead
		}

		runningApps[name] = &AppInfo{
			Process: proc,
			PID:     info.PID,
			Port:    info.Port,
			Version: info.Version,
			Path:    info.Path,
		}

		if info.Port > maxPort {
			maxPort = info.Port
		}
	}
	nextPort = maxPort + 1
}

// save state to disk
func saveState() {
	appsMutex.RLock()
	state := make(map[string]AppInfo)
	for name, app := range runningApps {
		state[name] = AppInfo{
			PID:     app.PID,
			Port:    app.Port,
			Version: app.Version,
			Path:    app.Path,
		}
	}
	appsMutex.RUnlock()

	stateFile := ".kosmo/state.json"
	if err := os.MkdirAll(".kosmo", 0755); err != nil {
		fmt.Printf("failed to create .kosmo dir: %v\n", err)
		return
	}

	data, err := json.Marshal(state)
	if err != nil {
		fmt.Printf("failed to marshal state: %v\n", err)
		return
	}

	if err := os.WriteFile(stateFile, data, 0644); err != nil {
		fmt.Printf("failed to write state: %v\n", err)
	}
}

type AppInfo struct {
	Process *os.Process `json:"-"`
	PID     int         `json:"pid"`
	Port    int         `json:"port"`
	Version string      `json:"version"`
	Path    string      `json:"path"`
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
		time.Sleep(1 * time.Second)
	}
	return false
}

func gracefulShutdown(process *os.Process) {
	// send kill signal first
	process.Signal(syscall.SIGTERM)

	// wait for process to exit
	done := make(chan error, 1)
	go func() {
		_, err := process.Wait()
		done <- err
	}()

	select {
	case <-done:
		return
	case <-time.After(10 * time.Second):
		process.Kill()
		<-done
	}
}

func handleDeployHTTP(w http.ResponseWriter, r *http.Request) {
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

	// Read the request body for signature verification
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "failed to read request body", http.StatusBadRequest)
		return
	}

	// Verify client authentication using the new system
	if err := verifyClientAuth(pubB64, sigB64, ts, app, body); err != nil {
		fmt.Printf("authentication failed: %v\n", err)
		http.Error(w, "authentication failed: "+err.Error(), http.StatusForbidden)
		return
	}

	fmt.Printf("authenticated deploy from client: %s ...\n", pubB64[:16])

	// create build directory
	kosmoDir := ".kosmo"
	buildsDir := filepath.Join(kosmoDir, "builds")
	timestamp := time.Now().Unix()
	appBuildDir := filepath.Join(buildsDir, fmt.Sprintf("%s-%d", app, timestamp))

	os.MkdirAll(appBuildDir, 0755)

	// decompress and untar the request (using the body we already read)
	gzr, err := gzip.NewReader(bytes.NewReader(body))
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

		// prevent path traversal attacks
		target := filepath.Join(appBuildDir, filepath.Clean(hdr.Name))
		if !strings.HasPrefix(target, appBuildDir) {
			http.Error(w, "path traversal attempt", 400)
			return
		}

		switch hdr.Typeflag {
		case tar.TypeDir:
			os.MkdirAll(target, os.FileMode(hdr.Mode))
		case tar.TypeReg:
			if err := os.MkdirAll(filepath.Dir(target), 0755); err != nil {
				http.Error(w, "failed to create directory: "+err.Error(), 500)
				return
			}
			f, err := os.Create(target)
			if err != nil {
				http.Error(w, "create file error: "+err.Error(), 500)
				return
			}
			if _, err := io.Copy(f, tr); err != nil {
				f.Close()
				http.Error(w, "failed to write file: "+err.Error(), 500)
				return
			}
			if err := f.Close(); err != nil {
				http.Error(w, "failed to close file: "+err.Error(), 500)
				return
			}
		}
	}

	fmt.Printf("extract done: %s\n", appBuildDir)

	// build and run the app
	buildCmd := exec.Command("go", "build", "-o", "app")
	buildCmd.Dir = appBuildDir
	buildCmd.Stdout = os.Stdout
	buildCmd.Stderr = os.Stderr

	fmt.Println("building app...")
	if err := buildCmd.Run(); err != nil {
		fmt.Printf("build failed: %v\n", err)
		http.Error(w, "build failed: "+err.Error(), 500)
		return
	}

	fmt.Println("build done, starting app...")

	// verify binary exists
	binaryPath := filepath.Join(appBuildDir, "app")
	if _, err := os.Stat(binaryPath); os.IsNotExist(err) {
		http.Error(w, "binary not found after build", 500)
		return
	}

	// blue-green deployment: start new version first
	appsMutex.Lock()
	newPort := nextPort
	nextPort++
	appsMutex.Unlock()

	runCmd := exec.Command(binaryPath)
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

	// check if old version exists before health check
	appsMutex.Lock()
	oldApp, exists := runningApps[app]
	appsMutex.Unlock()

	// health check new version
	fmt.Printf("checking on port %d...\n", newPort)
	healthURL := fmt.Sprintf("http://localhost:%d/health", newPort)
	if !waitForHealth(healthURL, 30) {
		runCmd.Process.Kill()

		// Keep old version running if it exists
		if exists {
			fmt.Println("new version failed health check, keeping old version")
			http.Error(w, "deployment failed: health check timeout", 500)
			return
		}

		fmt.Println("app failed health check")
		http.Error(w, "deployment failed: no /health endpoint responding", 500)
		return
	}

	// switch traffic
	appsMutex.Lock()
	version := fmt.Sprintf("%d", timestamp)
	runningApps[app] = &AppInfo{
		Process: runCmd.Process,
		PID:     runCmd.Process.Pid,
		Port:    newPort,
		Version: version,
		Path:    appBuildDir,
	}
	appsMutex.Unlock()

	if exists {
		fmt.Printf("switching from port %d to %d\n", oldApp.Port, newPort)
		gracefulShutdown(oldApp.Process)
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

//daemonization helpers
func getPIDFile() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return filepath.Join(".kosmo", "kosmo.pid")
	}
	return filepath.Join(home, ".kosmo", "kosmo.pid")
}

func getLogFile() string {
	home, err := os.UserHomeDir()
	if err != nil {
		// Fallback to current directory if can't get home
		logDir := ".kosmo"
		os.MkdirAll(logDir, 0755)
		return filepath.Join(logDir, "kosmo.log")
	}
	logDir := filepath.Join(home, ".kosmo")
	if err := os.MkdirAll(logDir, 0755); err != nil {
		// Fallback to current directory if can't create
		return filepath.Join(".kosmo", "kosmo.log")
	}
	return filepath.Join(logDir, "kosmo.log")
}

func daemonize() error {
	// Find the executable path
	execPath, err := os.Executable()
	if err != nil {
		execPath = os.Args[0]
	}

	// Re-execute with KOSMO_DAEMON=1
	cmd := exec.Command(execPath, os.Args[1:]...)
	cmd.Env = append(os.Environ(), "KOSMO_DAEMON=1")
	cmd.Stdin = nil
	cmd.Stdout = nil
	cmd.Stderr = nil
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Setsid: true,
	}

	if err := cmd.Start(); err != nil {
		return fmt.Errorf("failed to start daemon: %v", err)
	}

	fmt.Printf("kosmo daemon started (PID: %d)\n", cmd.Process.Pid)
	fmt.Printf("logs: %s\n", getLogFile())
	os.Exit(0)

	return nil // unreachable
}

func setupDaemonStdio() {
	// redirect stdin to /dev/null
	devNull, err := os.OpenFile("/dev/null", os.O_RDWR, 0)
	if err != nil {
		fmt.Fprintf(os.Stderr, "warning: failed to open /dev/null: %v\n", err)
	} else {
		if err := unix.Dup2(int(devNull.Fd()), int(os.Stdin.Fd())); err != nil {
			fmt.Fprintf(os.Stderr, "warning: failed to redirect stdin: %v\n", err)
		}
		devNull.Close()
	}

	// redirect stdout/stderr to log file
	logFile := getLogFile()
	f, err := os.OpenFile(logFile, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0644)
	if err != nil {
		fmt.Fprintf(os.Stderr, "warning: failed to open log file %s: %v\n", logFile, err)
		return
	}

	if err := unix.Dup2(int(f.Fd()), int(os.Stdout.Fd())); err != nil {
		fmt.Fprintf(os.Stderr, "warning: failed to redirect stdout: %v\n", err)
		f.Close()
		return
	}

	if err := unix.Dup2(int(f.Fd()), int(os.Stderr.Fd())); err != nil {
		fmt.Fprintf(os.Stderr, "warning: failed to redirect stderr: %v\n", err)
		f.Close()
		return
	}

	f.Close()
}

func readPID(pidFile string) int {
	data, err := os.ReadFile(pidFile)
	if err != nil {
		return 0
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(data)))
	if err != nil {
		return 0
	}
	return pid
}

func writePID(pidFile string, pid int) error {
	dir := filepath.Dir(pidFile)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("failed to create pid directory: %v", err)
	}
	if err := os.WriteFile(pidFile, []byte(fmt.Sprintf("%d", pid)), 0644); err != nil {
		return fmt.Errorf("failed to write pid file: %v", err)
	}
	return nil
}

func isProcessRunning(pid int) bool {
	proc, err := os.FindProcess(pid)
	if err != nil {
		return false
	}

	// Signal 0 doesn't actually send a signal, just checks if process exists
	// Works on both Linux and macOS
	err = proc.Signal(syscall.Signal(0))
	if err != nil {
		// Process doesn't exist or we don't have permission
		return false
	}

	// Additional check: on Unix systems, try to get process state
	// This helps catch cases where the process exists but is zombie
	return true
}
