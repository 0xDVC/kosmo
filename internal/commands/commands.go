package commands

import (
	"bytes"
	"fmt"
	"os"

	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/0xDVC/kosmo/internal/auth"
)

func Setup() {
	auth.InitServer()
}

func Init() {
	cwd, err := os.Getwd()
	if err != nil {
		fmt.Printf("failed to get cwd: %v\n", err)
		os.Exit(1)
	}

	kosmoDir := filepath.Join(cwd, ".kosmo")
	buildsDir := filepath.Join(kosmoDir, "builds")

	fmt.Println("initializing kosmo...")
	if err := os.MkdirAll(buildsDir, 0755); err != nil {
		fmt.Printf("failed to create builds dir: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("kosmo initialized.")
	fmt.Println("-- run 'kosmo deploy --server http://<ip>:8080'")
}

func Up(args []string) {
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

	// if we're in a tty and not already daemonized, fork and exit parent
	if os.Getenv("KOSMO_DAEMON") == "" {
		if shouldDaemonize() {
			if err := daemonize(); err != nil {
				fmt.Printf("failed to daemonize: %v\n", err)
				os.Exit(1)
			}
			return
		}
	}

	// if we should be a daemon, redirect stdio to logfile
	if shouldDaemonize() {
		setupDaemonStdio()
	}

	port := findAvailablePort(startPort)
	if port != startPort {
		fmt.Printf("port %d in use, using %d instead\n", startPort, port)
	}

	// restore any apps that were running before we crashed/restarted
	loadState()

	if err := writePID(pidFile, os.Getpid()); err != nil {
		fmt.Printf("failed to write PID file: %v\n", err)
	}

	fmt.Printf("kosmo server running on port %d (PID: %d)\n", port, os.Getpid())
	fmt.Println("ready for deployments...")

	http.HandleFunc("/deploy", deploy)

	fmt.Printf("starting HTTP server on :%d\n", port)
	if err := http.ListenAndServe(fmt.Sprintf(":%d", port), nil); err != nil {
		fmt.Printf("server failed: %v\n", err)
		if err := os.Remove(pidFile); err != nil {
			fmt.Printf("failed to remove PID file: %v\n", err)
		}
		os.Exit(1)
	}
}

func Down() {
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

	if err := os.Remove(pidFile); err != nil {
		fmt.Printf("warning: failed to remove PID file: %v\n", err)
	}
	fmt.Println("kosmo stopped")
}

func Status() {
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
		if err := os.Remove(pidFile); err != nil {
			fmt.Printf("warning: failed to remove stale PID file: %v\n", err)
		}
	}
}

func Deploy(args []string) {
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

	// sign the tarball with our ed25519 private key
	timestamp := time.Now().Unix()
	authReq := auth.AuthRequest{
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

func Logs(args []string) {
	app, _ := parseArgs(args, "--app", "")
	if app == "" {
		fmt.Println("usage: kosmo logs --app <app-name>")
		os.Exit(1)
	}

	appsMutex.RLock()
	appInfo, exists := runningApps[app]
	appsMutex.RUnlock()

	if !exists {
		fmt.Printf("app '%s' is not running\n", app)
		os.Exit(1)
	}

	if appInfo.LogFile == "" {
		fmt.Printf("no log file found for app '%s'\n", app)
		os.Exit(1)
	}

	cmd := exec.Command("tail", "-f", appInfo.LogFile)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		fmt.Printf("failed to tail logs: %v\n", err)
		os.Exit(1)
	}
}

func Rollback(args []string) {
	app, _ := parseArgs(args, "--app", "")
	if app == "" {
		fmt.Println("usage: kosmo rollback --app <app-name>")
		os.Exit(1)
	}

	appsMutex.Lock()
	defer appsMutex.Unlock()

	appInfo, exists := runningApps[app]
	if !exists {
		fmt.Printf("app '%s' is not running\n", app)
		os.Exit(1)
	}

	if appInfo.PreviousPath == "" {
		fmt.Printf("no previous version found for app '%s'\n", app)
		os.Exit(1)
	}

	// make sure the old build directory and binary still exist
	if _, err := os.Stat(appInfo.PreviousPath); os.IsNotExist(err) {
		fmt.Printf("previous build not found: %s\n", appInfo.PreviousPath)
		os.Exit(1)
	}

	prevBinary := filepath.Join(appInfo.PreviousPath, "app")
	if _, err := os.Stat(prevBinary); os.IsNotExist(err) {
		fmt.Printf("previous binary not found: %s\n", prevBinary)
		os.Exit(1)
	}

	fmt.Printf("rolling back app '%s' to previous version...\n", app)

	if appInfo.Process != nil {
		gracefulShutdown(appInfo.Process)
	}

	// start previous version
	runCmd := exec.Command(prevBinary)
	runCmd.Dir = appInfo.PreviousPath
	runCmd.Env = append(os.Environ(), fmt.Sprintf("PORT=%d", appInfo.Port))

	// use previous log file
	prevLogFile := appInfo.PreviousLog
	if prevLogFile == "" {
		prevLogFile = filepath.Join(appInfo.PreviousPath, "app.log")
	}

	f, err := os.OpenFile(prevLogFile, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0644)
	if err != nil {
		fmt.Printf("failed to open previous log file: %v\n", err)
		os.Exit(1)
	}
	runCmd.Stdout = f
	runCmd.Stderr = f

	runCmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}

	if err := runCmd.Start(); err != nil {
		fmt.Printf("failed to start previous version: %v\n", err)
		os.Exit(1)
	}

	// health check previous version
	healthURL := fmt.Sprintf("http://localhost:%d/health", appInfo.Port)
	if !waitForHealth(healthURL, 30) {
		runCmd.Process.Kill()
		fmt.Println("previous version failed health check")
		os.Exit(1)
	}

	// swap current and previous versions
	oldPath := appInfo.Path
	oldLog := appInfo.LogFile
	oldVersion := appInfo.Version

	appInfo.Path = appInfo.PreviousPath
	appInfo.LogFile = appInfo.PreviousLog
	appInfo.Version = "rollback-" + oldVersion
	appInfo.Process = runCmd.Process
	appInfo.PID = runCmd.Process.Pid
	appInfo.PreviousPath = oldPath
	appInfo.PreviousLog = oldLog

	runningApps[app] = appInfo
	saveState()

	fmt.Printf("rollback successful! app '%s' running on port %d\n", app, appInfo.Port)
	fmt.Printf("logs: %s\n", appInfo.LogFile)
}

func Apps() {
	appsMutex.RLock()
	defer appsMutex.RUnlock()

	if len(runningApps) == 0 {
		fmt.Println("no apps running")
		return
	}

	fmt.Printf("%-15s %-8s %-6s %-6s %-10s\n", "APP", "STATUS", "PORT", "PID", "VERSION")
	fmt.Println(strings.Repeat("-", 50))

	for name, app := range runningApps {
		status := "running"
		if app.Process == nil || !isProcessRunning(app.PID) {
			status = "stopped"
		}
		fmt.Printf("%-15s %-8s %-6d %-6d %-10s\n", name, status, app.Port, app.PID, app.Version)
	}
}

func Stop(args []string) {
	app, _ := parseArgs(args, "--app", "")
	if app == "" {
		fmt.Println("usage: kosmo stop --app <app-name>")
		os.Exit(1)
	}

	appsMutex.Lock()
	defer appsMutex.Unlock()

	appInfo, exists := runningApps[app]
	if !exists {
		fmt.Printf("app '%s' not found\n", app)
		os.Exit(1)
	}

	if appInfo.Process != nil {
		gracefulShutdown(appInfo.Process)
	}

	delete(runningApps, app)
	saveState()
	fmt.Printf("app '%s' stopped\n", app)
}

func Restart(args []string) {
	app, _ := parseArgs(args, "--app", "")
	if app == "" {
		fmt.Println("usage: kosmo restart --app <app-name>")
		os.Exit(1)
	}

	appsMutex.Lock()
	appInfo, exists := runningApps[app]
	if !exists {
		appsMutex.Unlock()
		fmt.Printf("app '%s' not found\n", app)
		os.Exit(1)
	}
	appsMutex.Unlock()

	// stop current version
	appsMutex.Lock()
	if appInfo.Process != nil {
		gracefulShutdown(appInfo.Process)
	}
	delete(runningApps, app)
	appsMutex.Unlock()

	// redeploy from current build
	runCmd := exec.Command(filepath.Join(appInfo.Path, "app"))
	runCmd.Dir = appInfo.Path
	runCmd.Env = append(os.Environ(), fmt.Sprintf("PORT=%d", appInfo.Port))

	f, err := os.OpenFile(appInfo.LogFile, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0644)
	if err != nil {
		fmt.Printf("failed to open log file: %v\n", err)
		os.Exit(1)
	}
	runCmd.Stdout = f
	runCmd.Stderr = f
	runCmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}

	if err := runCmd.Start(); err != nil {
		fmt.Printf("failed to start app: %v\n", err)
		os.Exit(1)
	}

	healthURL := fmt.Sprintf("http://localhost:%d/health", appInfo.Port)
	if !waitForHealth(healthURL, 30) {
		runCmd.Process.Kill()
		fmt.Println("app failed health check")
		os.Exit(1)
	}

	// update state
	appsMutex.Lock()
	appInfo.Process = runCmd.Process
	appInfo.PID = runCmd.Process.Pid
	runningApps[app] = appInfo
	appsMutex.Unlock()
	saveState()

	fmt.Printf("app '%s' restarted on port %d\n", app, appInfo.Port)
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
