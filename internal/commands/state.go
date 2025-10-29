package commands

import (
	"encoding/json"
	"fmt"
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

type AppInfo struct {
	Process      *os.Process `json:"-"`
	PID          int         `json:"pid"`
	Port         int         `json:"port"`
	Version      string      `json:"version"`
	Path         string      `json:"path"`
	LogFile      string      `json:"log_file"`
	PreviousPath string      `json:"previous_path"`
	PreviousLog  string      `json:"previous_log"`
}

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
		proc, err := os.FindProcess(info.PID)
		if err != nil {
			continue
		}
		if proc.Signal(syscall.Signal(0)) != nil {
			continue
		}

		runningApps[name] = &AppInfo{
			Process:      proc,
			PID:          info.PID,
			Port:         info.Port,
			Version:      info.Version,
			Path:         info.Path,
			LogFile:      info.LogFile,
			PreviousPath: info.PreviousPath,
			PreviousLog:  info.PreviousLog,
		}

		if info.Port > maxPort {
			maxPort = info.Port
		}
	}
	nextPort = maxPort + 1
}

func saveState() {
	appsMutex.RLock()
	state := make(map[string]AppInfo)
	for name, app := range runningApps {
		state[name] = AppInfo{
			PID:          app.PID,
			Port:         app.Port,
			Version:      app.Version,
			Path:         app.Path,
			LogFile:      app.LogFile,
			PreviousPath: app.PreviousPath,
			PreviousLog:  app.PreviousLog,
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
	process.Signal(syscall.SIGTERM)
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
		logDir := ".kosmo"
		os.MkdirAll(logDir, 0755)
		return filepath.Join(logDir, "kosmo.log")
	}
	logDir := filepath.Join(home, ".kosmo")
	if err := os.MkdirAll(logDir, 0755); err != nil {
		return filepath.Join(".kosmo", "kosmo.log")
	}
	return filepath.Join(logDir, "kosmo.log")
}

func daemonize() error {
	execPath, err := os.Executable()
	if err != nil {
		execPath = os.Args[0]
	}

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

	return nil
}

func setupDaemonStdio() {
	devNull, err := os.OpenFile("/dev/null", os.O_RDWR, 0)
	if err != nil {
		fmt.Fprintf(os.Stderr, "warning: failed to open /dev/null: %v\n", err)
	} else {
		if err := unix.Dup2(int(devNull.Fd()), int(os.Stdin.Fd())); err != nil {
			fmt.Fprintf(os.Stderr, "warning: failed to redirect stdin: %v\n", err)
		}
		devNull.Close()
	}

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
	return proc.Signal(syscall.Signal(0)) == nil
}

func shouldDaemonize() bool {
	if stat, err := os.Stdin.Stat(); err == nil {
		return (stat.Mode() & os.ModeCharDevice) != 0
	}
	return false
}
