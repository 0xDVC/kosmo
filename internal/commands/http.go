package commands

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/0xDVC/kosmo/internal/auth"
	"github.com/rs/zerolog/log"
)

func deploy(w http.ResponseWriter, r *http.Request) {
	log.Info().Msg("deployment request received")
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

	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "failed to read request body", http.StatusBadRequest)
		return
	}

	if err := auth.Verify(pubB64, sigB64, ts, app, body); err != nil {
		log.Error().Err(err).Msg("authentication failed")
		http.Error(w, fmt.Sprintf("authentication failed: %v", err), http.StatusForbidden)
		return
	}
	log.Info().Msgf("authenticated deploy from client: %s", pubB64[:16])

	kosmoDir := ".kosmo"
	buildsDir := filepath.Join(kosmoDir, "builds")
	timestamp := time.Now().Unix()
	appBuildDir := filepath.Join(buildsDir, fmt.Sprintf("%s-%d", app, timestamp))

	if err := os.MkdirAll(appBuildDir, 0755); err != nil {
		http.Error(w, fmt.Sprintf("failed to create build directory: %v", err), 500)
		return
	}

	gzr, err := gzip.NewReader(bytes.NewReader(body))
	if err != nil {
		http.Error(w, fmt.Sprintf("failed to read gzip: %v", err), 500)
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
			http.Error(w, fmt.Sprintf("failed to read tar: %v", err), 500)
			return
		}

		target := filepath.Join(appBuildDir, filepath.Clean(hdr.Name))
		if !strings.HasPrefix(target, appBuildDir) {
			http.Error(w, "path traversal attempt", 400)
			return
		}

		switch hdr.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(target, os.FileMode(hdr.Mode)); err != nil {
				http.Error(w, fmt.Sprintf("failed to create directory: %v", err), 500)
				return
			}
		case tar.TypeReg:
			if err := os.MkdirAll(filepath.Dir(target), 0755); err != nil {
				http.Error(w, fmt.Sprintf("failed to create directory: %v", err), 500)
				return
			}
			f, err := os.Create(target)
			if err != nil {
				http.Error(w, fmt.Sprintf("create file error: %v", err), 500)
				return
			}
			if _, err := io.Copy(f, tr); err != nil {
				f.Close()
				http.Error(w, fmt.Sprintf("failed to write file: %v", err), 500)
				return
			}
			if err := f.Close(); err != nil {
				http.Error(w, fmt.Sprintf("failed to close file: %v", err), 500)
				return
			}
		}
	}

	log.Info().Msgf("extract done: %s", appBuildDir)
	buildCmd := exec.Command("go", "build", "-o", "app")
	buildCmd.Dir = appBuildDir
	buildCmd.Stdout = os.Stdout
	buildCmd.Stderr = os.Stderr

	log.Info().Msg("building app")
	if err := buildCmd.Run(); err != nil {
		log.Error().Err(err).Msg("build failed")
		http.Error(w, fmt.Sprintf("build failed: %v", err), 500)
		return
	}
	log.Info().Msg("build done, starting app")

	binaryPath := filepath.Join(appBuildDir, "app")
	if _, err := os.Stat(binaryPath); os.IsNotExist(err) {
		http.Error(w, "binary not found after build", 500)
		return
	}

	appsMutex.Lock()
	newPort := nextPort
	nextPort++
	appsMutex.Unlock()

	logFile := filepath.Join(appBuildDir, "app.log")
	f, err := os.OpenFile(logFile, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0644)
	if err != nil {
		http.Error(w, fmt.Sprintf("failed to create app log file: %v", err), 500)
		return
	}

	runCmd := exec.Command(binaryPath)
	runCmd.Dir = appBuildDir
	runCmd.Env = append(os.Environ(), fmt.Sprintf("PORT=%d", newPort))
	runCmd.Stdout = f
	runCmd.Stderr = f
	runCmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}

	err = runCmd.Start()
	if err != nil {
		http.Error(w, fmt.Sprintf("failed to start app: %v", err), 500)
		return
	}

	appsMutex.Lock()
	oldApp, exists := runningApps[app]
	appsMutex.Unlock()

	log.Info().Msgf("checking on port %d", newPort)
	healthURL := fmt.Sprintf("http://localhost:%d/health", newPort)
	if !waitForHealth(healthURL, 30) {
		runCmd.Process.Kill()
		if exists {
			log.Error().Msg("new version failed health check, keeping old version")
			http.Error(w, "deployment failed: health check timeout", 500)
			return
		}
		log.Error().Msg("app failed health check")
		http.Error(w, "deployment failed: no /health endpoint responding", 500)
		return
	}

	appsMutex.Lock()
	version := fmt.Sprintf("%d", timestamp)

	var prevPath, prevLog string
	if oldApp != nil {
		prevPath = oldApp.Path
		prevLog = oldApp.LogFile
	}

	runningApps[app] = &AppInfo{
		Process:      runCmd.Process,
		PID:          runCmd.Process.Pid,
		Port:         newPort,
		Version:      version,
		Path:         appBuildDir,
		LogFile:      logFile,
		PreviousPath: prevPath,
		PreviousLog:  prevLog,
	}
	appsMutex.Unlock()

	if exists {
		log.Info().Msgf("switching from port %d to %d", oldApp.Port, newPort)
		gracefulShutdown(oldApp.Process)
	}

	saveState()

	host := r.Host
	if host == "" {
		host = "localhost"
	}
	url := fmt.Sprintf("http://%s:%d", host, newPort)

	fmt.Fprintf(w, "deployed to %s (version %s)\n", url, version)
	fmt.Fprintf(w, "logs: %s\n", logFile)
}
