package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Println("kosmo: missing command")
		os.Exit(1)
	}

	cmd := os.Args[1]

	// initialize kosmo
	if cmd == "init" {
		cwd, err := os.Getwd()
		if err != nil {
			msg := err.Error()
			if strings.Contains(msg, ":") {
				parts := strings.Split(msg, ":")
				msg = strings.TrimSpace(parts[len(parts)-1])
			}
			fmt.Println("failed to get the working dir: ", msg)

		}
		// check if system level data is available for access, so we have some sort of global data sync for all our apps
		globalDir := "/var/lib/kosmo"
		localDir := filepath.Join(cwd, ".kosmo")
		var kosmoDir string
		mode := "global"

		// attempt creating taht global path(doesn't work on darwin-bsd though)
		err = os.MkdirAll(globalDir, 0755)
		if err != nil {
			kosmoDir = localDir
			mode = "local"
		} else {
			kosmoDir = globalDir
		}

		appsDir := filepath.Join(kosmoDir, "apps")
		buildsDir := filepath.Join(kosmoDir, "builds")
		releasesDir := filepath.Join(kosmoDir, "releasesDir")

		fmt.Printf("initializing [%s]...\n", mode)

		dirs := []string{kosmoDir, appsDir, buildsDir, releasesDir}
		for _, dir := range dirs {
			err := os.MkdirAll(dir, 0755) // rwxr-xr-x permission
			if err != nil {
				msg := err.Error()
				if strings.Contains(msg, ":") {
					parts := strings.Split(msg, ":")
					msg = strings.TrimSpace(parts[len(parts)-1])
				}
				fmt.Println("failed to create dir: ", msg)
			}

		}
		// current user
		user := os.Getenv("USER")
		if user == "" {
			user = "deploy"
		}

		host, _ := os.Hostname()
		fmt.Printf("\nkosmo initialized...\n")
		fmt.Printf("-- git remote add kosmo %s@%s:app\n", user, host)
		fmt.Printf("-- git push kosmo main\n")
		os.Exit(0)
	}

	
	if cmd == "git-receive-pack" {
		fmt.Fprintf(os.Stderr, "[DEBUG] git-receive-pack called\n")
		fmt.Fprintf(os.Stderr, "[DEBUG] args: %v\n", os.Args)
	
		if len(os.Args) < 3 {
			fmt.Println("no repo path provided")
			os.Exit(1)
		}
	
		repoArg := strings.Trim(os.Args[2], "'\"")
		repoArg = strings.TrimPrefix(repoArg, "/")
		appName := filepath.Base(repoArg)
	
		fmt.Fprintf(os.Stderr, "[DEBUG] parsed app name: %s\n", appName)
	
		if appName == "" || appName == "." {
			appName = "myapp"
		}
	
		// get dir for .kosmo(local/var)
		cwd, _ := os.Getwd()
		localKosmo := filepath.Join(cwd, ".kosmo")
		globalKosmo := "/var/lib/kosmo"
		kosmoDir := ""
		if _, err := os.Stat(localKosmo); err == nil {
			kosmoDir = localKosmo
			fmt.Fprintf(os.Stderr, "[DEBUG] using local kosmo: %s\n", kosmoDir)
		} else {
			kosmoDir = globalKosmo
			fmt.Fprintf(os.Stderr, "[DEBUG] using global kosmo: %s\n", kosmoDir)
		}
	
		appsDir := filepath.Join(kosmoDir, "apps")
		buildsDir := filepath.Join(kosmoDir, "builds")
		gitDir := filepath.Join(appsDir, appName, "repo.git")
	
		fmt.Fprintf(os.Stderr, "[DEBUG] git dir: %s\n", gitDir)
		fmt.Fprintf(os.Stderr, "[DEBUG] checking if repo exists...\n")
	
		// initialize bare repo if needed
		if _, err := os.Stat(gitDir); os.IsNotExist(err) {
			fmt.Fprintf(os.Stderr, "[DEBUG] repo doesn't exist, creating...\n")
			fmt.Printf("initializing repo for %s...\n", appName)
		
			if err := os.MkdirAll(gitDir, 0755); err != nil {
				fmt.Fprintf(os.Stderr, "[DEBUG] failed to create dir: %v\n", err)
				fmt.Println("failed to create repo directory: ", err)
				os.Exit(1)
			}
		
			fmt.Fprintf(os.Stderr, "[DEBUG] created dir, running git init --bare\n")
		
			// init bare repo
			initCmd := exec.Command("git", "init", "--bare")
			initCmd.Dir = gitDir
			if err := initCmd.Run(); err != nil {
				fmt.Fprintf(os.Stderr, "[DEBUG] git init failed: %v\n", err)
				fmt.Println("failed to init git repo: ", err)
				os.Exit(1)
			}
		
			fmt.Fprintf(os.Stderr, "[DEBUG] git init success\n")
		
			hooksDir := filepath.Join(gitDir, "hooks")
			if err := os.MkdirAll(hooksDir, 0755); err != nil {
				fmt.Fprintf(os.Stderr, "[DEBUG] failed to create hooks dir: %v\n", err)
				fmt.Println("failed to create hooks dir:", err)
				os.Exit(1)
			}
		
			// create post-receive-hook
			hookPath := filepath.Join(gitDir, "hooks", "post-receive")
			hook := fmt.Sprintf(`#!/bin/bash
			set -e
			while read oldrev newrev refname; do
			if [ "$refname" = "refs/heads/main" ] || [ "$refname" = "refs/heads/master" ]; then
					echo "receiving..."
		
					BUILD_DIR="%s/%s-$(date +%%s)"
					mkdir -p "$BUILD_DIR"
					git --work-tree="$BUILD_DIR" --git-dir="%s" checkout -f "$refname"
		
					echo "ready at: $BUILD_DIR"
				fi
			done
			`, buildsDir, appName, gitDir)
		
			os.WriteFile(hookPath, []byte(hook), 0755)
			fmt.Fprintf(os.Stderr, "[DEBUG] created post-receive hook\n")
		} else {
			fmt.Fprintf(os.Stderr, "[DEBUG] repo exists, skipping creation\n")
		}
		
		fmt.Fprintf(os.Stderr, "[DEBUG] running git-receive-pack %s\n", gitDir)
	
		// init git-receive-pack so git can push
		cmd := exec.Command("git-receive-pack", gitDir)
		cmd.Stdin = os.Stdin
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		if err := cmd.Run(); err != nil {
			fmt.Fprintf(os.Stderr, "[DEBUG] git-receive-pack error: %v\n", err)
			fmt.Println("git-receive-pack failed: ", err)
			os.Exit(1)
		}
	
		fmt.Fprintf(os.Stderr, "[DEBUG] git-receive-pack completed\n")
		os.Exit(0)
	}

	fmt.Printf("kosmo: unknown command '%s'\n", cmd)
	os.Exit(1)
}
