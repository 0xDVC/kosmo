package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
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
		if len(os.Args) < 3 {
			fmt.Println("no repo path provided")
		}

		repoArg := strings.Trim(os.Args[2], "'\"")
		repoArg = strings.TrimPrefix(repoArg, "/")
		appName := filepath.Base(repoArg)
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
		} else {
			kosmoDir = globalKosmo
		}

		appsDir := filepath.Join(kosmoDir, "apps")
		buildsDir := filepath.Join(kosmoDir, "builds")

		appDir := filepath.Join(appsDir, appName)
		gitDir := filepath.Join(appDir, "repo.git")
		buildDir := filepath.Join(buildsDir, fmt.Sprintf("%s-%d", appName, time.Now().Unix()))

		// initialize bare repo if needed
		if _, err := os.Stat(gitDir); os.IsNotExist(err) {
			fmt.Printf("initializing repo for %s...\n", appName)
			os.MkdirAll(gitDir, 0755)
			initCmd := exec.Command("git", "init", "--bare")
			if err := initCmd.Run(); err != nil {
				fmt.Println("failed to init git repo: ", err)
			}

			// creat post-receive-hook
			hookPath := filepath.Join(gitDir, "hooks", "post-receive")
			hook := fmt.Sprintf(`#!/bin/bash
			while read oldrev newrev refname; do
				if ["$refname" ="refs/heads/main"] || ["$refname"= "refs/heads/master"]; then
					echo "receiving..."
					mkdir "%s"
					git --work-tree="%s" --git-dir="%s checkout -f
					echo "ready.."
				fi
			done`, buildDir, buildDir, gitDir)

			os.WriteFile(hookPath, []byte(hook), 0755)
		}
		//init git-receive-pack so git can push
		cmd := exec.Command("git-receive-pack", gitDir)
		cmd.Stdin = os.Stdin
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		if err := cmd.Run(); err != nil {
			fmt.Println("git-receive-pack failed: ", err)
		}
		os.Exit(0)
	}

	fmt.Printf("kosmo: unknwon command '%s'\n", cmd)
	os.Exit(1)
}
