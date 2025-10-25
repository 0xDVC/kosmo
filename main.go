package main

import (
	"fmt"
	"os"
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

		kosmoDir := filepath.Join(cwd, ".kosmo")
		appsDir := filepath.Join(kosmoDir, "apps")
		buildsDir := filepath.Join(kosmoDir, "builds")
		releasesDir := filepath.Join(kosmoDir, "releasesDir")

		fmt.Println("initializing...\n", kosmoDir)

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

}

