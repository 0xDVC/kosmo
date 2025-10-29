package commands

import (
	"archive/tar"
	"compress/gzip"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/0xDVC/kosmo/internal/auth"
)

func loadClientConfig() (*auth.Config, error) {
	home, _ := os.UserHomeDir()
	cfgPath := filepath.Join(home, ".kosmo", "config.json")
	cfgData, err := os.ReadFile(cfgPath)
	if err != nil {
		return nil, err
	}

	var cfg auth.Config
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
