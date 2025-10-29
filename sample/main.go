package main

import (
	"fmt"
	"net/http"
	"os"
	"time"
)

func main() {
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "Hello from kosmo-deployed app! Time: %s\n", time.Now().Format(time.RFC3339))
	})

	http.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		fmt.Fprintf(w, "ok")
	})

	fmt.Printf("Server starting on port %s\n", port)
	http.ListenAndServe(":"+port, nil)
}
