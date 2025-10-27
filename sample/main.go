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
		port = "8081"
	}

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "Hello from kosmo-deployed app! Time: %s\n", time.Now().Format(time.RFC3339))
	})

	fmt.Printf("Sample app starting on :%s\n", port)
	http.ListenAndServe(":"+port, nil)
}
