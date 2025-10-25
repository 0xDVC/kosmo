package main

import (
	"fmt"
	"net/http"
)

func main() {
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "hello from kosmo!\n")
	})

	fmt.Println("starting app on port 3000...")
	http.ListenAndServe(":3000", nil)
}
