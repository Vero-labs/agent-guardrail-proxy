package main

import (
	"log"
	"net/http"
)

func main() {
	log.Println("Proxy started")

	http.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("OK"))
	})

	log.Fatal(http.ListenAndServe(":8080", nil))
}
