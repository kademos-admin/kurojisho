package main

import (
	"net/http"

	"example.com/inventory/internal/store"
)

func main() {
	s := store.New()
	srv := &Server{items: s}
	http.HandleFunc("/items", srv.List)
	http.HandleFunc("POST /items", srv.Create)
	http.HandleFunc("/health", health)
	http.ListenAndServe(":8080", nil)
}

func health(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte("ok"))
}
