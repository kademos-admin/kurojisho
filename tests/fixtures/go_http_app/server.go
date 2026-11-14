package main

import (
	"net/http"
	"reflect"

	"example.com/inventory/internal/store"
)

type Logger struct{}

func (l *Logger) Log(msg string) {}

type Server struct {
	Logger
	items *store.Store
}

func (s *Server) List(w http.ResponseWriter, r *http.Request) {
	s.Log("list")
	s.write(w, s.items.All())
}

func (s *Server) Create(w http.ResponseWriter, r *http.Request) {
	s.items.Add(r.FormValue("name"))
	hook := r.FormValue("hook")
	reflect.ValueOf(s).MethodByName(hook).Call(nil)
}

func (s *Server) write(w http.ResponseWriter, items []string) {
	for _, item := range items {
		w.Write([]byte(item))
	}
}
