package main

import (
	"crypto/md5"
	"crypto/tls"
	"database/sql"
	"fmt"
	"net/http"
	"os/exec"
)

func lookup(db *sql.DB, name string) (*sql.Rows, error) {
	return db.Query(fmt.Sprintf("SELECT * FROM t WHERE name = '%s'", name))
}

func run(w http.ResponseWriter, r *http.Request) {
	out, _ := exec.Command("sh", "-c", r.URL.Query().Get("cmd")).Output()
	w.Write(out)
}

func sum(data []byte) [16]byte {
	return md5.Sum(data)
}

func client() *http.Client {
	return &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}}
}

func main() {
	http.HandleFunc("/run", run)
	http.ListenAndServe(":8080", nil)
}
