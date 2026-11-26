// Fixture for engine/myelin_engine/rules/sast/go.yaml (opengrep --test). Not compiled.
package main

import (
	"crypto/md5"
	"crypto/sha256"
	"crypto/tls"
	"database/sql"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"strconv"
)

var db *sql.DB

func user(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id")
	// ruleid: nervve.go.sql-injection
	db.Query(fmt.Sprintf("SELECT * FROM users WHERE id = %s", id))
	// ruleid: nervve.go.sql-injection
	db.Query("SELECT * FROM users WHERE id = " + id)
	// ok: nervve.go.sql-injection
	db.Query("SELECT * FROM users WHERE id = $1", id)
	n, _ := strconv.Atoi(id)
	// ok: nervve.go.sql-injection
	db.Query(fmt.Sprintf("SELECT * FROM users WHERE id = %d", n))
}

func ping(w http.ResponseWriter, r *http.Request) {
	host := r.FormValue("host")
	// ruleid: nervve.go.command-injection
	exec.Command("sh", "-c", "ping -c 1 "+host).Run()
	// ok: nervve.go.command-injection
	exec.Command("ping", "-c", "1", host).Run()
}

func file(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("name")
	// ruleid: nervve.go.path-traversal
	data, _ := os.ReadFile("/srv/files/" + name)
	w.Write(data)
}

func fetch(w http.ResponseWriter, r *http.Request) {
	// ruleid: nervve.go.ssrf
	resp, _ := http.Get(r.URL.Query().Get("url"))
	defer resp.Body.Close()
	// ok: nervve.go.ssrf
	http.Get("https://api.example.com/status")
}

func goTo(w http.ResponseWriter, r *http.Request) {
	// ruleid: nervve.go.open-redirect
	http.Redirect(w, r, r.URL.Query().Get("next"), http.StatusFound)
}

func hello(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("name")
	// ruleid: nervve.go.xss
	fmt.Fprintf(w, "<h1>Hello %s</h1>", name)
}

func client() *http.Client {
	// ruleid: nervve.go.tls-verification-disabled
	cfg := &tls.Config{InsecureSkipVerify: true}
	return &http.Client{Transport: &http.Transport{TLSClientConfig: cfg}}
}

func digest(b []byte) {
	// ruleid: nervve.go.weak-crypto
	md5.Sum(b)
	// ok: nervve.go.weak-crypto
	sha256.Sum256(b)
}
