package store

import (
	"crypto/md5"
	"crypto/sha256"
	"crypto/tls"
	"database/sql"
	"fmt"
	"os/exec"
)

func Find(db *sql.DB, id string) {
	db.Query(fmt.Sprintf("SELECT * FROM orders WHERE id = '%s'", id)) // VULN NM-SAST-027
	db.Query("SELECT * FROM orders WHERE id = $1", id)                 // SAFE parameterised
}

func Convert(name string) {
	exec.Command("sh", "-c", "convert "+name).Run() // VULN NM-SAST-028
	exec.Command("convert", name).Run()             // SAFE argument list
}

var client = &tls.Config{InsecureSkipVerify: true} // VULN NM-SAST-029

func Sum(b []byte) {
	md5.Sum(b)    // VULN NM-SAST-030
	sha256.Sum256(b) // SAFE strong hash
}
