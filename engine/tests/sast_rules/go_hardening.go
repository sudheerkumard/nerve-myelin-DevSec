// Fixture for engine/myelin_engine/rules/sast/go_hardening.yaml (opengrep --test). Not compiled.
package main

func demo(tok string, f *zip.File, dest string) {
	// ruleid: nervve.go.jwt-unverified
	t, _, _ := jwt.NewParser().ParseUnverified(tok, claims)
	// ruleid: nervve.go.insecure-tls-version
	c := &tls.Config{MinVersion: tls.VersionTLS10}
	// ok: nervve.go.insecure-tls-version
	d := &tls.Config{MinVersion: tls.VersionTLS12}
	// ruleid: nervve.go.zip-slip
	p := filepath.Join(dest, f.Name)
	// ruleid: nervve.go.insecure-cookie
	ck := http.Cookie{Name: "s", Value: v, Secure: false}
	// ruleid: nervve.go.server-without-timeouts
	http.ListenAndServe(":8080", nil)
}
