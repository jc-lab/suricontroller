// Package web serves suri-controller-web, the management UI, from files
// embedded at build time (web/dist, produced by `npm run build` in web/ui).
//
// The UI uses hash-based routing and relative URLs, so it can be mounted
// under any path prefix. By default it calls the API at "./api"
// relative to the page.
package web

import (
	"bytes"
	"embed"
	"html"
	"io/fs"
	"net/http"
	"strings"
)

//go:embed all:dist
var dist embed.FS

// Options configures the handler.
type Options struct {
	// APIBase overrides the API URL used by the UI (default "api",
	// relative to the page).
	APIBase string
}

// Handler returns an http.Handler serving the UI. Mount it with its prefix
// stripped.
func Handler(opts Options) http.Handler {
	sub, _ := fs.Sub(dist, "dist")
	index, err := fs.ReadFile(sub, "index.html")
	if err != nil {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Error(w, "suri-controller-web is not built: run `npm ci && npm run build` in web/ui and rebuild", http.StatusNotFound)
		})
	}
	if opts.APIBase != "" {
		meta := `<meta name="suricontroller-api" content="` + html.EscapeString(opts.APIBase) + `">`
		index = bytes.Replace(index, []byte("<head>"), []byte("<head>"+meta), 1)
	}
	files := http.FileServerFS(sub)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "same-origin")
		// Inline styles are needed by Mantine and CodeMirror; scripts are
		// only loaded from the embedded files.
		w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; "+
			"img-src 'self' data:; connect-src 'self'; font-src 'self' data:; frame-ancestors 'none'; base-uri 'self'; form-action 'self'")
		if r.URL.Path == "/" || r.URL.Path == "" || r.URL.Path == "/index.html" {
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.Header().Set("Cache-Control", "no-cache")
			_, _ = w.Write(index)
			return
		}
		if strings.HasPrefix(r.URL.Path, "/assets/") {
			w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
		}
		files.ServeHTTP(w, r)
	})
}
