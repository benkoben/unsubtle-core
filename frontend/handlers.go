package frontend

import (
	"mime"
	"net/http"
	"path/filepath"
	"strings"
)

// setMimeType is an internal middleware handler that sets the correct Content-Type headers.
func setMIMEType(next http.Handler) http.Handler {
	// Set appropriate MIME types for common file types

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ext := filepath.Ext(r.URL.Path)
		// Set appropriate MIME types for common file types
		switch strings.ToLower(ext) {
		case ".js":
			w.Header().Set("Content-Type", "application/javascript")
		case ".css":
			w.Header().Set("Content-Type", "text/css")
		case ".html":
			w.Header().Set("Content-Type", "text/html")
		case ".json":
			w.Header().Set("Content-Type", "application/json")
		case ".png":
			w.Header().Set("Content-Type", "image/png")
		case ".jpg", ".jpeg":
			w.Header().Set("Content-Type", "image/jpeg")
		case ".gif":
			w.Header().Set("Content-Type", "image/gif")
		case ".svg":
			w.Header().Set("Content-Type", "image/svg+xml")
		default:
			// Try to detect MIME type automatically
			mimeType := mime.TypeByExtension(ext)
			if mimeType != "" {
				w.Header().Set("Content-Type", mimeType)
			}
		}
		next.ServeHTTP(w, r)
	})
}

// HandleStatic expose the static files by creating a http handler with proper MIME types
func HandleStatic() http.Handler {
	staticDir := http.Dir(filepath.Join("frontend", "static"))
	fileServer := http.FileServer(staticDir)

	return setMIMEType(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Strip the /static prefix from the URL path
		// so /static/js/helloworld.js becomes /js/helloworld.js.
		//
		// Without this the fileserver does not find the correct files.
		r.URL.Path = strings.TrimPrefix(r.URL.Path, "/static")

		fileServer.ServeHTTP(w, r)
	}))
}

func HandleIndex() http.Handler {
	return setMIMEType(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, filepath.Join("frontend", "html", "index.html"))
	}))
}

func HandleDashboard() http.Handler {
	return setMIMEType(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, filepath.Join("frontend", "html", "dashboard.html"))
	}))
}
