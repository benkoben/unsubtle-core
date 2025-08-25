package logging

import (
	"log"
	"net/http"
	"time"
)

// ResponseWriter is a wrapper around http.ResponseWriter to capture status code
type ResponseWriter struct {
	http.ResponseWriter
	statusCode int
}

// NewResponseWriter creates a new ResponseWriter
func NewResponseWriter(w http.ResponseWriter) *ResponseWriter {
	return &ResponseWriter{ResponseWriter: w, statusCode: http.StatusOK}
}

// WriteHeader captures the status code and calls the original WriteHeader
func (rw *ResponseWriter) WriteHeader(code int) {
	rw.statusCode = code
	rw.ResponseWriter.WriteHeader(code)
}

// LoggingMiddleware creates a middleware that logs HTTP requests
func LoggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()

		// Wrap the response writer to capture status code
		wrapped := NewResponseWriter(w)

		// Log the incoming request
		log.Printf("Started %s %s from %s", r.Method, r.URL.Path, r.RemoteAddr)

		// Call the next handler
		next.ServeHTTP(wrapped, r)

		// Log the completed request
		duration := time.Since(start)
		log.Printf("Completed %s %s %d in %v",
			r.Method,
			r.URL.Path,
			wrapped.statusCode,
			duration,
		)
	})
}

// LoggingHandler is a convenience function for wrapping individual handlers
func LoggingHandler(handler http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()

		wrapped := NewResponseWriter(w)

		log.Printf("Started %s %s from %s", r.Method, r.URL.Path, r.RemoteAddr)

		handler.ServeHTTP(wrapped, r)

		duration := time.Since(start)
		log.Printf("Completed %s %s %d in %v",
			r.Method,
			r.URL.Path,
			wrapped.statusCode,
			duration,
		)
	}
}
