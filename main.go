package main

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/signal"
	"time"

	"github.com/benkoben/unsubtle-core/internal/database"
	"github.com/joho/godotenv"
	_ "github.com/lib/pq"
)

const (
	defaultPort = "8081"
	defaultHost = "localhost"

	gracefulShutdownTimeout = 10 * time.Second
)

// TODO: Implement support for parsing os.Args in run() to allow quick change of the app's behaviour. I.e. debug mode or changing logging levels.

// run prepares and runs the server. Preperation is done by parsing environment variables and flags used to initialize
// various external datasources such as databases and logfiles. These parameters can be mocked and used to call run() from unit tests.
func run(ctx context.Context, w io.Writer, getenv func(string) string) error {
	ctx, cancel := signal.NotifyContext(ctx, os.Interrupt)
	defer cancel()

	// Handle environment variables
	godotenv.Load()
	dbConnString := getenv("DB_CONNECTION_STRING")
	host := getenv("SVC_HOST")
	port := getenv("SVC_PORT")
	jwtSecret := getenv("JWT_SECRET")

	// Validate inputs
	if dbConnString == "" {
		return fmt.Errorf("DB_CONNECTION_STRING not set")
	}

    if jwtSecret == "" {
        return fmt.Errorf("JWT_SECRET not set")
    }

	if host == "" {
		host = defaultHost
	}

	if port == "" {
		port = defaultPort
	}

	// Build configuration
	config := Config{
		Database: &DatabaseConfig{dbConnString},
		Service:  &ServiceConfig{host, port},
        JWTSecret: jwtSecret,
	}

	// Initialize database
	db, err := sql.Open("postgres", config.Database.ConnectionString)
	if err != nil {
		log.Fatalf("could not open database connection: %s", err)
	}
	dbStore := database.New(db)

	// Initialize server
	server := &http.Server{
		Handler: NewServerHandler(
			&config,
			dbStore,
		),
		Addr: config.Service.Address(),
	}

	// Entrypoint for new connections. Keeps on running for as long as the server is not closed.
	go func() {
		log.Printf("Listening on %s\n", server.Addr)
		if err := server.ListenAndServe(); !errors.Is(err, http.ErrServerClosed) {
			log.Fatalf("HTTP server error: %v", err)
		}
		log.Printf("Stopped accepting new connections")
		return
	}()

	// Gracefully shutdown the server whenever an os.Interrupt occurs, otherwise keep blocking code execution.
	// We give the server graceFulShutdownTimeout amount of seconds to shutdown.
	<-ctx.Done()

	// Signal received and stop blocking.
	log.Println("Shutting down server")

	shutdownCtx, shutdownCancel := context.WithTimeout(ctx, gracefulShutdownTimeout)
	defer shutdownCancel()

	// This will cause ListenAndServe to immediately return ErrServerClosed but keep waiting for all
	// connections to be gracefully handler for gracefulShutdownTimeout amount of seconds.
	if err := server.Shutdown(shutdownCtx); err != nil {
		log.Fatalf("Could not close server: %s", err)
	}

	// We are now safe to exit the program!
	log.Println("Server gracefully stopped")
	return nil
}

func main() {
	ctx := context.Background()
	if err := run(ctx, os.Stdout, os.Getenv); err != nil {
		fmt.Fprintf(os.Stderr, "%s\n", err)
		os.Exit(1)
	}
}
