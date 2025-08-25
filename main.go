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

	auth "github.com/benkoben/unsubtle-core/internal/auth_client"
	"github.com/benkoben/unsubtle-core/internal/database"
	"github.com/benkoben/unsubtle-core/internal/logging"
	"github.com/joho/godotenv"
	_ "github.com/lib/pq"
	"github.com/supabase-community/supabase-go"
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
	supabaseUrl := getenv("SUPABASE_URL")
	supabaseKey := getenv("SUPABASE_KEY")

	// Validate inputs
	if dbConnString == "" {
		return fmt.Errorf("DB_CONNECTION_STRING not set")
	}

	if supabaseKey == "" || supabaseUrl == "" {
		return fmt.Errorf("missing Supabase configuration, ensure both SUPABASE_KEY and SUPABASE_URL are set")
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
		JwksUrl:  fmt.Sprintf("%s/%s/.well-known/jwks.json", supabaseUrl, supabase.AUTH_URL),
	}

	// Initialize database
	db, err := sql.Open("postgres", config.Database.ConnectionString)
	if err != nil {
		log.Fatalf("could not open database connection: %s", err)
	}
	dbStore := database.New(db)

	// Initialize auth_client
	supabaseClient, err := auth.NewSupabaseClient(supabaseUrl, supabaseKey)
	if err != nil {
		fmt.Println("cannot initalize client", err)
	}
	client, err := auth.NewClient(supabaseClient)
	if err != nil {
		fmt.Println("cannot initialize client", err)
	}

	// Initialize server
	server := &http.Server{
		Handler: logging.LoggingMiddleware(NewServerHandler(
			&config,
			dbStore,
			*client,
		)),
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
