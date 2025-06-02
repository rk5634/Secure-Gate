package db

import (
	"context"
	"log"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/rkcuwork/auth-system/internal/config"
)

// Pool is the global PostgreSQL connection pool instance used throughout the application.
var Pool *pgxpool.Pool

// logPrefix standardizes the log message prefix for easier tracing and debugging.
const logPrefix = "auth-system:internal:db:postgres:Init():"

// Init initializes the PostgreSQL connection pool using configuration from environment variables.
// It sets up a context with a 5-second timeout for connection attempts.
// The function will log fatal errors and terminate the application if it fails to:
// - Parse the database configuration
// - Establish the connection pool
// - Verify the connection by pinging the database
func Init(cfg *config.Config) {
	// Create a context with timeout to avoid hanging during connection attempts
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Retrieve the database URL from environment variables
	dbURL := cfg.DbURL
	if dbURL == "" {
		log.Fatalf("%s Environment variable DB_URL is not set", logPrefix)
	}

	// Parse the database configuration from the URL string
	config, err := pgxpool.ParseConfig(dbURL)
	if err != nil {
		log.Fatalf("%s Failed to parse DB config: %v", logPrefix, err)
	}

	// Create a new connection pool with the parsed configuration
	Pool, err = pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		log.Fatalf("%s Failed to create DB pool: %v", logPrefix, err)
	}

	// Ping the database to verify connectivity and credentials
	if err = Pool.Ping(ctx); err != nil {
		log.Fatalf("%s DB connection failed: %v", logPrefix, err)
	}

	log.Println("Connected to PostgreSQL with pgx")
}
