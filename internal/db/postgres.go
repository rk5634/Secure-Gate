package db

import (
	"context"
	"log"
	"os"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

var Pool *pgxpool.Pool

func Init() {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	dbURL := os.Getenv("DB_URL")
	config, err := pgxpool.ParseConfig(dbURL)
	if err != nil {
		log.Fatalf("auth-system:internal:db:postgres:Init: Failed to parse DB config: %v", err)
	}

	Pool, err = pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		log.Fatalf("auth-system:internal:db:postgres:Init: Failed to create DB pool: %v", err)
	}

	if err = Pool.Ping(ctx); err != nil {
		log.Fatalf("auth-system:internal:db:postgres:Init: DB connection failed: %v", err)
	}

	log.Println("Connected to PostgreSQL with pgx")
}