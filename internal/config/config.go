package config

import (
	"log"
	"os"
	"github.com/joho/godotenv"
)

// Config holds all the environment variables needed by the application
type Config struct {
	Port     string
	DbURL    string
	JwtSecret string
	JwtIssuer string
	JwtAudience string

}

// LoadConfig loads environment variables from .env file and returns the Config struct
func LoadConfig() (*Config) {
	// Load environment variables from .env file
	err := godotenv.Load()
	if err != nil {
		log.Fatalf("auth-system:internal:config:config:LoadConfig():Error loading .env file - %v", err)
	}

	// Load variables from the environment
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080" // default to port 8080 if not set
	}

	dbURL := os.Getenv("DB_URL")
	if dbURL == "" {
		log.Fatalf("auth-system:internal:config:config:LoadConfig():DB_URL not found")
	}

	jwtSecret := os.Getenv("JWT_SECRET")
	if jwtSecret == "" {
		log.Fatalf("auth-system:internal:config:config:LoadConfig():JWT_SECRET is not found")
	}

	jwtIssuer := os.Getenv("JWT_ISSUER")
	if jwtIssuer == "" {
		log.Fatalf("auth-system:internal:config:config:LoadConfig():JWT_ISSUER is not found")
	}
	
	jwtAudience := os.Getenv("JWT_AUDIENCE")
	if jwtAudience == "" {
		log.Fatalf("auth-system:internal:config:config:LoadConfig():JWT_AUDIENCE is not found")
	}


	

	return &Config{
		Port:     port,
		DbURL:    dbURL,
		JwtSecret: jwtSecret,
		JwtIssuer: jwtIssuer,
		JwtAudience: jwtAudience,

	}
}
