package config

import (
	"log"
	"os"

	"github.com/joho/godotenv"
)

// Config holds all the necessary environment variables required by the application.
type Config_dev struct {
	Port                      string
	PostgresDB                string
	PostgresUser              string
	PostgresPassword          string
	DbURL                     string
	RedisPassword             string
	RedisDB                   string
	RedisAddress              string
	JwtSecret                 string
	JwtIssuer                 string
	JwtAudience               string
	AWSRegion                 string
	AWSAccessKeyID            string
	AWSSecretAccessKey        string
	SenderEmail               string
	BaseURL                   string
	TWILIO_ACCOUNT_SID        string
	TWILIO_AUTH_TOKEN         string
	TWILIO_VERIFY_SERVICE_SID string
	GoogleClientID            string
	GoogleClientSecret        string
}



// LoadConfig reads environment variables from the .env file and the OS environment,
// validates their presence, and returns a pointer to a Config struct.
// The function will log fatal errors and terminate the application if any required variable is missing.
func LoadConfig_dev() *Config_dev {
	// Load environment variables from .env file into the environment
	err := godotenv.Load()
	if err != nil {
		log.Fatalf("%s Error loading .env file: %v", logPrefix, err)
	}

	// Helper function to get environment variable or log fatal if missing
	getEnvOrFatal := func(key string) string {
		value := os.Getenv(key)
		if value == "" {
			log.Fatalf("%s Required environment variable %s is not set", logPrefix, key)
		}
		return value
	}

	// Load all required environment variables, fatal if missing (except PORT which has a default)
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	return &Config_dev{
		Port:                      port,
		PostgresDB:                getEnvOrFatal("POSTGRES_DB"),
		PostgresUser:              getEnvOrFatal("POSTGRES_USER"),
		PostgresPassword:          getEnvOrFatal("POSTGRES_PASSWORD"),
		DbURL:                     getEnvOrFatal("DB_URL"),
		RedisPassword:             getEnvOrFatal("REDIS_PASSWORD"),
		RedisDB:                   getEnvOrFatal("REDIS_DB"),
		RedisAddress:              getEnvOrFatal("REDIS_ADDRESS"),
		JwtSecret:                 getEnvOrFatal("JWT_SECRET"),
		JwtIssuer:                 getEnvOrFatal("JWT_ISSUER"),
		JwtAudience:               getEnvOrFatal("JWT_AUDIENCE"),
		AWSRegion:                 getEnvOrFatal("AWS_REGION"),
		AWSAccessKeyID:            getEnvOrFatal("AWS_ACCESS_KEY_ID"),
		AWSSecretAccessKey:        getEnvOrFatal("AWS_SECRET_ACCESS_KEY"),
		SenderEmail:               getEnvOrFatal("SENDER_EMAIL"),
		BaseURL:                   getEnvOrFatal("BASE_URL"),
		TWILIO_ACCOUNT_SID:        getEnvOrFatal("TWILIO_ACCOUNT_SID"),
		TWILIO_AUTH_TOKEN:         getEnvOrFatal("TWILIO_AUTH_TOKEN"),
		TWILIO_VERIFY_SERVICE_SID: getEnvOrFatal("TWILIO_VERIFY_SERVICE_SID"),
		GoogleClientID:            getEnvOrFatal("GOOGLE_CLIENT_ID"),
		GoogleClientSecret:        getEnvOrFatal("GOOGLE_CLIENT_SECRET"),
	}
}
