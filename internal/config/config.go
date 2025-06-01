package config

import (
	"log"
	"os"

	"github.com/joho/godotenv"
)



// Config holds all the necessary environment variables required by the application.
type Config struct {
	Port                      string
	DbURL                     string
	JwtSecret                 string
	JwtIssuer                 string
	JwtAudience               string
	SenderEmail               string
	BaseURL                   string
	TWILIO_ACCOUNT_SID        string
	TWILIO_AUTH_TOKEN         string
	TWILIO_VERIFY_SERVICE_SID string
}

// logPrefix is the standard prefix for all log messages in this package,
// improving consistency and making log messages easier to trace.
const logPrefix = "auth-system:internal:config:config:LoadConfig():"



// LoadConfig reads environment variables from the .env file and the OS environment,
// validates their presence, and returns a pointer to a Config struct.
// The function will log fatal errors and terminate the application if any required variable is missing.
func LoadConfig() *Config {
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
		port = "8080" // default port if not specified
	}

	dbURL := getEnvOrFatal("DB_URL")
	jwtSecret := getEnvOrFatal("JWT_SECRET")
	jwtIssuer := getEnvOrFatal("JWT_ISSUER")
	jwtAudience := getEnvOrFatal("JWT_AUDIENCE")
	senderEmail := getEnvOrFatal("SENDER_EMAIL")
	baseURL := getEnvOrFatal("BASE_URL")
	twilioAccountSID := getEnvOrFatal("TWILIO_ACCOUNT_SID")
	twilioAuthToken := getEnvOrFatal("TWILIO_AUTH_TOKEN")
	twilioVerifyServiceSID := getEnvOrFatal("TWILIO_VERIFY_SERVICE_SID")

	// Return the populated Config struct pointer
	return &Config{
		Port:                      port,
		DbURL:                     dbURL,
		JwtSecret:                 jwtSecret,
		JwtIssuer:                 jwtIssuer,
		JwtAudience:               jwtAudience,
		SenderEmail:               senderEmail,
		BaseURL:                   baseURL,
		TWILIO_ACCOUNT_SID:        twilioAccountSID,
		TWILIO_AUTH_TOKEN:         twilioAuthToken,
		TWILIO_VERIFY_SERVICE_SID: twilioVerifyServiceSID,
	}
}
