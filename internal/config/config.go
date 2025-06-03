package config

import (
	"context"
	"encoding/base64"
	"encoding/json"

	"log"
	"strings"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
)

// Config holds all the necessary environment variables required by the application.
type Config struct {
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
	PrivateKey                string
	PublicKey                 string
}



// LoadSecretFromAWS retrieves and parses secret JSON from Secrets Manager
func LoadSecretFromAWS(secretName string) (map[string]string, error) {
	// Load AWS config (uses default credentials or IAM role)
	cfg, err := config.LoadDefaultConfig(context.TODO())
	if err != nil {
		return nil, err
	}

	svc := secretsmanager.NewFromConfig(cfg)

	// Fetch secret
	out, err := svc.GetSecretValue(context.TODO(), &secretsmanager.GetSecretValueInput{
		SecretId: &secretName,
	})
	if err != nil {
		return nil, err
	}

	// Parse secret string as JSON
	var secrets map[string]string
	err = json.Unmarshal([]byte(*out.SecretString), &secrets)
	if err != nil {
		return nil, err
	}

	return secrets, nil
}

// LoadConfig fetches config from AWS Secrets Manager
func LoadConfig() *Config {
	const secretName = "auth-service/credentials" // change this to your actual secret name

	secrets, err := LoadSecretFromAWS(secretName)
	if err != nil {
		log.Fatalf("%s Failed to load secrets from AWS: %v", logPrefix, err)
	}

	get := func(key string) string {
		val, ok := secrets[key]
		if !ok || val == "" {
			log.Fatalf("%s Missing required secret key: %s", logPrefix, key)
		}

		// Convert `\n` to actual newlines for PEM keys
		if key == "PRIVATE_KEY" || key == "PUBLIC_KEY" {
			decodedBytes, err := base64.StdEncoding.DecodeString(val)
			if err != nil {
				log.Fatalf("Failed to decode base64 for key %s: %v", key, err)
			}
			val = string(decodedBytes)
		}
		return val
	}

	// Use default for port if not set
	port := secrets["PORT"]
	if port == "" {
		port = "8080"
	}

	return &Config{
		Port:                      port,
		PostgresDB:                get("POSTGRES_DB"),
		PostgresUser:              get("POSTGRES_USER"),
		PostgresPassword:          get("POSTGRES_PASSWORD"),
		DbURL:                     get("DB_URL"),
		RedisPassword:             get("REDIS_PASSWORD"),
		RedisDB:                   get("REDIS_DB"),
		RedisAddress:              get("REDIS_ADDRESS"),
		JwtSecret:                 get("JWT_SECRET"),
		JwtIssuer:                 get("JWT_ISSUER"),
		JwtAudience:               get("JWT_AUDIENCE"),
		AWSRegion:                 get("AWS_REGION"),
		AWSAccessKeyID:            get("AWS_ACCESS_KEY_ID"),
		AWSSecretAccessKey:        get("AWS_SECRET_ACCESS_KEY"),
		SenderEmail:               get("SENDER_EMAIL"),
		BaseURL:                   get("BASE_URL"),
		TWILIO_ACCOUNT_SID:        get("TWILIO_ACCOUNT_SID"),
		TWILIO_AUTH_TOKEN:         get("TWILIO_AUTH_TOKEN"),
		TWILIO_VERIFY_SERVICE_SID: get("TWILIO_VERIFY_SERVICE_SID"),
		GoogleClientID:            get("GOOGLE_CLIENT_ID"),
		GoogleClientSecret:        get("GOOGLE_CLIENT_SECRET"),
		PrivateKey:             get("PRIVATE_KEY"),
		PublicKey:              get("PUBLIC_KEY"),
	}
}



func convertEscapedNewlines(s string) string {
	return strings.ReplaceAll(s, `\n`, "\n")
}