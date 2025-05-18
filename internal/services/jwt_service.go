package services

import (
	"fmt"
	"os"
	"time"

	"crypto/rsa"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/rkcuwork/auth-system/internal/config"
	"github.com/rkcuwork/auth-system/internal/models"
	"github.com/rkcuwork/auth-system/internal/redis"
)

// GenerateJWT(userID int, email string) (string, error)
// ParseJWT(tokenString string) (jwt.MapClaims, error)
// ValidateJWT(tokenString string) (bool, error)

// NewJWTService(secret string, expiration time.Duration) JWTService
// GenerateToken(user *User) (string, error)
// ValidateToken(tokenString string) (*jwt.Token, error)


// Load RSA public key for signing
func LoadPublicKey() (*rsa.PublicKey, error) {
	keyData, err := os.ReadFile("public.key")
	if err != nil {
		fmt.Println("auth-system:internal:services:jwt_service:LoadPublicKey: Error reading public key file:", err)
		return nil, fmt.Errorf("failed to read public key file: %w", err)
	}

	publicKey, err := jwt.ParseRSAPublicKeyFromPEM(keyData)
	if err != nil {
		fmt.Println("auth-system:internal:services:jwt_service:LoadPublicKey: Error parsing public key:", err)
		return nil, fmt.Errorf("failed to parse RSA public key: %w", err)
	}

	return publicKey, nil
}


// Load RSA private key for signing
func LoadPrivateKey() (*rsa.PrivateKey, error) {
	
	keyData, err := os.ReadFile("private.key")
	if err != nil {
		fmt.Println("auth-system:internal:services:jwt_service:LoadPrivateKey: Error reading private key file:", err)
		return nil, fmt.Errorf("failed to read private key file: %w", err)
	}

	privateKey, err := jwt.ParseRSAPrivateKeyFromPEM(keyData)
	if err != nil {
		fmt.Println("auth-system:internal:services:jwt_service:LoadPrivateKey: Error loading private key:", err)
		return nil, fmt.Errorf("failed to parse RSA private key: %w", err)
	}

	return privateKey, nil
}

func GenerateJWT(user *models.User) (accessToken string, refreshToken string, err error) {
	conf := config.LoadConfig()
	now := time.Now()

	signedkey, err := LoadPrivateKey()
	if err != nil {
		fmt.Println("auth-system:internal:services:jwt_service:GenerateJWT: Error loading private key:", err)
		return "", "", err
	}
	// Create access token (short-lived)
	accessClaims := jwt.MapClaims{
		"sub":   user.ID,
		"email": user.Email,
		"iss":   conf.JwtIssuer,
		"aud":   conf.JwtAudience,
		"exp":   now.Add(15 * time.Minute).Unix(),
		"iat":   now.Unix(),
		"jti":   uuid.NewString(),
	}

	access := jwt.NewWithClaims(jwt.SigningMethodRS256, accessClaims)
	accessToken, err = access.SignedString(signedkey)

	if err != nil {
		fmt.Println("auth-system:internal:services:jwt_service: Error generating access token:", err)
		return "", "", err
	}

	// Create refresh token (long-lived, minimal claims)
	exp := time.Now().Add(7 * 24 * time.Hour)
	jti := uuid.NewString()
	refreshClaims := jwt.MapClaims{
		"sub": user.ID,
		"exp": exp.Unix(), // 7 days
		"iat": now.Unix(),
		"jti": jti,
	}

	refresh := jwt.NewWithClaims(jwt.SigningMethodRS256, refreshClaims)
	refreshToken, err = refresh.SignedString(signedkey)
	if err != nil {
		fmt.Println("auth-system:internal:services:jwt_service:GenerateJWT: Error generating refresh token:", err)
		return "", "", fmt.Errorf("signing refresh token failed: %w", err)
	}

	err = redis.RedisClient.Set("refresh_token:"+jti, user.ID, time.Until(exp))
	if err != nil {
		fmt.Println("auth-system:internal:services:jwt_service:GenerateJWT: Error storing refresh token in Redis:", err)
		return "", "", fmt.Errorf("failed to store refresh token in Redis: %w", err)
	}


	return accessToken, refreshToken, nil
}
