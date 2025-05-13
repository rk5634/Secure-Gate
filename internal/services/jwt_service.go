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
)

// GenerateJWT(userID int, email string) (string, error)
// ParseJWT(tokenString string) (jwt.MapClaims, error)
// ValidateJWT(tokenString string) (bool, error)

// NewJWTService(secret string, expiration time.Duration) JWTService
// GenerateToken(user *User) (string, error)
// ValidateToken(tokenString string) (*jwt.Token, error)

// Load RSA private key for signing
func loadPrivateKey() (*rsa.PrivateKey, error) {
	
	keyData, err := os.ReadFile("private.key")
	if err != nil {
		fmt.Println("auth-system:internal:services:jwt_service:loadPrivateKey: Error reading private key file:", err)
		return nil, fmt.Errorf("failed to read private key file: %w", err)
	}

	privateKey, err := jwt.ParseRSAPrivateKeyFromPEM(keyData)
	if err != nil {
		fmt.Println("auth-system:internal:services:jwt_service:loadPrivateKey: Error loading private key:", err)
		return nil, fmt.Errorf("failed to parse RSA private key: %w", err)
	}

	return privateKey, nil
}

func GenerateJWT(user *models.User) (accessToken string, refreshToken string, err error) {
	conf := config.LoadConfig()
	now := time.Now()

	signedkey, err := loadPrivateKey()
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
	refreshClaims := jwt.MapClaims{
		"sub": user.ID,
		"exp": now.Add(7 * 24 * time.Hour).Unix(), // 7 days
		"iat": now.Unix(),
		"jti": uuid.NewString(),
	}

	refresh := jwt.NewWithClaims(jwt.SigningMethodRS256, refreshClaims)
	refreshToken, err = refresh.SignedString(signedkey)
	if err != nil {
		fmt.Println("auth-system:internal:services:jwt_service:GenerateJWT: Error generating refresh token:", err)
		return "", "", fmt.Errorf("signing refresh token failed: %w", err)
	}
	return accessToken, refreshToken, nil
}
