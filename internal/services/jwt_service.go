package services

import (
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/rkcuwork/auth-system/internal/config"
)

// GenerateJWT(userID int, email string) (string, error)
// ParseJWT(tokenString string) (jwt.MapClaims, error)
// ValidateJWT(tokenString string) (bool, error)

// NewJWTService(secret string, expiration time.Duration) JWTService
// GenerateToken(user *User) (string, error)
// ValidateToken(tokenString string) (*jwt.Token, error)

func GenerateJWT(userID string, email string) (string, error) {
	claims := jwt.MapClaims{
		"user_id": userID,
		"email":   email,
		"exp":     time.Now().Add(24 * time.Hour).Unix(),
		"iat":     time.Now().Unix(),
	}

	conf := config.LoadConfig()
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	tokenString, err := token.SignedString([]byte(conf.JwtSecret))
	if err != nil {
		fmt.Println("auth-system:internal:services:jwt_service: Error generating token:", err)
		return "", err
	}

	return tokenString, nil
}
