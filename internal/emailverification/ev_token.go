package emailverification

import (
	"context"
	"crypto/rsa"
	"errors"
	"fmt"
	"log"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/rkcuwork/auth-system/internal/repository"
)

// ev_tokenFileLogPrefix is the file-level log prefix
const ev_tokenFileLogPrefix = packageLogPrefix + "ev_token:"

// TokenManager handles JWT generation and validation
type TokenManager struct {
	privateKey *rsa.PrivateKey
	publicKey  *rsa.PublicKey
}

// NewTokenManager creates a new TokenManager
func NewTokenManager(privateKey *rsa.PrivateKey, publicKey *rsa.PublicKey) *TokenManager {
	return &TokenManager{
		privateKey: privateKey,
		publicKey:  publicKey,
	}
}

// GenerateVerificationToken creates a JWT for email verification
func (tm *TokenManager) GenerateVerificationToken(userID string) (string, error) {
	const funcName = "GenerateVerificationToken:"
	funcLogPrefix := ev_tokenFileLogPrefix + funcName

	log.Printf("%s generating verification token for userID: %s", funcLogPrefix, userID)

	now := time.Now()
	expiration := now.Add(15 * time.Minute)

	if tm.privateKey == nil {
		log.Printf("%s private key is nil", funcLogPrefix)
		return "", errors.New("private key not found")
	}

	claims := jwt.MapClaims{
		"sub":  userID,
		"exp":  expiration.Unix(),
		"iat":  now.Unix(),
		"type": "email_verification",
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	signedToken, err := token.SignedString(tm.privateKey)
	if err != nil {
		log.Printf("%s error signing token: %v", funcLogPrefix, err)
		return "", fmt.Errorf("signing token failed: %w", err)
	}

	log.Printf("%s verification token successfully generated for userID: %s", funcLogPrefix, userID)
	return signedToken, nil
}

// ParseAndValidateToken parses and validates a JWT, returning the userID if valid
func (tm *TokenManager) ParseAndValidateToken(tokenStr string) (string, error) {
	const funcName = "ParseAndValidateToken:"
	funcLogPrefix := ev_tokenFileLogPrefix + funcName

	keyFunc := func(token *jwt.Token) (interface{}, error) {
		// Ensure the signing method is RSA
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			log.Printf("%s keyFunc: unexpected signing method: %v", funcLogPrefix, token.Header["alg"])
			return nil, errors.New("unexpected signing method")
		}
		return tm.publicKey, nil
	}

	token, err := jwt.Parse(tokenStr, keyFunc,
		jwt.WithExpirationRequired(),
		jwt.WithValidMethods([]string{"RS256"}),
	)

	if err != nil {
		log.Printf("%s error parsing token: %v", funcLogPrefix, err)
		return "", err
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		log.Printf("%s invalid claims type", funcLogPrefix)
		return "", errors.New("invalid claims type")
	}

	// Validate token type
	if typ, ok := claims["type"].(string); !ok || typ != "email_verification" {
		log.Printf("%s invalid or missing token type: %v", funcLogPrefix, claims["type"])
		return "", errors.New("invalid token type")
	}

	// Validate subject claim
	userID, ok := claims["sub"].(string)
	if !ok {
		log.Printf("%s missing or invalid subject (sub) claim", funcLogPrefix)
		return "", errors.New("invalid subject claim")
	}

	// Ensure user exists
	if _, err := repository.NewUserRepository().GetUserByID(context.Background(), userID); err != nil {
		log.Printf("%s error getting user by ID %s: %v", funcLogPrefix, userID, err)
		return "", fmt.Errorf("user not found")
	}

	log.Printf("%s token is valid for userID: %s", funcLogPrefix, userID)
	return userID, nil
}
