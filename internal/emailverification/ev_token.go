package emailverification

import (
	"context"
	"crypto/rsa"
	"errors"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/rkcuwork/auth-system/internal/repository"
)

type TokenManager struct {
	privateKey *rsa.PrivateKey
	publicKey  *rsa.PublicKey
}

func NewTokenManager(privateKey *rsa.PrivateKey, publicKey *rsa.PublicKey) *TokenManager {
	return &TokenManager{
		privateKey: privateKey,
		publicKey:  publicKey,
	}
}

// GenerateVerificationToken creates a JWT for email verification
func (tm *TokenManager) GenerateVerificationToken(userID string) (string, error) {
	fmt.Printf("auth-system:internal:emailverification:ev_token:GenerateVerificationToken: Generating verification token for user %s\n", userID)
	now := time.Now()
	expiration := now.Add(1 * time.Second)

	signedkey  := tm.privateKey
	if signedkey == nil {
		fmt.Println("auth-system:internal:emailverification:ev_token:GenerateVerificationToken: Error loading private key.")
		return "", errors.New("private key not found")
	}

	claims := jwt.MapClaims{
		"sub":  userID,
		"exp":  expiration.Unix(),
		"iat":  now.Unix(),
		"type": "email_verification",
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	signedtoken,err := token.SignedString(signedkey)
	

	if err != nil {
		fmt.Println("auth-system:internal:emailverification:ev_token: Error generating the token:", err)
		return "", fmt.Errorf("signing token failed: %w", err)
	}

	fmt.Printf("auth-system:internal:emailverification:ev_token:GenerateVerificationToken: Verification token generated successfully for user %s\n", userID)
	return signedtoken,nil
}

// ParseAndValidateToken parses and validates a JWT, returns userID if valid
func (tm *TokenManager) ParseAndValidateToken(tokenStr string) (string, error) {

	keyFunc := func(token *jwt.Token) (interface{}, error) {
		// Ensure the signing method is RSA
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			fmt.Println("auth-system:internal:emailverification:ev_token:ParseAndValidateToken:keyfunc: Error: unexpected signing method")
			return nil, errors.New("unexpected signing method")
		}
		// Return the RSA public key to verify the signature
		return tm.publicKey, nil
	}


	token, err := jwt.Parse(tokenStr, keyFunc,
		jwt.WithExpirationRequired(),
		jwt.WithValidMethods([]string{"RS256"}),
	)

	if err != nil {
		fmt.Println("auth-system:internal:emailverification:ev_token:ParseAndValidateToken: Error parsing token:", err)
		return "", err
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		fmt.Println("auth-system:internal:emailverification:ev_token:ParseAndValidateToken: Error: invalid claims type")
		return "", errors.New("invalid claims type")
	}

	// Validate custom claim "type"
	if typ, ok := claims["type"].(string); !ok || typ != "email_verification" {
		fmt.Println("auth-system:internal:emailverification:ev_token:ParseAndValidateToken: Error: invalid token type")
		return "", errors.New("invalid token type")
	}

	// Validate subject claim
	userID, ok := claims["sub"].(string)
	if !ok {
		fmt.Println("auth-system:internal:emailverification:ev_token:ParseAndValidateToken: Error: invalid subject claim")
		return "", errors.New("invalid subject claim")
	}

	_, err = repository.NewUserRepository().GetUserByID(context.Background(),userID)

	if err != nil {
		fmt.Println("auth-system:internal:emailverification:ev_token:ParseAndValidateToken: Error getting user by ID:", err)
		return "", fmt.Errorf("user not found")
	}


	return userID, nil
}