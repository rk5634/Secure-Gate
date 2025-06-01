package services

import (

	"errors"
	"fmt"
	"os"
	"time"

	"crypto/rsa"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/rkcuwork/auth-system/internal/config"
	"github.com/rkcuwork/auth-system/internal/models"
	"github.com/rkcuwork/auth-system/internal/redis"
	"github.com/rkcuwork/auth-system/internal/repository"
	"github.com/rkcuwork/auth-system/internal/utils"
	"maps"
)

// GenerateJWT(userID int, email string) (string, error)
// ParseJWT(tokenString string) (jwt.MapClaims, error)
// ValidateJWT(tokenString string) (bool, error)

// NewJWTService(secret string, expiration time.Duration) JWTService
// GenerateToken(user *User) (string, error)
// ValidateToken(tokenString string) (*jwt.Token, error)

type TokenManager struct {
	privateKey  *rsa.PrivateKey
	publicKey   *rsa.PublicKey
	Redisclient *redis.RedisClient
	Repo        repository.UserRepository
}

func NewTokenManager(privateKey *rsa.PrivateKey, publicKey *rsa.PublicKey, redisclient *redis.RedisClient, repo repository.UserRepository) *TokenManager {
	return &TokenManager{
		privateKey:  privateKey,
		publicKey:   publicKey,
		Redisclient: redisclient,
		Repo:        repo,
	}
}

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

func (tm *TokenManager) GenerateRefreshAndAccessToken(user *models.User, fp *models.Fingerprint, deviceid string) (accessToken string, refreshToken string, err error) {
	fmt.Printf("auth-system:internal:services:jwt_service:GenerateRefreshAndAccessToken:deviceid: %s\n", deviceid)

	// Fetch current token version from DB using repo
	tokenVersionInDB, err := tm.Repo.GetTokenVersionByID(user.ID)
	if err != nil {
		fmt.Printf("auth-system:internal:services:jwt_service:GenerateRefreshAndAccessToken: Error fetching token version: %v\n", err)
		return "", "", fmt.Errorf("failed to get token version: %w", err)
	}

	conf := config.LoadConfig()
	now := time.Now()

	signedkey := tm.privateKey
	if signedkey == nil {
		fmt.Println("auth-system:internal:services:jwt_service:GenerateRefreshAndAccessToken: Error loading private key:", err)
		return "", "", fmt.Errorf("Error generating token")
	}

	// Create access token (short-lived) with token_version claim
	accessClaims := jwt.MapClaims{
		"sub":           user.ID,
		"email":         user.Email,
		"iss":           conf.JwtIssuer,
		"aud":           conf.JwtAudience,
		"exp":           now.Add(15 * time.Minute).Unix(),
		"iat":           now.Unix(),
		"jti":           uuid.NewString(),
		"type":          "access",
		"token_version": tokenVersionInDB,
	}

	access := jwt.NewWithClaims(jwt.SigningMethodRS256, accessClaims)
	accessToken, err = access.SignedString(signedkey)
	if err != nil {
		fmt.Println("auth-system:internal:services:jwt_service:GenerateRefreshAndAccessToken: Error generating access token:", err)
		return "", "", err
	}

	// Create refresh token (long-lived, minimal claims) with token_version claim
	exp := now.Add(7 * 24 * time.Hour)
	jti := uuid.NewString()
	fmt.Printf("jti--->: %s\n", jti)
	fingerprint := fp.UserAgent + fp.AcceptLanguage + fp.AcceptEncoding + deviceid
	fmt.Printf("auth-system:internal:services:jwt_service:GenerateRefreshAndAccessToken:fingerprint: %s\n", fingerprint)
	fingerprinthash := utils.Hash(fingerprint)
	refreshClaims := jwt.MapClaims{
		"sub":           user.ID,
		"exp":           exp.Unix(),
		"iat":           now.Unix(),
		"jti":           jti,
		"type":          "refresh",
		"fingerprint":   fingerprinthash,
		"token_version": tokenVersionInDB,
	}

	refresh := jwt.NewWithClaims(jwt.SigningMethodRS256, refreshClaims)
	refreshToken, err = refresh.SignedString(signedkey)
	if err != nil {
		fmt.Println("auth-system:internal:services:jwt_service:GenerateRefreshAndAccessToken: Error generating refresh token:", err)
		return "", "", fmt.Errorf("signing refresh token failed: %w", err)
	}

	err = tm.Redisclient.Set("refresh_token:"+user.ID, jti, time.Until(exp))
	if err != nil {
		fmt.Println("auth-system:internal:services:jwt_service:GenerateRefreshAndAccessToken: Error storing refresh token in Redis:", err)
		return "", "", fmt.Errorf("failed to store refresh token in Redis: %w", err)
	}

	return accessToken, refreshToken, nil
}


// ParseAndValidateToken parses and validates a JWT, returns claims if valid
func (tm *TokenManager) ParseAndValidateToken(tokenStr string) (jwt.MapClaims, error) {
	keyFunc := func(token *jwt.Token) (interface{}, error) {
		// Ensure the signing method is RSA
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			fmt.Println("auth-system:internal:services:jwt_service:ParseAndValidateToken:keyfunc: Error: unexpected signing method")
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
		fmt.Println("auth-system:internal:services:jwt_service:ParseAndValidateToken: Error parsing token:", err)
		return nil, err
	}

	if !token.Valid {
		fmt.Println("auth-system:internal:services:jwt_service:ParseAndValidateToken: Error: token is not valid")
		return nil, errors.New("token is not valid")
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		fmt.Println("auth-system:internal:services:jwt_service:ParseAndValidateToken: Error: invalid claims type")
		return nil, errors.New("invalid claims type")
	}

	// Extract userID and token_version from claims
	userID, ok := claims["sub"].(string)
	if !ok {
		return nil, errors.New("user_id (sub) missing in token claims")
	}

	tokenVersionFromTokenFloat, ok := claims["token_version"].(float64) // JSON numbers decode to float64
	if !ok {
		return nil, errors.New("token_version missing or invalid in token claims")
	}
	tokenVersionFromToken := int(tokenVersionFromTokenFloat)

	// Compare token version from token with DB
	valid, err := tm.CompareTokenVersion(userID, tokenVersionFromToken)
	if err != nil {
		fmt.Println("auth-system:internal:services:jwt_service:ParseAndValidateToken: error comparing token version:", err)
		return nil, err
	}
	if !valid {
		return nil, errors.New("token version mismatch: token is outdated or revoked")
	}

	return claims, nil
}



func (tm *TokenManager) IsValidRefreshTokenRequest(req *models.NewAccessTokenRequest, fp *models.Fingerprint) (isvalid bool, userid string, err error) {
	refreshtoken := req.RefreshToken
	deviceid := req.DeviceID

	claims, err := tm.ParseAndValidateToken(refreshtoken)
	if err != nil {
		fmt.Printf("auth-system:internal:services:jwt_service:IsValidRefreshTokenRequest: Error parsing refresh token: %v\n", err)
		return false, "", fmt.Errorf("failed to parse refresh token: %w", err)
	}

	userid, ok := claims["sub"].(string)
	if !ok || userid == "" {
		fmt.Printf("auth-system:internal:services:jwt_service:IsValidRefreshTokenRequest: Error: invalid user ID\n")
		return false, userid, errors.New("invalid user ID")
	}

	jti, ok := claims["jti"].(string)
	if !ok || jti == "" {
		fmt.Printf("auth-system:internal:services:jwt_service:IsValidRefreshTokenRequest: Error: invalid jti\n")
		return false, userid, errors.New("invalid jti")
	}

	if tokenType, ok := claims["type"].(string); !ok || tokenType != "refresh" {
		fmt.Printf("auth-system:internal:services:jwt_service:IsValidRefreshTokenRequest: Error: invalid token type\n")
		return false, userid, errors.New("invalid token type")
	}

	// Check if the refresh token is in Redis
	err = tm.Redisclient.VerifyRefreshTokenJTI(jti, userid)
	if err != nil {
		fmt.Printf("auth-system:internal:services:jwt_service:IsValidRefreshTokenRequest: Error: invalid token type\n")
		return false, userid, errors.New("invalid token")
	}

	currentfingerprint := fp.UserAgent + fp.AcceptLanguage + fp.AcceptEncoding + deviceid
	fmt.Printf("auth-system:internal:services:jwt_service:IsValidRefreshTokenRequest:fingerprint: %s\n", currentfingerprint)
	if storedfingerprint, ok := claims["fingerprint"].(string); !ok || !utils.MatchHash(currentfingerprint, storedfingerprint) {
		fmt.Printf("auth-system:internal:services:jwt_service:IsValidRefreshTokenRequest: Error: invalid fingerprint\n")
		return false, userid, errors.New("invalid fingerprint")
	}

	return true, userid, nil

}


func (tm *TokenManager) IsValidAccessToken(accesstoken string) (isvalid bool, claims jwt.MapClaims, err error) {
	// 1. Parse and validate the JWT token
	claims, err = tm.ParseAndValidateToken(accesstoken)
	if err != nil {
		fmt.Printf("auth-system:internal:services:jwt_service:IsValidAccessTokenRequest: Error parsing access token: %v\n", err)
		return false, nil, fmt.Errorf("failed to parse access token: %w", err)
	}

	exp, ok := claims["exp"].(float64)
	if !ok || int64(exp) < time.Now().Unix() {
		fmt.Printf("auth-system:internal:services:jwt_service:IsValidAccessTokenRequest: Error: token expired\n")
		return false, claims, errors.New("token is expired")
	}

	// 2. Extract user ID (sub)
	userID, ok := claims["sub"].(string)
	if !ok || userID == "" {
		fmt.Printf("auth-system:internal:services:jwt_service:IsValidAccessTokenRequest: Error: invalid user ID\n")
		return false, claims, errors.New("invalid user ID")
	}

	// 3. Extract token ID (jti)
	jti, ok := claims["jti"].(string)
	if !ok || jti == "" {
		fmt.Printf("auth-system:internal:services:jwt_service:IsValidAccessTokenRequest: Error: invalid jti\n")
		return false, claims, errors.New("invalid jti")
	}

	// 4. Check token type
	if tokenType, ok := claims["type"].(string); !ok || tokenType != "access" {
		fmt.Printf("auth-system:internal:services:jwt_service:IsValidAccessTokenRequest: Error: invalid token type\n")
		return false, claims, errors.New("invalid token type")
	}

	// 5. Check if token is blacklisted (in Redis)
	err = tm.Redisclient.VerifyAccessTokenJTINotBlacklisted(jti)
	if err != nil {
		fmt.Printf("auth-system:internal:services:jwt_service:IsValidAccessTokenRequest: Error: token is blacklisted\n")
		return false, claims, errors.New("token is blacklisted or revoked")
	}

	return true, claims, nil
}

func (tm *TokenManager) GeneratePasswordResetToken(userID string) (string, error) {
	tokenVersionInDB, err := tm.Repo.GetTokenVersionByID(userID)
	if err != nil {
		fmt.Printf("auth-system:internal:services:jwt_service:GeneratePasswordResetToken: Error fetching token version: %v\n", err)
		return "", fmt.Errorf("failed to get token version: %w", err)
	}
	resetclaims := jwt.MapClaims{
		"sub": userID,
		"exp": time.Now().Add(5 * time.Minute).Unix(),
		"type": "reset", 
		"token_version": tokenVersionInDB,
	}

	reset := jwt.NewWithClaims(jwt.SigningMethodRS256, resetclaims)
	resetToken, err := reset.SignedString(tm.privateKey)

	if err != nil {
		fmt.Println("auth-system:internal:services:jwt_service:GeneratePasswordResetToken: Error generating password reset token:", err)
		return "", fmt.Errorf("failed to generate password reset token: %w", err)
	}

	return resetToken, nil
}

func (tm *TokenManager) VerifyResetToken(tokenString string) (string, error) {

	claims, err := tm.ParseAndValidateToken(tokenString)
	if err != nil {
		fmt.Println("auth-system:internal:services:jwt_service:ParsePasswordResetToken: Error parsing password reset token:", err)
		return "", fmt.Errorf("failed to parse password reset token: %w", err)
	}

	tokentype, ok := claims["type"].(string)
	if !ok || tokentype != "reset" {
		return "", errors.New("invalid token claims")
	}

	userID, ok := claims["sub"].(string)
	if !ok {
		return "", errors.New("user_id missing in token")
	}

	return userID, nil
}

func (tm *TokenManager) CompareTokenVersion(userID string, tokenVersionFromToken int) (bool, error) {
	// Get the current token_version from DB
	tokenVersionInDB, err := tm.Repo.GetTokenVersionByID(userID)
	if err != nil {
		fmt.Printf("auth-system:internal:repository:user_repository:CompareTokenVersion: Error fetching token version: %v\n", err)
		return false, err
	}

	// Compare versions
	if tokenVersionInDB != tokenVersionFromToken {
		return false, nil // Token is outdated or tampered
	}

	return true, nil // Token is valid
}






func(tm *TokenManager) GenerateJWT(claimsMap map[string]interface{}, expiryMinutes int) (string, error) {
	// Create a new token object
	claims := jwt.MapClaims{}

	// Add standard claims
	claims["exp"] = time.Now().Add(time.Minute * time.Duration(expiryMinutes)).Unix()
	claims["iat"] = time.Now().Unix()

	// Add custom claims
	maps.Copy(claims, claimsMap)


	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)

	// Sign the token with the secret key
	tokenString, err := token.SignedString(tm.privateKey)
	if err != nil {
		return "", err
	}

	return tokenString, nil
}

