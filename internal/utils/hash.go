package utils

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"

	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
)

func HashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		fmt.Errorf("auth-system:internal:utils:hash:HashPassword: Error hashing password: %v\n", err)
		return "", err
	}
	return string(bytes), err
}



func CheckPasswordHash(password, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	if err != nil {
		fmt.Errorf("auth-system:internal:services:auth_service:checkPasswordHash: Error comparing password hash: %v\n", err)
		return false
	}
	return true
}



func Hash(input string) string {
    hasher := sha256.New()
    hasher.Write([]byte(input))
    hashBytes := hasher.Sum(nil)
    return hex.EncodeToString(hashBytes)
}


// CheckHash compares input string with a given hash
func MatchHash(input string, hash string) bool {
    return Hash(input) == hash
}



// GenerateUUID generates a new random UUID v4 as a string.
func GenerateUUID() string {
    return uuid.New().String()
}


