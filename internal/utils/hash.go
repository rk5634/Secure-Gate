package utils

import (
	"fmt"

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


