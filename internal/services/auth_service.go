package services

import (
	"context"
	"fmt"

	"golang.org/x/crypto/bcrypt"

	"github.com/rkcuwork/auth-system/internal/models"
	"github.com/rkcuwork/auth-system/internal/repository"
)

type UserService interface {
	Register(ctx context.Context, input *models.User) error
}

type userService struct {
	repo repository.UserRepository
}

func NewUserService(repo repository.UserRepository) UserService {
	return &userService{repo: repo}
}

func (s *userService) Register(ctx context.Context, input *models.User) error {
	// Hash the password
	hashedPassword, err := hashPassword(input.PasswordHash)
	if err != nil {
		fmt.Errorf("auth-system:internal:services:auth_service:Register: Error hashing password: %v\n", err)
		return err
	}
	input.PasswordHash = hashedPassword

	// Call repository to create user
	return s.repo.CreateUser(ctx, input)
}

// --- Internal utility ---

func hashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		fmt.Errorf("auth-system:internal:services:auth_service:hashPassword: Error hashing password: %v\n", err)
		return "", err
	}
	return string(bytes), err
}
