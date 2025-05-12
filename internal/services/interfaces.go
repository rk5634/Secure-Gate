package services

import (
	"context"

	"github.com/golang-jwt/jwt/v5"
	"github.com/rkcuwork/auth-system/internal/models"
)

type UserService interface {
	Register(ctx context.Context, input *models.User) error
	Login(ctx context.Context, input *models.LoginRequest) (*models.LoginResponse, error)
}


type JWTService interface {
    GenerateToken(user *models.User) (string, error)
    ValidateToken(token string) (*jwt.Token, error)
}