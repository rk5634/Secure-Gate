package services

import (
	"context"

	"github.com/golang-jwt/jwt/v5"
	"github.com/rkcuwork/auth-system/internal/models"
)

type UserService interface {
	Register(ctx context.Context, input *models.User) error
	Login(ctx context.Context, input *models.LoginRequest,fp *models.Fingerprint) (*models.LoginResponse, error)
	RefreshTokenService(ctx context.Context, input *models.NewAccessTokenRequest, fp *models.Fingerprint) (*models.NewAccessTokenResponse, error)
	ValidateToken(token string) (jwt.MapClaims, error)
	Logout(req *models.LogoutRequest) (err error)
}


type JWTService interface {
    GenerateToken(user *models.User) (string, error)
    ValidateToken(token string) (*jwt.Token, error)
}