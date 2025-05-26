package repository

import (
	"context"

	"github.com/rkcuwork/auth-system/internal/models"
)

type UserRepository interface {
	CreateUser(ctx context.Context, user *models.User) error
	GetUserByEmail(ctx context.Context, email string) (*models.User, error)
	GetUserByID(ctx context.Context, userid string) (*models.User, error)
	UpdatePassword(userid string, newpassword string) (err error)
	GetTokenVersionByID(id string) (int, error)
	InvalidateAllTokensByID(id string) error
	
}