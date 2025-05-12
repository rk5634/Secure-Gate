package services

import (
	"context"

	"github.com/rkcuwork/auth-system/internal/models"
)

type UserService interface {
	Register(ctx context.Context, input *models.User) error
}