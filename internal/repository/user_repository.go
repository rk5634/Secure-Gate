package repository

import (
	"context"
	"fmt"
	"time"

	"github.com/rkcuwork/auth-system/internal/db"
	"github.com/rkcuwork/auth-system/internal/models"
)

type UserRepository interface {
	CreateUser(ctx context.Context, user *models.User) error
	GetUserByEmail(ctx context.Context, email string) (*models.User, error)
}

type userRepo struct{}

func NewUserRepository() UserRepository {
	return &userRepo{}
}

func (r *userRepo) CreateUser(ctx context.Context, user *models.User) error {
	query := `
		INSERT INTO users (full_name, email, phone, password_hash, is_verified, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
	`
	now := time.Now()
	user.CreatedAt = now
	user.UpdatedAt = now

	_, err := db.Pool.Exec(ctx, query,
		user.FullName,
		user.Email,
		user.Phone,
		user.PasswordHash,
		user.IsVerified,
		user.CreatedAt,
		user.UpdatedAt,
	)
	if err != nil {
		fmt.Printf("auth-system:internal:repository:user_repository:CreateUser: Error in creating user: %v\n", err)
	}
	return err
}

func (r *userRepo) GetUserByEmail(ctx context.Context, email string) (*models.User, error) {
	query := `SELECT id, full_name, email, phone, password_hash, is_verified, created_at, updated_at FROM users WHERE email=$1`
	row := db.Pool.QueryRow(ctx, query, email)

	var user models.User
	err := row.Scan(
		&user.ID,
		&user.FullName,
		&user.Email,
		&user.Phone,
		&user.PasswordHash,
		&user.IsVerified,
		&user.CreatedAt,
		&user.UpdatedAt,
	)
	if err != nil {
		fmt.Printf("auth-system:internal:repository:user_repository:GetUserByEmail: Error fetching user by email: %v\n", err)
		return nil, err
	}

	return &user, nil
}
