package repository

import (
	"context"
	"fmt"
	"time"

	"github.com/rkcuwork/auth-system/internal/db"
	"github.com/rkcuwork/auth-system/internal/models"
	"github.com/jackc/pgx/v5"
)

type userRepo struct{}

func NewUserRepository() UserRepository {
	return &userRepo{}
}

func (r *userRepo) CreateUser(ctx context.Context, user *models.User) error {
	query := `
		INSERT INTO users (full_name, email, phone, password_hash, is_email_verified, is_phone_verified, token_version, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
	`
	now := time.Now()
	user.CreatedAt = now
	user.UpdatedAt = now

	_, err := db.Pool.Exec(ctx, query,
		user.FullName,
		user.Email,
		user.Phone,
		user.PasswordHash,
		user.IsEmailVerified,
		user.IsPhoneVerified,
		user.TokenVersion,
		user.CreatedAt,
		user.UpdatedAt,
	)
	if err != nil {
		fmt.Printf("auth-system:internal:repository:user_repository:CreateUser: Error in creating user: %v\n", err)
	}

	return err
}

func (r *userRepo) GetUserByEmail(ctx context.Context, email string) (*models.User, error) {
	query := `
		SELECT id, full_name, email, phone, password_hash, is_email_verified, is_phone_verified, token_version, created_at, updated_at
		FROM users WHERE email=$1
	`
	row := db.Pool.QueryRow(ctx, query, email)

	var user models.User
	err := row.Scan(
		&user.ID,
		&user.FullName,
		&user.Email,
		&user.Phone,
		&user.PasswordHash,
		&user.IsEmailVerified,
		&user.IsPhoneVerified,
		&user.TokenVersion,
		&user.CreatedAt,
		&user.UpdatedAt,
	)
	if err != nil {
		fmt.Printf("auth-system:internal:repository:user_repository:GetUserByEmail: Error fetching user by email: %v\n", err)
		return nil, err
	}

	return &user, nil
}

func (r *userRepo) GetUserByID(ctx context.Context, id string) (*models.User, error) {
	query := `
		SELECT id, full_name, email, phone, password_hash, is_email_verified, is_phone_verified, token_version, created_at, updated_at
		FROM users WHERE id=$1
	`
	row := db.Pool.QueryRow(ctx, query, id)

	var user models.User
	err := row.Scan(
		&user.ID,
		&user.FullName,
		&user.Email,
		&user.Phone,
		&user.PasswordHash,
		&user.IsEmailVerified,
		&user.IsPhoneVerified,
		&user.TokenVersion,
		&user.CreatedAt,
		&user.UpdatedAt,
	)

	if err != nil {
		if err == pgx.ErrNoRows {
			fmt.Printf("auth-system:internal:repository:user_repository:GetUserByID: No user found with ID: %v\n", id)
			return nil, fmt.Errorf("user with ID %v not found", id)
		}
		fmt.Printf("auth-system:internal:repository:user_repository:GetUserByID: Error fetching user by ID: %v\n", err)
		return nil, err
	}

	return &user, nil
}

func (r *userRepo) UpdatePassword(userid string, newpassword string) (err error) {
	query := `UPDATE users SET password_hash=$1, updated_at=$2 WHERE id=$3`
	_, err = db.Pool.Exec(context.Background(), query, newpassword, time.Now(), userid)
	if err != nil {
		fmt.Printf("auth-system:internal:repository:user_repository:UpdatePassword: Error updating password: %v\n", err)
		return err
	}

	err = r.InvalidateAllTokensByID(userid)

	if err != nil {
		fmt.Printf("auth-system:internal:repository:user_repository:UpdatePassword: Error invalidating tokens after password update: %v\n", err)
		return err
	}
	fmt.Printf("auth-system:internal:repository:user_repository:UpdatePassword: Password updated and tokens invalidated for user ID %s\n", userid)
	return nil
}



func (r *userRepo) GetTokenVersionByID(id string) (int, error) {
	query := `SELECT token_version FROM users WHERE id=$1`
	var tokenVersion int
	err := db.Pool.QueryRow(context.Background(), query, id).Scan(&tokenVersion)
	if err != nil {
		fmt.Printf("auth-system:internal:repository:user_repository:GetTokenVersionByID: Error fetching token version for user ID %s: %v\n", id, err)
		return -1, err
	}
	return tokenVersion, nil
}


func (r *userRepo) InvalidateAllTokensByID(id string) error {
	query := `UPDATE users SET token_version = token_version + 1 WHERE id = $1`
	_, err := db.Pool.Exec(context.Background(), query, id)
	if err != nil {
		fmt.Printf("auth-system:internal:repository:user_repository:InvalidateAllTokensByID: Error incrementing token version for user ID %s: %v\n", id, err)
		return err
	}
	return nil
}



func (r *userRepo) UpdatePhoneVerificationStatus(phone string, isVerified bool) error {
	query := `UPDATE users SET is_phone_verified = $1 WHERE phone = $2`

	_, err := db.Pool.Exec(context.Background(),query, isVerified, phone)
	if err != nil {
		fmt.Printf("auth-system:internal:repository:user_repository:UpdatePhoneVerificationStatus: failed to update verification status: %v\n", err)
		return err
	}
	return nil
}



func (r *userRepo) GetUserByPhone( phone string) (*models.User, error) {
	query := `
		SELECT id, full_name, email, phone, password_hash, is_email_verified, is_phone_verified, token_version, created_at, updated_at
		FROM users WHERE phone = $1
	`
	row := db.Pool.QueryRow(context.Background(), query, phone)

	var user models.User
	err := row.Scan(
		&user.ID,
		&user.FullName,
		&user.Email,
		&user.Phone,
		&user.PasswordHash,
		&user.IsEmailVerified,
		&user.IsPhoneVerified,
		&user.TokenVersion,
		&user.CreatedAt,
		&user.UpdatedAt,
	)

	if err != nil {
		if err == pgx.ErrNoRows {
			fmt.Printf("auth-system:internal:repository:user_repository:GetUserByPhone: No user found with phone: %v\n", phone)
			return nil, fmt.Errorf("user with phone %v not found", phone)
		}
		fmt.Printf("auth-system:internal:repository:user_repository:GetUserByPhone: Error fetching user by phone: %v\n", err)
		return nil, err
	}

	return &user, nil
}

