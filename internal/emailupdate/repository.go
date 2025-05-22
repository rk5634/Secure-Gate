package emailupdate

import (
	"context"
	"fmt"

	"github.com/rkcuwork/auth-system/internal/db"
)

type Repository interface {
	EmailExists(ctx context.Context, email string) (bool, error)
	SetUnverifiedEmail(ctx context.Context, userID, newEmail string) error
}

type userRepository struct{}

func NewRepository() Repository {
	return &userRepository{}
}


func (r *userRepository) EmailExists(ctx context.Context, email string) (bool, error) {
	// SELECT COUNT(*) FROM users WHERE email = ?
	var count int
	err := db.Pool.QueryRow(ctx, "SELECT COUNT(*) FROM users WHERE email = $1", email).Scan(&count)
	if err != nil {
		// Log the error
		fmt.Printf("auth-system:internal:emailupdate:userRepository:EmailExists: Error checking email existence: %v\n", err)
		return false, err
	}
	return count > 0, nil
}

func (r *userRepository) SetUnverifiedEmail(ctx context.Context, userID, newEmail string) error {
	// UPDATE users SET email = ?, is_verified = false WHERE id = ?
	query := `UPDATE users SET email = $1, is_verified = false WHERE id = $2`

	_, err := db.Pool.Exec(ctx, query, newEmail, userID)
	if err != nil {
		// Log the error
		fmt.Printf("auth-system:internal:emailupdate:userRepository:SetUnverifiedEmail: Error updating email: %v\n", err)
		return fmt.Errorf("failed to update email and set as unverified: %w", err)
	}

	return nil
}
