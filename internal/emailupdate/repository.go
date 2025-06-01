package emailupdate

import (
	"context"
	"fmt"

	"github.com/rkcuwork/auth-system/internal/db"
)

// repositoryFileLogPrefix is the file-level prefix for all log messages in this file
const repositoryFileLogPrefix = packageLogPrefix+"repository:"

// Repository defines the interface for email update related DB operations.
type Repository interface {
	EmailExists(ctx context.Context, email string) (bool, error)
	SetUnverifiedEmail(ctx context.Context, userID, newEmail string) error
}

// userRepository implements the Repository interface with Postgres queries.
type userRepository struct{}

// NewRepository creates a new instance of userRepository.
func NewRepository() Repository {
	return &userRepository{}
}

// EmailExists checks if the given email already exists in the users table.
func (r *userRepository) EmailExists(ctx context.Context, email string) (bool, error) {
	const funcName = "EmailExists:"
	funcLogPrefix := repositoryFileLogPrefix + funcName

	var count int
	err := db.Pool.QueryRow(ctx, "SELECT COUNT(*) FROM users WHERE email = $1", email).Scan(&count)
	if err != nil {
		fmt.Printf("%s error checking email existence for '%s': %v\n", funcLogPrefix, email, err)
		return false, err
	}

	return count > 0, nil
}

// SetUnverifiedEmail updates the user's email and marks it as unverified in the database.
func (r *userRepository) SetUnverifiedEmail(ctx context.Context, userID, newEmail string) error {
	const funcName = "SetUnverifiedEmail:"
	funcLogPrefix := repositoryFileLogPrefix + funcName

	query := `UPDATE users SET email = $1, is_verified = false WHERE id = $2`

	_, err := db.Pool.Exec(ctx, query, newEmail, userID)
	if err != nil {
		fmt.Printf("%s error updating email for user '%s': %v\n", funcLogPrefix, userID, err)
		return fmt.Errorf("failed to update email and set as unverified: %w", err)
	}

	return nil
}
