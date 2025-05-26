package emailverification

import (
	"context"
	"errors"
	"fmt"

	"github.com/rkcuwork/auth-system/internal/db"
)

type Repository struct{}

func NewRepository() *Repository {
	return &Repository{}
}

func (r *Repository) MarkUserVerified(ctx context.Context, userID string) error {
	commandTag, err := db.Pool.Exec(ctx,
		"UPDATE users SET is_email_verified = TRUE WHERE id = $1", userID)
	if err != nil {
		// Log the error
		fmt.Printf("auth-system:internal:emailverification:ev_repository:MarkUserVerified: Error in updating user verification status: %v\n", err)
		return err
	}

	if commandTag.RowsAffected() == 0 {
		return errors.New("user not found or already verified")
	}
	return nil
}
