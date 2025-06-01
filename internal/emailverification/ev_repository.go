package emailverification

import (
	"context"
	"errors"
	"log"

	"github.com/rkcuwork/auth-system/internal/db"
)

// ev_repositoryFileLogPrefix is the file-level log prefix for all log messages in this file
const ev_repositoryFileLogPrefix = packageLogPrefix + "ev_repository:"

// Repository handles database operations related to email verification.
type Repository struct{}

// NewRepository creates and returns a new Repository instance.
func NewRepository() *Repository {
	const funcName = "NewRepository:"
	funcLogPrefix := ev_repositoryFileLogPrefix + funcName

	log.Printf("%s initialized email verification repository", funcLogPrefix)
	return &Repository{}
}

// MarkUserVerified sets the user's email as verified in the database.
func (r *Repository) MarkUserVerified(ctx context.Context, userID string) error {
	const funcName = "MarkUserVerified:"
	funcLogPrefix := ev_repositoryFileLogPrefix + funcName

	commandTag, err := db.Pool.Exec(ctx,
		"UPDATE users SET is_email_verified = TRUE WHERE id = $1", userID)
	if err != nil {
		log.Printf("%s failed to update verification status for user ID %s: %v", funcLogPrefix, userID, err)
		return err
	}

	if commandTag.RowsAffected() == 0 {
		log.Printf("%s no rows affected for user ID %s — user may not exist or already verified", funcLogPrefix, userID)
		return errors.New("user not found or already verified")
	}

	log.Printf("%s successfully marked email as verified for user ID %s", funcLogPrefix, userID)
	return nil
}
