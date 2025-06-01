package emailverification

import (
	"context"
	"log"
)

// ev_serviceFileLogPrefix is the file-level log prefix for all log messages in this file
const ev_serviceFileLogPrefix = packageLogPrefix + "ev_service:"

// Service coordinates email verification logic between repository, token manager, and email sender.
type Service struct {
	repo        *Repository
	tokenMgr    *TokenManager
	emailSender EmailSender
	baseURL     string
}

// NewService creates and returns a new Service instance.
func NewService(repo *Repository, tokenMgr *TokenManager, sender EmailSender, baseURL string) *Service {
	const funcName = "NewService:"
	funcLogPrefix := ev_serviceFileLogPrefix + funcName

	log.Printf("%s initializing email verification service", funcLogPrefix)
	return &Service{
		repo:        repo,
		tokenMgr:    tokenMgr,
		emailSender: sender,
		baseURL:     baseURL,
	}
}

// SendVerificationEmail generates a verification token and sends a verification email.
func (s *Service) SendVerificationEmail(ctx context.Context, userID string, email string) error {
	const funcName = "SendVerificationEmail:"
	funcLogPrefix := ev_serviceFileLogPrefix + funcName

	log.Printf("%s sending verification email to %s", funcLogPrefix, email)

	token, err := s.tokenMgr.GenerateVerificationToken(userID)
	if err != nil {
		log.Printf("%s failed to generate verification token for user %s: %v", funcLogPrefix, userID, err)
		return err
	}

	log.Printf("%s verification token generated for user %s", funcLogPrefix, userID)

	verificationLink := s.baseURL + "/verify-email?token=" + token
	subject := "Verify your email"
	body := "Please verify your email by clicking the link: " + verificationLink

	err = s.emailSender.Send(email, subject, body)
	if err != nil {
		log.Printf("%s failed to send verification email to %s: %v", funcLogPrefix, email, err)
		return err
	}

	log.Printf("%s verification email sent successfully to %s", funcLogPrefix, email)
	return nil
}

// VerifyEmail parses and validates the token, then marks the user as verified.
func (s *Service) VerifyEmail(ctx context.Context, token string) error {
	const funcName = "VerifyEmail:"
	funcLogPrefix := ev_serviceFileLogPrefix + funcName

	userID, err := s.tokenMgr.ParseAndValidateToken(token)
	if err != nil {
		log.Printf("%s token validation failed: %v", funcLogPrefix, err)
		return err
	}

	log.Printf("%s token validated, marking user %s as verified", funcLogPrefix, userID)
	err = s.repo.MarkUserVerified(ctx, userID)
	if err != nil {
		log.Printf("%s failed to mark user %s as verified: %v", funcLogPrefix, userID, err)
		return err
	}

	log.Printf("%s user %s marked as verified successfully", funcLogPrefix, userID)
	return nil
}

// SendResetPasswordLink sends a reset password link using the provided reset token.
func (s *Service) SendResetPasswordLink(ctx context.Context, email string, resetToken string) error {
	const funcName = "SendResetPasswordLink:"
	funcLogPrefix := ev_serviceFileLogPrefix + funcName

	log.Printf("%s sending reset password link to %s", funcLogPrefix, email)

	resetLink := s.baseURL + "/reset-password?token=" + resetToken
	subject := "Reset your password"
	body := "You can reset your password by clicking the link: " + resetLink

	err := s.emailSender.Send(email, subject, body)
	if err != nil {
		log.Printf("%s failed to send reset password email to %s: %v", funcLogPrefix, email, err)
		return err
	}

	log.Printf("%s reset password link sent successfully to %s", funcLogPrefix, email)
	return nil
}
