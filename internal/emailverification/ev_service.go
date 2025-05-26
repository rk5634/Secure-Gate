package emailverification

import (
	"context"
	"fmt"
)

type Service struct {
	repo        *Repository
	tokenMgr    *TokenManager
	emailSender EmailSender
	baseURL     string
}

func NewService(repo *Repository, tokenMgr *TokenManager, sender EmailSender, baseURL string) *Service {
	return &Service{
		repo:        repo,
		tokenMgr:    tokenMgr,
		emailSender: sender,
		baseURL:     baseURL,
	}
}

// SendVerificationEmail generates token and sends email
func (s *Service) SendVerificationEmail(ctx context.Context, userID string, email string) error {
	fmt.Printf("auth-system:internal:emailverification:ev_service:SendVerfificationEmail: Sending verification email to %s\n", email)
	token, err := s.tokenMgr.GenerateVerificationToken(userID)
	if err != nil {
		// log error
		fmt.Printf("auth-system:internal:emailverification:ev_service:SendVerfificationEmail: Error generating verification token, %v", err)
		return err
	}

	fmt.Printf("auth-system:internal:emailverification:ev_service:SendVerfificationEmail: Verification token generated, %s\n", token)

	verificationLink := s.baseURL + "/verify-email?token=" + token
	subject := "Verify your email"
	body := "Please verify your email by clicking the link: " + verificationLink

	return s.emailSender.Send(email, subject, body)
}

// VerifyEmail validates token and marks user verified
func (s *Service) VerifyEmail(ctx context.Context, token string) error {
	userID, err := s.tokenMgr.ParseAndValidateToken(token)
	if err != nil {
		// log error
		fmt.Printf("auth-system:internal:emailverification:ev_service:VerifyEmail: Error parsing and validating token, %v", err)
		return err
	}
	return s.repo.MarkUserVerified(ctx, userID)
}





// SendResetPasswordLink sends a reset password link using the provided reset token
func (s *Service) SendResetPasswordLink(ctx context.Context, email string, resetToken string) error {
	fmt.Printf("auth-system:internal:passwordreset:service:SendResetPasswordLink: Sending reset password email to %s\n", email)

	resetLink := s.baseURL + "/reset-password?token=" + resetToken
	subject := "Reset your password"
	body := "You can reset your password by clicking the link: " + resetLink

	err := s.emailSender.Send(email, subject, body)
	if err != nil {
		fmt.Printf("auth-system:internal:passwordreset:service:SendResetPasswordLink: Error sending email, %v", err)
		return err
	}

	fmt.Printf("auth-system:internal:passwordreset:service:SendResetPasswordLink: Reset link sent successfully\n")
	return nil
}