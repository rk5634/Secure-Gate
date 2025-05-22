package emailupdate

import (
	"context"
	"fmt"

	"github.com/rkcuwork/auth-system/internal/emailverification"
)

type Service struct {
	repo         Repository
	emailService *emailverification.Service // Reuse your existing verification email sender
}

func NewService(repo Repository, emailService *emailverification.Service) *Service {
	return &Service{repo: repo, emailService: emailService}
}

func (s *Service) UpdateEmail(ctx context.Context, userID, newEmail string) (*UpdateEmailResponse,error) {
	resp := &UpdateEmailResponse{}
	exists, err := s.repo.EmailExists(ctx, newEmail)
	if err != nil {
		// Log the error
		fmt.Printf("auth-system:internal:emailupdate:UpdateEmail: Error checking email existence: %v\n", err)
		resp.Status = "Error"
		resp.Message = "could not check email existence"
		return resp,fmt.Errorf("could not check email existence")
	}
	if exists {
		// Log the error
		fmt.Printf("auth-system:internal:emailupdate:UpdateEmail: Email already in use: %s\n", newEmail)
		resp.Status = "Update Failed"
		resp.Message = "New email already in use"
		return resp,fmt.Errorf("email already in use")
	}

	err = s.repo.SetUnverifiedEmail(ctx, userID, newEmail)
	if err != nil {
		// Log the error
		fmt.Printf("auth-system:internal:emailupdate:UpdateEmail: Error setting new email: %v\n", err)
		resp.Status = "Error"
		resp.Message = "Error setting new email"
		return resp,fmt.Errorf("could not set new email")
	}

	go s.emailService.SendVerificationEmail(ctx, userID, newEmail)
	resp.Status = "Success"
	resp.Message = "New email updated and verification email sent"
	resp.NewEmail = newEmail
	return resp,nil
}
