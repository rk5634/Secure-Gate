package services

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/rkcuwork/auth-system/internal/emailverification"
	"github.com/rkcuwork/auth-system/internal/models"
	"github.com/rkcuwork/auth-system/internal/repository"
	"github.com/rkcuwork/auth-system/internal/utils"
	"github.com/rkcuwork/auth-system/pkg/twilio"
)

const authServiceLogPrefix = packageLogPrefix + "auth_service:"

type userService struct {
	repo          repository.UserRepository
	emailservice  *emailverification.Service
	tokenmanager  *TokenManager
	twilioService *twilio.TwilioService
}

func NewUserService(repo repository.UserRepository, emailservice *emailverification.Service, tokenmanager *TokenManager, twilioService *twilio.TwilioService) UserService {
	return &userService{repo: repo, emailservice: emailservice, tokenmanager: tokenmanager, twilioService: twilioService}
}

func (s *userService) Register(ctx context.Context, input *models.User) error {
	const funcName = "Register:"
	funcLogPrefix := authServiceLogPrefix + funcName

	hashedPassword, err := utils.HashPassword(input.PasswordHash)
	if err != nil {
		log.Printf("%s Error hashing password: %v", funcLogPrefix, err)
		return err
	}
	input.PasswordHash = hashedPassword

	err = s.repo.CreateUser(ctx, input)
	if err != nil {
		log.Printf("%s Error creating user: %v", funcLogPrefix, err)
		return err
	}

	user, err := s.repo.GetUserByEmail(ctx, input.Email)
	if err != nil {
		log.Printf("%s Error fetching user by email: %v", funcLogPrefix, err)
		return err
	}

	go func(userID, email string) {
		bgCtx := context.Background()
		if err := s.emailservice.SendVerificationEmail(bgCtx, userID, email); err != nil {
			log.Printf("%s Failed to send verification email to %s: %v", funcLogPrefix, email, err)
		} else {
			log.Printf("%s Verification email sent to %s", funcLogPrefix, email)
		}
	}(user.ID, input.Email)

	log.Printf("%s Registration successful! Please check your email for verification.", funcLogPrefix)
	return nil
}

func (s *userService) Login(ctx context.Context, input *models.LoginRequest, fp *models.Fingerprint) (*models.LoginResponse, error) {
	const funcName = "Login:"
	funcLogPrefix := authServiceLogPrefix + funcName

	user, err := s.repo.GetUserByEmail(ctx, input.LoginEmail)
	if err != nil {
		log.Printf("%s Error fetching user by email: %v", funcLogPrefix, err)
		return nil, fmt.Errorf("email not found")
	}

	if !user.IsEmailVerified {
		log.Printf("%s User is not verified", funcLogPrefix)
		return nil, fmt.Errorf("user is not verified")
	}

	if !utils.CheckPasswordHash(input.LoginPassword, user.PasswordHash) {
		log.Printf("%s Password does not match", funcLogPrefix)
		return nil, fmt.Errorf("password does not match")
	}

	deviceID := uuid.NewString()
	log.Printf("%s Device ID generated: %s", funcLogPrefix, deviceID)

	accessToken, refreshToken, err := s.tokenmanager.GenerateRefreshAndAccessToken(user, fp, deviceID)
	if err != nil {
		log.Printf("%s Error generating JWT tokens: %v", funcLogPrefix, err)
		return nil, err
	}

	res := &models.LoginResponse{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		UserID:       user.ID,
		Email:        user.Email,
		Role:         "user",
		DeviceID:     deviceID,
	}

	return res, nil
}

func (s *userService) RefreshTokenService(ctx context.Context, input *models.NewAccessTokenRequest, fp *models.Fingerprint) (*models.NewAccessTokenResponse, error) {
	const funcName = "RefreshTokenService:"
	funcLogPrefix := authServiceLogPrefix + funcName

	isValid, userID, err := s.tokenmanager.IsValidRefreshTokenRequest(input, fp)
	if isValid {
		s.tokenmanager.Redisclient.DeleteKey("refresh_token:" + userID)

		user, err := s.repo.GetUserByID(ctx, userID)
		if err != nil {
			log.Printf("%s Error fetching user: %v", funcLogPrefix, err)
			return nil, err
		}

		accessToken, refreshToken, err := s.tokenmanager.GenerateRefreshAndAccessToken(user, fp, input.DeviceID)
		if err != nil {
			log.Printf("%s Error generating tokens: %v", funcLogPrefix, err)
			return nil, fmt.Errorf("error generating tokens")
		}

		return &models.NewAccessTokenResponse{
			AccessToken:  accessToken,
			RefreshToken: refreshToken,
		}, nil
	}

	if !isValid && userID != "" {
		s.tokenmanager.Redisclient.DeleteKey("refresh_token:" + userID)
		return nil, err
	}

	return nil, err
}

func (s *userService) ValidateToken(token string) (jwt.MapClaims, error) {
	return s.tokenmanager.ParseAndValidateToken(token)
}

func (s *userService) Logout(req *models.LogoutRequest) error {
	const funcName = "Logout:"
	funcLogPrefix := authServiceLogPrefix + funcName

	isValid, claims, err := s.tokenmanager.IsValidAccessToken(req.AccessToken)
	if !isValid {
		log.Printf("%s Token validation failed: %v", funcLogPrefix, err)
		return fmt.Errorf("token validation failed")
	}

	if err != nil {
		log.Printf("%s Error validating token: %v", funcLogPrefix, err)
		return fmt.Errorf("error occurred during re-login")
	}

	user, err := s.repo.GetUserByID(context.Background(), claims["sub"].(string))
	if err != nil {
		log.Printf("%s Error fetching user: %v", funcLogPrefix, err)
		return err
	}

	err = s.tokenmanager.Redisclient.RemoveRefreshTokenJTI(user.ID)
	if err != nil {
		log.Printf("%s Error removing refresh token jti from redis: %v", funcLogPrefix, err)
		return err
	}

	expirationTime, err := claims.GetExpirationTime()
	if err != nil {
		return err
	}

	ttl := time.Until(expirationTime.Time)

	err = s.tokenmanager.Redisclient.BlocklistTokenJTI(claims["jti"].(string), ttl, user.ID, "Logout")
	if err != nil {
		log.Printf("%s Error blocklisting token jti: %v", funcLogPrefix, err)
		return err
	}

	return nil
}

func (s *userService) ForgotPasswordService(req *models.ForgotPasswordRequest) error {
	const funcName = "ForgotPasswordService:"
	funcLogPrefix := authServiceLogPrefix + funcName

	user, err := s.repo.GetUserByEmail(context.Background(), req.Email)
	if err != nil {
		log.Printf("%s Email not found: %v", funcLogPrefix, err)
		return fmt.Errorf("email not found")
	}

	token, err := s.tokenmanager.GeneratePasswordResetToken(user.ID)
	if err != nil {
		log.Printf("%s Error generating password reset token: %v", funcLogPrefix, err)
		return fmt.Errorf("error generating password reset token")
	}

	err = s.emailservice.SendResetPasswordLink(context.Background(), user.Email, token)
	if err != nil {
		log.Printf("%s Error sending password reset email: %v", funcLogPrefix, err)
		return fmt.Errorf("error sending password reset email")
	}

	log.Printf("%s Password reset email sent to %s", funcLogPrefix, user.Email)
	return nil
}

func (s *userService) ResetPasswordService(req models.ResetPasswordRequest) error {
	const funcName = "ResetPasswordService:"
	funcLogPrefix := authServiceLogPrefix + funcName

	userID, err := s.tokenmanager.VerifyResetToken(req.Token)
	if err != nil {
		log.Printf("%s Invalid or expired token: %v", funcLogPrefix, err)
		return fmt.Errorf("invalid or expired token")
	}

	hashedPassword, err := utils.HashPassword(req.NewPassword)
	if err != nil {
		log.Printf("%s Error hashing password: %v", funcLogPrefix, err)
		return fmt.Errorf("error hashing password")
	}

	err = s.repo.UpdatePassword(userID, hashedPassword)
	if err != nil {
		log.Printf("%s Error updating password: %v", funcLogPrefix, err)
		return fmt.Errorf("error updating password")
	}

	log.Printf("%s Password reset successfully for user ID %s", funcLogPrefix, userID)
	return nil
}
