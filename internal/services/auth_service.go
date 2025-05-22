package services

import (
	"context"
	"fmt"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/rkcuwork/auth-system/internal/emailverification"
	"github.com/rkcuwork/auth-system/internal/models"
	"github.com/rkcuwork/auth-system/internal/repository"
	"github.com/rkcuwork/auth-system/internal/utils"
)

type userService struct {
	repo         repository.UserRepository
	emailservice *emailverification.Service
	tokenmanager *TokenManager
}

func NewUserService(repo repository.UserRepository, emailservice *emailverification.Service, tokenmanager *TokenManager) UserService {
	return &userService{repo: repo, emailservice: emailservice, tokenmanager: tokenmanager}
}

func (s *userService) Register(ctx context.Context, input *models.User) error {
	// Hash the password
	hashedPassword, err := utils.HashPassword(input.PasswordHash)
	if err != nil {
		fmt.Errorf("auth-system:internal:services:auth_service:Register: Error hashing password: %v\n", err)
		return err
	}
	input.PasswordHash = hashedPassword

	// Create user in the repository
	err = s.repo.CreateUser(ctx, input)
	if err != nil {
		fmt.Printf("auth-system:internal:services:auth_service:Register: Error in creating user: %v\n", err)
		return err
	}

	user, err := s.repo.GetUserByEmail(ctx, input.Email)
	if err != nil {
		fmt.Printf("auth-system:internal:services:auth_service:Register: Error in getting user by email: %v\n", err)
		return err
	}

	// 🔄 Send verification email in a goroutine
	go func(userID string, email string) {
		// NOTE: Do not use request context inside goroutine — it might be cancelled
		bgCtx := context.Background()

		err := s.emailservice.SendVerificationEmail(bgCtx, user.ID, email)
		if err != nil {
			fmt.Printf("auth-system:internal:services:auth_service:Register: Failed to send verification email to %s: %v\n", email, err)
			// Optional: Save to retry queue / failed email log table
		} else {
			fmt.Printf("auth-system:internal:services:auth_service:Register: Verification email sent to %s\n", email)
		}
	}(user.ID, input.Email)

	// ✅ Return success response immediately
	fmt.Println("Registration successful! Please check your email for verification.")
	return nil
}

func (s *userService) Login(ctx context.Context, input *models.LoginRequest, fp *models.Fingerprint) (*models.LoginResponse, error) {
	var user *models.User

	user, err := s.repo.GetUserByEmail(ctx, input.LoginEmail)

	if err != nil {
		fmt.Printf("auth-system:internal:services:auth_service:Login: Error in getting user by email: %v\n", err)
		return nil, fmt.Errorf("email not found")
	}

	if !user.IsVerified {
		fmt.Printf("auth-system:internal:services:auth_service:Login: User is not verified\n")
		return nil, fmt.Errorf("user is not verified")
	}

	passwordMatch := utils.CheckPasswordHash(input.LoginPassword, user.PasswordHash)
	if !passwordMatch {
		fmt.Printf("auth-system:internal:services:auth_service:Login: Password does not match\n")
		return nil, fmt.Errorf("password does not match")
	}

	deviceid := uuid.NewString()
	fmt.Printf("auth-system:internal:services:auth_service:Login: Device ID generated: %s\n", deviceid)
	accesstoken, refreshtoken, err := s.tokenmanager.GenerateRefreshAndAccessToken(user, fp, deviceid)

	if err != nil {
		fmt.Printf("auth-system:internal:services:auth_service:Login: Error in generating JWT token: %v\n", err)
		return nil, err
	}

	res := &models.LoginResponse{
		AccessToken:  accesstoken,
		RefreshToken: refreshtoken,
		UserID:       user.ID,
		Email:        user.Email,
		Role:         "user",
		DeviceID:     deviceid,
	}

	return res, nil
}

func (s *userService) RefreshTokenService(ctx context.Context, input *models.NewAccessTokenRequest, fp *models.Fingerprint) (*models.NewAccessTokenResponse, error) {

	isvalid, userid, err := s.tokenmanager.IsValidRefreshTokenRequest(input, fp)
	// if err!=nil {
	// 	fmt.Printf("auth-system:internal:services:auth_service:RefreshTokenService: Error in validating refresh token: %v\n", err)
	// 	return nil, fmt.Errorf("Error occured Relogin")
	// }
	if isvalid {
		s.tokenmanager.Redisclient.Delete("refresh_token:" + userid)
		user, err := s.repo.GetUserByID(ctx, userid)
		if err != nil {
			fmt.Printf("auth-system:internal:services:auth_service:RefreshTokenService: Error in fetching user: %v\n", err)
			return nil, err
		}

		accesstoken, refreshtoken, err := s.tokenmanager.GenerateRefreshAndAccessToken(user, fp, input.DeviceID)
		if err != nil {
			fmt.Printf("auth-system:internal:services:auth_service:RefreshTokenService: Error in in generating token: %v\n", err)
			return nil, fmt.Errorf("error generating tokens")
		}

		res := &models.NewAccessTokenResponse{
			AccessToken:  accesstoken,
			RefreshToken: refreshtoken,
		}

		return res, nil

	}
	if !isvalid && userid != "" {
		s.tokenmanager.Redisclient.Delete("refresh_token:" + userid)
		return nil, err
	}

	return nil, err

}



func (s *userService) ValidateToken(token string) (jwt.MapClaims, error) {
	return s.tokenmanager.ParseAndValidateToken(token)
}
