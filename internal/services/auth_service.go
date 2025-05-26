package services

import (
	"context"
	"fmt"
	"time"

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

	if !user.IsEmailVerified {
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
		s.tokenmanager.Redisclient.DeleteKey("refresh_token:" + userid)
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
		s.tokenmanager.Redisclient.DeleteKey("refresh_token:" + userid)
		return nil, err
	}

	return nil, err

}



func (s *userService) ValidateToken(token string) (jwt.MapClaims, error) {
	return s.tokenmanager.ParseAndValidateToken(token)
}


func (s *userService) Logout(req *models.LogoutRequest) (err error) {

	isvalid,claims, err := s.tokenmanager.IsValidAccessToken(req.AccessToken)
	if !isvalid {
		fmt.Printf("auth-system:internal:services:auth_service:Logout: Failed validating token: %v\n", err)
		return fmt.Errorf("Token validation failed")
	}
	if err!=nil {
		fmt.Printf("auth-system:internal:services:auth_service:Logout: Error in validating token: %v\n", err)
		return fmt.Errorf("Error occured Relogin")
	}

	user, err := s.repo.GetUserByID(context.Background(), claims["sub"].(string))
	if err != nil {
		fmt.Printf("auth-system:internal:services:auth_service:Logout: Error in fetching user: %v\n", err)
		return err
	}

	err = s.tokenmanager.Redisclient.RemoveRefreshTokenJTI(user.ID)
	if err != nil {
		fmt.Printf("auth-system:internal:services:auth_service:Logout: Error in removing refresh token jti from redis: %v\n", err)
		return err
	}

	expirationTime, err := claims.GetExpirationTime()
	if err != nil {
		// Handle the error appropriately
		return err
	}

	ttl := time.Until(expirationTime.Time)

	// Blacklist the access token using jti
	err = s.tokenmanager.Redisclient.BlocklistTokenJTI(claims["jti"].(string),ttl,user.ID, "Logout")
	if err != nil {
		fmt.Printf("auth-system:internal:services:auth_service:Logout: Error in blocklisting token jti: %v\n", err)
		return err
	}

	return nil

}





func (s *userService) ForgotPasswordService(req *models.ForgotPasswordRequest) (err error) {
	user, err := s.repo.GetUserByEmail(context.Background(),req.Email)

	if err != nil {
		fmt.Printf("auth-system:internal:services:auth_service:ForgotPasswordService: Error in getting user by email: %v\n", err)
		return fmt.Errorf("email not found")
	}

	// Generate a password reset token
	token, err := s.tokenmanager.GeneratePasswordResetToken(user.ID)
	if err != nil {
		fmt.Printf("auth-system:internal:services:auth_service:ForgotPasswordService: Error in generating password reset token: %v\n", err)
		return fmt.Errorf("error generating password reset token")
	}


	// Send the password reset email
	err = s.emailservice.SendResetPasswordLink(context.Background(), user.Email, token)
	if err != nil {
		fmt.Printf("auth-system:internal:services:auth_service:ForgotPasswordService: Error in sending password reset email: %v\n", err)
		return fmt.Errorf("error sending password reset email")
	}


	fmt.Printf("auth-system:internal:services:auth_service:ForgotPasswordService: Password reset email sent to %s\n", user.Email)
	return nil

}





func (s *userService) ResetPasswordService(req models.ResetPasswordRequest) (err error){
	userID, err := s.tokenmanager.VerifyResetToken(req.Token)
	if err != nil {
		fmt.Printf("auth-system:internal:services:auth_service:ResetPasswordService: Error in parsing password reset token: %v\n", err)
		return fmt.Errorf("invalid or expired token")
	}

	hashedPassword, err := utils.HashPassword(req.NewPassword)
	if err != nil {
		fmt.Printf("auth-system:internal:services:auth_service:ResetPasswordService: Error in hashing password: %v\n", err)
		return fmt.Errorf("error hashing password")
	}

	err = s.repo.UpdatePassword(userID, hashedPassword)
	if err != nil {
		fmt.Printf("auth-system:internal:services:auth_service:ResetPasswordService: Error in updating password: %v\n", err)
		return fmt.Errorf("error updating password")
	}

	

	fmt.Printf("auth-system:internal:services:auth_service:ResetPasswordService: Password reset successfully for user ID %s\n", userID)
	return nil
}
