package services

import (
	"context"
	"fmt"
	
	"github.com/rkcuwork/auth-system/internal/models"
	"github.com/rkcuwork/auth-system/internal/repository"
	"github.com/rkcuwork/auth-system/internal/utils"
	"github.com/rkcuwork/auth-system/internal/emailverification"
)


type userService struct {
	repo repository.UserRepository
	emailservice *emailverification.Service
}

func NewUserService(repo repository.UserRepository, emailservice *emailverification.Service) UserService {
	return &userService{repo: repo, emailservice: emailservice}
}

func (s *userService) Register(ctx context.Context, input *models.User) error {
	// Hash the password
	hashedPassword, err := utils.HashPassword(input.PasswordHash)
	if err != nil {
		fmt.Errorf("auth-system:internal:services:auth_service:Register: Error hashing password: %v\n", err)
		return err
	}
	input.PasswordHash = hashedPassword

	// Call repository to create user
	err = s.repo.CreateUser(ctx, input)
	if err != nil {
		fmt.Printf("auth-system:internal:services:auth_service:Register: Error in creating user: %v\n", err)
		return err
	}

	user,err := s.repo.GetUserByEmail(ctx, input.Email)
	if err != nil {
		fmt.Printf("auth-system:internal:services:auth_service:Register: Error in getting user by email: %v\n", err)
		return err
	}

	// Send verification email
	err = s.emailservice.SendVerificationEmail(ctx, user.ID, input.Email)
	if err != nil {
		fmt.Printf("auth-system:internal:services:auth_service:Register: Error in sending verification email: %v\n", err)
    	return fmt.Errorf("registration partially completed: verification email not sent")
	}
	fmt.Printf("auth-system:internal:services:auth_service:Register: Verification email sent to %s\n", input.Email)
	fmt.Println("Registration successful! Please check your email for verification.")

	return nil
}






func (s *userService) Login(ctx context.Context, input *models.LoginRequest) (*models.LoginResponse, error) {
	var user *models.User

	user,err := s.repo.GetUserByEmail(ctx, input.LoginEmail)
	
	if err != nil {
		fmt.Printf("auth-system:internal:repository:user_repository:LoginUser: Error in getting user by email: %v\n", err)
		return nil,fmt.Errorf("email not found")
	}

	if(!user.IsVerified) {
		fmt.Printf("auth-system:internal:repository:user_repository:LoginUser: User is not verified\n")
		return nil, fmt.Errorf("user is not verified");
	}

	passwordMatch := utils.CheckPasswordHash(input.LoginPassword, user.PasswordHash);
	if !passwordMatch {
		fmt.Printf("auth-system:internal:repository:user_repository:LoginUser: Password does not match\n")
		return nil, fmt.Errorf("password does not match")
	}

	accesstoken,refreshtoken,err := GenerateJWT(user)

	if( err != nil) {
		fmt.Printf("auth-system:internal:repository:user_repository:LoginUser: Error in generating JWT token: %v\n", err)
		return nil,err
	}

	res := &models.LoginResponse{
		AccessToken:  accesstoken,
		RefreshToken: refreshtoken,
		UserID: user.ID,
		Email: user.Email,
		Role: "user",
	}

	return res,nil
}
