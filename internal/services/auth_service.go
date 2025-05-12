package services

import (
	"context"
	"fmt"


	"github.com/rkcuwork/auth-system/internal/models"
	"github.com/rkcuwork/auth-system/internal/repository"
	"github.com/rkcuwork/auth-system/internal/utils"
)


type userService struct {
	repo repository.UserRepository
}

func NewUserService(repo repository.UserRepository) UserService {
	return &userService{repo: repo}
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
	return s.repo.CreateUser(ctx, input)
}






func (s *userService) Login(ctx context.Context, input *models.LoginRequest) (*models.LoginResponse, error) {
	var user *models.User

	user,err := s.repo.GetUserByEmail(ctx, input.LoginEmail)
	
	if err != nil {
		fmt.Printf("auth-system:internal:repository:user_repository:LoginUser: Error in getting user by email: %v\n", err)
		return nil,fmt.Errorf("email not found")
	}

	passwordMatch := utils.CheckPasswordHash(input.LoginPassword, user.PasswordHash);
	if !passwordMatch {
		fmt.Printf("auth-system:internal:repository:user_repository:LoginUser: Password does not match\n")
		return nil, fmt.Errorf("password does not match")
	}

	jwttoken,err := GenerateJWT(user.ID,user.Email)

	if( err != nil) {
		fmt.Printf("auth-system:internal:repository:user_repository:LoginUser: Error in generating JWT token: %v\n", err)
		return nil,err
	}

	res := &models.LoginResponse{
		Token: jwttoken,
		UserID: user.ID,
	}

	return res,nil
}
