package oauth

import (
	"context"
	"fmt"

	"os"


	"github.com/google/uuid"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"

	"github.com/rkcuwork/auth-system/internal/models"
	"github.com/rkcuwork/auth-system/internal/services"
)

type GoogleOauthService struct {
	OAuthConfig  *oauth2.Config
	TokenManager *services.TokenManager
}

func NewGoogleOauthService(tokenManager *services.TokenManager) *GoogleOauthService {
	return &GoogleOauthService{
		OAuthConfig: &oauth2.Config{
			RedirectURL:  "http://localhost:8080/oauth/google/callback",
			ClientID:     os.Getenv("GOOGLE_CLIENT_ID"),
			ClientSecret: os.Getenv("GOOGLE_CLIENT_SECRET"),
			Scopes: []string{
				"https://www.googleapis.com/auth/userinfo.email",
				"https://www.googleapis.com/auth/userinfo.profile",
			},
			Endpoint: google.Endpoint,
		},
		TokenManager: tokenManager,
	}
}



// Step 2: Handle Google callback
func (g *GoogleOauthService) GoogleLogin(user *models.User, fp *models.Fingerprint)  (*models.LoginResponse,error) {
	


	// TODO: Check if user exists in DB; if not, create user with email, firstName, lastName
	_ = g.TokenManager.Repo.CreateUser(context.Background(), user)
	user, err := g.TokenManager.Repo.GetUserByEmail(context.Background(), user.Email)
	if err != nil {
		fmt.Printf("auth-system:internal:oauth:google:HandleGoogleCallback: Error fetching user by email: %v\n", err)
		return nil, fmt.Errorf("failed to fetch user by email: %w", err)
	}

	deviceid := uuid.NewString()
	accesstoken,refreshtoken,err := g.TokenManager.GenerateRefreshAndAccessToken(user,fp,deviceid)


	if err != nil {
		fmt.Printf("auth-system:internal:oauth:google:HandleGoogleCallback: Error generating tokens: %v\n", err)
		return nil, fmt.Errorf("error generating tokens: %w", err)
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
