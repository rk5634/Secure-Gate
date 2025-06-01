package oauth

import (
	"context"
	"fmt"
	"log"
	"os"

	"github.com/google/uuid"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"

	"github.com/rkcuwork/auth-system/internal/models"
	"github.com/rkcuwork/auth-system/internal/services"
)

// Define file-level log prefix
const googleOauthLogPrefix = packageLogPrefix + "oauth_google:"

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

// GoogleLogin handles Google OAuth login, user creation, and token generation.
func (g *GoogleOauthService) GoogleLogin(user *models.User, fp *models.Fingerprint) (*models.LoginResponse, error) {
	const funcName = "GoogleLogin:"
	funcLogPrefix := googleOauthLogPrefix + funcName

	// Create user if not exists
	if err := g.TokenManager.Repo.CreateUser(context.Background(), user); err != nil {
		log.Printf("%s Error creating user: %v", funcLogPrefix, err)
		// proceed anyway to fetch user to handle possible duplication gracefully
	}

	user, err := g.TokenManager.Repo.GetUserByEmail(context.Background(), user.Email)
	if err != nil {
		log.Printf("%s Error fetching user by email: %v", funcLogPrefix, err)
		return nil, fmt.Errorf("failed to fetch user by email: %w", err)
	}

	deviceID := uuid.NewString()
	accessToken, refreshToken, err := g.TokenManager.GenerateRefreshAndAccessToken(user, fp, deviceID)
	if err != nil {
		log.Printf("%s Error generating tokens: %v", funcLogPrefix, err)
		return nil, fmt.Errorf("error generating tokens: %w", err)
	}

	res := &models.LoginResponse{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		UserID:       user.ID,
		Email:        user.Email,
		Role:         "user",
		DeviceID:     deviceID,
	}

	log.Printf("%s Successful login for userID: %s, deviceID: %s", funcLogPrefix, user.ID, deviceID)
	return res, nil
}
