package oauth

import (
	"context"
	"encoding/json"
	"os"

	"github.com/gin-gonic/gin"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"

	"github.com/rkcuwork/auth-system/internal/services" // Adjust as needed
)

type OAuthHandler struct {
	OAuthConfig  *oauth2.Config
	TokenManager *services.TokenManager
}

func NewOAuthHandler(tokenManager *services.TokenManager) *OAuthHandler {
	return &OAuthHandler{
		OAuthConfig: &oauth2.Config{
			RedirectURL:  "http://localhost:8080/oauth/google/callback",
			ClientID:     os.Getenv("GOOGLE_CLIENT_ID"),
			ClientSecret: os.Getenv("GOOGLE_CLIENT_SECRET"),
			Scopes:       []string{"https://www.googleapis.com/auth/userinfo.email"},
			Endpoint:     google.Endpoint,
		},
		TokenManager: tokenManager,
	}
}

// Redirect to Google's OAuth consent screen
func (h *OAuthHandler) HandleGoogleLogin(c *gin.Context) {
	state := "random" // TODO: Generate and store securely (e.g., Redis/session)
	url := h.OAuthConfig.AuthCodeURL(state)
	c.Redirect(302, url)
}

// Handle Google OAuth callback
func (h *OAuthHandler) HandleGoogleCallback(c *gin.Context) {
	code := c.Query("code")
	if code == "" {
		c.JSON(400, gin.H{"error": "Code not provided"})
		return
	}

	token, err := h.OAuthConfig.Exchange(context.Background(), code)
	if err != nil {
		c.JSON(400, gin.H{"error": "Failed to exchange token"})
		return
	}

	client := h.OAuthConfig.Client(context.Background(), token)
	resp, err := client.Get("https://www.googleapis.com/oauth2/v2/userinfo")
	if err != nil {
		c.JSON(400, gin.H{"error": "Failed to get user info"})
		return
	}
	defer resp.Body.Close()

	var userData map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&userData); err != nil {
		c.JSON(500, gin.H{"error": "Invalid user data"})
		return
	}

	email, ok := userData["email"].(string)
	if !ok || email == "" {
		c.JSON(500, gin.H{"error": "Email not found"})
		return
	}

	

	// TODO: Check if user exists in DB, else create new user.

	// Generate JWT
	claims := map[string]interface{}{
		"email": email,
		"sub":   email, // sub can act as a unique subject identifier
	}
	jwtToken, err := h.TokenManager.GenerateJWT(claims, 15)
	if err != nil {
		c.JSON(500, gin.H{"error": "Failed to generate JWT"})
		return
	}

	// Set JWT in a cookie (or respond with JSON, if preferred)
	c.SetCookie("token", jwtToken, 900, "/", "localhost", false, true) // 900 seconds = 15 min
	c.JSON(200, gin.H{
		"message": "Login successful",
		"token":   jwtToken,
		"email":   email,
	})
}
