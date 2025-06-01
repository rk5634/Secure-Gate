package oauth

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/gin-gonic/gin"
	"golang.org/x/oauth2"

	"github.com/rkcuwork/auth-system/internal/models"
)

type GoogleOAuthHandler struct {
	GoogleService *GoogleOauthService
}


func NewGoogleOAuthHandler(GoogleService *GoogleOauthService) *GoogleOAuthHandler {
	return &GoogleOAuthHandler{
		GoogleService: GoogleService,
	}
}

func (h *GoogleOAuthHandler) HandleGoogleLogin(c *gin.Context) {
	state := "secure-random-state" // Replace with securely generated state
	url := h.GoogleService.OAuthConfig.AuthCodeURL(state, oauth2.AccessTypeOffline)
	c.Redirect(http.StatusFound, url)
}

// Step 2: Handle Google callback
func (h *GoogleOAuthHandler) HandleGoogleCallback(c *gin.Context) {
	code := c.Query("code")
	if code == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Code not provided"})
		return
	}

	// Step 3: Exchange code for token
	token, err := h.GoogleService.OAuthConfig.Exchange(context.Background(), code)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Failed to exchange token"})
		return
	}

	// Step 4: Use token to get user info
	client := h.GoogleService.OAuthConfig.Client(context.Background(), token)
	resp, err := client.Get("https://www.googleapis.com/oauth2/v3/userinfo")
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Failed to get user info"})
		return
	}
	defer resp.Body.Close()

	var userData map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&userData); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Invalid user data"})
		return
	}

	// Extract relevant fields
	email := userData["email"].(string)
	firstName := userData["given_name"].(string)
	lastName := userData["family_name"].(string)
	// picture := userData["picture"].(string)
	is_email_verified := userData["email_verified"].(bool)

	user := &models.User{
		FullName:        fmt.Sprintf("%s %s", firstName, lastName),
		Email:           email,
		Phone:           "", // Phone number is not provided by Google
		PasswordHash:    "", // No password hash for OAuth users
		IsEmailVerified: is_email_verified,
		IsPhoneVerified: false,
		TokenVersion:    0,
	}

	fp := &models.Fingerprint{
		UserAgent:      c.Request.UserAgent(),
		IPAddress:      c.ClientIP(),
		AcceptLanguage: c.GetHeader("Accept-Language"),
		AcceptEncoding: c.GetHeader("Accept-Encoding"),
	}

	response, err := h.GoogleService.GoogleLogin(user, fp)
	if err != nil {
		fmt.Printf("auth-system:internal:oauth:google:HandleGoogleCallback: Error during Google login: %v\n", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to log in with Google"})
		return
	}

	// Set refresh token in secure HTTP-only cookie
	http.SetCookie(c.Writer, &http.Cookie{
		Name:     "refresh_token",
		Value:    response.RefreshToken,
		Path:     "/",
		HttpOnly: true,
		Secure:   false, // set to false in local development if needed (not recommended)
		SameSite: http.SameSiteStrictMode,
		MaxAge:   7 * 24 * 60 * 60, // 7 days
	})

	// Send only relevant data (no refresh token) in response
	c.JSON(http.StatusOK, gin.H{
		"message": "Login successful",
		"data": gin.H{
			"accesstoken": response.AccessToken,
			"userid":      response.UserID,
			"email":       response.Email,
			"role":        response.Role,
			"deviceid":    response.DeviceID,
		},
	})

}
