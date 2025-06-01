package oauth

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
	"fmt"

	"github.com/gin-gonic/gin"
	"golang.org/x/oauth2"

	"github.com/rkcuwork/auth-system/internal/models"
)

// file-level log prefix
const handlerLogPrefix = packageLogPrefix + "handler:"

type GoogleOAuthHandler struct {
	GoogleService *GoogleOauthService
}

func NewGoogleOAuthHandler(GoogleService *GoogleOauthService) *GoogleOAuthHandler {
	return &GoogleOAuthHandler{
		GoogleService: GoogleService,
	}
}

func (h *GoogleOAuthHandler) HandleGoogleLogin(c *gin.Context) {
	const funcName = "HandleGoogleLogin:"
	funcLogPrefix := handlerLogPrefix + funcName

	state := "secure-random-state" // Replace with securely generated state
	url := h.GoogleService.OAuthConfig.AuthCodeURL(state, oauth2.AccessTypeOffline)

	log.Printf("%s Redirecting to Google OAuth URL", funcLogPrefix)
	c.Redirect(http.StatusFound, url)
}

// Step 2: Handle Google callback
func (h *GoogleOAuthHandler) HandleGoogleCallback(c *gin.Context) {
	const funcName = "HandleGoogleCallback:"
	funcLogPrefix := handlerLogPrefix + funcName

	code := c.Query("code")
	if code == "" {
		log.Printf("%s Missing code in callback request", funcLogPrefix)
		c.JSON(http.StatusBadRequest, gin.H{"error": "Code not provided"})
		return
	}

	// Step 3: Exchange code for token
	token, err := h.GoogleService.OAuthConfig.Exchange(context.Background(), code)
	if err != nil {
		log.Printf("%s Failed to exchange token: %v", funcLogPrefix, err)
		c.JSON(http.StatusBadRequest, gin.H{"error": "Failed to exchange token"})
		return
	}

	// Step 4: Use token to get user info
	client := h.GoogleService.OAuthConfig.Client(context.Background(), token)
	resp, err := client.Get("https://www.googleapis.com/oauth2/v3/userinfo")
	if err != nil {
		log.Printf("%s Failed to get user info: %v", funcLogPrefix, err)
		c.JSON(http.StatusBadRequest, gin.H{"error": "Failed to get user info"})
		return
	}
	defer resp.Body.Close()

	var userData map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&userData); err != nil {
		log.Printf("%s Invalid user data received: %v", funcLogPrefix, err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Invalid user data"})
		return
	}

	// Extract relevant fields safely
	email, _ := userData["email"].(string)
	firstName, _ := userData["given_name"].(string)
	lastName, _ := userData["family_name"].(string)
	isEmailVerified, _ := userData["email_verified"].(bool)

	user := &models.User{
		FullName:        fmt.Sprintf("%s %s", firstName, lastName),
		Email:           email,
		Phone:           "", // Phone number is not provided by Google
		PasswordHash:    "", // No password hash for OAuth users
		IsEmailVerified: isEmailVerified,
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
		log.Printf("%s Error during Google login: %v", funcLogPrefix, err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to log in with Google"})
		return
	}

	// Set refresh token in secure HTTP-only cookie
	http.SetCookie(c.Writer, &http.Cookie{
		Name:     "refresh_token",
		Value:    response.RefreshToken,
		Path:     "/",
		HttpOnly: true,
		Secure:   false, // Set false for local dev; should be true in prod
		SameSite: http.SameSiteStrictMode,
		MaxAge:   7 * 24 * 60 * 60, // 7 days
	})

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
