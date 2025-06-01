package handlers

import (
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/rkcuwork/auth-system/internal/models"
	"github.com/rkcuwork/auth-system/internal/services"
)

// auth_handlerFileLogPrefix is the file-level prefix for all log messages in this file
const auth_handlerFileLogPrefix = packageLogPrefix + "auth_handler:"

// AuthHandler handles all authentication related HTTP requests.
type AuthHandler struct {
	authService services.UserService
}

// NewAuthHandler creates a new AuthHandler instance with the required service dependency.
// It panics if the service is nil since the handler cannot function without it.
func NewAuthHandler(authService services.UserService) *AuthHandler {
	const funcName = "NewAuthHandler:"
	funcLogPrefix := auth_handlerFileLogPrefix + funcName

	if authService == nil {
		log.Fatalf("%s service dependency cannot be nil", funcLogPrefix)
	}
	return &AuthHandler{authService: authService}
}

// Register handles user registration.
// It validates the input payload, constructs a User model, calls the service layer, and responds accordingly.
func (h *AuthHandler) Register(c *gin.Context) {
	const funcName = "Register:"
	funcLogPrefix := auth_handlerFileLogPrefix + funcName

	var req models.RegisterRequest

	// Bind and validate input JSON
	if err := c.ShouldBindJSON(&req); err != nil {
		log.Printf("%s error binding JSON request: %v", funcLogPrefix, err)
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request payload"})
		return
	}

	// Construct User model; PasswordHash will be hashed inside the service
	user := &models.User{
		FullName:        req.FullName,
		Email:           req.Email,
		Phone:           req.Phone,
		PasswordHash:    req.Password,
		IsEmailVerified: false,
		IsPhoneVerified: false,
		TokenVersion:    0,
		CreatedAt:       time.Now(),
		UpdatedAt:       time.Now(),
	}

	// Call service layer to register the user
	if err := h.authService.Register(c.Request.Context(), user); err != nil {
		log.Printf("%s error registering user: %v", funcLogPrefix, err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to register user"})
		return
	}

	c.JSON(http.StatusCreated, gin.H{"message": "User registered successfully. Please check your email to verify your account."})
}

// Login handles user login requests.
// Validates input, verifies existing login session, and returns JWT tokens upon success.
func (h *AuthHandler) Login(c *gin.Context) {
	const funcName = "Login:"
	funcLogPrefix := auth_handlerFileLogPrefix + funcName

	// Check if user already has a valid refresh token cookie (already logged in)
	if cookie, err := c.Request.Cookie("refresh_token"); err == nil {
		if _, err := h.authService.ValidateToken(cookie.Value); err == nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "User already logged in"})
			return
		}
	}

	var req models.LoginRequest

	// Bind and validate input JSON
	if err := c.ShouldBindJSON(&req); err != nil {
		log.Printf("%s error binding JSON request: %v", funcLogPrefix, err)
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid login credentials"})
		return
	}

	// Prepare fingerprint info for device/session info
	fp := &models.Fingerprint{
		UserAgent:      c.Request.UserAgent(),
		IPAddress:      c.ClientIP(),
		AcceptLanguage: c.GetHeader("Accept-Language"),
		AcceptEncoding: c.GetHeader("Accept-Encoding"),
	}

	loginData := &models.LoginRequest{
		LoginEmail:    req.LoginEmail,
		LoginPassword: req.LoginPassword,
	}

	// Call login service
	loginResponse, err := h.authService.Login(c.Request.Context(), loginData, fp)
	if err != nil {
		log.Printf("%s error logging in user: %v", funcLogPrefix, err)
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid email or password"})
		return
	}

	// Set refresh token as secure, HTTP-only cookie
	http.SetCookie(c.Writer, &http.Cookie{
		Name:     "refresh_token",
		Value:    loginResponse.RefreshToken,
		Path:     "/",
		HttpOnly: true,
		Secure:   false, // TODO: set true in production with HTTPS
		SameSite: http.SameSiteStrictMode,
		MaxAge:   7 * 24 * 60 * 60, // 7 days
	})

	// Return login response (without refresh token)
	c.JSON(http.StatusOK, gin.H{
		"message": "Login successful",
		"data": gin.H{
			"accesstoken": loginResponse.AccessToken,
			"userid":      loginResponse.UserID,
			"email":       loginResponse.Email,
			"role":        loginResponse.Role,
			"deviceid":    loginResponse.DeviceID,
		},
	})
}

// RefreshTokenHandler issues a new access token based on a valid refresh token and device ID.
func (h *AuthHandler) RefreshTokenHandler(c *gin.Context) {
	const funcName = "RefreshTokenHandler:"
	funcLogPrefix := auth_handlerFileLogPrefix + funcName

	// Extract refresh token cookie
	refreshToken, err := c.Cookie("refresh_token")
	if err != nil || refreshToken == "" {
		log.Printf("%s missing refresh token cookie: %v", funcLogPrefix, err)
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Refresh token missing"})
		return
	}

	// Validate device ID header
	deviceID := c.GetHeader("X-Device-ID")
	if deviceID == "" {
		log.Printf("%s missing device ID header", funcLogPrefix)
		c.JSON(http.StatusBadRequest, gin.H{"error": "Device ID missing"})
		return
	}

	reqData := &models.NewAccessTokenRequest{
		RefreshToken: refreshToken,
		DeviceID:     deviceID,
	}

	fp := &models.Fingerprint{
		UserAgent:      c.Request.UserAgent(),
		IPAddress:      c.ClientIP(),
		AcceptLanguage: c.GetHeader("Accept-Language"),
		AcceptEncoding: c.GetHeader("Accept-Encoding"),
	}

	// Call service to refresh token
	res, err := h.authService.RefreshTokenService(c.Request.Context(), reqData, fp)
	if err != nil {
		log.Printf("%s error refreshing token: %v", funcLogPrefix, err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to refresh token"})
		return
	}

	// Set new refresh token cookie
	http.SetCookie(c.Writer, &http.Cookie{
		Name:     "refresh_token",
		Value:    res.RefreshToken,
		Path:     "/",
		HttpOnly: true,
		Secure:   false, // TODO: set true in production
		SameSite: http.SameSiteStrictMode,
		MaxAge:   7 * 24 * 60 * 60,
	})

	c.JSON(http.StatusOK, gin.H{
		"message": "New access token issued successfully.",
		"data":    res,
	})
}

// LogoutHandler handles user logout by invalidating tokens and clearing refresh token cookie.
func (h *AuthHandler) LogoutHandler(c *gin.Context) {
	const funcName = "LogoutHandler:"
	funcLogPrefix := auth_handlerFileLogPrefix + funcName

	authHeader := c.GetHeader("Authorization")
	if authHeader == "" || !strings.HasPrefix(authHeader, "Bearer ") {
		log.Printf("%s missing or invalid Authorization header", funcLogPrefix)
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Access token missing"})
		return
	}
	accessToken := strings.TrimPrefix(authHeader, "Bearer ")

	refreshToken, err := c.Cookie("refresh_token")
	if err != nil || refreshToken == "" {
		log.Printf("%s missing refresh token cookie: %v", funcLogPrefix, err)
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Refresh token missing"})
		return
	}

	req := &models.LogoutRequest{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
	}

	if err := h.authService.Logout(req); err != nil {
		log.Printf("%s error logging out user: %v", funcLogPrefix, err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Logout failed"})
		return
	}

	// Clear refresh token cookie
	http.SetCookie(c.Writer, &http.Cookie{
		Name:     "refresh_token",
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   false, // TODO: set true in production
		SameSite: http.SameSiteStrictMode,
	})

	c.JSON(http.StatusOK, gin.H{"message": "Logout successful"})
}

// ForgotPasswordHandler initiates the password reset process by sending a reset link if the email exists.
func (h *AuthHandler) ForgotPasswordHandler(c *gin.Context) {
	const funcName = "ForgotPasswordHandler:"
	funcLogPrefix := auth_handlerFileLogPrefix + funcName

	var req models.ForgotPasswordRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		log.Printf("%s invalid forgot password request: %v", funcLogPrefix, err)
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid input"})
		return
	}

	if err := h.authService.ForgotPasswordService(&req); err != nil {
		log.Printf("%s error sending password reset link: %v", funcLogPrefix, err)
		// Intentionally do not reveal failure to client for security reasons
	}

	c.JSON(http.StatusOK, gin.H{"message": "If the email is registered, a reset link has been sent."})
}

// ResetPasswordHandler processes password reset requests using a valid reset token.
func (h *AuthHandler) ResetPasswordHandler(c *gin.Context) {
	const funcName = "ResetPasswordHandler:"
	funcLogPrefix := auth_handlerFileLogPrefix + funcName

	token := c.Query("token")
	if token == "" {
		log.Printf("%s missing reset token in query", funcLogPrefix)
		c.JSON(http.StatusBadRequest, gin.H{"error": "Missing reset token"})
		return
	}

	var req models.ResetPasswordRequest
	req.Token = token

	if err := c.ShouldBindJSON(&req); err != nil {
		log.Printf("%s invalid reset password request: %v", funcLogPrefix, err)
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid input"})
		return
	}

	if err := h.authService.ResetPasswordService(req); err != nil {
		log.Printf("%s error resetting password: %v", funcLogPrefix, err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to reset password"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Password has been reset successfully"})
}
