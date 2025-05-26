package handlers

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/rkcuwork/auth-system/internal/models"
	"github.com/rkcuwork/auth-system/internal/services"
)

type AuthHandler struct {
	authService services.UserService

}

func NewAuthHandler(authService services.UserService, ) *AuthHandler {
	return &AuthHandler{authService: authService}
}

func (h *AuthHandler) Register(c *gin.Context) {
	var req models.RegisterRequest

	// Bind and validate input
	if err := c.ShouldBindJSON(&req); err != nil {
		fmt.Errorf("auth-system:internal:handlers:auth_handler:Register: Error binding JSON: %v\n", err)
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Construct internal User model
	user := &models.User{
		FullName:        req.FullName,
		Email:           req.Email,
		Phone:           req.Phone,
		PasswordHash:    req.Password, // will be hashed inside the service
		IsEmailVerified: false,
		IsPhoneVerified: false,
		TokenVersion:    0,
		CreatedAt:       time.Now(),
		UpdatedAt:       time.Now(),
	}


	err := h.authService.Register(c.Request.Context(), user)
	if err != nil {
		fmt.Errorf("auth-system:internal:handlers:auth_handler:Register: Error registering user: %v\n", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusCreated, gin.H{"message": "User registered successfully. Please check your email to verify your account."})
}




func (h *AuthHandler) Login(c *gin.Context) {

	// Check refresh token cookie
    if cookie, err := c.Request.Cookie("refresh_token"); err == nil {
        _, err := h.authService.ValidateToken(cookie.Value)
        if err == nil {
            c.JSON(http.StatusBadRequest, gin.H{"error": "User already logged in"})
            return
        }
    }




	var req models.LoginRequest

	// Bind and validate input
	if err := c.ShouldBindJSON(&req); err != nil {
		fmt.Errorf("auth-system:internal:handlers:auth_handler:Login: Error binding JSON: %v\n", err)
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Construct internal User model
	LoginData := &models.LoginRequest{
		LoginEmail:     req.LoginEmail,
		LoginPassword: req.LoginPassword, // will be hashed inside the service
		
	}

	fp := &models.Fingerprint{
		UserAgent:      c.Request.UserAgent(),
		IPAddress:      c.ClientIP(),
		AcceptLanguage: c.GetHeader("Accept-Language"),
		AcceptEncoding: c.GetHeader("Accept-Encoding"),
	}

	fmt.Printf("user-agent: %s\n", fp.UserAgent)

	LoginResponse,err := h.authService.Login(c.Request.Context(), LoginData,fp)
	if err != nil {
		fmt.Errorf("auth-system:internal:handlers:auth_handler:Login: Error Logging user: %v\n", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return 
	}


	// Set refresh token in secure HTTP-only cookie
	http.SetCookie(c.Writer, &http.Cookie{
		Name:     "refresh_token",
		Value:    LoginResponse.RefreshToken,
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
			"accesstoken": LoginResponse.AccessToken,
			"userid":      LoginResponse.UserID,
			"email":       LoginResponse.Email,
			"role":        LoginResponse.Role,
			"deviceid":    LoginResponse.DeviceID,
		},
	})
}



func (h *AuthHandler) RefreshTokenHandler(c *gin.Context) {
	
    // 1. Get refresh token from cookie
    refreshToken, err := c.Cookie("refresh_token")
    if err != nil || refreshToken == ""{
		c.JSON(http.StatusUnauthorized, gin.H{"error": "refresh token missing"})
        return
    }
	
	deviceID := c.GetHeader("X-Device-ID")
	if deviceID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "device ID missing"})
		return
	}

	newtokenreqdata := &models.NewAccessTokenRequest{
		RefreshToken: refreshToken,
		DeviceID: deviceID,
		
	}

	fp := &models.Fingerprint{
		UserAgent: c.Request.UserAgent(), 
		IPAddress: c.ClientIP(), 
		AcceptLanguage: c.GetHeader("Accept-Language"), 
		AcceptEncoding: c.GetHeader("Accept-Encoding"), 
	}

    res,err := h.authService.RefreshTokenService(c.Request.Context(),newtokenreqdata,fp)

	if err != nil {
		fmt.Printf("auth-system:internal:handlers:auth_handler:RefreshTokenHandler: Error: %v\n", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return 
	}

	http.SetCookie(c.Writer, &http.Cookie{
		Name:     "refresh_token",
		Value:    res.RefreshToken,
		Path:     "/",
		HttpOnly: true,
		Secure:   false, // set to false in local development if needed (not recommended)
		SameSite: http.SameSiteStrictMode,
		MaxAge:   7 * 24 * 60 * 60, // 7 days
	})

	c.JSON(http.StatusOK, gin.H{
		"message": "New access token issued successfully.",
		"data":    res, 
	})

}




func (h *AuthHandler) LogoutHandler(c *gin.Context) {
	// Get access token from Authorization header
	authHeader := c.GetHeader("Authorization")
	if authHeader == "" || !strings.HasPrefix(authHeader, "Bearer ") {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "access token missing"})
		return
	}
	accessToken := strings.TrimPrefix(authHeader, "Bearer ")

	// Get refresh token from cookie
    refreshToken, err := c.Cookie("refresh_token")
    if err != nil || refreshToken == ""{
		c.JSON(http.StatusUnauthorized, gin.H{"error": "refresh token missing"})
        return
    }

	req := &models.LogoutRequest{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
	}

	// Parse JWT to get jti and sub
	err = h.authService.Logout(req)
	if err != nil {
		fmt.Printf("auth-system:internal:handlers:auth_handler:LogoutHandler: Error Logging out user: %v\n", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	
	// 5. Clear refresh token cookie
	http.SetCookie(c.Writer, &http.Cookie{
		Name:     "refresh_token",
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   false, // change to true in production
		SameSite: http.SameSiteStrictMode,
	})

	// 6. Return response
	c.JSON(http.StatusOK, gin.H{
		"message": "Logout successful",
	})
}








func (h *AuthHandler) ForgotPasswordHandler(c *gin.Context) {
	var req *models.ForgotPasswordRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid input"})
		return
	}

	err := h.authService.ForgotPasswordService(req)
	if err != nil {
		fmt.Printf("auth-system:internal:handlers:auth_handler:ForgotPasswordHandler: Error in sending reset link: %v\n", err)
	}

	c.JSON(http.StatusOK, gin.H{"message": "If the email is registered, a reset link has been sent."})
}








func (h *AuthHandler) ResetPasswordHandler(c *gin.Context) {
	fmt.Printf("Inside ResetPasswordHandler\n")
	token := c.Query("token")
	if token == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "missing token"})
		return
	}

	fmt.Printf("token: %s\n", token)
	
	
	var req models.ResetPasswordRequest
	req.Token = token
	if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid input"})
			return
		}

	fmt.Printf("binded json: %v\n", req)

	err := h.authService.ResetPasswordService(req)
	if err != nil {
		fmt.Printf("auth-system:internal:handlers:auth_handler:ResetPasswordHandler: Error in resetting password: %v\n", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Password has been reset successfully"})
}





