package handlers

import (
	"fmt"
	"net/http"
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
		FullName:     req.FullName,
		Email:        req.Email,
		Phone:        req.Phone,
		PasswordHash: req.Password, // will be hashed inside the service
		IsVerified:   false,
		CreatedAt:    time.Now(),
		UpdatedAt:    time.Now(),
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

	LoginResponse,err := h.authService.Login(c.Request.Context(), LoginData)
	if err != nil {
		fmt.Errorf("auth-system:internal:handlers:auth_handler:Login: Error Logging user: %v\n", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return 
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "Login successful",
		"data":    LoginResponse, // resp should be of type LoginResponse
	})
}
