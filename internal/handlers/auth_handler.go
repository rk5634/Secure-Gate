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

func NewAuthHandler(authService services.UserService) *AuthHandler {
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
		c.JSON(http.StatusInternalServerError, gin.H{"error": "could not create user"})
		return
	}

	c.JSON(http.StatusCreated, gin.H{"message": "user registered successfully"})
}
