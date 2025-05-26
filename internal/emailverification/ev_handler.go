package emailverification

import (
	"fmt"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/rkcuwork/auth-system/internal/repository"
)

type Handler struct {
	service *Service
	repo    repository.UserRepository
}

func NewHandler(s *Service,repo repository.UserRepository) *Handler {
	return &Handler{service: s, repo: repo}
}

// VerifyEmailHandler handles GET /verify-email?token=...
func (h *Handler) VerifyEmailHandler(c *gin.Context) {
	token := c.Query("token")
	if token == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "missing token"})
		return
	}

	err := h.service.VerifyEmail(c.Request.Context(), token)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid or expired token"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Email verified successfully! You can now login."})
}



func (h *Handler) SendVerificationEmailHandler(c *gin.Context) {
	var req struct {
		Email string `json:"email" binding:"required,email"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		fmt.Printf("auth-system:internal:emailverification:ev_handler:SendVerificationEmailHandler: Error binding JSON: %v\n", err)
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid email format"})
		return
	}

	user, err := (h.repo).GetUserByEmail(c.Request.Context(), req.Email)

	if(user.IsEmailVerified) {
		c.JSON(http.StatusOK, gin.H{"message": "Email already verified"})
		return
	}

	if err != nil {
		fmt.Printf("auth-system:internal:emailverification:ev_handler:GetUserByEmail: Error getting user by email: %v\n", err)
		c.JSON(http.StatusNotFound, gin.H{"error": "User not found"})
		return
	}
	err = h.service.SendVerificationEmail(c.Request.Context(), user.ID, req.Email)
	if err != nil {
		fmt.Printf("auth-system:internal:emailverification:ev_handler:SendVerificationEmailHandler: Error sending verification email: %v\n", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to send verification email"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "Verification email sent"})

}



