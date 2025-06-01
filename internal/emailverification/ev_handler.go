package emailverification

import (
	"log"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/rkcuwork/auth-system/internal/repository"
)

// ev_handlerFileLogPrefix is the file-level prefix for all log messages in this file
const ev_handlerFileLogPrefix = packageLogPrefix + "ev_handler:"

// Handler handles email verification-related HTTP requests.
type Handler struct {
	service *Service
	repo    repository.UserRepository
}

// NewHandler creates a new Handler instance with service and repository dependencies.
func NewHandler(s *Service, repo repository.UserRepository) *Handler {
	const funcName = "NewHandler:"
	funcLogPrefix := ev_handlerFileLogPrefix + funcName

	if s == nil {
		log.Fatalf("%s service dependency cannot be nil", funcLogPrefix)
	}
	if repo == nil {
		log.Fatalf("%s user repository dependency cannot be nil", funcLogPrefix)
	}

	return &Handler{service: s, repo: repo}
}

// VerifyEmailHandler handles GET /verify-email?token=...
func (h *Handler) VerifyEmailHandler(c *gin.Context) {
	const funcName = "VerifyEmailHandler:"
	funcLogPrefix := ev_handlerFileLogPrefix + funcName

	token := c.Query("token")
	if token == "" {
		log.Printf("%s missing token in query", funcLogPrefix)
		c.JSON(http.StatusBadRequest, gin.H{"error": "Missing token"})
		return
	}

	if err := h.service.VerifyEmail(c.Request.Context(), token); err != nil {
		log.Printf("%s token verification failed: %v", funcLogPrefix, err)
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid or expired token"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Email verified successfully! You can now login."})
}


// SendVerificationEmailHandler handles POST /send-verification-email
func (h *Handler) SendVerificationEmailHandler(c *gin.Context) {
	const funcName = "SendVerificationEmailHandler:"
	funcLogPrefix := ev_handlerFileLogPrefix + funcName

	var req struct {
		Email string `json:"email" binding:"required,email"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		log.Printf("%s error binding request JSON: %v", funcLogPrefix, err)
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid email format"})
		return
	}

	user, err := h.repo.GetUserByEmail(c.Request.Context(), req.Email)
	if err != nil {
		log.Printf("%s failed to get user by email (%s): %v", funcLogPrefix, req.Email, err)
		c.JSON(http.StatusNotFound, gin.H{"error": "User not found"})
		return
	}

	if user == nil {
		log.Printf("%s no user returned from repository for email: %s", funcLogPrefix, req.Email)
		c.JSON(http.StatusNotFound, gin.H{"error": "User not found"})
		return
	}

	if user.IsEmailVerified {
		log.Printf("%s email already verified for user ID: %s", funcLogPrefix, user.ID)
		c.JSON(http.StatusOK, gin.H{"message": "Email already verified"})
		return
	}

	if err := h.service.SendVerificationEmail(c.Request.Context(), user.ID, req.Email); err != nil {
		log.Printf("%s error sending verification email to %s: %v", funcLogPrefix, req.Email, err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to send verification email"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Verification email sent"})
}
