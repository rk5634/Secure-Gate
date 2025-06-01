package emailupdate

import (
	"log"
	"net/http"

	"github.com/gin-gonic/gin"
)

// handlerFileLogPrefix is the file-level prefix for all log messages in this file
const handlerFileLogPrefix = packageLogPrefix+"handler:"

// Handler handles HTTP requests related to email updates.
type Handler struct {
	service *Service
}

// NewHandler creates a new Handler instance with the provided service dependency.
// It validates input parameters and prepares the Handler for use.
func NewHandler(service *Service) *Handler {
	const funcName = "NewHandler:"
	funcLogPrefix := handlerFileLogPrefix + funcName

	if service == nil {
		log.Fatalf("%s service dependency cannot be nil", funcLogPrefix)
	}
	return &Handler{service: service}
}

// UpdateEmailHandler handles the update email HTTP request.
// It validates input, calls the service layer, and responds accordingly.
func (h *Handler) UpdateEmailHandler(c *gin.Context) {
	const funcName = "UpdateEmailHandler:"
	funcLogPrefix := handlerFileLogPrefix + funcName

	var req UpdateEmailRequest

	// Validate and bind JSON request payload
	if err := c.ShouldBindJSON(&req); err != nil {
		log.Printf("%s invalid request payload: %v", funcLogPrefix, err)
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
		return
	}

	// Perform the email update operation via service layer
	res, err := h.service.UpdateEmail(c.Request.Context(), req.UserID, req.NewEmail)
	if err != nil {
		log.Printf("%s failed to update email for user %s: %v", funcLogPrefix, req.UserID, err)
		c.JSON(http.StatusInternalServerError, gin.H{
			"error":    err.Error(),
			"response": res,
		})
		return
	}

	// Success response
	c.JSON(http.StatusOK, gin.H{"response": res})
}
