package emailupdate

import (

	"net/http"

	"github.com/gin-gonic/gin"
)

type Handler struct {
	service *Service
}

func NewHandler(service *Service) *Handler {
	return &Handler{service: service}
}

func (h *Handler) UpdateEmailHandler(c *gin.Context) {
	var req UpdateEmailRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
		return
	}

	
	res, err := h.service.UpdateEmail(c.Request.Context(), req.UserID, req.NewEmail)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error(),
													"response": res})
		return
	}

	c.JSON(http.StatusOK, gin.H{"response": res})
}
