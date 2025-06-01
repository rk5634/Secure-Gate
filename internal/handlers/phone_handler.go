package handlers

import (
	"fmt"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/rkcuwork/auth-system/internal/models"
)

const phoneHandlerLogPrefix = packageLogPrefix + "phone_handler:"

// SendOTPHandler handles sending OTP codes to user phone numbers.
func (h *AuthHandler) SendOTPHandler(c *gin.Context) {
	const funcName = "SendOTPHandler:"
	funcLogPrefix := phoneHandlerLogPrefix + funcName

	var req *models.SendOTPRequest

	if err := c.ShouldBindJSON(&req); err != nil || req.PhoneNumber == "" {
		fmt.Printf("%s Invalid input or missing phone number\n", funcLogPrefix)
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid input or missing phone number"})
		return
	}

	err := h.authService.SendOTPService(req.PhoneNumber)
	if err != nil {
		fmt.Printf("%s Error sending OTP: %v\n", funcLogPrefix, err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to send OTP"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "OTP sent successfully"})
}

// VerifyOTPHandler handles verifying OTP codes for phone number confirmation.
func (h *AuthHandler) VerifyOTPHandler(c *gin.Context) {
	const funcName = "VerifyOTPHandler:"
	funcLogPrefix := phoneHandlerLogPrefix + funcName

	var req *models.VerifyOTPRequest

	if err := c.ShouldBindJSON(&req); err != nil || req.PhoneNumber == "" || req.OTP == "" {
		fmt.Printf("%s Invalid input. Phone number and OTP are required\n", funcLogPrefix)
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid input. Phone number and OTP are required"})
		return
	}

	err := h.authService.VerifyOTPService(req.PhoneNumber, req.OTP)
	if err != nil {
		fmt.Printf("%s Error verifying OTP: %v\n", funcLogPrefix, err)
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid or expired OTP"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Phone number verified successfully"})
}
