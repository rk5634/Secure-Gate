package handlers

import (
	"fmt"
	"net/http"
	"github.com/gin-gonic/gin"
	"github.com/rkcuwork/auth-system/internal/models"

)



func (h *AuthHandler) SendOTPHandler(c *gin.Context) {
	var req *models.SendOTPRequest

	if err := c.ShouldBindJSON(&req); err != nil || req.PhoneNumber == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid input or missing phone number"})
		return
	}

	err := h.authService.SendOTPService(req.PhoneNumber)
	if err != nil {
		fmt.Printf("auth-system:internal:handlers:phone_handler:SendOTPHandler: Error sending OTP: %v\n", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to send OTP"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "OTP sent successfully"})
}




func (h *AuthHandler) VerifyOTPHandler(c *gin.Context) {
	var req *models.VerifyOTPRequest

	if err := c.ShouldBindJSON(&req); err != nil || req.PhoneNumber == "" || req.OTP == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid input. Phone number and OTP are required"})
		return
	}

	err := h.authService.VerifyOTPService(req.PhoneNumber, req.OTP)
	if err != nil {
		fmt.Printf("auth-system:internal:handlers:phone_handler:VerifyOTPHandler: Error verifying OTP: %v\n", err)
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid or expired OTP"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Phone number verified successfully"})
}
