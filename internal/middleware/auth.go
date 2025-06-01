package middleware

import (
	"net/http"
	"strings"
	"log"

	"github.com/gin-gonic/gin"
	"github.com/rkcuwork/auth-system/internal/services" // adjust import path
)

// Define a file-level log prefix for the auth middleware
const authMiddlewareLogPrefix = packageLogPrefix + "auth"

// AuthMiddleware validates JWT access tokens and extracts user info into context.
func AuthMiddleware(tokenManager *services.TokenManager) gin.HandlerFunc {
	return func(c *gin.Context) {
		const funcName = "AuthMiddleware:"
		funcLogPrefix := authMiddlewareLogPrefix + funcName

		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			log.Printf("%s Missing Authorization header", funcLogPrefix)
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Missing Authorization header"})
			return
		}

		parts := strings.Split(authHeader, " ")
		if len(parts) != 2 || strings.ToLower(parts[0]) != "bearer" {
			log.Printf("%s Invalid Authorization format: %s", funcLogPrefix, authHeader)
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Invalid Authorization format"})
			return
		}

		accessToken := parts[1]

		isValid, claims, err := tokenManager.IsValidAccessToken(accessToken)
		if err != nil || !isValid {
			log.Printf("%s Invalid access token: %v", funcLogPrefix, err)
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
			return
		}

		userID, _ := claims["sub"].(string)
		email, _ := claims["email"].(string)

		c.Set("userID", userID)
		c.Set("email", email)

		log.Printf("%s Access token validated for userID: %s", funcLogPrefix, userID)
		c.Next()
	}
}
