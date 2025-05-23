package middleware

import (
    "github.com/rkcuwork/auth-system/internal/services" // adjust import path
    "net/http"
    "strings"

    "github.com/gin-gonic/gin"
)

func AuthMiddleware(tokenManager *services.TokenManager) gin.HandlerFunc {
    return func(c *gin.Context) {
        authHeader := c.GetHeader("Authorization")
        if authHeader == "" {
            c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Missing Authorization header"})
            return
        }

        parts := strings.Split(authHeader, " ")
        if len(parts) != 2 || strings.ToLower(parts[0]) != "bearer" {
            c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Invalid Authorization format"})
            return
        }

        accessToken := parts[1]

        // ✅ Validate using your service function
        isValid, claims, err := tokenManager.IsValidAccessToken(accessToken)
        if err != nil || !isValid {
            c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
            return
        }

        // ✅ Extract userID and role and add to Gin context
        userID, _ := claims["sub"].(string)
		email, _ := claims["email"].(string)
      

        c.Set("userID", userID)
        c.Set("email", email)


        c.Next()
    }
}
