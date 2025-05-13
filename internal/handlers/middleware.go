package handlers


// import (
// 	"net/http"
// 	"strings"

// 	"github.com/gin-gonic/gin"
// 	"github.com/rkcuwork/auth-system/internal/services"
// )

// func AuthMiddleware(jwtService services.JWTService) gin.HandlerFunc {
// 	return func(c *gin.Context) {
// 		authHeader := c.GetHeader("Authorization")
// 		if authHeader == "" {
// 			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Authorization header is missing"})
// 			return
// 		}

// 		// Expecting format: "Bearer <token>"
// 		parts := strings.Split(authHeader, " ")
// 		if len(parts) != 2 || parts[0] != "Bearer" {
// 			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Invalid Authorization header format"})
// 			return
// 		}

// 		tokenStr := parts[1]

// 		// Validate the token
// 		claims, err := jwtService.ValidateToken(tokenStr)
// 		if err != nil {
// 			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Invalid or expired token"})
// 			return
// 		}

// 		// You can now store claims (like user ID or email) in context
// 		c.Set("user_id", claims.UserID)
// 		c.Set("email", claims.Email)

// 		// Continue to next handler
// 		c.Next()
// 	}
// }
