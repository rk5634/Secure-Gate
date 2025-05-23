package main

import (
	"fmt"
	"log"

	"github.com/gin-gonic/gin"
	"github.com/rkcuwork/auth-system/internal/config"
	"github.com/rkcuwork/auth-system/internal/db"
	"github.com/rkcuwork/auth-system/internal/emailupdate"
	"github.com/rkcuwork/auth-system/internal/emailverification"
	"github.com/rkcuwork/auth-system/internal/handlers"
	"github.com/rkcuwork/auth-system/internal/middleware"        
	"github.com/rkcuwork/auth-system/internal/redis"
	"github.com/rkcuwork/auth-system/internal/repository"
	"github.com/rkcuwork/auth-system/internal/services"
)

func main() {
	// Load configuration
	cfg := config.LoadConfig()
	fmt.Printf("Loaded Config: %+v\n", cfg)

	// Initialize DB and Redis
	db.Init()
	redisclient := redis.Init()

	// Gin router
	r := gin.Default()

	// Test route
	r.GET("/", func(c *gin.Context) {
		c.JSON(200, gin.H{"message": "Hi dev, Auth System is up and running!"})
	})

	// Initialize services
	repo := repository.NewUserRepository()
	privateKey, _ := services.LoadPrivateKey()
	publicKey, _ := services.LoadPublicKey()
	tokenManager := services.NewTokenManager(privateKey, publicKey, redisclient)

	emailRepo := emailverification.NewRepository()
	emailTokenMgr := emailverification.NewTokenManager(privateKey, publicKey)
	emailSender, err := emailverification.NewSESClient(cfg.SenderEmail)
	if err != nil {
		log.Fatalf("Failed to initialize SES client: %v", err)
	}
	emailService := emailverification.NewService(emailRepo, emailTokenMgr, emailSender, cfg.BaseURL)
	emailHandler := emailverification.NewHandler(emailService, repo)

	authService := services.NewUserService(repo, emailService, tokenManager)
	authHandler := handlers.NewAuthHandler(authService)

	emailUpdateRepo := emailupdate.NewRepository()
	emailUpdateService := emailupdate.NewService(emailUpdateRepo, emailService)
	emailUpdateHandler := emailupdate.NewHandler(emailUpdateService)

	// Public routes
	r.GET("/verify-email", emailHandler.VerifyEmailHandler)
	r.POST("/signup", authHandler.Register)
	r.POST("/login", authHandler.Login)
	r.POST("/resend-email-verification", emailHandler.SendVerificationEmailHandler)
	r.PUT("/update-email", emailUpdateHandler.UpdateEmailHandler)
	r.POST("/refresh", authHandler.RefreshTokenHandler)
	r.POST("/logout", authHandler.LogoutHandler)

	// ✅ Protected routes using AuthMiddleware
	protected := r.Group("/api")
	protected.Use(middleware.AuthMiddleware(tokenManager))
	{
		protected.GET("/me", func(c *gin.Context) {
			userID := c.GetString("userID")
			role := c.GetString("email")
			c.JSON(200, gin.H{"message": "Welcome to protected route", "userID": userID, "email": role})
		})
	}

	// Start server
	log.Printf("Server is starting on port %s...\n", cfg.Port)
	err = r.Run(":" + cfg.Port)
	if err != nil {
		log.Fatalf("auth-system:cmd:server:main: failed to start server on port %s: %v", cfg.Port, err)
	}
}
