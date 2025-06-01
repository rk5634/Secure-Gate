package main

import (
	"fmt"
	"log"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/rkcuwork/auth-system/internal/config"
	"github.com/rkcuwork/auth-system/internal/db"
	"github.com/rkcuwork/auth-system/internal/emailupdate"
	"github.com/rkcuwork/auth-system/internal/emailverification"
	"github.com/rkcuwork/auth-system/internal/handlers"
	"github.com/rkcuwork/auth-system/internal/middleware"
	"github.com/rkcuwork/auth-system/internal/oauth"
	"github.com/rkcuwork/auth-system/internal/redis"
	"github.com/rkcuwork/auth-system/internal/repository"
	"github.com/rkcuwork/auth-system/internal/services"
	"github.com/rkcuwork/auth-system/pkg/twilio"
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
	tokenManager := services.NewTokenManager(privateKey, publicKey, redisclient,repo)

	emailRepo := emailverification.NewRepository()
	emailTokenMgr := emailverification.NewTokenManager(privateKey, publicKey)
	emailSender, err := emailverification.NewSESClient(cfg.SenderEmail)
	if err != nil {
		log.Fatalf("Failed to initialize SES client: %v", err)
	}
	emailService := emailverification.NewService(emailRepo, emailTokenMgr, emailSender, cfg.BaseURL)
	emailHandler := emailverification.NewHandler(emailService, repo)

	twilioservice := twilio.NewTwilioService(cfg.TWILIO_ACCOUNT_SID, cfg.TWILIO_AUTH_TOKEN, cfg.TWILIO_VERIFY_SERVICE_SID)

	authService := services.NewUserService(repo, emailService, tokenManager, twilioservice)
	authHandler := handlers.NewAuthHandler(authService)

	emailUpdateRepo := emailupdate.NewRepository()
	emailUpdateService := emailupdate.NewService(emailUpdateRepo, emailService)
	emailUpdateHandler := emailupdate.NewHandler(emailUpdateService)
	googleservice := oauth.NewGoogleOauthService(tokenManager)
	googleoauthHandler := oauth.NewGoogleOAuthHandler(googleservice)





	// Assume redisClient, maxTokens, refillInterval are already initialized, e.g.:
	// maxTokens := 5
	refillInterval := time.Minute

	// IP rate limit middleware instance
	ipRateLimit := handlers.IPRateLimitMiddleware(redisclient.Client, 10, refillInterval)

	// Advanced rate limit middleware instance (usually stricter or per user/device)
	advancedRateLimit := handlers.AdvancedRateLimitMiddleware(redisclient.Client, 10, refillInterval)

	// Public routes with IP-based rate limiting (general limit per IP)
	public := r.Group("/", ipRateLimit)
	{
		public.GET("/verify-email", emailHandler.VerifyEmailHandler)
		public.POST("/signup", authHandler.Register)
		public.POST("/login", authHandler.Login)
		public.POST("/resend-email-verification", emailHandler.SendVerificationEmailHandler)
		public.PUT("/update-email", emailUpdateHandler.UpdateEmailHandler)
		public.POST("/forgot-password", authHandler.ForgotPasswordHandler)
		public.POST("/reset-password", authHandler.ResetPasswordHandler)
		public.POST("/send-otp", authHandler.SendOTPHandler)
		public.POST("/verify-otp", authHandler.VerifyOTPHandler)
		public.GET("/oauth/google/login", googleoauthHandler.HandleGoogleLogin)
		public.GET("/oauth/google/callback", googleoauthHandler.HandleGoogleCallback)
	}


	// Group routes that require Advanced Rate Limiting
	advancedRateLimited := r.Group("/")
	advancedRateLimited.Use(advancedRateLimit)
	{
		advancedRateLimited.POST("/refresh", authHandler.RefreshTokenHandler)
		advancedRateLimited.POST("/logout", authHandler.LogoutHandler)
	}

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
