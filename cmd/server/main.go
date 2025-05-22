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
	"github.com/rkcuwork/auth-system/internal/redis"
	"github.com/rkcuwork/auth-system/internal/repository"
	"github.com/rkcuwork/auth-system/internal/services"
)

func main() {
	// Load configuration
	cfg := config.LoadConfig()

	// Print the config (optional)
	fmt.Printf("Loaded Config: %+v\n", cfg)

	// Initialize DB connection
	db.Init()
	redisclient := redis.Init()

	// Set up Gin router
	r := gin.Default()

	// Test route
	r.GET("/", func(c *gin.Context) {
		c.JSON(200, gin.H{"message": "Hi dev, Auth System is up and running!"})
	})

	
	
	repo := repository.NewUserRepository()

	
	// Email verification setup
	private_key,_ := services.LoadPrivateKey()
	public_key,_ := services.LoadPublicKey()
	emailRepo := emailverification.NewRepository()
	tokenMgr := emailverification.NewTokenManager(private_key,public_key)
	emailSender, err := emailverification.NewSESClient(cfg.SenderEmail)
	if err != nil {
		log.Fatalf("Failed to initialize SES client: %v", err)
	}
	emailService := emailverification.NewService(emailRepo, tokenMgr, emailSender, cfg.BaseURL)
	emailHandler := emailverification.NewHandler(emailService,repo)

	tokenmanager := services.NewTokenManager(private_key,public_key,redisclient)
	authService := services.NewUserService(repo, emailService,tokenmanager)
	authHandler := handlers.NewAuthHandler(authService)

	emailupdaterepo := emailupdate.NewRepository()
	emailupdateservice := emailupdate.NewService(emailupdaterepo, emailService)
	emailupdatehandler := emailupdate.NewHandler(emailupdateservice)
	
	r.GET("/verify-email", emailHandler.VerifyEmailHandler)
	r.POST("/signup", authHandler.Register)
	r.POST("/login", authHandler.Login)
	r.POST("/resend-email-verification", emailHandler.SendVerificationEmailHandler)
	r.PUT("/update-email", emailupdatehandler.UpdateEmailHandler)
	r.POST("/refresh", authHandler.RefreshTokenHandler)
	
	
	






	// Start server
	log.Printf("Server is starting on port %s...\n", cfg.Port)
	err = r.Run(":" + cfg.Port)
	if err != nil {
		log.Fatalf("auth-system:cmd:server:main: failed to start server on port %s: %v", cfg.Port, err)
	}

}
