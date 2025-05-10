package main

import (
	"fmt"
	"log"

	"github.com/rkcuwork/auth-system/internal/config"
	"github.com/gin-gonic/gin"
	"github.com/rkcuwork/auth-system/internal/db"
	"github.com/rkcuwork/auth-system/internal/handlers"
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

	// Set up Gin router
	r := gin.Default()

	// Test route
	r.GET("/", func(c *gin.Context) {
		c.JSON(200, gin.H{"message": "Auth System is up and running!"})
	})
	
	
	repo := repository.NewUserRepository()
	authService := services.NewUserService(repo)
	authHandler := handlers.NewAuthHandler(authService)

	r.POST("/signup", authHandler.Register)


	// Start server
	log.Printf("Server is starting on port %s...\n", cfg.Port)
	err := r.Run(":" + cfg.Port)
	if err != nil {
		log.Fatalf("auth-system:cmd:server:main: failed to start server on port %s: %v", cfg.Port, err)
	}





}
