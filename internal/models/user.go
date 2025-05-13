package models

import "time"

type User struct {
	ID           string    `json:"id"`
	FullName     string    `json:"full_name"`
	Email        string    `json:"email"`
	Phone        string    `json:"phone,omitempty"`
	PasswordHash string    `json:"-"`
	IsVerified   bool      `json:"is_verified"`
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`
}




type RegisterRequest struct {
	FullName string `json:"full_name" binding:"required"`
	Email    string `json:"email" binding:"required,email"`   // Validates correct email format
	Phone    string `json:"phone" binding:"omitempty,e164"`  // Validates phone number (E.164 format)
	Password string `json:"password" binding:"required,min=8,max=50"` // Password complexity
}



// LoginRequest represents login input
type LoginRequest struct {
    LoginEmail    string `json:"email" validate:"required,email"`
    LoginPassword string `json:"password" validate:"required"`
}

// LoginResponse represents login success output
type LoginResponse struct {
    AccessToken string `json:"accesstoken"`
	RefreshToken string `json:"refreshtoken"`
    UserID  string   `json:"userid"`
	Email string `json:"email"`
	Role string `json:"role"`
}