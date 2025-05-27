package models

import "time"




type User struct {
	ID              string    `json:"id"`
	FullName        string    `json:"full_name"`
	Email           string    `json:"email"`
	Phone           string    `json:"phone,omitempty"`
	PasswordHash    string    `json:"-"`
	IsEmailVerified bool      `json:"is_email_verified"`
	IsPhoneVerified bool      `json:"is_phone_verified"`
	TokenVersion    int       `json:"token_version"`
	CreatedAt       time.Time `json:"created_at"`
	UpdatedAt       time.Time `json:"updated_at"`
}





type RegisterRequest struct {
	FullName string `json:"full_name" binding:"required"`
	Email    string `json:"email" binding:"required,email"`   // Validates correct email format
	Phone    string `json:"phone" binding:"omitempty,e164"`  // Validates phone number (E.164 format)
	Password string `json:"password" binding:"required,min=8,max=50"` // Password complexity
}


type Fingerprint struct{
	UserAgent string `json:"useragent"` // User agent for tracking
	IPAddress string `json:"ipaddress"` // IP address for tracking
	AcceptLanguage string `json:"acceptlanguage"` // Accept language for tracking
	AcceptEncoding string `json:"acceptencoding"` // Accept encoding for tracking	
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
	DeviceID string `json:"deviceid"`
}

type NewAccessTokenRequest struct {
	RefreshToken string `json:"refreshtoken" validate:"required"`
	DeviceID string `json:"deviceid" validate:"required"`
}



type NewAccessTokenResponse struct{
	AccessToken string `json:"accesstoken"`
	RefreshToken string `json:"refreshtoken"`
}


type LogoutRequest struct {
	AccessToken string `json:"accesstoken"`
	RefreshToken string `json:"refreshtoken"`
}


type ForgotPasswordRequest struct {
	Email string `json:"email" validate:"required,email"`
}

type ResetPasswordRequest struct {
	Token       string `json:"token" binding:"required"`
	NewPassword string `json:"newpassword" binding:"required,min=8"`
}



type SendOTPRequest struct {
	PhoneNumber string `json:"phone" binding:"required"`
}

type VerifyOTPRequest struct {
	PhoneNumber string `json:"phone" binding:"required"`
	OTP   string `json:"otp" binding:"required"`
}
